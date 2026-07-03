# nlaproxy

NLA (Network Level Authentication) front-end for xrdp on Linux.

## What problem does this solve?

A Privileged Access Management (PAM) product — CyberArk PSM, BeyondTrust, Delinea,
HashiCorp Boundary, etc. — needs to broker an RDP session to a Linux target. The
PAM product *requires* NLA (CredSSP/NTLMv2) on the wire. The Linux target runs
**xrdp**, which **does not implement NLA**: it only speaks legacy
RDP-Security and TLS-only-with-cleartext-creds-in-the-Client-Info-PDU.

`nlaproxy` sits in front of xrdp and bridges the two:

```
┌────────────────┐        NLA (CredSSP/NTLMv2)        ┌─────────────────────────┐
│ PAM/CyberArk   │ ─────────── tcp/3389 ────────────► │ freerdp-proxy3          │
│ session broker │                                    │ + nlaproxy plugin       │
└────────────────┘                                    └─────────────────────────┘
                                                                  │
                                                                  │  TLS only
                                                                  │  + creds in
                                                                  │  Client Info PDU
                                                                  ▼
                                                       ┌─────────────────────────┐
                                                       │ xrdp on 127.0.0.1:3390  │
                                                       │  → sesman → PAM         │
                                                       │  → Xorg/Xvnc session    │
                                                       └─────────────────────────┘
```

## The "where does the password come from?" problem

NLA is a mutual-knowledge handshake: the server must already know the password
in order to verify the client's NTLM proof. Linux PAM (`pam_authenticate`) can
*verify* a password but cannot produce one, so a textbook "validate NLA via
PAM" implementation is mathematically impossible.

`nlaproxy` works around this by **harvesting passwords from a prior SSH login**:

1. The user (or an automated system) SSH's in to the target with password auth.
   A small custom PAM module (`pam_nlaproxy.so`) captures `PAM_AUTHTOK` on the
   `auth` stack (before sshd wipes it) and replays it on `session` to the local
   daemon.
2. The daemon (`nlaproxy-cached`) keeps the cleartext in memory encrypted with
   an ephemeral ChaCha20-Poly1305 key, TTL 5 min by default. It also exposes an
   NTHASH lookup for CredSSP.
3. The PAM/CyberArk server now does RDP-NLA to `:3389`. `freerdp-proxy3` walks
   NLA, and our plugin's `SspiNtlmHashCallback` provides the NT-hash on demand,
   computed from the client's *exact* Domain field so the NTLMv2 MIC always
   matches (see "NLA validation" below).
4. Our FreeRDP plugin (`proxy-nlaproxy-plugin.so`) hooks `ServerPostConnect`,
   queries the daemon for the plaintext password, and injects it into the
   upstream RDP settings along with `FreeRDP_AutoLogonEnabled=TRUE` so xrdp
   receives a Client Info PDU with `INFO_AUTOLOGON` set.
5. `freerdp-proxy3` opens a TLS connection to xrdp on `127.0.0.1:3390`, the
   creds land in the Client Info PDU, xrdp-sesman PAM-authenticates the user
   normally, and the session opens.

The cleartext password never leaves the host. The NT-hash is derived on demand
from the ephemeral-key-encrypted cache and never written to disk.

## The three subtle bugs this project had to solve

If you're reading this because you're building something similar, these are the
three non-obvious things that will bite you:

### 1. NLA MIC verification: match the client's Domain field exactly

Textbook approach: write an NTLMv1-style SAM file (`user:::nthash:::`) and let
WinPR do the CredSSP dance. That does not work for a proxy in front of a
generic RDP client, because NTLMv2 hashes bake in the *Domain* the client sent
in its NEGOTIATE_MESSAGE. Every RDP client picks a different Domain — mstsc
sends its own hostname, Delinea sends the target's hostname, other clients send
`.` or empty. You cannot enumerate all of them.

**Fix:** install `peer->SspiNtlmHashCallback` (`freerdp/peer.h:213`). WinPR
invokes it inside its NTLMv2 derivation with the exact (User, Domain) the
client sent. We compute `NTOWFv2FromHashW(nt_hash, user, domain)` on the fly.
MIC always matches, regardless of what Domain the client chose.

### 2. Delinea's password rewrite: capture identity in the NTLM callback

Delinea PSM is *itself* an NLA relay. It validates the incoming NLA against
its own vault and then **rewrites the TSPasswordCreds `authInfo` blob with a
per-session UUID** before forwarding it to us. By the time `ServerPostConnect`
runs, `settings->Username` and `settings->Password` contain that garbage UUID
(something like `d0489e30-d18c-4ae9-9b8d-10079bab68b8`), not the real user.

**Fix:** the `SspiNtlmHashCallback` receives the *raw* NTLM AUTHENTICATE_MESSAGE
identity, which is the real user (Delinea's rewrite happens only to
TSPasswordCreds, not to NTLM). We stash it in a per-peer session map keyed on
`freerdp_peer*` and retrieve it in `ServerPostConnect`.

### 3. xrdp autologin and fast-path output need explicit setting flips

Two settings on the pf_client's back-side rdpSettings must be forced TRUE, but
at very different points in the FreeRDP proxy lifecycle:

- **`FreeRDP_AutoLogonEnabled`** — Without this, FreeRDP's outbound Client Info
  PDU omits the `INFO_AUTOLOGON` flag, and xrdp treats our connection as
  "connected but hasn't submitted credentials yet" and displays its login
  screen. Populating Username/Password is not sufficient. Set this in
  `ServerPostConnect` on the back settings.

- **`FreeRDP_FastPathOutput`** — Delinea's Confirm Active PDU does not
  advertise the fast-path output capability bit, even though it decodes
  fast-path output PDUs fine. Setting it in `ServerPostConnect` on the front
  settings is not enough: `pf_client_post_connect` later calls
  `proxy_server_reactivate` → `pf_context_copy_settings(ps->settings,
  pc->settings)` which is a full `freerdp_settings_copy` that clobbers the
  setting with whatever xrdp's Demand Active PDU declared. **Fix:** register a
  `ServerPeerActivate` hook that re-forces `FastPathOutput=TRUE` on the front
  settings — this hook fires *after* the reactivation copy, so the setting
  survives to be readable by `fastpath_send_update_pdu`.

## Components

| Path                                                | Language | Purpose                                                |
|-----------------------------------------------------|----------|--------------------------------------------------------|
| `cached/`                                           | Rust     | Credential cache daemon + NTLM hash provider           |
| `pam_module/pam_nlaproxy.c`                         | C        | sshd-side PAM auth+session module (captures the password) |
| `proxy_plugin/nlaproxy_plugin.c`                    | C        | `freerdp-proxy3` plugin: NTLM hash callback, credential injection, session hooks |
| `packaging/systemd/nlaproxy-cached.service`         | unit     | Daemon service (root, RuntimeDirectory=nlaproxy)        |
| `packaging/systemd/nlaproxy-freerdp.service`        | unit     | freerdp-proxy3 service (user=nlaproxy, CAP_NET_BIND)    |
| `packaging/config/proxy.ini`                        | INI      | freerdp-proxy3 config (NLA front on 3389, TLS back to 3390) |
| `packaging/config/startwm.sh`                       | shell    | xrdp session launcher (KDE → Xfce → LXQt → xterm)      |
| `packaging/config/sshd.pam.snippet`                 | PAM      | Lines to add to `/etc/pam.d/sshd`                       |
| `packaging/install/install.sh`                      | bash     | One-shot idempotent installer                          |
| `packaging/install/nlaproxy.sysusers`               | sysusers | Creates the unprivileged `nlaproxy` system user        |

## Requirements

- Linux with systemd
- Rust 1.80+ (`cargo`) — only at build time
- C toolchain (`cc`, `make`, `pkg-config`)
- **FreeRDP 3** with the proxy binary, the proxy plugin runtime, **and** the
  development headers
- `xrdp` (the back-end)
- `openssh-server` on the same host (the credential capture point)
- PAM development headers

### Packages by distro

**Ubuntu / Debian:**

```sh
sudo apt install \
    freerdp3-proxy freerdp3-proxy-modules freerdp3-dev \
    winpr3-utils libpam0g-dev \
    xrdp openssh-server \
    build-essential pkg-config cargo
```

Verify the plugin dir exists (`/usr/lib/x86_64-linux-gnu/freerdp3/proxy/`):

```sh
ls /usr/lib/x86_64-linux-gnu/freerdp3/proxy/
# proxy-bitmap-filter-plugin.so  proxy-demo-plugin.so  proxy-dyn-channel-dump-plugin.so
```

**Arch:**

```sh
sudo pacman -S freerdp pam xrdp openssh rust
```

**Fedora / RHEL:**

```sh
sudo dnf install \
    freerdp freerdp-devel pam-devel \
    xrdp openssh-server \
    gcc make pkgconf cargo
```

If the installer complains that the FreeRDP plugin directory couldn't be
located, install `freerdp3-proxy-modules` (Debian/Ubuntu) or `freerdp` (Arch)
first — those packages ship the demo plugins that we use as a marker for the
correct directory, and are what the installer looks for.

### Desktop environment on the target

`xrdp` needs an **X11** session to render into — it cannot proxy Wayland. Our
`startwm.sh` searches for `startplasma-x11`, `startxfce4`, `startlxqt`, then
`xterm` in that order.

On **Ubuntu 26.04**, the default `kde-plasma-desktop` metapackage installs the
Wayland session only. To get an X11 Plasma session:

```sh
sudo apt install -y plasma-session-x11 dbus-x11
```

That installs `/usr/bin/startplasma-x11` which our launcher will auto-detect.

For a lighter footprint (or if you don't need KDE specifically):

```sh
sudo apt install -y xfce4 dbus-x11
# or
sudo apt install -y lxqt dbus-x11
```

You do not need to touch `startwm.sh` — it picks whichever launcher exists.

## Build and install

```sh
git clone https://github.com/anomalyco/nlaproxy
cd nlaproxy

# Build and install in one shot (interactive: asks before editing
# /etc/pam.d/sshd and /etc/xrdp/xrdp.ini)
sudo ./packaging/install/install.sh

# Or fully non-interactive:
sudo ASSUME_YES=1 ./packaging/install/install.sh

# Enable services
sudo systemctl enable --now nlaproxy-cached nlaproxy-freerdp
sudo systemctl restart sshd xrdp
```

The installer is idempotent — running it again to upgrade is safe and will
leave `/etc/nlaproxy/proxy.ini` alone if it already exists (a fresh copy
goes to `/etc/nlaproxy/proxy.ini.example`).

## Verifying the deployment

1. **SSH-capture path:**

   ```sh
   ssh alice@target              # password auth required
   sudo journalctl -u nlaproxy-cached --since '10s ago' | grep 'stored'
   ```

   You should see the daemon log the STORE. That confirms the sshd PAM module
   is wired in correctly.

2. **Front-end NLA:**

   ```sh
   xfreerdp3 /v:target:3389 /u:alice /p:'<the same password>' /sec:nla
   ```

   You should land in the xrdp session.

3. **Back-end xrdp is on the loopback-only port:**

   ```sh
   sudo ss -tnlp | grep -E ':3389|:3390'
   # LISTEN  0  4096   0.0.0.0:3389   ...  freerdp-proxy3
   # LISTEN  0  4096  127.0.0.1:3390  ...  xrdp
   ```

   3390 must be loopback-only — plaintext credentials pass through it.

4. **Diagnostic logs:**

   ```sh
   journalctl -u nlaproxy-cached -u nlaproxy-freerdp -u sshd -u xrdp -f
   ```

   For verbose protocol traces, override the freerdp-proxy unit:

   ```sh
   sudo systemctl edit nlaproxy-freerdp
   # [Service]
   # Environment=WLOG_LEVEL=DEBUG
   sudo systemctl restart nlaproxy-freerdp
   ```

5. **Session log:**

   `~/.xrdp-startwm.log` (in the RDP user's home) shows which launcher fired
   and any output from the desktop session start-up. Useful when the session
   opens but the desktop doesn't appear.

## Configuration knobs

### Cache daemon (`/etc/systemd/system/nlaproxy-cached.service.d/override.conf`)

| Env var                    | Default                          | Notes                                      |
|----------------------------|----------------------------------|--------------------------------------------|
| `NLAPROXY_SOCKET`          | `/run/nlaproxy/cached.sock`      | Where the daemon listens                   |
| `NLAPROXY_CONSUMER_USER`   | `nlaproxy`                       | Username allowed to LOOKUP / EVICT / NTHASH |
| `NLAPROXY_CONSUMER_GROUP`  | `nlaproxy`                       | Group that owns the socket                 |
| `NLAPROXY_TTL_SECS`        | `300`                            | How long cached passwords live             |

### PAM module (`/etc/pam.d/sshd`)

Two lines are required — one on the `auth` stack to snapshot the password
while it is still in `PAM_AUTHTOK`, and one on the `session` stack to replay
the snapshot to the daemon. Both must appear AFTER the real authenticator
(`@include common-auth` / `auth substack password-auth` / etc.):

```
auth       optional    pam_nlaproxy.so   socket=/run/nlaproxy/cached.sock
session    optional    pam_nlaproxy.so   socket=/run/nlaproxy/cached.sock
```

Arguments (apply to both stacks):
- `socket=<path>` — override the daemon socket
- `silent` — suppress non-error syslog output
- `keys_too` — call the daemon even when no password was captured (default:
  silently skip, e.g. for SSH key auth)

### FreeRDP plugin (`/etc/systemd/system/nlaproxy-freerdp.service.d/override.conf`)

| Env var                    | Default                          | Notes                                      |
|----------------------------|----------------------------------|--------------------------------------------|
| `NLAPROXY_PLUGIN_SOCKET`   | `/run/nlaproxy/cached.sock`      | Daemon socket to query. Used both at plugin load and per-session by the NTLM `SspiNtlmHashCallback`. |
| `NLAPROXY_PLUGIN_REQUIRE`  | `1`                              | If `1`, abort the session when no cache hit |

## Security model and limitations

**What `nlaproxy` does and does NOT promise:**

- The plaintext password is held in process memory in `nlaproxy-cached`,
  encrypted with a per-process random ChaCha20-Poly1305 key, for at most
  `NLAPROXY_TTL_SECS` seconds. It is never written to disk. On daemon shutdown
  the cache is wiped (`SIGTERM`/`SIGINT` handler).
- The NT-hash is derived on demand inside the daemon in response to `NTHASH`
  socket requests from the `nlaproxy` user, and returned in-memory to the
  FreeRDP plugin. It is never persisted anywhere.
- The threat model assumes the local host is trusted (only operators and
  services log in to it). An attacker with code execution as `root` can read
  everything; this proxy adds no defence against that.
- Access to the daemon socket is restricted via `SO_PEERCRED`:
  - `STORE` (0x01) requires uid 0 (only the PAM module during sshd auth)
  - `LOOKUP` / `EVICT` / `NTHASH` require uid 0 or the `nlaproxy` group
    (only `nlaproxy-freerdp` running as that user).
- Network paths:
  - Front (`PAM server → :3389`) is full NLA: NTLMv2 mutual auth + TLS-tunneled
    CredSSP. Compromise here requires breaking TLS or NTLM.
  - Back (`proxy → 127.0.0.1:3390`) is TLS but loopback-only; the cleartext
    password is inside the Client Info PDU on the tunnel. Verify 3390 is bound
    to 127.0.0.1 only.

**Known limitations:**

- **Password must already be in the cache** for an NLA login to succeed. If
  the PAM-server connects without a recent SSH login by the same user,
  freerdp-proxy3 will fail the CredSSP handshake (no cache entry → NTLM proof
  rejected). Workflow: SSH first, RDP shortly after.
- **The client's NLA session is terminated at the proxy.** Because we hand the
  cleartext to xrdp via the Client Info PDU on the loopback TLS tunnel, we
  cannot benefit from NLA's "the password never leaves the client" property
  end-to-end. We only get it on the public-facing leg.
- **Drive / printer redirection** through `freerdp-proxy3 → xrdp` is known to
  be brittle in current FreeRDP releases (upstream issues #10667, #12069).
  Default config disables both.
- **Only password auth** is supported. Smartcards, Kerberos, and SSH key auth
  produce no `PAM_AUTHTOK` and therefore no cache entry.
- **No clustering.** Cache lives in one process on one host. If you have
  multiple front-end hosts you need to SSH to each one (or replicate the
  cache, out of scope).
- **X11 desktop required on target.** xrdp cannot proxy Wayland. See "Desktop
  environment on the target" above.

## Uninstall

```sh
sudo systemctl disable --now nlaproxy-freerdp nlaproxy-cached
sudo rm -f /usr/lib/systemd/system/nlaproxy-{cached,freerdp}.service
sudo rm -f /usr/local/bin/nlaproxy-cached
sudo rm -f /usr/lib/security/pam_nlaproxy.so   # or the dir on your distro
sudo rm -f /usr/lib/x86_64-linux-gnu/freerdp3/proxy/proxy-nlaproxy-plugin.so \
           /usr/lib/freerdp/server/proxy/plugins/proxy-nlaproxy-plugin.so \
           /usr/lib/freerdp/server/proxy/plugins/libproxy-nlaproxy-plugin.so
sudo rm -rf /etc/nlaproxy
sudo userdel nlaproxy && sudo groupdel nlaproxy
sudo systemctl daemon-reload

# Restore /etc/xrdp/startwm.sh, /etc/pam.d/sshd, and /etc/xrdp/xrdp.ini from
# the timestamped .bak the installer left alongside each.
```

## License

MIT
