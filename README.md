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
*verify* a password but cannot produce one, so a textbook
"validate NLA via PAM" implementation is mathematically impossible.

`nlaproxy` works around this by **harvesting passwords from a prior SSH login**:

1. The user (or an automated system) SSH's in to the target with password auth.
   A small custom PAM module (`pam_nlaproxy.so`) loaded into sshd's `session`
   stack captures `PAM_AUTHTOK` after auth succeeds and sends it to a local
   daemon.
2. The daemon (`nlaproxy-cached`) keeps the cleartext in memory (encrypted with
   an ephemeral key, TTL 5 min by default), and atomically rewrites
   `/run/nlaproxy/users.sam` with an NTLMv1-style NT-OWF entry per cached user.
3. The PAM/CyberArk server now does RDP-NLA to `:3389`. `freerdp-proxy3` reads
   the SAM file and validates the client's NTLM response against it.
4. Our FreeRDP plugin (`proxy-nlaproxy-plugin.so`) hooks
   `ServerPostConnect`, queries the daemon for the plaintext password, and
   injects it into the upstream RDP settings.
5. `freerdp-proxy3` opens a TLS connection to xrdp on `127.0.0.1:3390`, the
   creds land in the Client Info PDU, xrdp-sesman PAM-authenticates the user
   normally, and the session opens.

The cleartext password never leaves the host. The NT-OWF on tmpfs is wiped on
daemon shutdown and on entry expiry.

## Components

| Path                                                | Language | Purpose                                                |
|-----------------------------------------------------|----------|--------------------------------------------------------|
| `cached/`                                           | Rust     | Credential cache daemon + NTLM SAM file maintainer     |
| `pam_module/pam_nlaproxy.c`                         | C        | sshd-side PAM session module that captures the password |
| `proxy_plugin/nlaproxy_plugin.c`                    | C        | `freerdp-proxy3` plugin that injects cached creds       |
| `packaging/systemd/nlaproxy-cached.service`         | unit     | Daemon service (root, RuntimeDirectory=nlaproxy)        |
| `packaging/systemd/nlaproxy-freerdp.service`        | unit     | freerdp-proxy3 service (user=nlaproxy, CAP_NET_BIND)    |
| `packaging/config/proxy.ini`                        | INI      | freerdp-proxy3 config (NLA front, TLS back)             |
| `packaging/config/sshd.pam.snippet`                 | PAM      | Line to add to `/etc/pam.d/sshd`                        |
| `packaging/install/install.sh`                      | bash     | One-shot installer                                     |
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
   sudo cat /run/nlaproxy/users.sam
   #   alice:::878d8014606cda29677a44efa1353fc7:::
   ```

   If you see the line, the PAM module is wired in correctly.

2. **NLA front:**

   ```sh
   xfreerdp3 /v:target:3389 /u:alice /p:'<the same password>' /sec:nla
   ```

   You should land in the xrdp session.

3. **Diagnostic logs:**

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

## Configuration knobs

### Cache daemon (`/etc/systemd/system/nlaproxy-cached.service.d/override.conf`)

| Env var                    | Default                          | Notes                                      |
|----------------------------|----------------------------------|--------------------------------------------|
| `NLAPROXY_SOCKET`          | `/run/nlaproxy/cached.sock`      | Where the daemon listens                   |
| `NLAPROXY_SAM`             | `/run/nlaproxy/users.sam`        | Where freerdp-proxy3 reads the SAM file    |
| `NLAPROXY_CONSUMER_USER`   | `nlaproxy`                       | Username allowed to LOOKUP/EVICT           |
| `NLAPROXY_CONSUMER_GROUP`  | `nlaproxy`                       | Group that owns the socket and SAM file    |
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
| `NLAPROXY_PLUGIN_SOCKET`   | `/run/nlaproxy/cached.sock`      | Daemon socket to query                     |
| `NLAPROXY_PLUGIN_SAM`      | `/run/nlaproxy/users.sam`        | SAM file path pushed onto each peer as `FreeRDP_NtlmSamFile`. Required on FreeRDP < 3.25 (Ubuntu 24.04's freerdp3 3.24.2) where proxy.ini's `SamFile=` is silently ignored. Set to empty to disable the pushdown. |
| `NLAPROXY_PLUGIN_REQUIRE`  | `1`                              | If `1`, abort the session when no cache hit |

## Security model and limitations

**What `nlaproxy` does and does NOT promise:**

- The plaintext password is held in process memory in
  `nlaproxy-cached`, encrypted with a per-process random ChaCha20-Poly1305 key,
  for at most `NLAPROXY_TTL_SECS` seconds. It is not written to disk in any
  form. On daemon shutdown the cache is wiped (`SIGTERM`/`SIGINT` handler).
- The NT-OWF in `users.sam` lives on tmpfs (`/run`, courtesy of
  systemd's `RuntimeDirectory=`). It is **password-equivalent** for NLA
  purposes and rainbow-table-trivial for weak passwords. Treat the host
  accordingly:
  - Restrict who can become `root` or join the `nlaproxy` group (they can read
    the SAM file).
  - Use a strong password policy.
  - Enforce a low `NLAPROXY_TTL_SECS` (5 min is fine for the PAM-server
    workflow; lower if the broker connects RDP within seconds of SSH).
- The threat model assumes the local host is trusted (only operators and
  services log in to it). An attacker with code execution as `root` can read
  everything; this proxy adds no defence against that.
- Network paths:
  - Front (`PAM server → :3389`) is full NLA: NTLMv2 mutual auth + TLS-tunneled
    CredSSP. Compromise here requires breaking TLS or NTLM.
  - Back (`proxy → 127.0.0.1:3390`) is TLS only; the cleartext password is
    inside the Client Info PDU but the tunnel is local-loopback TLS only.

**Known limitations:**

- **Password must already be in the cache** for an NLA login to succeed. If
  the PAM-server connects without a recent SSH login by the same user,
  freerdp-proxy3 will fail the CredSSP handshake (no SAM entry → NTLM proof
  rejected). Workflow: SSH first, RDP shortly after.
- **NTLMv1-equivalent strength.** Because we hand the cleartext to xrdp via
  the Client Info PDU, we cannot benefit from NLA's "the password never leaves
  the client" property end-to-end. We only get it on the public-facing leg.
- **Drive / printer redirection** through `freerdp-proxy3 → xrdp` is known to
  be brittle in current FreeRDP releases (upstream issues #10667, #12069).
  Default config disables both.
- **Only password auth** is supported. Smartcards, Kerberos, and SSH key auth
  produce no `PAM_AUTHTOK` and therefore no cache entry.
- **No clustering.** Cache lives in one process on one host. If you have
  multiple front-end hosts you need to SSH to each one (or replicate the
  cache, out of scope).

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

# Manually undo your /etc/pam.d/sshd and /etc/xrdp/xrdp.ini edits (the
# installer leaves a timestamped .bak alongside each).
```

## License

MIT
