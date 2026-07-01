#!/usr/bin/env bash
#
# nlaproxy/packaging/install/install.sh
#
# End-to-end installer for nlaproxy. Builds and installs:
#   * /usr/local/bin/nlaproxy-cached        (Rust daemon)
#   * <pam-dir>/pam_nlaproxy.so             (PAM module captured at SSH login)
#   * <freerdp-plugin-dir>/proxy-nlaproxy-plugin.so     (FreeRDP plugin)
#   * /etc/nlaproxy/proxy.ini               (freerdp-proxy3 config)
#   * /usr/lib/systemd/system/nlaproxy-cached.service
#   * /usr/lib/systemd/system/nlaproxy-freerdp.service
#   * /usr/lib/sysusers.d/nlaproxy.conf
#
# Then, with operator confirmation, edits:
#   * /etc/pam.d/sshd       (adds pam_nlaproxy.so session line)
#   * /etc/xrdp/xrdp.ini    (moves xrdp from 3389 to 3390 and forces TLS + creds)
#
# Re-run is safe; the script is idempotent.

set -euo pipefail

# -------------------------------------------------------------------- helpers

err() { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
warn() { printf '\033[33mwarn:\033[0m %s\n' "$*" >&2; }
info() { printf '\033[32m==>\033[0m %s\n' "$*" >&2; }

REPO_ROOT="$(cd "$(dirname "$0")"/../.. && pwd)"
cd "$REPO_ROOT"

[[ $EUID -eq 0 ]] || err "must run as root"

# -------------------------------------------------------------------- discover

# PAM module dir
PAM_MODULE_DIR=
for d in /lib64/security /lib/x86_64-linux-gnu/security \
         /usr/lib64/security /usr/lib/x86_64-linux-gnu/security \
         /usr/lib/security /lib/security; do
    [[ -d $d ]] && { PAM_MODULE_DIR=$d; break; }
done
[[ -n $PAM_MODULE_DIR ]] || err "could not find a PAM module directory"

# FreeRDP plugin dir. The layout varies across distros:
#
#   Debian/Ubuntu (freerdp3-proxy-modules):
#     /usr/lib/<multiarch>/freerdp3/proxy/proxy-*-plugin.so
#   Arch (freerdp):
#     /usr/lib/freerdp/server/proxy/plugins/libproxy-*-plugin.so
#   Some distros (freerdp3):
#     /usr/lib64/freerdp3/proxy/proxy-*-plugin.so
#
# We detect the correct dir by looking for at least one stock demo plugin.
# Operator can override by exporting FREERDP_PLUGIN_DIR.
if [[ -z ${FREERDP_PLUGIN_DIR:-} ]]; then
    for d in /usr/lib/x86_64-linux-gnu/freerdp3/proxy \
             /usr/lib/aarch64-linux-gnu/freerdp3/proxy \
             /usr/lib64/freerdp3/proxy \
             /usr/lib/freerdp3/proxy \
             /usr/lib/freerdp/server/proxy/plugins \
             /usr/lib64/freerdp/server/proxy/plugins \
             /usr/lib/x86_64-linux-gnu/freerdp/server/proxy/plugins; do
        if [[ -d $d ]] && compgen -G "$d/proxy-*-plugin.so" >/dev/null 2>&1; then
            FREERDP_PLUGIN_DIR=$d; break
        fi
        if [[ -d $d ]] && compgen -G "$d/libproxy-*-plugin.so" >/dev/null 2>&1; then
            FREERDP_PLUGIN_DIR=$d; break
        fi
    done
fi
if [[ -z ${FREERDP_PLUGIN_DIR:-} ]]; then
    err "FreeRDP 3 proxy plugins directory not found (looked for a proxy-*-plugin.so in the usual paths).
       Debian/Ubuntu:  apt install freerdp3-proxy freerdp3-proxy-modules freerdp3-dev libpam0g-dev
       RHEL/Fedora:    dnf install freerdp freerdp-devel pam-devel
       Arch:           pacman -S freerdp pam
       Or point us at the right directory explicitly:
           FREERDP_PLUGIN_DIR=/path/to/dir sudo ./packaging/install/install.sh"
fi
if [[ ! -d $FREERDP_PLUGIN_DIR ]]; then
    err "FREERDP_PLUGIN_DIR=$FREERDP_PLUGIN_DIR is not a directory"
fi

command -v cargo >/dev/null || err "cargo not found - install Rust 1.80+"
command -v cc    >/dev/null || err "cc not found"
command -v make  >/dev/null || err "make not found"
command -v freerdp-proxy3 >/dev/null || err "freerdp-proxy3 not found - install freerdp3-proxy / freerdp"
command -v pkg-config >/dev/null || err "pkg-config not found"
pkg-config --exists freerdp-server-proxy3 || err "missing pkg-config 'freerdp-server-proxy3' (install freerdp dev headers)"

info "PAM module dir:      $PAM_MODULE_DIR"
info "FreeRDP plugin dir:  $FREERDP_PLUGIN_DIR"

# -------------------------------------------------------------------- build

info "Building Rust daemon..."
cargo build --release -p nlaproxy-cached

info "Building PAM module..."
make -C pam_module clean all

info "Building FreeRDP plugin..."
make -C proxy_plugin clean all

# -------------------------------------------------------------------- install user

info "Creating system user 'nlaproxy' (idempotent)..."
install -d -m 0755 /usr/lib/sysusers.d
install -m 0644 packaging/install/nlaproxy.sysusers /usr/lib/sysusers.d/nlaproxy.conf
if command -v systemd-sysusers >/dev/null; then
    systemd-sysusers
else
    # Manual fallback for non-systemd / minimal containers
    getent group  nlaproxy >/dev/null || groupadd -r nlaproxy
    getent passwd nlaproxy >/dev/null || \
        useradd -r -g nlaproxy -d / -s /usr/sbin/nologin -c "nlaproxy NLA proxy" nlaproxy
fi

# -------------------------------------------------------------------- install binaries

info "Installing nlaproxy-cached binary..."
install -d -m 0755 /usr/local/bin
install -m 0755 -o root -g root target/release/nlaproxy-cached /usr/local/bin/nlaproxy-cached

info "Installing PAM module..."
install -m 0755 -o root -g root pam_module/pam_nlaproxy.so "$PAM_MODULE_DIR/pam_nlaproxy.so"

info "Installing FreeRDP plugin..."
install -m 0755 -o root -g root proxy_plugin/proxy-nlaproxy-plugin.so \
    "$FREERDP_PLUGIN_DIR/proxy-nlaproxy-plugin.so"
# On upgrade from an older nlaproxy that installed the plugin as
# libproxy-nlaproxy-plugin.so, remove the stale copy so it doesn't get loaded
# twice (once by each filename variant on FreeRDP >= 3.27).
rm -f "$FREERDP_PLUGIN_DIR/libproxy-nlaproxy-plugin.so"

# -------------------------------------------------------------------- install config

info "Installing /etc/nlaproxy/proxy.ini (only if missing - preserves operator edits)..."
install -d -m 0755 /etc/nlaproxy
if [[ -e /etc/nlaproxy/proxy.ini ]]; then
    install -m 0644 packaging/config/proxy.ini /etc/nlaproxy/proxy.ini.example
    warn "left existing /etc/nlaproxy/proxy.ini untouched; new template at /etc/nlaproxy/proxy.ini.example"
else
    install -m 0644 packaging/config/proxy.ini /etc/nlaproxy/proxy.ini
fi

# -------------------------------------------------------------------- install systemd

info "Installing systemd units..."
install -d -m 0755 /usr/lib/systemd/system
install -m 0644 packaging/systemd/nlaproxy-cached.service \
    /usr/lib/systemd/system/nlaproxy-cached.service
install -m 0644 packaging/systemd/nlaproxy-freerdp.service \
    /usr/lib/systemd/system/nlaproxy-freerdp.service
systemctl daemon-reload

# -------------------------------------------------------------------- pam stack edit

PAM_AUTH_LINE='auth       optional    pam_nlaproxy.so'
PAM_SESS_LINE='session    optional    pam_nlaproxy.so'
have_auth=0
have_sess=0
grep -qE '^[[:space:]]*auth[[:space:]]+(optional|required|sufficient)[[:space:]]+pam_nlaproxy\.so' \
    /etc/pam.d/sshd 2>/dev/null && have_auth=1
grep -qE '^[[:space:]]*session[[:space:]]+(optional|required|sufficient)[[:space:]]+pam_nlaproxy\.so' \
    /etc/pam.d/sshd 2>/dev/null && have_sess=1

if [[ $have_auth = 1 && $have_sess = 1 ]]; then
    info "/etc/pam.d/sshd already loads pam_nlaproxy.so on both stacks - leaving untouched"
else
    missing=()
    [[ $have_auth = 0 ]] && missing+=("$PAM_AUTH_LINE")
    [[ $have_sess = 0 ]] && missing+=("$PAM_SESS_LINE")
    if [[ ${ASSUME_YES:-0} = 1 ]]; then
        ans=y
    else
        printf '\nAppend the following lines to /etc/pam.d/sshd?\n'
        for ln in "${missing[@]}"; do
            printf '  %s\n' "$ln"
        done
        printf '[y/N] '
        read -r ans
    fi
    if [[ $ans =~ ^[Yy]$ ]]; then
        cp /etc/pam.d/sshd "/etc/pam.d/sshd.nlaproxy.bak.$(date +%s)"
        {
            printf '\n# Added by nlaproxy installer\n'
            for ln in "${missing[@]}"; do
                printf '%s\n' "$ln"
            done
        } >> /etc/pam.d/sshd
        info "appended to /etc/pam.d/sshd; restart sshd to take effect"
    else
        warn "skipped; you must manually add these lines to /etc/pam.d/sshd:"
        for ln in "${missing[@]}"; do
            warn "  $ln"
        done
    fi
fi

# -------------------------------------------------------------------- xrdp edit

XRDP_INI=/etc/xrdp/xrdp.ini
if [[ -e $XRDP_INI ]]; then
    if grep -qE '^port=3390$' "$XRDP_INI"; then
        info "$XRDP_INI already on port 3390"
    else
        if [[ ${ASSUME_YES:-0} = 1 ]]; then
            ans=y
        else
            printf '\nEdit %s to listen on 3390 and accept pre-supplied credentials? [y/N] ' "$XRDP_INI"
            read -r ans
        fi
        if [[ $ans =~ ^[Yy]$ ]]; then
            cp "$XRDP_INI" "$XRDP_INI.nlaproxy.bak.$(date +%s)"
            # port=3389 -> port=3390
            sed -i -E 's/^port=3389$/port=3390/' "$XRDP_INI"
            # security_layer=negotiate|rdp -> security_layer=tls
            sed -i -E 's/^security_layer=.*/security_layer=tls/' "$XRDP_INI"
            # require_credentials: ensure present and =true
            if grep -qE '^require_credentials=' "$XRDP_INI"; then
                sed -i -E 's/^require_credentials=.*/require_credentials=true/' "$XRDP_INI"
            else
                sed -i -E '/^\[Globals\]/a require_credentials=true' "$XRDP_INI"
            fi
            info "xrdp.ini patched - run 'systemctl restart xrdp' to apply"
        else
            warn "left $XRDP_INI alone; you must manually set port=3390 and require_credentials=true"
        fi
    fi
else
    warn "xrdp.ini not found at $XRDP_INI; ensure xrdp is installed before starting nlaproxy"
fi

# -------------------------------------------------------------------- enable

cat <<EOF

$(info "Install complete.")

Next steps:
  1. Review /etc/nlaproxy/proxy.ini (cert paths, ports).
  2. Enable & start the services:
       systemctl enable --now nlaproxy-cached.service
       systemctl enable --now nlaproxy-freerdp.service
       systemctl restart sshd       # picks up new PAM module
       systemctl restart xrdp       # picks up port change
  3. Test:
       a) From a workstation:  ssh user@thishost   (password auth)
       b) journalctl -u nlaproxy-cached -e | grep cached
       c) cat /run/nlaproxy/users.sam        (as root)
       d) From the PAM server:  rdp://thishost:3389 with NLA

Troubleshooting:
  * journalctl -u nlaproxy-cached -u nlaproxy-freerdp -u sshd -u xrdp -f
  * WLOG_LEVEL=DEBUG to nlaproxy-freerdp.service for protocol traces
  * cat /etc/nlaproxy/proxy.ini.example   for the bundled defaults
EOF
