#!/bin/sh
# xrdp session start - launched by xrdp-sesman after PAM authentication
# succeeds. Runs as the target user with a valid $HOME.
#
# Order of preference:
#   1. ~/.xsession or ~/.xsessionrc   (user override)
#   2. KDE Plasma X11                 (startplasma-x11 / startplasma / startkde)
#   3. Xfce                           (startxfce4)
#   4. LXQt                           (startlxqt)
#   5. xterm                          (bare-metal fallback for pipeline validation)
#
# On failure we NEVER silently fall through to /etc/X11/Xsession, because
# that path eats logs and exits ~0s later, which is indistinguishable from
# our own failure at the xrdp-sesman level. Instead we log a hard error and
# exec xmessage so the user sees the failure inside the RDP window.

# --- environment -----------------------------------------------------------

# Load user's profile so PATH and locale are set.
if test -r /etc/profile;        then . /etc/profile;                        fi
if test -r /etc/default/locale; then . /etc/default/locale && export LANG;  fi
if test -r "$HOME/.profile";    then . "$HOME/.profile";                    fi

# Force X11. xrdp cannot proxy Wayland.
export XDG_SESSION_TYPE=x11
export XDG_CURRENT_DESKTOP=KDE
export DESKTOP_SESSION=plasma

# All script output (and, via `exec dbus-launch --exit-with-session ...`, the
# session's stdout/stderr) is captured here. Truncate on each session start
# so the file is always "the current session's log".
LOGFILE="$HOME/.xrdp-startwm.log"
exec >"$LOGFILE" 2>&1
echo "$(date -Is) starting session for $USER (HOME=$HOME) DISPLAY=$DISPLAY"
echo "PATH=$PATH"

# --- launcher selection ----------------------------------------------------

launch() {
    _label="$1"; shift
    echo "$(date -Is) launcher: $_label ($*)"
    exec dbus-launch --exit-with-session "$@"
}

# 1) User override.
if test -x "$HOME/.xsession"; then
    launch 'user ~/.xsession' "$HOME/.xsession"
fi
if test -r "$HOME/.xsessionrc"; then
    # shellcheck disable=SC1090
    . "$HOME/.xsessionrc"
fi

# 2) KDE Plasma variants.
if   command -v startplasma-x11 >/dev/null 2>&1; then launch 'startplasma-x11' startplasma-x11
elif command -v startplasma     >/dev/null 2>&1; then launch 'startplasma'     startplasma
elif command -v startkde        >/dev/null 2>&1; then launch 'startkde'        startkde
fi

# 3) Xfce.
if command -v startxfce4 >/dev/null 2>&1; then launch 'startxfce4' startxfce4; fi

# 4) LXQt.
if command -v startlxqt >/dev/null 2>&1; then launch 'startlxqt' startlxqt; fi

# 5) Bare xterm fallback. Useful for pipeline validation on a headless server
#    without a desktop environment. Presence of `xterm` alone is enough:
#    dbus-launch can still wrap it so DBUS_SESSION_BUS_ADDRESS is set.
if command -v xterm >/dev/null 2>&1; then
    echo "$(date -Is) launcher: xterm (no desktop environment installed)"
    # xterm is the "window manager" here - once it exits, the session ends.
    # -bg / -fg make it very obvious we hit the fallback branch, so operators
    # know to install a real DE.
    exec dbus-launch --exit-with-session \
        xterm -geometry 132x40 -bg '#101820' -fg '#66ccff' \
              -T 'xrdp fallback shell' \
              -e /bin/sh -l
fi

# --- hard failure ----------------------------------------------------------

echo "$(date -Is) FATAL: no session starter found (no KDE, no Xfce, no LXQt, no xterm)"
if command -v xmessage >/dev/null 2>&1; then
    exec xmessage -center \
        -title 'xrdp session failed' \
        "No desktop environment or xterm is installed on this host.
Ask the administrator to install one of:
  - kde-plasma-desktop
  - xfce4
  - lxqt
  - or at minimum: xterm"
fi
exit 1
