#!/usr/bin/env bash
# Virtual display -> window manager -> VNC server (internal only) -> capture.py.
# VNC listens on 5900 but is NOT published to the host; the xlogin service
# reaches it over the internal docker network and bridges it to the browser.
set -euo pipefail

: "${XLOGIN_VNC_PASSWORD:?XLOGIN_VNC_PASSWORD is required}"
: "${XLOGIN_SESSION_ID:?XLOGIN_SESSION_ID is required}"

export DISPLAY=:99
SCREEN="${XLOGIN_SCREEN:-1440x900x24}"

cleanup() { kill $(jobs -p) 2>/dev/null || true; }
trap cleanup EXIT

Xvfb "$DISPLAY" -screen 0 "$SCREEN" -nolisten tcp &
for i in $(seq 1 50); do xdpyinfo >/dev/null 2>&1 && break; sleep 0.1; done
fluxbox >/dev/null 2>&1 &

mkdir -p /tmp/.vnc
x11vnc -storepasswd "$XLOGIN_VNC_PASSWORD" /tmp/.vnc/passwd >/dev/null 2>&1
# -nocursor off so the user sees their pointer; -noxdamage for stability.
x11vnc -display "$DISPLAY" -rfbauth /tmp/.vnc/passwd -rfbport 5900 \
       -forever -shared -noxdamage -quiet -bg -o /tmp/x11vnc.log

# If the session uses an authenticated proxy, start the localhost forwarder that
# injects the upstream credentials (Chrome can't take them on the CLI). It binds
# 127.0.0.1 only; capture.py points Chrome at it.
if [ -n "${XLOGIN_PROXY_URL:-}" ] && printf '%s' "$XLOGIN_PROXY_URL" | grep -q '@'; then
    python3 /app/proxy_forwarder.py &
fi

# capture.py launches Chrome, then exits when login is captured or TTL expires;
# AutoRemove cleans up the container.
exec python3 /app/capture.py
