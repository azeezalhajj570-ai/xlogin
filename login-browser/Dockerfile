# Disposable interactive-login browser: Xvfb + real Google Chrome + x11vnc.
# One container == one login session. Started by the xlogin service, never run
# by hand. Runs as a non-root user with a read-only root filesystem.
#
# Why real Chrome (not the Playwright Chromium bundled in the base image): X
# blocks Playwright-driven browsers at the username step. The person drives a
# genuine Chrome over VNC; Playwright is used only to attach over the DevTools
# protocol and read the session cookies at the end (see capture.py).
FROM mcr.microsoft.com/playwright/python:v1.56.0-jammy

RUN DEBIAN_FRONTEND=noninteractive apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        xvfb x11vnc fluxbox x11-utils wget gnupg ca-certificates \
    && wget -qO /tmp/chrome.deb https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends /tmp/chrome.deb \
    && rm -f /tmp/chrome.deb \
    && rm -rf /var/lib/apt/lists/*

# The playwright Python package is not present in this base image pull; it is
# used only as a DevTools-protocol client (connect_over_cdp), never to launch a
# browser. Pinned to the base image's version.
RUN pip install --no-cache-dir playwright==1.56.0

WORKDIR /app
COPY entrypoint.sh capture.py proxy_forwarder.py ./
RUN chmod +x entrypoint.sh \
    && mkdir -p /profile \
    && chown -R pwuser:pwuser /app /profile

USER pwuser
ENV HOME=/tmp
EXPOSE 5900
ENTRYPOINT ["/app/entrypoint.sh"]
