# Disposable interactive-login browser: Xvfb + Chromium (Playwright) + x11vnc.
# One container == one login session. Started by the xlogin service, never run
# by hand. Runs as a non-root user with a read-only root filesystem.
FROM mcr.microsoft.com/playwright/python:v1.56.0-jammy

RUN DEBIAN_FRONTEND=noninteractive apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        xvfb x11vnc fluxbox x11-utils \
    && rm -rf /var/lib/apt/lists/*

# The playwright Python package is not present in this base image pull, so
# install it pinned to the version whose bundled browsers ship in the image
# (chromium build 1194 == playwright 1.56.0, matching the base image tag).
# PLAYWRIGHT_BROWSERS_PATH=/ms-playwright is already set, so no browser download.
RUN pip install --no-cache-dir playwright==1.56.0

# Chromium is already in the Playwright base image.
WORKDIR /app
COPY entrypoint.sh capture.py ./
RUN chmod +x entrypoint.sh \
    && mkdir -p /profile \
    && chown -R pwuser:pwuser /app /profile

USER pwuser
ENV HOME=/tmp
EXPOSE 5900
ENTRYPOINT ["/app/entrypoint.sh"]
