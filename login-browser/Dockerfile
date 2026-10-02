# Disposable interactive-login browser: Xvfb + Chromium (Playwright) + x11vnc.
# One container == one login session. Started by the xlogin service, never run
# by hand. Runs as a non-root user with a read-only root filesystem.
FROM mcr.microsoft.com/playwright/python:v1.56.0-jammy

RUN apt-get update && apt-get install -y --no-install-recommends \
        xvfb x11vnc fluxbox x11-utils \
    && rm -rf /var/lib/apt/lists/*

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
