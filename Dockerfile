# The xlogin API service (FastAPI/Starlette + the VNC WebSocket bridge).
FROM python:3.12-slim

ARG NOVNC_VERSION=v1.5.0
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Bundle the noVNC client (served from /static/novnc). Pinned to a tag.
RUN git clone --depth 1 --branch "${NOVNC_VERSION}" https://github.com/novnc/noVNC /opt/novnc \
    && rm -rf /opt/novnc/.git /opt/novnc/tests /opt/novnc/snap /opt/novnc/docs

RUN pip install --no-cache-dir \
        "starlette>=0.37,<1" "uvicorn[standard]>=0.29" "cryptography>=42" \
        "websockets>=12"

WORKDIR /srv
COPY app ./app
# Serve the bundled noVNC from within the static dir the app already exposes.
RUN ln -s /opt/novnc /srv/app/static/novnc

RUN useradd -r -u 10001 xlogin && mkdir -p /data && chown xlogin /data
USER xlogin
ENV XLOGIN_DATABASE_PATH=/data/xlogin.db

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", \
     "--proxy-headers", "--forwarded-allow-ips", "*", "--no-server-header"]
