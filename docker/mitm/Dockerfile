# agenticbench mitm: mitmproxy 11.0.2 (TLS interception with the lab CA) plus iptables, so one container can hold a unit's
# network namespace, redirect the harness user's outbound TCP 80/443 to mitmproxy in transparent mode, and reject QUIC.
FROM debian:bookworm-slim
LABEL org.opencontainers.image.title="agenticbench-mitm" org.agenticbench.rig="mitm"
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates python3 python3-venv iptables \
 && rm -rf /var/lib/apt/lists/* \
 && python3 -m venv /opt/mitm && /opt/mitm/bin/pip install --no-cache-dir --disable-pip-version-check mitmproxy==11.0.2
ENV PATH=/opt/mitm/bin:$PATH
