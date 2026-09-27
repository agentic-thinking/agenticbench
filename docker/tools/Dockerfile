# agenticbench tools: capture proxy runtime, packet capture and analysis (python3, tcpdump, tshark). Never contains a harness.
FROM debian:bookworm-slim
LABEL org.opencontainers.image.title="agenticbench-tools" org.agenticbench.rig="tools"
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates python3 python3-brotli python3-zstandard tcpdump tshark procps \
 && rm -rf /var/lib/apt/lists/*
