# agenticbench base: minimal Debian + Node LTS + Python 3 + git + strace. Nothing from the lab inside.
# Pinned by digest so vendors can rebuild the same base.
FROM node:24-bookworm-slim@sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6
LABEL org.opencontainers.image.title="agenticbench-base" org.agenticbench.rig="base"
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl git strace python3 python3-venv procps bsdutils bzip2 xz-utils gzip \
 && rm -rf /var/lib/apt/lists/*
# The harness runs as uid 1000 ("lab") inside every container; at run time /home/lab is an empty in-memory directory.
RUN userdel -r node && useradd -u 1000 -m -d /home/lab -s /bin/bash lab
ENV LANG=C.UTF-8
WORKDIR /work
