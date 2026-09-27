# agenticbench-hermes: Hermes Agent (NousResearch) 0.21.5 = GitHub release tag v2026.9.24, installed by the vendor's own installer
# (scripts/install.sh at that release commit), which clones the repository at the commit given with --commit and installs its
# dependencies. build.sh builds this file with BASE = the shared agenticbench-base image. The installer is pinned by commit and
# sha256; the dependencies it resolves at build time are not pinned here (see KNOWN-LIMITATIONS.md).
ARG BASE
FROM ${BASE}
ARG VERSION=0.21.5
ARG COMMIT=f97608f178d1ffeca59860195ab7da295f7c8e5f
ARG INSTALLER_SHA256=2017ddf0cc7bc6cfb70d40dc9fba1d916f47dbcccf5fe73bdee2cf93a11262af
LABEL org.opencontainers.image.title="agenticbench-hermes" org.agenticbench.rig="harness" org.agenticbench.source="https://github.com/NousResearch/hermes-agent" org.agenticbench.version="${VERSION}" org.agenticbench.channel="GitHub release tag v2026.9.24, vendor installer --commit ${COMMIT}"
USER root
RUN apt-get update && apt-get install -y --no-install-recommends build-essential && rm -rf /var/lib/apt/lists/*
RUN mkdir -p /opt/agenticbench /opt/hl && chown lab:lab /opt/hl && date -u +%FT%TZ > /opt/agenticbench/built-at \
 && curl -fsSL -o /opt/agenticbench/install.sh "https://raw.githubusercontent.com/NousResearch/hermes-agent/${COMMIT}/scripts/install.sh" \
 && echo "${INSTALLER_SHA256}  /opt/agenticbench/install.sh" | sha256sum -c - \
 && sha256sum /opt/agenticbench/install.sh > /opt/agenticbench/installer.sha256
# the installer runs as the harness user, with its home and HERMES_HOME under /opt/hl (the unit's HOME is a fresh tmpfs)
USER lab
ENV HOME=/opt/hl
RUN HERMES_HOME=/opt/hl/.hermes bash /opt/agenticbench/install.sh --dir /opt/hl/hermes-agent --commit "${COMMIT}" --non-interactive > /opt/hl/install.out 2>&1; rc=$?; echo "rc=$rc" >> /opt/hl/install.out; tail -25 /opt/hl/install.out; [ $rc = 0 ] || tail -80 /opt/hl/.hermes/logs/install.log; exit $rc
USER root
# provenance: installed commit, sha256 of the entry point; then every file readable (and executables runnable) by any user
RUN cp /opt/hl/install.out /opt/agenticbench/install.out \
 && git -c safe.directory=* -C /opt/hl/hermes-agent rev-parse HEAD > /opt/agenticbench/commit.txt && git -c safe.directory=* -C /opt/hl/hermes-agent describe --tags --always >> /opt/agenticbench/commit.txt \
 && test "$(head -1 /opt/agenticbench/commit.txt)" = "${COMMIT}" \
 && ln -sf "$(readlink -f /opt/hl/.local/bin/hermes)" /usr/local/bin/hermes \
 && sha256sum "$(readlink -f /usr/local/bin/hermes)" > /opt/agenticbench/artefact.sha256 \
 && find /opt/hl \( \( -type d ! -perm -a+rx \) -o \( -type f ! -perm -a+r \) -o \( -type f -perm -u+x ! -perm -a+x \) \) -exec chmod a+rX {} +
ENV HOME=/home/lab
RUN command -v hermes >/dev/null
USER lab
