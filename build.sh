#!/bin/bash
# Build every image the rig uses and create the lab CA.
# Usage: build.sh [HARNESS...]     no arguments = every harness in harnesses.txt
#   agenticbench-base:TAG, agenticbench-tools:TAG, agenticbench-mitm:TAG   always built
#   agenticbench-<harness>:<version>                                      the vendor's package from its official channel
#   ca/                                                                   lab CA, created on first run (git-ignored, private key inside)
# Provenance (registry integrity, sha256 of the downloaded artefact and installed executable) is written to
# /opt/agenticbench/ in each harness image. Any failed build makes the script exit non-zero.
set -euo pipefail
L=$(cd "$(dirname "$0")" && pwd); cd "$L"
source "$L/bench/common.sh"
fail=()

step(){ echo "== $*"; }
build(){ # tag dockerfile context [docker build arguments]
  if docker build -q -t "$1" -f "$2" "${@:4}" "$3" >/dev/null; then echo "built $1"; else echo "FAILED $1" >&2; fail+=("$1"); fi; }

pin(){ # file sha256 -> check command (nothing when no pin is given; kind gz requires one)
  [ -z "$2" ] || echo " && echo '$2  $1' | sha256sum -c - \\"; }

gen(){ # name kind src ver exe [sha256] -> Dockerfile on stdout
  local n=$1 k=$2 s=$3 v=$4 e=$5 p=${6:-}
  [ -z "$p" ] || [[ $p =~ ^[0-9a-f]{64}$ ]] || { echo "bad sha256 pin for $n" >&2; return 1; }
  echo "# agenticbench-$n: $s $v from the vendor's official channel ($k), nothing else added."
  echo "FROM $BASE"
  echo "LABEL org.opencontainers.image.title=\"agenticbench-$n\" org.agenticbench.rig=\"harness\" org.agenticbench.source=\"$s\" org.agenticbench.version=\"$v\" org.agenticbench.channel=\"$k\""
  echo "USER root"
  echo "RUN mkdir -p /opt/agenticbench && date -u +%FT%TZ > /opt/agenticbench/built-at"
  case $k in
    npm)  echo "RUN npm view $s@$v dist.integrity dist.shasum time.$v > /opt/agenticbench/registry.txt \\"
          echo " && npm install -g --no-fund --no-audit $s@$v \\"
          echo " && sha256sum \"\$(readlink -f \"\$(command -v $e)\")\" > /opt/agenticbench/artefact.sha256 \\"
          echo " && find /usr/local/lib/node_modules -type f -size +20M -perm -u+x -exec sha256sum {} + >> /opt/agenticbench/artefact.sha256" ;;
    tar)  echo "RUN curl -fsSL -o /tmp/a.tar.bz2 $s \\"; pin /tmp/a.tar.bz2 "$p"
          echo " && sha256sum /tmp/a.tar.bz2 > /opt/agenticbench/artefact.sha256 \\"
          echo " && mkdir /tmp/x && tar -xjf /tmp/a.tar.bz2 -C /tmp/x && f=\"\$(find /tmp/x -name $e -type f | head -1)\" && test -n \"\$f\" \\"
          echo " && install -m 755 \"\$f\" /usr/local/bin/$e && sha256sum /usr/local/bin/$e >> /opt/agenticbench/artefact.sha256 && rm -rf /tmp/a.tar.bz2 /tmp/x" ;;
    appimage) # desktop app bundle: the rig runs its bundled agent CLI (resources/glm/zcode.cjs) with the image's Node, keeping the resources/ layout
          echo "RUN curl -fsSL -o /tmp/a.AppImage $s \\"; pin /tmp/a.AppImage "$p"
          echo " && sha256sum /tmp/a.AppImage > /opt/agenticbench/artefact.sha256 && chmod +x /tmp/a.AppImage \\"
          echo " && cd /tmp && ./a.AppImage --appimage-extract >/dev/null && mkdir -p /opt/$n && cp -a squashfs-root/resources/glm squashfs-root/resources/config squashfs-root/resources/tools /opt/$n/ && cp -a /opt/$n/config/provider /opt/$n/glm/provider \\"
          echo " && chmod -R a+rX /opt/$n && sha256sum /opt/$n/glm/zcode.cjs >> /opt/agenticbench/artefact.sha256 \\"
          echo " && printf '#!/bin/sh\\nexec node /opt/$n/glm/zcode.cjs \"\$@\"\\n' > /usr/local/bin/$e && chmod 755 /usr/local/bin/$e && rm -rf /tmp/a.AppImage /tmp/squashfs-root" ;;
    gz)   # a single gzip-compressed executable
          [ -n "$p" ] || { echo "kind gz needs a sha256 pin for $n (harnesses.txt, sixth column)" >&2; return 1; }
          echo "RUN curl -fsSL -o /tmp/a.gz $s \\"; pin /tmp/a.gz "$p"
          echo " && sha256sum /tmp/a.gz > /opt/agenticbench/artefact.sha256 \\"
          echo " && gunzip -c /tmp/a.gz > /usr/local/bin/$e && chmod 755 /usr/local/bin/$e && sha256sum /usr/local/bin/$e >> /opt/agenticbench/artefact.sha256 && rm /tmp/a.gz" ;;
    pypi) echo "RUN python3 -m venv /opt/$n && /opt/$n/bin/pip install --no-cache-dir --disable-pip-version-check $s==$v \\"
          echo " && ln -s /opt/$n/bin/$e /usr/local/bin/$e && /opt/$n/bin/pip download --no-deps --no-cache-dir -d /tmp/w $s==$v -q \\"
          echo " && sha256sum /tmp/w/* > /opt/agenticbench/artefact.sha256 && rm -rf /tmp/w" ;;
    *)    echo "unknown kind $k for $n" >&2; return 1 ;;
  esac
  echo "RUN command -v $e >/dev/null"
  echo "USER lab"
}

want=("$@"); [ ${#want[@]} -eq 0 ] && want=($(harness_names))
for h in "${want[@]}"; do harness_row "$h" >/dev/null || { echo "unknown harness $h (see harnesses.txt)" >&2; exit 2; }; done

step "infrastructure images"
build "$BASE" docker/base/Dockerfile docker/base
build "$TOOLS" docker/tools/Dockerfile docker/tools
build "$MITM" docker/mitm/Dockerfile docker/mitm
[ ${#fail[@]} -eq 0 ] || { echo "FAILED: ${fail[*]}" >&2; exit 1; }

if [ ! -s "$CA/mitmproxy-ca-cert.pem" ] || [ ! -s "$CA/bundle.pem" ]; then
  step "lab CA (first run): $CA"
  mkdir -p "$CA"; chmod 700 "$CA"
  docker run --rm --network none --user "$(id -u):$(id -g)" -e HOME=/tmp -v "$CA:/ca" "$MITM" \
    python3 -c "from mitmproxy.certs import CertStore; CertStore.from_store('/ca', 'mitmproxy', 2048)"
  # trust bundle for the harness containers = the base image's system CAs + the lab CA
  { docker run --rm --network none "$BASE" cat /etc/ssl/certs/ca-certificates.crt; cat "$CA/mitmproxy-ca-cert.pem"; } > "$CA/bundle.pem"
  test -s "$CA/mitmproxy-ca-cert.pem" && test -s "$CA/mitmproxy-ca.pem" && test -s "$CA/bundle.pem"
  echo "created $CA (private key: never publish or commit this directory)"
fi

step "harness images: ${want[*]}"
mkdir -p "$L/build"
for h in "${want[@]}"; do
  read -r n k s v e p <<< "$(harness_row "$h")"
  if [ "$k" = dockerfile ]; then   # a Dockerfile kept in this repository (it pins its own sources); built on the shared base
    [ -f "$L/$s/Dockerfile" ] || { echo "FAILED agenticbench-$n:$v: no $s/Dockerfile" >&2; fail+=("agenticbench-$n:$v"); continue; }
    build "agenticbench-$n:$v" "$L/$s/Dockerfile" "$L/$s" --build-arg "BASE=$BASE" --build-arg "VERSION=$v"
    continue
  fi
  mkdir -p "$L/build/$n"
  gen "$n" "$k" "$s" "$v" "$e" "$p" > "$L/build/$n/Dockerfile" || { echo "FAILED agenticbench-$n:$v: $k" >&2; fail+=("agenticbench-$n:$v"); continue; }
  build "agenticbench-$n:$v" "$L/build/$n/Dockerfile" "$L/build/$n"
done
if [ ${#fail[@]} -gt 0 ]; then echo "FAILED: ${fail[*]}" >&2; exit 1; fi
echo "all images built"
