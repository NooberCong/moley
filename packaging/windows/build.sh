#!/bin/bash
# Builds the Windows release: moley.exe, moley-ui.exe and the installer
# (NSIS, run in Docker so no local install is needed), into dist/windows.
#
#   packaging/windows/build.sh [version]
#
# For a self-updating build, set MOLEY_UPDATE_URL and MOLEY_UPDATE_KEY
# (base64 Ed25519 public key) in the environment.
set -euo pipefail
export MSYS_NO_PATHCONV=1 # Git Bash: pass the container's /src paths to Docker as written
cd "$(dirname "$0")/../.."
VERSION=${1:-0.3.0}
OUT=dist/windows
mkdir -p "$OUT"
export GOOS=windows GOARCH=amd64 CGO_ENABLED=0
TAGS=with_gvisor,with_quic,with_wireguard,with_openvpn,with_utls

(cd cmd/moley && go run github.com/tc-hib/go-winres@v0.3.3 simply --arch amd64 --icon ../moley-ui/build/icon.png --manifest cli \
  --product-name Moley --file-description "Moley daemon and CLI" --product-version "$VERSION" --file-version "$VERSION" --original-filename moley.exe)
go build -tags "$TAGS" -trimpath -ldflags "-s -w" -o "$OUT/moley.exe" ./cmd/moley

(cd extension && npm ci --silent && npm run build --silent)
(cd cmd/moley-ui/frontend && npm ci --silent && npm run build --silent)
(cd cmd/moley-ui && go run github.com/tc-hib/go-winres@v0.3.3 simply --arch amd64 --icon build/icon.png --manifest gui \
  --product-name Moley --file-description Moley --product-version "$VERSION" --file-version "$VERSION" --original-filename moley-ui.exe)
(cd cmd/moley-ui && go build -trimpath \
  -ldflags "-s -w -H windowsgui -X main.version=$VERSION -X main.updateURL=${MOLEY_UPDATE_URL:-} -X main.updateKey=${MOLEY_UPDATE_KEY:-}" \
  -o "../../$OUT/moley-ui.exe" .)

docker build -q -t moley-nsis - >/dev/null <<'EOF'
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends nsis && rm -rf /var/lib/apt/lists/*
EOF
id=$(docker create moley-nsis makensis -V2 -DVERSION="$VERSION" -DROOT=/src -DBIN=/src/$OUT -DEXT=/src/extension/dist \
  -DICON=/src/cmd/moley-ui/build/moley.ico /src/packaging/windows/moley.nsi)
trap 'docker rm -f "$id" >/dev/null' EXIT
tar -cf - --transform 's,^,src/,' LICENSE "$OUT/moley.exe" "$OUT/moley-ui.exe" extension/dist   cmd/moley-ui/build/moley.ico packaging/windows/moley.nsi | docker cp - "$id:/"
docker start -a "$id"
docker cp "$id:/src/packaging/windows/Moley-Setup-$VERSION.exe" "$OUT/"
ls -la "$OUT"
