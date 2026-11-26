#!/bin/bash
# Builds the Linux release in Docker: moley, moley-ui (GTK 4 / WebKitGTK
# 6), a .deb, an .rpm and an AppImage, into dist/linux.
#
#   packaging/linux/build.sh [version]
set -euo pipefail
cd "$(dirname "$0")/../.."
VERSION=${1:-0.2.0}
OUT=dist/linux
mkdir -p "$OUT/units"
(cd extension && npm ci --silent && npm run build --silent)
(cd cmd/moley-ui/frontend && npm ci --silent && npm run build --silent)

docker build -q -t moley-linux-build - >/dev/null <<'DOCKER'
FROM golang:1.27.4-trixie
RUN apt-get update && apt-get install -y --no-install-recommends libgtk-4-dev libwebkitgtk-6.0-dev file desktop-file-utils \
    && rm -rf /var/lib/apt/lists/*
RUN go install github.com/goreleaser/nfpm/v2/cmd/nfpm@v2.44.1
RUN curl -fsSL -o /usr/local/bin/appimagetool https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-x86_64.AppImage \
    && chmod +x /usr/local/bin/appimagetool
DOCKER

id=$(docker create -e VERSION="$VERSION" -e APPIMAGE_EXTRACT_AND_RUN=1 -w /src moley-linux-build bash -euc '
  export GOFLAGS=-buildvcs=false CGO_CFLAGS="-O2 -w"
  mkdir -p dist/linux/units
  go build -tags with_gvisor,with_quic,with_wireguard,with_openvpn,with_utls -trimpath -ldflags "-s -w" -o dist/linux/moley ./cmd/moley
  (cd cmd/moley-ui && go build -trimpath -ldflags "-s -w -X main.version=$VERSION" -o ../../dist/linux/moley-ui .)
  for u in moley.service moley-killswitch.service; do
    sed "s#@EXE@#/usr/bin/moley#" internal/platform/systemd/$u > dist/linux/units/$u
  done
  printf "{\n  \"name\": \"com.moley.host\",\n  \"description\": \"Moley\",\n  \"path\": \"/usr/bin/moley\",\n  \"type\": \"stdio\",\n  \"allowed_origins\": [\"chrome-extension://jgocaoindhiabkkjonnhimocmpeinmmp/\"]\n}\n" > dist/linux/com.moley.host.json
  nfpm package -f packaging/linux/nfpm.yaml -p deb -t dist/linux/
  nfpm package -f packaging/linux/nfpm.yaml -p rpm -t dist/linux/
  app=/tmp/Moley.AppDir
  mkdir -p $app/usr/bin $app/usr/share/moley
  cp dist/linux/moley dist/linux/moley-ui $app/usr/bin/
  cp -r extension/dist $app/usr/share/moley/extension
  install -m755 packaging/linux/AppRun $app/AppRun
  cp packaging/linux/moley.desktop $app/moley.desktop
  cp cmd/moley-ui/build/icon.png $app/moley.png
  ARCH=x86_64 appimagetool --no-appstream $app dist/linux/Moley-$VERSION-x86_64.AppImage >/dev/null
')
trap 'docker rm -f "$id" >/dev/null' EXIT
tar -cf - --exclude=node_modules --exclude=dist --exclude=bin --exclude=.git --transform 's,^\./,src/,' . | docker cp - "$id:/"
tar -cf - --transform 's,^,src/,' extension/dist cmd/moley-ui/frontend/dist | docker cp - "$id:/"
docker start -a "$id"
docker cp "$id:/src/$OUT/." "$OUT/"
ls -la "$OUT"
