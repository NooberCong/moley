#!/bin/bash
# End-to-end test of the Linux service, system mode and kill switch in a
# privileged container running systemd. Needs Docker.
#
#   test/linux/run.sh
set -euo pipefail
cd "$(dirname "$0")/../.."

export GOOS=linux GOARCH=amd64 CGO_ENABLED=0 GOFLAGS=-tags=with_gvisor,with_quic,with_wireguard,with_openvpn,with_utls
go build -trimpath -o bin/linux/moley ./cmd/moley
go build -trimpath -o bin/linux/teststack ./internal/teststack/cmd/teststack

docker build -q -t moley-test-linux test/linux >/dev/null
docker network inspect moleynet >/dev/null 2>&1 || docker network create moleynet >/dev/null
docker rm -f moley-echo moley-box >/dev/null 2>&1 || true
trap '[ -n "${KEEP:-}" ] || docker rm -f moley-echo moley-box >/dev/null 2>&1 || true' EXIT

docker run -d --name moley-echo --network moleynet --cap-add NET_ADMIN moley-test-linux sleep infinity >/dev/null
docker exec moley-echo ip addr add 203.0.113.10/32 dev lo
docker run -d --name moley-box --network moleynet --privileged --cgroupns=host \
  -v /sys/fs/cgroup:/sys/fs/cgroup:rw moley-test-linux >/dev/null
for f in test/linux/echo.py test/linux/inside.sh bin/linux/moley bin/linux/teststack; do
  docker exec moley-echo mkdir -p /t && docker cp "$f" moley-echo:/t/ >/dev/null
  docker exec moley-box mkdir -p /t && docker cp "$f" moley-box:/t/ >/dev/null
done
docker exec -d moley-echo python3 /t/echo.py
for _ in $(seq 50); do docker exec moley-box systemctl is-system-running --quiet 2>/dev/null && break
  [ "$(docker exec moley-box systemctl is-system-running 2>/dev/null)" = degraded ] && break; sleep 0.2; done
docker exec moley-box bash /t/inside.sh
