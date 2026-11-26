#!/bin/bash
# Installs the .deb in a systemd container the way a user would
# (sudo apt install), checks the service, then starts the tray app on a
# virtual display and screenshots it. Run packaging/linux/build.sh first.
#
#   test/linux/package.sh   (screenshot: bin/linux-ui.png)
set -euo pipefail
cd "$(dirname "$0")/../.."
docker build -q -t moley-test-linux test/linux >/dev/null
docker rm -f moley-pkg >/dev/null 2>&1 || true
trap '[ -n "${KEEP:-}" ] || docker rm -f moley-pkg >/dev/null 2>&1 || true' EXIT
docker run -d --name moley-pkg --privileged --cgroupns=host -v /sys/fs/cgroup:/sys/fs/cgroup:rw moley-test-linux >/dev/null
docker exec moley-pkg mkdir -p /t
docker cp dist/linux/moley_0.3.0_amd64.deb moley-pkg:/t/
sleep 2
docker exec moley-pkg bash -euc '
  apt-get update -qq >/dev/null
  # alice installs it with sudo, as on a desktop.
  echo "alice ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/alice
  su alice -c "sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq /t/moley_0.3.0_amd64.deb" >/tmp/apt.log 2>&1 || { tail -20 /tmp/apt.log; exit 1; }
  grep -i "moley:\|service is installed" /tmp/apt.log || true
  systemctl is-active --quiet moley && echo "  ok   service active after install"
  id -nG alice | grep -qw moley && echo "  ok   alice is in the moley group"
  su alice -c "moley status" | head -2
  test -f /etc/opt/chrome/native-messaging-hosts/com.moley.host.json && echo "  ok   native host registered for Chrome"
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq xvfb imagemagick dbus-x11 >/dev/null 2>&1
  su alice -c "cd ~ && (Xvfb :9 -screen 0 1280x900x24 >/dev/null 2>&1 &) && sleep 1 && \
    DISPLAY=:9 dbus-launch --exit-with-session moley-ui >/tmp/ui.log 2>&1 & sleep 8; \
    DISPLAY=:9 import -window root /tmp/ui.png 2>&1 | tail -2; pgrep -x moley-ui >/dev/null && echo \"  ok   tray app running\""
  tail -3 /tmp/ui.log
  apt-get remove -y -qq moley >/dev/null 2>&1
  systemctl is-active --quiet moley || echo "  ok   removing the package stops the service"
'
docker exec moley-pkg cat /tmp/ui.png > bin/linux-ui.png # /tmp is a tmpfs under systemd
