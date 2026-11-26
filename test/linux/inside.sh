#!/bin/bash
# Runs inside the test box (see run.sh): installs the Moley service the way
# a user would, then checks system mode and the kill switch with real
# traffic. The echo host reports who connected, so each check proves the
# path a request took.
set -euo pipefail

pass=0
ok() { echo "  ok   $*"; pass=$((pass + 1)); }
fail() { echo "  FAIL $*"; exit 1; }
check() { local what=$1; shift; if "$@" >/dev/null 2>&1; then ok "$what"; else fail "$what"; fi; }
refuse() { local what=$1; shift; if "$@" >/dev/null 2>&1; then fail "$what"; else ok "$what"; fi; }
as_alice() { su alice -c "$*"; }

# The echo host is on the local network (ECHO) and also stands in for an
# Internet server (NET, routed through it like a gateway).
ECHO=$(getent ahostsv4 moley-echo | awk 'NR==1 {print $1}')
NET=203.0.113.10
ip route replace default via "$ECHO" # the echo host is the gateway to "the Internet"
BOX=$(ip -4 -o addr show eth0 | awk '{print $4}' | cut -d/ -f1)
install -m 0755 /t/moley /usr/bin/moley

echo "== local VPN servers"
mkdir -p /tmp/stack
/t/teststack /tmp/stack >/tmp/stack.log 2>&1 &
for _ in $(seq 50); do [ -s /tmp/stack/urls.txt ] && break; sleep 0.2; done
PORT=$(awk '/^public/ {print $2}' /tmp/stack/urls.txt | sed -E 's#.*:([0-9]+)/.*#\1#')
install -o alice -m 0600 /tmp/stack/ss.txt /home/alice/ss.txt
check "teststack up (echo port $PORT)" test -n "$PORT"

echo "== per-user daemon first, then the service takes its config"
as_alice "moley start" >/dev/null
as_alice "moley import ~/ss.txt --id ss" >/dev/null
as_alice "moley rules add echo --exit ss --domain echo.test" >/dev/null
refuse "a per-user daemon refuses system mode" as_alice "moley mode --tun on"
as_alice "moley stop" >/dev/null
SUDO_USER=alice SUDO_UID=$(id -u alice) moley service install
check "service is active" systemctl is-active --quiet moley
check "alice joined the moley group" bash -c "id -nG alice | grep -qw moley"
check "socket is moley:moley 0660" bash -c '[ "$(stat -c "%U:%G %a" /run/moley/moley.sock)" = "moley:moley 660" ]'
check "the service runs as moley, not root" bash -c '[ "$(ps -o user= -C moley | head -1)" = moley ]'
check "alice's profile and rule moved over" bash -c 'as() { su alice -c "$*"; }; as moley rules --json | grep -q "\"id\":\"echo\""'
check "alice controls the service" as_alice "moley status --json"

echo "== system mode"
as_alice "moley mode --tun on" >/dev/null
refuse "disconnected, the adapter stays down" ip link show moley
as_alice "moley holds put e2e --for 30m" >/dev/null # up without connecting
for _ in $(seq 50); do ip link show moley >/dev/null 2>&1 && break; sleep 0.1; done
check "a hold brings the tun interface up" ip link show moley
echo "nameserver 9.9.9.9" >/etc/resolv.conf # a resolver the TUN answers for
out=$(curl -s --max-time 5 "http://$NET:8080/")
[ "$out" = "$(printf 'ip=%s\nloc=XX' "$BOX")" ] && ok "unmatched traffic goes direct ($out)" || fail "direct: $out"
tun_conn() { moley conns --closed --json | python3 -c 'import json, sys; sys.exit(not any(c["inbound"] == "tun" and c["host"] == sys.argv[1] for c in json.load(sys.stdin)["conns"]))' "$1"; }
check "and Moley carried it (inbound tun)" tun_conn $NET
out=$(curl -s --max-time 5 "http://echo.test:$PORT/trace")
case $out in *ip=127.0.0.4*) ok "a rule sends echo.test via Shadowsocks, named through FakeIP";; *) fail "via ss: $out";; esac
check "apps got a FakeIP address" bash -c "getent ahostsv4 echo.test | grep -q '^198\.1[89]\.'"
check "events stream for alice" bash -c "su alice -c 'timeout 3 moley events --json' | grep -q '\"event\":\"status\"'"

echo "== kill switch"
check "without it, a socket bound to eth0 leaks past the tunnel" curl -s --max-time 3 --interface eth0 "http://$NET:8080/"
as_alice "moley mode --kill-switch on" >/dev/null
check "nftables table loaded" nft list table inet moley
refuse "with it, the bound socket is blocked" curl -s --max-time 3 --interface eth0 "http://$NET:8080/"
check "the local network stays reachable" curl -s --max-time 3 --interface eth0 "http://$ECHO:8080/"
check "traffic through Moley still flows" curl -s --max-time 5 "http://$NET:8080/"
check "a structural change (rebuild) keeps it" as_alice "moley rules add other --exit direct --domain other.test"
refuse "still blocked after the rebuild" curl -s --max-time 3 --interface eth0 "http://$NET:8080/"
systemctl stop moley
refuse "on: lifted when the service stops" nft list table inet moley
check "  so traffic flows again" curl -s --max-time 3 "http://$NET:8080/"
systemctl start moley
for _ in $(seq 50); do moley status >/dev/null 2>&1 && break; sleep 0.2; done
check "on: back with the service" nft list table inet moley

echo "== persistent kill switch"
refuse "persistent needs --yes" as_alice "moley mode --kill-switch persistent"
as_alice "moley mode --kill-switch persistent --yes" >/dev/null
check "boot marker written" test -e /var/lib/moley/killswitch-persistent
systemctl stop moley
check "persistent: still blocking with the service stopped" nft list table inet moley
refuse "  nothing gets out" curl -s --max-time 3 "http://$NET:8080/"
nft delete table inet moley # a reboot: the boot unit restores it
systemctl restart moley-killswitch
check "persistent: restored at boot" nft list table inet moley
refuse "  nothing gets out at boot" curl -s --max-time 3 "http://$NET:8080/"
systemctl start moley
for _ in $(seq 50); do moley status >/dev/null 2>&1 && break; sleep 0.2; done
check "traffic flows once Moley is up" curl -s --max-time 5 "http://$NET:8080/"

echo "== back to normal"
as_alice "moley mode --kill-switch off" >/dev/null
refuse "kill switch off: table gone" nft list table inet moley
refuse "  and no boot marker" test -e /var/lib/moley/killswitch-persistent
as_alice "moley mode --tun off" >/dev/null
refuse "tun off: interface gone" ip link show moley
as_alice "moley mode --kill-switch persistent --yes" >/dev/null
moley service uninstall --yes
refuse "uninstall: service gone" systemctl is-active --quiet moley
refuse "uninstall lifts a persistent kill switch" nft list table inet moley

echo "linux system mode: $pass checks passed"
