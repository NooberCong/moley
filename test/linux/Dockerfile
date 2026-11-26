# A Linux box with systemd, to test the Moley service, system mode (TUN)
# and the nftables kill switch for real. See test/linux/run.sh.
FROM debian:trixie-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
      systemd systemd-sysv dbus nftables iproute2 curl ca-certificates python3 procps sudo \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home alice
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
