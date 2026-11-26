#!/bin/sh
# On removal (not upgrade): stop the service and lift a persistent kill
# switch, so uninstalling never leaves the machine offline.
case "$1" in
  remove|purge|0) /usr/bin/moley service uninstall --yes || true ;;
esac
exit 0
