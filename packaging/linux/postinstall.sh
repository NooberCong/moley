#!/bin/sh
# Set up and start the Moley service (user, group, units). Whoever ran the
# install through sudo may control it; others join the moley group.
set -e
/usr/bin/moley service install || echo "moley: the service didn't start; see: journalctl -u moley" >&2
exit 0
