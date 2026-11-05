#!/bin/sh
set -eu

if [ -x "/usr/local/sbin/da-wptoolkit" ] && [ -f "/usr/local/share/da-wptoolkit/scripts/uninstall.sh" ]; then
    /usr/local/share/da-wptoolkit/scripts/uninstall.sh
    exit 0
fi

PLUGIN_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
if [ -x "${PLUGIN_DIR}/bundle/scripts/uninstall.sh" ]; then
    "${PLUGIN_DIR}/bundle/scripts/uninstall.sh"
    exit 0
fi

echo "DA WordPress Toolkits plugin uninstalled."
exit 0
