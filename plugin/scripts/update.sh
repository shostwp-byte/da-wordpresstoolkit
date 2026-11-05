#!/bin/sh
set -eu

PLUGIN_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"

if [ -x "${PLUGIN_DIR}/bundle/scripts/install.sh" ]; then
    "${PLUGIN_DIR}/bundle/scripts/install.sh"
    rm -rf "${PLUGIN_DIR}/bundle"
    echo "WordPress Manager plugin updated successfully."
    exit 0
fi

chmod 0755 "${PLUGIN_DIR}/admin/index.html" "${PLUGIN_DIR}/admin/api.raw" "${PLUGIN_DIR}/user/index.html" "${PLUGIN_DIR}/user/api.raw"
echo "WordPress Manager plugin updated."
exit 0
