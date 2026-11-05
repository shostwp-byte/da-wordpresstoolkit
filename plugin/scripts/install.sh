#!/bin/sh
set -eu

PLUGIN_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"

if [ -x "${PLUGIN_DIR}/bundle/scripts/install.sh" ]; then
    "${PLUGIN_DIR}/bundle/scripts/install.sh"
    rm -rf "${PLUGIN_DIR}/bundle"
    echo "DA WordPress Toolkits plugin installed successfully."
    exit 0
fi

find "${PLUGIN_DIR}/admin" "${PLUGIN_DIR}/user" "${PLUGIN_DIR}/hooks" "${PLUGIN_DIR}/images" "${PLUGIN_DIR}/scripts" -type d -exec chmod 0755 {} + 2>/dev/null || true
find "${PLUGIN_DIR}/admin" "${PLUGIN_DIR}/user" "${PLUGIN_DIR}/hooks" "${PLUGIN_DIR}/images" -type f -exec chmod 0644 {} + 2>/dev/null || true
chmod 0644 "${PLUGIN_DIR}/plugin.conf" 2>/dev/null || true
chmod 0755 "${PLUGIN_DIR}/admin/index.html" "${PLUGIN_DIR}/admin/api.raw" "${PLUGIN_DIR}/user/index.html" "${PLUGIN_DIR}/user/api.raw"
chmod 0755 "${PLUGIN_DIR}/scripts/"*.sh 2>/dev/null || true
echo "DA WordPress Toolkits plugin UI permissions verified."
exit 0
