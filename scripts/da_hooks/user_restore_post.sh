#!/usr/bin/env bash
set -uo pipefail

# DirectAdmin Subdirectory Hook: /usr/local/directadmin/scripts/custom/user_restore_post/da_wp_toolkits.sh
# Reloads user registry and auto-discovers WordPress instances after account restore or migration (cPanel/Plesk/DA).

BIN="${DA_WPTK_BIN:-/usr/local/sbin/da-wptoolkit}"
ADMIN_SOCK="${DA_WPTK_ADMIN_SOCK:-/var/run/da-wptoolkit.sock}"
# shellcheck disable=SC2154
TARGET_USER="${username:-}"

if [[ -n "$TARGET_USER" && -x "$BIN" && -S "$ADMIN_SOCK" ]]; then
  "$BIN" hook user_restore --user "$TARGET_USER" --sock "$ADMIN_SOCK" >/dev/null 2>&1 || true
fi

exit 0
