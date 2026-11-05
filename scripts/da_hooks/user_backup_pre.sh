#!/usr/bin/env bash
set -uo pipefail

# DirectAdmin Subdirectory Hook: /usr/local/directadmin/scripts/custom/user_backup_pre/da_wp_toolkits.sh
# Temporarily unlocks Fortress Core Lock (root:<user>) instances before DirectAdmin tars the user account.

BIN="${DA_WPTK_BIN:-/usr/local/sbin/da-wptoolkit}"
ADMIN_SOCK="${DA_WPTK_ADMIN_SOCK:-/var/run/da-wptoolkit.sock}"
# shellcheck disable=SC2154
TARGET_USER="${username:-}"

if [[ -n "$TARGET_USER" && -x "$BIN" && -S "$ADMIN_SOCK" ]]; then
  "$BIN" hook user_backup_pre --user "$TARGET_USER" --sock "$ADMIN_SOCK" >/dev/null 2>&1 || true
fi

exit 0
