#!/usr/bin/env bash
set -uo pipefail

# DirectAdmin Subdirectory Hook: /usr/local/directadmin/scripts/custom/user_destroy_post/da_wp_toolkits.sh
# Purges Registry entries, inotify watches, Quarantine Vault items, Snapshots, and Nginx snippets when a user is deleted.

BIN="${DA_WPTK_BIN:-/usr/local/sbin/da-wptoolkit}"
ADMIN_SOCK="${DA_WPTK_ADMIN_SOCK:-/var/run/da-wptoolkit.sock}"
# shellcheck disable=SC2154
TARGET_USER="${username:-}"

if [[ -n "$TARGET_USER" && -x "$BIN" && -S "$ADMIN_SOCK" ]]; then
  "$BIN" hook user_destroy --user "$TARGET_USER" --sock "$ADMIN_SOCK" >/dev/null 2>&1 || true
fi

exit 0
