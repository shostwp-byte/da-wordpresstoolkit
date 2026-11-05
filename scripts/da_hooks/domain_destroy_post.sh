#!/usr/bin/env bash
set -uo pipefail

# DirectAdmin Subdirectory Hook: /usr/local/directadmin/scripts/custom/domain_destroy_post/da_wp_toolkits.sh
# Purges Registry records, Nginx snippets, Quarantine items, and inotify watches when a domain is deleted.

BIN="${DA_WPTK_BIN:-/usr/local/sbin/da-wptoolkit}"
ADMIN_SOCK="${DA_WPTK_ADMIN_SOCK:-/var/run/da-wptoolkit.sock}"
# shellcheck disable=SC2154
TARGET_USER="${username:-}"
# shellcheck disable=SC2154
TARGET_DOMAIN="${domain:-}"

if [[ -n "$TARGET_USER" && -n "$TARGET_DOMAIN" && -x "$BIN" && -S "$ADMIN_SOCK" ]]; then
  "$BIN" hook domain_destroy --user "$TARGET_USER" --domain "$TARGET_DOMAIN" --sock "$ADMIN_SOCK" >/dev/null 2>&1 || true
fi

exit 0
