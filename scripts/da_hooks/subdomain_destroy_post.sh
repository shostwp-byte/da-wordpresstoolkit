#!/usr/bin/env bash
set -uo pipefail

# DirectAdmin Subdirectory Hook: /usr/local/directadmin/scripts/custom/subdomain_destroy_post/da_wp_toolkits.sh
# Purges Registry records, Nginx snippets, Quarantine items, and inotify watches when a subdomain is deleted.

BIN="${DA_WPTK_BIN:-/usr/local/sbin/da-wptoolkit}"
ADMIN_SOCK="${DA_WPTK_ADMIN_SOCK:-/var/run/da-wptoolkit.sock}"
# shellcheck disable=SC2154
TARGET_USER="${username:-}"
# shellcheck disable=SC2154
TARGET_DOMAIN="${domain:-}"
# shellcheck disable=SC2154
TARGET_SUB="${subdomain:-}"

if [[ -n "$TARGET_USER" && -n "$TARGET_DOMAIN" && -n "$TARGET_SUB" && -x "$BIN" && -S "$ADMIN_SOCK" ]]; then
  "$BIN" hook subdomain_destroy --user "$TARGET_USER" --domain "$TARGET_DOMAIN" --subdomain "$TARGET_SUB" --sock "$ADMIN_SOCK" >/dev/null 2>&1 || true
fi

exit 0
