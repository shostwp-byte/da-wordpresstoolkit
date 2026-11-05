#!/usr/bin/env bash
set -uo pipefail

# DirectAdmin Subdirectory Hook: /usr/local/directadmin/scripts/custom/subdomain_create_post/da_wp_toolkits.sh
# Refreshes DirectAdmin subdomain mapping in da-wptoolkitd immediately when a subdomain is created.

BIN="${DA_WPTK_BIN:-/usr/local/sbin/da-wptoolkit}"
ADMIN_SOCK="${DA_WPTK_ADMIN_SOCK:-/var/run/da-wptoolkit.sock}"
# shellcheck disable=SC2154
TARGET_USER="${username:-}"
# shellcheck disable=SC2154
TARGET_DOMAIN="${domain:-}"
# shellcheck disable=SC2154
TARGET_SUB="${subdomain:-}"

if [[ -n "$TARGET_USER" && -x "$BIN" && -S "$ADMIN_SOCK" ]]; then
  "$BIN" hook subdomain_create --user "$TARGET_USER" --domain "$TARGET_DOMAIN" --subdomain "$TARGET_SUB" --sock "$ADMIN_SOCK" >/dev/null 2>&1 || true
fi

exit 0
