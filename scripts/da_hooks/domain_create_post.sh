#!/usr/bin/env bash
set -uo pipefail

# DirectAdmin Subdirectory Hook: /usr/local/directadmin/scripts/custom/domain_create_post/da_wp_toolkits.sh
# Refreshes DirectAdmin domain mapping in da-wptoolkitd immediately when a main or addon domain is created.

BIN="${DA_WPTK_BIN:-/usr/local/sbin/da-wptoolkit}"
ADMIN_SOCK="${DA_WPTK_ADMIN_SOCK:-/var/run/da-wptoolkit.sock}"
# shellcheck disable=SC2154
TARGET_USER="${username:-}"
# shellcheck disable=SC2154
TARGET_DOMAIN="${domain:-}"

if [[ -n "$TARGET_USER" && -x "$BIN" && -S "$ADMIN_SOCK" ]]; then
  "$BIN" hook domain_create --user "$TARGET_USER" --domain "$TARGET_DOMAIN" --sock "$ADMIN_SOCK" >/dev/null 2>&1 || true
fi

exit 0
