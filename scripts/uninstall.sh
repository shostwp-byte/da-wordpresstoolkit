#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# DA-WordPressToolkits Safe Production Uninstaller
# Safely unlocks any Fortress Core Lock (root:<user>) sites BEFORE stopping daemon,
# removes Nginx snippets & DirectAdmin hooks, and preserves backups unless --purge-data.
# ==============================================================================

PURGE_DATA=0
for arg in "$@"; do
  case "$arg" in
    --purge-data) PURGE_DATA=1 ;;
  esac
done

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "ERROR: scripts/uninstall.sh must be executed as root." >&2
  exit 1
fi

BIN_DST="/usr/local/sbin/da-wptoolkit"
ADMIN_SOCK="/var/run/da-wptoolkit.sock"
USER_SOCK="/var/run/da-wptoolkit-user.sock"
DA_ROOT="/usr/local/directadmin"
PLUGIN_DST="${DA_ROOT}/plugins/da_wp_toolkits"
HOOKS_DST="${DA_ROOT}/scripts/custom"
SHARE_DST="/usr/local/share/da-wptoolkit"
STATE_DIR="/var/lib/da-wptoolkit"
CACHE_DIR="/var/cache/da-wptoolkit"
CONF_DIR="/etc/da-wptoolkit"
NGINX_SNIPPET_DIR="/etc/nginx/da-wptoolkit"
SERVICE_DST="/etc/systemd/system/da-wptoolkitd.service"

echo "[1/5] Releasing any active Fortress Core Lock (root:<user>) instances safely..."
if [[ -x "$BIN_DST" && -S "$ADMIN_SOCK" ]]; then
  LOCKED_IDS="$("$BIN_DST" list 2>/dev/null | awk '/shield=fortress_lock/{gsub(/[\[\]]/, "", $2); print $2}' || true)"
  for wp_id in $LOCKED_IDS; do
    if [[ -n "$wp_id" ]]; then
      echo "  -> Unlocking Core ownership on ${wp_id}..."
      "$BIN_DST" unlock-core "$wp_id" --sock "$ADMIN_SOCK" >/dev/null 2>&1 || true
    fi
  done
fi

# Secondary filesystem safety net in case daemon was already stopped while a site was locked
if [[ -f "${STATE_DIR}/instances.json" ]]; then
  while IFS='|' read -r owner docroot; do
    if [[ -n "$owner" && -n "$docroot" && -d "$docroot" ]] && id "$owner" >/dev/null 2>&1; then
      for core_dir in "${docroot}/wp-admin" "${docroot}/wp-includes"; do
        if [[ -d "$core_dir" && ! -L "$core_dir" ]]; then
          chown -hR "${owner}:${owner}" "$core_dir" 2>/dev/null || true
        fi
      done
      find "$docroot" -maxdepth 1 -type f -name 'wp-*.php' -user root -exec chown "${owner}:${owner}" {} + 2>/dev/null || true
      if [[ -f "${docroot}/index.php" && ! -L "${docroot}/index.php" ]]; then
        chown "${owner}:${owner}" "${docroot}/index.php" 2>/dev/null || true
      fi
    fi
  done < <(grep -B5 -A5 '"fortress_lock"' "${STATE_DIR}/instances.json" 2>/dev/null | awk -F'"' '
    /"owner":/ { u=$4 }
    /"doc_root":/ { d=$4 }
    u != "" && d != "" { print u "|" d; u=""; d="" }
  ' || true)
fi

echo "[2/5] Stopping and disabling da-wptoolkitd service..."
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop da-wptoolkitd.service >/dev/null 2>&1 || true
  systemctl disable da-wptoolkitd.service >/dev/null 2>&1 || true
  rm -f "$SERVICE_DST"
  systemctl daemon-reload >/dev/null 2>&1 || true
fi
rm -f "$ADMIN_SOCK" "$USER_SOCK"

echo "[3/5] Removing DirectAdmin Event Hooks & custom Nginx snippets..."
HOOK_NAMES=(
  domain_create_post
  domain_destroy_post
  subdomain_create_post
  subdomain_destroy_post
  user_modify_post
  user_backup_pre
  user_backup_post
  user_restore_post
  user_destroy_post
)
for hk in "${HOOK_NAMES[@]}"; do
  rm -f "${HOOKS_DST}/${hk}/da_wp_toolkits.sh"
done

if [[ -d "$NGINX_SNIPPET_DIR" ]]; then
  rm -rf "$NGINX_SNIPPET_DIR"
  if command -v nginx >/dev/null 2>&1 && nginx -t >/dev/null 2>&1; then
    systemctl reload nginx >/dev/null 2>&1 || true
  fi
fi

echo "[4/5] Removing daemon binary & DirectAdmin plugin files..."
rm -f "$BIN_DST"
rm -rf "$SHARE_DST" "$PLUGIN_DST"

if [[ "$PURGE_DATA" -eq 1 ]]; then
  echo "[5/5] Purging state store, Core cache & configuration (--purge-data)..."
  rm -rf "$STATE_DIR" "$CACHE_DIR" "$CONF_DIR" /etc/sysctl.d/90-da-wptoolkit.conf
else
  echo "[5/5] Preserved state store & quarantine/backups at ${STATE_DIR} (pass --purge-data to remove)."
fi

echo "DA-WordPressToolkits uninstalled cleanly."
