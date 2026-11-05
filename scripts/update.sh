#!/usr/bin/env bash
set -uo pipefail

# ==============================================================================
# WordPress Manager Detached Atomic Updater & Auto-Rollback Runner (TC-10)
# Executed outside da-wptoolkitd.service cgroup via systemd-run so restarting
# da-wptoolkitd never interrupts the atomic swap or healthcheck/auto-rollback!
# ==============================================================================

BIN_DST="${DA_WPTK_BIN:-/usr/local/sbin/da-wptoolkit}"
PLUGIN_DST="${DA_WPTK_PLUGIN_DIR:-/usr/local/directadmin/plugins/da_wp_toolkits}"
ADMIN_SOCK="${DA_WPTK_ADMIN_SOCK:-/var/run/da-wptoolkit.sock}"
SERVICE_NAME="${DA_WPTK_SERVICE:-da-wptoolkitd}"

STAGED_DIR=""
BACKUP_TAR=""
TARGET_VER=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --staged)
      STAGED_DIR="${2:-}"
      shift 2
      ;;
    --backup)
      BACKUP_TAR="${2:-}"
      shift 2
      ;;
    --target-version)
      TARGET_VER="${2:-}"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

emergency_shell_rollback() {
  echo "[update.sh] Triggering emergency shell rollback from ${BACKUP_TAR}..." >&2
  if [[ -z "$BACKUP_TAR" || ! -f "$BACKUP_TAR" ]]; then
    echo "[update.sh] CRITICAL: backup archive missing (${BACKUP_TAR})" >&2
    return 1
  fi
  RB_TMP="$(mktemp -d /tmp/dawptk-rb.XXXXXX)"
  if tar -xzf "$BACKUP_TAR" -C "$RB_TMP"; then
    if [[ -f "${RB_TMP}/bin/da-wptoolkit" ]]; then
      install -m 0755 "${RB_TMP}/bin/da-wptoolkit" "${BIN_DST}.rb"
      mv -f "${BIN_DST}.rb" "$BIN_DST"
    fi
    if [[ -d "${RB_TMP}/plugin" ]]; then
      for sub in admin user hooks images scripts; do
        if [[ -d "${RB_TMP}/plugin/${sub}" ]]; then
          install -d -m 0755 "${PLUGIN_DST}/${sub}"
          cp -rf "${RB_TMP}/plugin/${sub}/." "${PLUGIN_DST}/${sub}/"
          find "${PLUGIN_DST}/${sub}" -type d -exec chmod 0755 {} +
          find "${PLUGIN_DST}/${sub}" -type f -exec chmod 0644 {} +
        fi
      done
      if [[ -f "${RB_TMP}/plugin/plugin.conf" ]]; then
        install -m 0644 "${RB_TMP}/plugin/plugin.conf" "${PLUGIN_DST}/plugin.conf"
      fi
      chmod 0755 "$PLUGIN_DST" "${PLUGIN_DST}/admin/index.html" "${PLUGIN_DST}/admin/api.raw" "${PLUGIN_DST}/user/index.html" "${PLUGIN_DST}/user/api.raw" 2>/dev/null || true
      chmod 0755 "${PLUGIN_DST}/scripts/"*.sh 2>/dev/null || true
      if id diradmin >/dev/null 2>&1; then
        chown -R diradmin:diradmin "$PLUGIN_DST"
      fi
    fi
  fi
  rm -rf "$RB_TMP"
  systemctl restart "$SERVICE_NAME" >/dev/null 2>&1 || true
}

# Mode 1: Invoked with pre-verified --staged payload & --backup snapshot
if [[ -n "$STAGED_DIR" && -n "$BACKUP_TAR" ]]; then
  if "$BIN_DST" apply-staged --staged "$STAGED_DIR" --backup "$BACKUP_TAR" --target-version "$TARGET_VER" --sock "$ADMIN_SOCK"; then
    if [[ -d "$PLUGIN_DST" ]]; then
      find "${PLUGIN_DST}/admin" "${PLUGIN_DST}/user" "${PLUGIN_DST}/hooks" "${PLUGIN_DST}/images" "${PLUGIN_DST}/scripts" -type d -exec chmod 0755 {} + 2>/dev/null || true
      find "${PLUGIN_DST}/admin" "${PLUGIN_DST}/user" "${PLUGIN_DST}/hooks" "${PLUGIN_DST}/images" -type f -exec chmod 0644 {} + 2>/dev/null || true
      chmod 0644 "${PLUGIN_DST}/plugin.conf" 2>/dev/null || true
      chmod 0755 "$PLUGIN_DST" "${PLUGIN_DST}/admin/index.html" "${PLUGIN_DST}/admin/api.raw" "${PLUGIN_DST}/user/index.html" "${PLUGIN_DST}/user/api.raw" 2>/dev/null || true
      chmod 0755 "${PLUGIN_DST}/scripts/"*.sh 2>/dev/null || true
      if id diradmin >/dev/null 2>&1; then
        chown -R diradmin:diradmin "$PLUGIN_DST"
      fi
    fi
    systemctl reload-or-restart directadmin.service >/dev/null 2>&1 || true
    exit 0
  fi

  # Double safety net: verify daemon responds to ping; if not, run emergency shell rollback!
  HEALTHY=0
  for _ in $(seq 1 12); do
    if "$BIN_DST" ping --sock "$ADMIN_SOCK" >/dev/null 2>&1; then
      HEALTHY=1
      break
    fi
    sleep 0.5
  done

  if [[ "$HEALTHY" -ne 1 ]]; then
    emergency_shell_rollback
  fi
  exit 1
fi

# Mode 2: Standalone CLI invocation (`scripts/update.sh` with no args)
exec "$BIN_DST" update "$@"
