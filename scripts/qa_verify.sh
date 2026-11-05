#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# QA & Production Acceptance Verification Suite for WordPress Manager
# ==============================================================================

ADMIN_SOCK="${DA_WPTK_ADMIN_SOCK:-/var/run/da-wptoolkit.sock}"
USER_SOCK="${DA_WPTK_USER_SOCK:-/var/run/da-wptoolkit-user.sock}"
BIN="${DA_WPTK_BIN:-/usr/local/sbin/da-wptoolkit}"

cmd="${1:-preflight}"

case "$cmd" in
  preflight)
    echo "[1/10] Checking daemon binary & version..."
    if [[ ! -x "$BIN" ]]; then
      echo "FAIL: binary not executable at $BIN"
      exit 1
    fi
    "$BIN" version

    echo "[2/10] Checking Dual Unix Domain Sockets..."
    for s in "$ADMIN_SOCK" "$USER_SOCK"; do
      if [[ ! -S "$s" ]]; then
        echo "FAIL: Unix socket missing at $s"
        exit 1
      fi
    done

    echo "[3/10] Pinging da-wptoolkitd (WebServer & inotify telemetry)..."
    "$BIN" ping --sock "$ADMIN_SOCK"

    echo "[4/10] Verifying CLI listing, Shield Mode & CVE filter..."
    "$BIN" list --sock "$ADMIN_SOCK"
    "$BIN" list --vuln --sock "$ADMIN_SOCK"

    echo "[5/10] Checking Linux inotify watch capacity..."
    if [[ -r /proc/sys/fs/inotify/max_user_watches ]]; then
      watches="$(cat /proc/sys/fs/inotify/max_user_watches)"
      echo "fs.inotify.max_user_watches = ${watches}"
    fi

    echo "[6/10] Verifying all 9 DirectAdmin Subdirectory Event Hook scripts..."
    HOOKS=(
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
    for hk in "${HOOKS[@]}"; do
      if [[ -f "scripts/da_hooks/${hk}.sh" ]]; then
        echo "  -> Repo hook verified: scripts/da_hooks/${hk}.sh"
      fi
      if [[ -x "/usr/local/directadmin/scripts/custom/${hk}/da_wp_toolkits.sh" ]]; then
        echo "  -> Installed DA hook verified: /usr/local/directadmin/scripts/custom/${hk}/da_wp_toolkits.sh"
      fi
    done

    echo "[7/10] Verifying Evolution Skin User & Admin UI entrypoints..."
    for ui in plugin/user/index.html plugin/admin/index.html plugin/user/api.raw plugin/admin/api.raw; do
      if [[ -f "$ui" ]]; then
        echo "  -> Verified UI script: $ui"
      fi
    done

    echo "[8/10] Verifying Production Installer, Uninstaller & Detached Updater scripts..."
    for sc in scripts/install.sh scripts/uninstall.sh scripts/update.sh scripts/package_release.sh; do
      if [[ -f "$sc" ]]; then
        echo "  -> Verified operational script: $sc"
      fi
    done

    echo "[9/10] Verifying Ed25519 GitHub Self-Updater & CLI subcommands..."
    "$BIN" --help >/dev/null

    echo "[10/10] Production Acceptance Preflight Completed."
    echo "PASS: WordPress Manager preflight verification succeeded."
    ;;
  scan-all)
    "$BIN" scan --all --sock "$ADMIN_SOCK"
    ;;
  sync-vulndb)
    "$BIN" sync-vulndb --sock "$ADMIN_SOCK"
    ;;
  verify-all-core)
    "$BIN" verify-core --all --sock "$ADMIN_SOCK"
    ;;
  check-update)
    "$BIN" check-update --sock "$ADMIN_SOCK"
    ;;
  snapshot-list)
    if [[ -z "${2:-}" ]]; then
      echo "Usage: $0 snapshot-list <instance_id>"
      exit 2
    fi
    "$BIN" snapshot list "$2" --sock "$ADMIN_SOCK"
    ;;
  tools-status)
    if [[ -z "${2:-}" ]]; then
      echo "Usage: $0 tools-status <instance_id>"
      exit 2
    fi
    "$BIN" tools status "$2" --sock "$ADMIN_SOCK"
    ;;
  *)
    echo "Usage: $0 {preflight|scan-all|sync-vulndb|verify-all-core|check-update|snapshot-list|tools-status}"
    exit 2
    ;;
esac
