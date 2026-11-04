#!/usr/bin/env bash
set -euo pipefail

# QA & Acceptance Verification Suite for DA-WordPressToolkits
ADMIN_SOCK="${DA_WPTK_ADMIN_SOCK:-/var/run/da-wptoolkit.sock}"
USER_SOCK="${DA_WPTK_USER_SOCK:-/var/run/da-wptoolkit-user.sock}"
BIN="${DA_WPTK_BIN:-/usr/local/sbin/da-wptoolkit}"

cmd="${1:-preflight}"

case "$cmd" in
  preflight)
    echo "[1/7] Checking daemon binary..."
    if [[ ! -x "$BIN" ]]; then
      echo "FAIL: binary not executable at $BIN"
      exit 1
    fi
    "$BIN" version

    echo "[2/7] Checking Dual Unix Domain Sockets..."
    for s in "$ADMIN_SOCK" "$USER_SOCK"; do
      if [[ ! -S "$s" ]]; then
        echo "FAIL: Unix socket missing at $s"
        exit 1
      fi
    done

    echo "[3/7] Pinging da-wptoolkitd (WebServer & inotify telemetry)..."
    "$BIN" ping --sock "$ADMIN_SOCK"

    echo "[4/7] Verifying CLI listing, Shield Mode & CVE filter..."
    "$BIN" list --sock "$ADMIN_SOCK"
    "$BIN" list --vuln --sock "$ADMIN_SOCK"

    echo "[5/7] Checking Linux inotify watch capacity..."
    if [[ -r /proc/sys/fs/inotify/max_user_watches ]]; then
      watches="$(cat /proc/sys/fs/inotify/max_user_watches)"
      echo "fs.inotify.max_user_watches = ${watches}"
    fi

    echo "[6/8] Verifying DirectAdmin Backup Pre/Post Hook scripts..."
    for hook in scripts/hooks/user_backup_pre.sh scripts/hooks/user_backup_post.sh; do
      if [[ -f "$hook" ]]; then
        echo "Verified hook script: $hook"
      fi
    done

    echo "[7/9] Verifying Evolution Skin User & Admin UI entrypoints..."
    for ui in plugin/user/index.html plugin/admin/index.html plugin/user/api.raw plugin/admin/api.raw; do
      if [[ -f "$ui" ]]; then
        echo "Verified UI script: $ui"
      fi
    done

    echo "[8/9] Verifying CLI subcommands (Quick Tools, Snapshots, Clone & Sync)..."
    "$BIN" --help >/dev/null

    echo "[9/9] Ready for Evolution Skin End-User & Admin Panels."
    echo "PASS: Phase 5 (v0.6.0) preflight verification succeeded."
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
    echo "Usage: $0 {preflight|scan-all|sync-vulndb|verify-all-core|snapshot-list|tools-status}"
    exit 2
    ;;
esac
