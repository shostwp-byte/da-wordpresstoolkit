#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# DA-WordPressToolkits 1-Click Production Installer (DirectAdmin Evolution Skin)
# Supports: CloudLinux / AlmaLinux / Rocky Linux 8-9, Ubuntu 20.04-24.04, Debian 11-12
# Architectures: x86_64 (amd64), aarch64 (arm64)
# ==============================================================================

REPO="${DA_WPTK_REPO:-shostwp-byte/da-wordpresstoolkit}"
REL_VER="${DA_WPTK_VERSION:-latest}"
BIN_DST="/usr/local/sbin/da-wptoolkit"
DA_ROOT="/usr/local/directadmin"
PLUGIN_DST="${DA_ROOT}/plugins/da_wp_toolkits"
HOOKS_DST="${DA_ROOT}/scripts/custom"
SHARE_DST="/usr/local/share/da-wptoolkit"
STATE_DIR="/var/lib/da-wptoolkit"
CACHE_DIR="/var/cache/da-wptoolkit/wp-core"
CONF_DIR="/etc/da-wptoolkit"
SYSCTL_FILE="/etc/sysctl.d/90-da-wptoolkit.conf"
SERVICE_DST="/etc/systemd/system/da-wptoolkitd.service"
WPCLI_DST="/usr/local/bin/wp"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "ERROR: scripts/install.sh must be executed as root." >&2
  exit 1
fi

if [[ ! -d "$DA_ROOT" ]]; then
  echo "ERROR: DirectAdmin installation not found at ${DA_ROOT}." >&2
  exit 1
fi

UNAME_ARCH="$(uname -m)"
case "$UNAME_ARCH" in
  x86_64|amd64) TARGET_ARCH="amd64" ;;
  aarch64|arm64) TARGET_ARCH="arm64" ;;
  *)
    echo "ERROR: Unsupported CPU architecture: ${UNAME_ARCH} (expected x86_64 or aarch64)." >&2
    exit 1
    ;;
esac

SCRIPT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)"
BUNDLE_ROOT="$(CDPATH='' cd -- "${SCRIPT_DIR}/.." && pwd)"
TMP_DL=""
cleanup() {
  if [[ -n "$TMP_DL" && -d "$TMP_DL" ]]; then
    rm -rf "$TMP_DL"
  fi
}
trap cleanup EXIT

# Locate binary & bundle either from local extracted package or GitHub Releases
SRC_BIN=""
if [[ -f "${BUNDLE_ROOT}/bin/da-wptoolkit" ]]; then
  SRC_BIN="${BUNDLE_ROOT}/bin/da-wptoolkit"
elif [[ -f "${BUNDLE_ROOT}/dist/da-wptoolkit-linux-${TARGET_ARCH}" ]]; then
  SRC_BIN="${BUNDLE_ROOT}/dist/da-wptoolkit-linux-${TARGET_ARCH}"
else
  echo "[1/7] Downloading DA-WordPressToolkits release (${REL_VER} / ${TARGET_ARCH}) from GitHub..."
  TMP_DL="$(mktemp -d /tmp/dawptk-install.XXXXXX)"
  TARBALL="da-wptoolkit-linux-${TARGET_ARCH}.tar.gz"
  if [[ "$REL_VER" == "latest" ]]; then
    DL_BASE="https://github.com/${REPO}/releases/latest/download"
  else
    DL_BASE="https://github.com/${REPO}/releases/download/${REL_VER}"
  fi
  curl -fsSL "${DL_BASE}/${TARBALL}" -o "${TMP_DL}/${TARBALL}"
  curl -fsSL "${DL_BASE}/checksums.txt" -o "${TMP_DL}/checksums.txt"
  (cd "$TMP_DL" && grep "  ${TARBALL}\$" checksums.txt | sha256sum -c -)
  tar -xzf "${TMP_DL}/${TARBALL}" -C "$TMP_DL"
  BUNDLE_ROOT="$TMP_DL"
  SRC_BIN="${BUNDLE_ROOT}/bin/da-wptoolkit"
fi

echo "[2/7] Verifying WP-CLI (${WPCLI_DST})..."
if [[ ! -x "$WPCLI_DST" ]]; then
  WP_TMP="$(mktemp /tmp/wp-cli.XXXXXX.phar)"
  WP_SHA="$(mktemp /tmp/wp-cli.XXXXXX.sha512)"
  curl -fsSL "https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar" -o "$WP_TMP"
  curl -fsSL "https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar.sha512" -o "$WP_SHA"
  EXPECTED_SHA512="$(awk '{print $1}' "$WP_SHA" | tr -d '[:space:]')"
  ACTUAL_SHA512="$(sha512sum "$WP_TMP" | awk '{print $1}')"
  rm -f "$WP_SHA"
  if [[ -z "$EXPECTED_SHA512" || "$EXPECTED_SHA512" != "$ACTUAL_SHA512" ]]; then
    rm -f "$WP_TMP"
    echo "ERROR: WP-CLI SHA-512 checksum verification failed!" >&2
    exit 1
  fi
  chmod 0755 "$WP_TMP"
  mv -f "$WP_TMP" "$WPCLI_DST"
  echo "  -> Installed verified WP-CLI to ${WPCLI_DST}"
else
  echo "  -> Existing WP-CLI binary detected at ${WPCLI_DST}"
fi

echo "[3/7] Checking Linux kernel inotify watch limits..."
if [[ -r /proc/sys/fs/inotify/max_user_watches ]]; then
  CUR_WATCHES="$(cat /proc/sys/fs/inotify/max_user_watches)"
  if [[ "$CUR_WATCHES" -lt 524288 ]]; then
    cat >"$SYSCTL_FILE" <<'EOF'
# Raised automatically by DA-WordPressToolkits for high-density Core Integrity Shield
fs.inotify.max_user_watches = 524288
fs.inotify.max_user_instances = 1024
EOF
    sysctl --system >/dev/null 2>&1 || sysctl -p "$SYSCTL_FILE" >/dev/null 2>&1 || true
    echo "  -> Raised fs.inotify.max_user_watches (${CUR_WATCHES} -> 524288)"
  else
    echo "  -> fs.inotify.max_user_watches = ${CUR_WATCHES} (sufficient)"
  fi
fi

echo "[4/7] Installing daemon binary, state directories & DirectAdmin Evolution Skin plugin..."
install -d -m 0700 "$STATE_DIR" "${STATE_DIR}/backups" "${STATE_DIR}/quarantine" "$CONF_DIR"
install -d -m 0755 "$CACHE_DIR" "${SHARE_DST}/scripts" "$PLUGIN_DST" "${PLUGIN_DST}/data" "${PLUGIN_DST}/data/packages"

install -m 0755 "$SRC_BIN" "${BIN_DST}.new"
mv -f "${BIN_DST}.new" "$BIN_DST"

if [[ -f "${BUNDLE_ROOT}/scripts/update.sh" ]]; then
  install -m 0700 "${BUNDLE_ROOT}/scripts/update.sh" "${SHARE_DST}/scripts/update.sh"
fi

if [[ ! -f "${CONF_DIR}/updater.conf" ]]; then
  cat >"${CONF_DIR}/updater.conf" <<EOF
GITHUB_REPO=${REPO}
UPDATE_CHANNEL=stable
BACKUP_RETENTION=5
EOF
  chmod 0600 "${CONF_DIR}/updater.conf"
fi

# Sync plugin files without overwriting live policy configs in plugin/data/
for sub in admin user hooks images scripts; do
  if [[ -d "${BUNDLE_ROOT}/plugin/${sub}" ]]; then
    install -d -m 0755 "${PLUGIN_DST}/${sub}"
    cp -rf "${BUNDLE_ROOT}/plugin/${sub}/." "${PLUGIN_DST}/${sub}/"
  fi
done
install -m 0644 "${BUNDLE_ROOT}/plugin/plugin.conf" "${PLUGIN_DST}/plugin.conf"
if [[ -f "${BUNDLE_ROOT}/plugin/data/default_policy.conf.example" ]]; then
  install -m 0644 "${BUNDLE_ROOT}/plugin/data/default_policy.conf.example" "${PLUGIN_DST}/data/default_policy.conf.example"
  if [[ ! -f "${PLUGIN_DST}/data/default_policy.conf" ]]; then
    install -m 0640 "${BUNDLE_ROOT}/plugin/data/default_policy.conf.example" "${PLUGIN_DST}/data/default_policy.conf"
  fi
fi

chmod 0755 "${PLUGIN_DST}/admin/index.html" "${PLUGIN_DST}/admin/api.raw" "${PLUGIN_DST}/user/index.html" "${PLUGIN_DST}/user/api.raw"
if [[ -d "${PLUGIN_DST}/scripts" ]]; then
  chmod 0755 "${PLUGIN_DST}/scripts/"*.sh 2>/dev/null || true
fi
if id diradmin >/dev/null 2>&1; then
  chown -R diradmin:diradmin "$PLUGIN_DST"
fi

echo "[5/7] Installing 9 DirectAdmin non-intrusive Subdirectory Event Hooks..."
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
  SRC_HK="${BUNDLE_ROOT}/scripts/da_hooks/${hk}.sh"
  if [[ -f "$SRC_HK" ]]; then
    install -d -m 0755 "${HOOKS_DST}/${hk}"
    install -m 0700 "$SRC_HK" "${HOOKS_DST}/${hk}/da_wp_toolkits.sh"
    if id diradmin >/dev/null 2>&1; then
      chown diradmin:diradmin "${HOOKS_DST}/${hk}/da_wp_toolkits.sh"
    fi
  fi
done

echo "[6/7] Configuring & starting systemd service (da-wptoolkitd.service)..."
if [[ -f "${BUNDLE_ROOT}/systemd/da-wptoolkitd.service" ]]; then
  install -m 0644 "${BUNDLE_ROOT}/systemd/da-wptoolkitd.service" "$SERVICE_DST"
  systemctl daemon-reload
  systemctl enable da-wptoolkitd.service
  systemctl restart da-wptoolkitd.service
fi

# Wait up to 10s for Dual Unix Sockets & ping healthcheck
READY=0
for _ in $(seq 1 20); do
  if "$BIN_DST" ping >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 0.5
done

if [[ "$READY" -ne 1 ]]; then
  echo "ERROR: da-wptoolkitd did not respond on /var/run/da-wptoolkit.sock within 10s." >&2
  systemctl status da-wptoolkitd.service --no-pager || true
  exit 1
fi

echo "[7/7] Running initial Zero-Eval WordPress Auto-Discovery across all DirectAdmin accounts..."
"$BIN_DST" scan --all || true
nohup "$BIN_DST" sync-vulndb >/dev/null 2>&1 &

echo ""
echo "=============================================================================="
echo " DA-WordPressToolkits installed successfully!"
echo "   Version    : $("$BIN_DST" version)"
echo "   User Panel : DirectAdmin Evolution Skin -> Extra Features -> DA WordPress Toolkits"
echo "   Admin Panel: DirectAdmin Evolution Skin -> Admin -> DA WordPress Toolkits"
echo "=============================================================================="
