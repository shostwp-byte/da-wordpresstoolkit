#!/usr/bin/env bash
set -euo pipefail

# ==============================================================================
# WordPress Manager Multi-Arch Release & DirectAdmin Plugin Packager
# Produces:
#   - dist/release/da-wptoolkit-linux-amd64.tar.gz
#   - dist/release/da-wptoolkit-linux-arm64.tar.gz
#   - dist/release/da_wp_toolkits.tar.gz (DirectAdmin Plugin Manager package)
#   - dist/release/checksums.txt (+ checksums.txt.sig if DA_WPTK_RELEASE_PRIVATE_KEY set)
# ==============================================================================

ROOT_DIR="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$ROOT_DIR"

REL_DIR="${ROOT_DIR}/dist/release"
rm -rf "$REL_DIR"
mkdir -p "$REL_DIR"

make build-linux-amd64
make build-linux-arm64

for arch in amd64 arm64; do
  STAGE="$(mktemp -d)"
  mkdir -p "${STAGE}/bin" "${STAGE}/plugin" "${STAGE}/scripts/da_hooks" "${STAGE}/systemd" "${STAGE}/docs"
  install -m 0755 "dist/da-wptoolkit-linux-${arch}" "${STAGE}/bin/da-wptoolkit"
  cp -rf plugin/. "${STAGE}/plugin/"
  rm -f "${STAGE}/plugin/data/default_policy.conf" "${STAGE}/plugin/data/packages/"*.conf 2>/dev/null || true
  find "${STAGE}/plugin" -type d -exec chmod 0755 {} +
  find "${STAGE}/plugin" -type f -exec chmod 0644 {} +
  chmod 0755 "${STAGE}/plugin/admin/index.html" "${STAGE}/plugin/admin/api.raw" "${STAGE}/plugin/user/index.html" "${STAGE}/plugin/user/api.raw"
  if [[ -d "${STAGE}/plugin/scripts" ]]; then
    chmod 0755 "${STAGE}/plugin/scripts/"*.sh 2>/dev/null || true
  fi

  install -m 0755 scripts/install.sh "${STAGE}/scripts/install.sh"
  install -m 0755 scripts/uninstall.sh "${STAGE}/scripts/uninstall.sh"
  install -m 0755 scripts/update.sh "${STAGE}/scripts/update.sh"
  install -m 0755 scripts/qa_verify.sh "${STAGE}/scripts/qa_verify.sh"
  install -m 0755 scripts/da_hooks/*.sh "${STAGE}/scripts/da_hooks/"
  install -m 0644 systemd/da-wptoolkitd.service "${STAGE}/systemd/da-wptoolkitd.service"
  install -m 0644 README.md LICENSE "${STAGE}/"
  if [[ -f docs/RUNBOOK.md ]]; then
    install -m 0644 docs/RUNBOOK.md "${STAGE}/docs/RUNBOOK.md"
  fi
  install -m 0644 docs/IPC_PROTOCOL.md "${STAGE}/docs/IPC_PROTOCOL.md"

  tar -C "$STAGE" -czf "${REL_DIR}/da-wptoolkit-linux-${arch}.tar.gz" .
  rm -rf "$STAGE"
done

# Build DirectAdmin Plugin Manager compatible archive (da_wp_toolkits.tar.gz)
DA_STAGE="$(mktemp -d)"
cp -rf plugin/. "$DA_STAGE/"
rm -f "${DA_STAGE}/data/default_policy.conf" "${DA_STAGE}/data/packages/"*.conf 2>/dev/null || true
mkdir -p "${DA_STAGE}/bundle/dist" "${DA_STAGE}/bundle/scripts/da_hooks" "${DA_STAGE}/bundle/systemd" "${DA_STAGE}/bundle/plugin"
install -m 0755 dist/da-wptoolkit-linux-amd64 "${DA_STAGE}/bundle/dist/da-wptoolkit-linux-amd64"
install -m 0755 dist/da-wptoolkit-linux-arm64 "${DA_STAGE}/bundle/dist/da-wptoolkit-linux-arm64"
cp -rf plugin/. "${DA_STAGE}/bundle/plugin/"
install -m 0755 scripts/install.sh "${DA_STAGE}/bundle/scripts/install.sh"
install -m 0755 scripts/uninstall.sh "${DA_STAGE}/bundle/scripts/uninstall.sh"
install -m 0755 scripts/update.sh "${DA_STAGE}/bundle/scripts/update.sh"
install -m 0755 scripts/da_hooks/*.sh "${DA_STAGE}/bundle/scripts/da_hooks/"
install -m 0644 systemd/da-wptoolkitd.service "${DA_STAGE}/bundle/systemd/da-wptoolkitd.service"
find "${DA_STAGE}/admin" "${DA_STAGE}/user" "${DA_STAGE}/hooks" "${DA_STAGE}/images" "${DA_STAGE}/scripts" -type d -exec chmod 0755 {} +
find "${DA_STAGE}/admin" "${DA_STAGE}/user" "${DA_STAGE}/hooks" "${DA_STAGE}/images" -type f -exec chmod 0644 {} +
chmod 0644 "${DA_STAGE}/plugin.conf"
chmod 0755 "${DA_STAGE}/admin/index.html" "${DA_STAGE}/admin/api.raw" "${DA_STAGE}/user/index.html" "${DA_STAGE}/user/api.raw" "${DA_STAGE}/scripts/"*.sh
tar -C "$DA_STAGE" -czf "${REL_DIR}/da_wp_toolkits.tar.gz" .
rm -rf "$DA_STAGE"

if [[ -n "${DA_WPTK_RELEASE_PRIVATE_KEY:-}" ]]; then
  go run ./cmd/da-wptoolkit sign-release --dir "$REL_DIR"
else
  (cd "$REL_DIR" && sha256sum ./*.tar.gz | sed 's|\./||' >checksums.txt)
fi

ls -lh "$REL_DIR"
