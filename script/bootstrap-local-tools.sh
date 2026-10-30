#!/usr/bin/env bash
# ==============================================================================
# CyberLab OS — Local Self-Contained Tool Bootstrap (.cyberlab/bin)
# ==============================================================================
# Downloads optional standalone open-source security binaries directly into
# .cyberlab/bin/ inside your local CyberLab-OS workspace (gitignored) so that
# external engines live right inside your project directory without polluting
# the MIT git repository or global OS paths.
#
# Usage:
#   ./script/bootstrap-local-tools.sh              # installs MIT Go tools (nuclei, ffuf)
#   ./script/bootstrap-local-tools.sh --with-agpl  # also fetches OpenTRAP AppImage (AGPL-3.0)
# ==============================================================================

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="${ROOT_DIR}/.cyberlab/bin"
mkdir -p "${BIN_DIR}"

WITH_AGPL=0
for arg in "$@"; do
  if [[ "${arg}" == "--with-agpl" ]]; then
    WITH_AGPL=1
  fi
done

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "${ARCH}" in
  x86_64|amd64) ARCH_NUCLEI="amd64"; ARCH_FFUF="amd64" ;;
  aarch64|arm64) ARCH_NUCLEI="arm64"; ARCH_FFUF="arm64" ;;
  *) echo "Unsupported CPU architecture: ${ARCH}" >&2; exit 1 ;;
esac

echo "[CyberLab OS] Local workspace binary directory: ${BIN_DIR}"

# 1. ProjectDiscovery Nuclei (MIT License)
NUCLEI_VERSION="3.3.7"
NUCLEI_ZIP="nuclei_${NUCLEI_VERSION}_${OS}_${ARCH_NUCLEI}.zip"
if [[ ! -x "${BIN_DIR}/nuclei" ]]; then
  echo "[CyberLab OS] Downloading Nuclei v${NUCLEI_VERSION} (MIT)..."
  TMP_DIR="$(mktemp -d)"
  curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/${NUCLEI_ZIP}" -o "${TMP_DIR}/nuclei.zip"
  unzip -q -o "${TMP_DIR}/nuclei.zip" nuclei -d "${BIN_DIR}"
  chmod +x "${BIN_DIR}/nuclei"
  rm -rf "${TMP_DIR}"
  echo "[CyberLab OS] Installed ${BIN_DIR}/nuclei"
else
  echo "[CyberLab OS] Nuclei already present at ${BIN_DIR}/nuclei"
fi

# 2. ffuf — Fast Web Fuzzer (MIT License)
FFUF_VERSION="2.1.0"
FFUF_TAR="ffuf_${FFUF_VERSION}_${OS}_${ARCH_FFUF}.tar.gz"
if [[ ! -x "${BIN_DIR}/ffuf" ]]; then
  echo "[CyberLab OS] Downloading ffuf v${FFUF_VERSION} (MIT)..."
  TMP_DIR="$(mktemp -d)"
  curl -fsSL "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/${FFUF_TAR}" -o "${TMP_DIR}/ffuf.tar.gz"
  tar -xzf "${TMP_DIR}/ffuf.tar.gz" -C "${TMP_DIR}" ffuf
  mv "${TMP_DIR}/ffuf" "${BIN_DIR}/ffuf"
  chmod +x "${BIN_DIR}/ffuf"
  rm -rf "${TMP_DIR}"
  echo "[CyberLab OS] Installed ${BIN_DIR}/ffuf"
else
  echo "[CyberLab OS] ffuf already present at ${BIN_DIR}/ffuf"
fi

# 3. Optional: OpenTRAP Desktop Proxy AppImage (AGPL-3.0, Linux x86_64 only, opt-in)
if [[ "${WITH_AGPL}" -eq 1 ]]; then
  if [[ "${OS}" == "linux" && "${ARCH_NUCLEI}" == "amd64" ]]; then
    OPENTRAP_VERSION="1.0.2"
    if [[ ! -x "${BIN_DIR}/opentrap.AppImage" ]]; then
      echo "[CyberLab OS] Downloading OpenTRAP v${OPENTRAP_VERSION} AppImage (AGPL-3.0 opt-in)..."
      curl -fsSL "https://github.com/opentrap/opentrap/releases/download/v${OPENTRAP_VERSION}/opentrap-x86_64.appimage" -o "${BIN_DIR}/opentrap.AppImage"
      chmod +x "${BIN_DIR}/opentrap.AppImage"
      echo "[CyberLab OS] Installed ${BIN_DIR}/opentrap.AppImage"
    else
      echo "[CyberLab OS] OpenTRAP already present at ${BIN_DIR}/opentrap.AppImage"
    fi
  else
    echo "[CyberLab OS] Skipping OpenTRAP AppImage (requires Linux x86_64)."
  fi
fi

echo ""
echo "[CyberLab OS] Local tool bootstrap complete!"
echo "Add .cyberlab/bin to your shell PATH when running local sessions:"
echo "  export PATH=\"${BIN_DIR}:\$PATH\""
