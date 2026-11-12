#!/usr/bin/env bash
set -euo pipefail

BIN_PATH="$1"
TARGET_NAME="$2"
ASSET_NAME="$3"
VERSION="${4:-}"

if [ -z "$BIN_PATH" ] || [ -z "$TARGET_NAME" ] || [ -z "$ASSET_NAME" ]; then
    echo "Uso: $0 <caminho-binario> <target> <asset-name> [versao]"
    exit 1
fi

if [ -z "$VERSION" ]; then
    if [ -f "Cargo.toml" ]; then
        VERSION="$(grep -m1 '^version = ' Cargo.toml | cut -d '"' -f2)"
    else
        VERSION="0.3.3"
    fi
fi

calc_sha256() {
    local file="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file"
    else
        shasum -a 256 "$file"
    fi
}

# 1. Empacota Tarball (.tar.gz)
mkdir -p dist
cp "$BIN_PATH" dist/sentinela
cp install.sh dist/
cp README.md dist/
cp LICENSE dist/
chmod +x dist/sentinela dist/install.sh

tar -czf "${ASSET_NAME}.tar.gz" -C dist sentinela install.sh README.md LICENSE
calc_sha256 "${ASSET_NAME}.tar.gz" > "${ASSET_NAME}.tar.gz.sha256"

# Se não for Linux (ex.: macOS), conclui após gerar o tarball
if [ "$(uname -s)" != "Linux" ]; then
    exit 0
fi

# 2. Empacota Debian (.deb)
DEB_ARCH="amd64"
if [ "$TARGET_NAME" = "aarch64-unknown-linux-gnu" ]; then
    DEB_ARCH="arm64"
fi

DEB_ROOT="sentinela_deb_pkg"
rm -rf "$DEB_ROOT"
mkdir -p "${DEB_ROOT}/DEBIAN"
mkdir -p "${DEB_ROOT}/usr/bin"
mkdir -p "${DEB_ROOT}/usr/share/doc/sentinela"

cp "$BIN_PATH" "${DEB_ROOT}/usr/bin/sentinela"
chmod 755 "${DEB_ROOT}/usr/bin/sentinela"
cp README.md LICENSE "${DEB_ROOT}/usr/share/doc/sentinela/"

cat << EOF > "${DEB_ROOT}/DEBIAN/control"
Package: sentinela
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: ${DEB_ARCH}
Maintainer: Salvador Pontes <123838416+teizinh@users.noreply.github.com>
Depends: libc6 (>= 2.31)
Recommends: libcap2-bin, iptables
Description: Sentinela - Honeypot & Network Intrusion Detection System
 Sistema leve de deteção de intrusões (NIDS) e armadilhas honeypot em Rust.

EOF

cat << 'EOF' > "${DEB_ROOT}/DEBIAN/postinst"
#!/bin/sh
set -e

SETCAP_BIN=""
if command -v setcap >/dev/null 2>&1; then
    SETCAP_BIN="setcap"
elif [ -x /usr/sbin/setcap ]; then
    SETCAP_BIN="/usr/sbin/setcap"
elif [ -x /sbin/setcap ]; then
    SETCAP_BIN="/sbin/setcap"
fi

if [ -n "$SETCAP_BIN" ]; then
    "$SETCAP_BIN" cap_net_raw,cap_net_admin+eip /usr/bin/sentinela 2>/dev/null || true
fi
EOF
chmod 755 "${DEB_ROOT}/DEBIAN/postinst"

cat << 'EOF' > "${DEB_ROOT}/DEBIAN/postrm"
#!/bin/sh
set -e
exit 0
EOF
chmod 755 "${DEB_ROOT}/DEBIAN/postrm"

if command -v dpkg-deb >/dev/null 2>&1; then
    dpkg-deb -Zxz --root-owner-group --build "${DEB_ROOT}" "${ASSET_NAME}.deb"
    calc_sha256 "${ASSET_NAME}.deb" > "${ASSET_NAME}.deb.sha256"
fi
rm -rf "$DEB_ROOT"

# 3. Empacota RPM (.rpm) para x86_64 se alien estiver disponivel
if [ "$TARGET_NAME" = "x86_64-unknown-linux-gnu" ] && [ -f "${ASSET_NAME}.deb" ]; then
    if command -v alien >/dev/null 2>&1; then
        if [ "$(id -u)" -eq 0 ]; then
            alien --to-rpm --scripts "${ASSET_NAME}.deb"
        else
            sudo -n alien --to-rpm --scripts "${ASSET_NAME}.deb"
        fi
        mv sentinela-*.rpm "${ASSET_NAME}.rpm" 2>/dev/null || true
        if [ -f "${ASSET_NAME}.rpm" ]; then
            calc_sha256 "${ASSET_NAME}.rpm" > "${ASSET_NAME}.rpm.sha256"
        fi
    fi
fi
