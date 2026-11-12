#!/usr/bin/env sh
# ==============================================================================
# Sentinela HIDS - Script de Instalação Automatizado (Linux & macOS)
# Repositório: https://github.com/SirEntr0pyy/sentimela
# Licença: MIT
# ==============================================================================

set -e

REPO="SirEntr0pyy/sentimela"
BINARY_NAME="sentinela"

# Cores para o terminal (compatível com POSIX sh e dash)
RED=$(printf '\033[0;31m')
GREEN=$(printf '\033[0;32m')
BLUE=$(printf '\033[0;34m')
CYAN=$(printf '\033[0;36m')
YELLOW=$(printf '\033[1;33m')
BOLD=$(printf '\033[1m')
NC=$(printf '\033[0m')

printf "${CYAN}"
cat << 'EOF'
   ___           _   _            _       
  / __| ___ _ _ | |_(_)_ _  ___  | | __ _ 
  \__ \/ -_) ' \|  _| | ' \/ -_) | |/ _` |
  |___/\___|_||_|\__|_|_||_\___| |_|\__,_|
      Honeypot & Intrusion Detection System
EOF
printf "${NC}\n"

echo "${BOLD}==> A iniciar a instalação do Sentinela...${NC}"

# 1. Deteta o Sistema Operativo e Arquitetura
OS="$(uname -s)"
ARCH="$(uname -m)"

case "$OS" in
    Linux)
        OS_TAG="linux"
        ;;
    Darwin)
        OS_TAG="macos"
        ;;
    *)
        echo "${RED}Erro: Sistema Operativo não suportado: $OS${NC}"
        echo "O Sentinela suporta oficialmente Linux e macOS através deste script (e Windows via install.ps1)."
        exit 1
        ;;
esac

case "$ARCH" in
    x86_64|amd64)
        ARCH_TAG="x86_64"
        ;;
    aarch64|arm64)
        ARCH_TAG="arm64"
        ;;
    *)
        echo "${RED}Erro: Arquitetura não suportada: $ARCH${NC}"
        exit 1
        ;;
esac

ASSET_NAME="sentinela-${OS_TAG}-${ARCH_TAG}.tar.gz"
echo "  • Sistema detetado: ${BLUE}${OS} (${ARCH})${NC} -> Pacote: ${CYAN}${ASSET_NAME}${NC}"

# 2. Localiza ou Descarrega o Binário
TMP_DIR="$(mktemp -d /tmp/sentinela-install-XXXXXX)"
cleanup() {
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

TARGET_BIN=""

# Verifica se o binário já está no diretório atual (extração local de tarball)
if [ -f "./sentinela" ] && [ -x "./sentinela" ]; then
    echo "  • Binário local encontrado no diretório atual."
    TARGET_BIN="./sentinela"
elif [ -f "./target/release/sentinela" ]; then
    echo "  • Binário compilado encontrado em ./target/release/sentinela."
    TARGET_BIN="./target/release/sentinela"
else
    echo "  • A descarregar o último lançamento oficial do GitHub..."
    DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/${ASSET_NAME}"
    
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL "$DOWNLOAD_URL" -o "${TMP_DIR}/${ASSET_NAME}" || {
            echo "${RED}Erro: Falha ao descarregar ${DOWNLOAD_URL}${NC}"
            echo "Verifique a sua ligação ou se existe uma release com o asset: ${ASSET_NAME}"
            exit 1
        }
    elif command -v wget >/dev/null 2>&1; then
        wget -q "$DOWNLOAD_URL" -O "${TMP_DIR}/${ASSET_NAME}" || {
            echo "${RED}Erro: Falha ao descarregar ${DOWNLOAD_URL}${NC}"
            exit 1
        }
    else
        echo "${RED}Erro: Nem 'curl' nem 'wget' foram encontrados no sistema.${NC}"
        exit 1
    fi

    tar -xzf "${TMP_DIR}/${ASSET_NAME}" -C "$TMP_DIR"
    TARGET_BIN="${TMP_DIR}/sentinela"
fi

if [ ! -f "$TARGET_BIN" ]; then
    echo "${RED}Erro: Não foi possível obter o binário executável do Sentinela.${NC}"
    exit 1
fi

# 3. Determina o diretório de destino
USE_SUDO=0
if [ "$(id -u)" -eq 0 ]; then
    INSTALL_DIR="/usr/local/bin"
    DEST_PATH="${INSTALL_DIR}/${BINARY_NAME}"
    echo "  • A instalar o binário em: ${CYAN}${DEST_PATH}${NC}..."
    cp "$TARGET_BIN" "$DEST_PATH"
    chmod 755 "$DEST_PATH"
else
    INSTALLED=0
    if command -v sudo >/dev/null 2>&1; then
        # Testa se sudo não requer password ou se estamos num terminal interativo
        if sudo -n true 2>/dev/null || [ -t 0 ]; then
            INSTALL_DIR="/usr/local/bin"
            DEST_PATH="${INSTALL_DIR}/${BINARY_NAME}"
            echo "  • A tentar instalar em: ${CYAN}${DEST_PATH}${NC} (via sudo)..."
            if sudo cp "$TARGET_BIN" "$DEST_PATH" 2>/dev/null && sudo chmod 755 "$DEST_PATH" 2>/dev/null; then
                INSTALLED=1
                USE_SUDO=1
            fi
        fi
    fi

    # Fallback seguro para ~/.local/bin se não tiver sudo ou correr via pipe
    if [ "$INSTALLED" -eq 0 ]; then
        INSTALL_DIR="$HOME/.local/bin"
        mkdir -p "$INSTALL_DIR"
        DEST_PATH="${INSTALL_DIR}/${BINARY_NAME}"
        echo "  • A instalar em: ${CYAN}${DEST_PATH}${NC} (modo de utilizador)..."
        cp "$TARGET_BIN" "$DEST_PATH"
        chmod 755 "$DEST_PATH"
    fi
fi

# 4. No Linux: Aplica Permissões Raw Sockets e Gestão de Rede (CAP_NET_RAW + CAP_NET_ADMIN)
if [ "$OS" = "Linux" ]; then
    SETCAP_BIN=""
    if command -v setcap >/dev/null 2>&1; then
        SETCAP_BIN="setcap"
    elif [ -x "/usr/sbin/setcap" ]; then
        SETCAP_BIN="/usr/sbin/setcap"
    elif [ -x "/sbin/setcap" ]; then
        SETCAP_BIN="/sbin/setcap"
    fi

    if [ -n "$SETCAP_BIN" ]; then
        echo "  • A configurar capacidades de rede (CAP_NET_RAW + CAP_NET_ADMIN)..."
        if [ "$(id -u)" -eq 0 ]; then
            "$SETCAP_BIN" cap_net_raw,cap_net_admin+eip "$DEST_PATH" 2>/dev/null && \
                echo "    ${GREEN}✓ Permissões CAP_NET_RAW e CAP_NET_ADMIN atribuídas (Deteção SYN scan e Killswitch ativos sem root!)${NC}" || true
        elif [ "$USE_SUDO" -eq 1 ]; then
            sudo "$SETCAP_BIN" cap_net_raw,cap_net_admin+eip "$DEST_PATH" 2>/dev/null && \
                echo "    ${GREEN}✓ Permissões CAP_NET_RAW e CAP_NET_ADMIN atribuídas (Deteção SYN scan e Killswitch ativos sem root!)${NC}" || \
                echo "    ${YELLOW}! Aviso: Não foi possível atribuir capacidades completas. O Sentinela funcionará como honeypot TCP.${NC}"
        else
            echo "    ${YELLOW}! Dica: Para ativar a deteção SYN scan e Killswitch sem root, executa:${NC}"
            echo "      sudo $SETCAP_BIN cap_net_raw,cap_net_admin+eip \"$DEST_PATH\""
        fi
    else
        echo "    ${YELLOW}! Aviso: Utilitário 'setcap' não encontrado no sistema.${NC}"
        echo "      Em sistemas Debian/Ubuntu, podes instalar com: sudo apt install libcap2-bin"
        echo "      Depois executa: sudo setcap cap_net_raw,cap_net_admin+eip \"$DEST_PATH\""
    fi
fi

# 5. Validação de PATH
case ":$PATH:" in
    *":${INSTALL_DIR}:"*)
        PATH_OK=1
        ;;
    *)
        PATH_OK=0
        ;;
esac

echo ""
echo "${GREEN}======================================================================${NC}"
echo "${GREEN}${BOLD}       ✓ SENTINELA INSTALADO COM SUCESSO!                             ${NC}"
echo "${GREEN}======================================================================${NC}"
echo "  Binário: ${DEST_PATH}"

if [ "$PATH_OK" -eq 0 ]; then
    echo "${YELLOW}! ATENÇÃO: ${INSTALL_DIR} não está na sua variável PATH.${NC}"
    echo "  Adicione a seguinte linha ao seu ~/.bashrc ou ~/.zshrc:"
    echo "    export PATH=\"${INSTALL_DIR}:\$PATH\""
    echo ""
fi

echo "Para iniciar a monitorização:"
echo "  ${CYAN}${BINARY_NAME}${NC}                      # Portas padrão (22, 80, 443, 3306, 8080...)"
echo "  ${CYAN}${BINARY_NAME} 2222 8000 9000${NC}       # Portas personalizadas"
echo ""
echo "Atalhos rápidos dentro da TUI:"
echo "  [K] Ativar/Desativar Killswitch | [W] Auditar Portas Abertas | [Q] Sair"
echo ""
