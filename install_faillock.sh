#!/bin/sh
# =============================================================================
# install_faillock.sh
# Installation et configuration de pam_faillock sur WAGO PFC200
# Référence : ANSSI-PG-078 R10
# =============================================================================

set -e

IPK_URL="https://github.com/quenorha/hardening_repo/raw/refs/heads/main/pam_1.5.3_armhf.ipk"
IPK_FILE="/tmp/pam_faillock.ipk"

FAILLOCK_DIR="/var/run/faillock"
FAILLOCK_USER="authd"
FAILLOCK_CONF="/etc/security/faillock.conf"
COMMON_AUTH="/etc/pam.d/common-auth"
INIT_SCRIPT="/etc/init.d/faillock"
RCD_LINK="/etc/rc.d/S20faillock"

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()    { echo "${GREEN}[INFO]${NC} $1"; }
log_warning() { echo "${YELLOW}[WARN]${NC} $1"; }
log_error()   { echo "${RED}[ERROR]${NC} $1"; exit 1; }

# =============================================================================
# Vérifications préalables
# =============================================================================

check_root() {
    if [ "$(id -u)" != "0" ]; then
        log_error "Ce script doit être exécuté en tant que root"
    fi
    log_info "Exécution en root : OK"
}

check_user_authd() {
    if ! grep -q "^authd:" /etc/passwd; then
        log_error "Utilisateur authd introuvable — ce script est destiné au PFC200"
    fi
    log_info "Utilisateur authd : OK"
}

check_pam() {
    if [ ! -f /etc/pam.d/common-auth ]; then
        log_error "PAM non installé — /etc/pam.d/common-auth introuvable"
    fi
    log_info "PAM présent : OK"
}

# =============================================================================
# Étape 1 — Téléchargement et installation du package
# =============================================================================

install_package() {
    log_info "=== Étape 1 : Installation du package PAM ==="

    if [ -f /lib/security/pam_faillock.so ]; then
        log_warning "pam_faillock.so déjà présent — réinstallation"
    fi

    log_info "Téléchargement depuis $IPK_URL"
    wget -q -O "$IPK_FILE" "$IPK_URL" || log_error "Échec du téléchargement"

    log_info "Installation du package"
    opkg install --force-reinstall -V3 "$IPK_FILE" || log_error "Échec de l'installation opkg"

    rm -f "$IPK_FILE"

    if [ ! -f /lib/security/pam_faillock.so ]; then
        log_error "pam_faillock.so introuvable après installation"
    fi
    log_info "pam_faillock.so installé : OK"
}

# =============================================================================
# Étape 2 — Script init
# =============================================================================

install_init_script() {
    log_info "=== Étape 2 : Script init ==="

    cat > "$INIT_SCRIPT" << 'INITEOF'
#!/bin/sh
### BEGIN INIT INFO
# Provides:          faillock
# Required-Start:    $local_fs
# Required-Stop:
# Default-Start:     S
# Default-Stop:
# Short-Description: Create faillock tally directory
### END INIT INFO

FAILLOCK_DIR="/var/run/faillock"
FAILLOCK_USER="authd"

case "$1" in
    start)
        mkdir -p ${FAILLOCK_DIR}
        chown ${FAILLOCK_USER}:${FAILLOCK_USER} ${FAILLOCK_DIR}
        chmod 700 ${FAILLOCK_DIR}
        ;;
    stop)
        ;;
    *)
        echo "Usage: $0 {start|stop}"
        exit 1
        ;;
esac

exit 0
INITEOF

    chmod 755 "$INIT_SCRIPT"
    log_info "Script init créé : OK"

    ln -sf "$INIT_SCRIPT" "$RCD_LINK"
    log_info "Lien rc.d créé : OK"
}

# =============================================================================
# Étape 3 — Répertoire de tally
# =============================================================================

create_tally_dir() {
    log_info "=== Étape 3 : Répertoire de tally ==="

    "$INIT_SCRIPT" start

    if [ ! -d "$FAILLOCK_DIR" ]; then
        log_error "Répertoire $FAILLOCK_DIR non créé"
    fi

    OWNER=$(ls -la /var/run/ | grep faillock | awk '{print $3}')
    if [ "$OWNER" != "$FAILLOCK_USER" ]; then
        log_error "Propriétaire incorrect sur $FAILLOCK_DIR : $OWNER (attendu: $FAILLOCK_USER)"
    fi

    log_info "Répertoire $FAILLOCK_DIR : OK (propriétaire: $OWNER)"
}

# =============================================================================
# Étape 4 — Configuration faillock.conf
# =============================================================================

configure_faillock() {
    log_info "=== Étape 4 : Configuration faillock.conf ==="

    cat > "$FAILLOCK_CONF" << 'EOF'
deny = 6
fail_interval = 60
unlock_time = 120
audit
silent
EOF

    chmod 644 "$FAILLOCK_CONF"
    log_info "faillock.conf créé : OK"
}

# =============================================================================
# Étape 5 — Configuration PAM common-auth
# =============================================================================

configure_pam() {
    log_info "=== Étape 5 : Configuration PAM ==="

    # Backup
    cp "$COMMON_AUTH" "${COMMON_AUTH}.bak"
    log_info "Backup créé : ${COMMON_AUTH}.bak"

    cat > "$COMMON_AUTH" << 'EOF'
#
# /etc/pam.d/common-auth; Linux-PAM configuration file
#

auth required                   pam_faillock.so preauth silent audit
auth [success=2 default=ignore] pam_unix.so nullok
auth [default=die]              pam_faillock.so authfail audit
auth requisite                  pam_deny.so
auth sufficient                 pam_faillock.so authsucc audit
auth required                   pam_permit.so
EOF

    log_info "common-auth configuré : OK"
}

# =============================================================================
# Étape 6 — Vérification fonctionnelle
# =============================================================================

verify() {
    log_info "=== Étape 6 : Vérifications ==="

    # pam_faillock.so
    [ -f /lib/security/pam_faillock.so ] && \
        log_info "pam_faillock.so : OK" || \
        log_error "pam_faillock.so : MANQUANT"

    # Répertoire tally
    [ -d "$FAILLOCK_DIR" ] && \
        log_info "$FAILLOCK_DIR : OK" || \
        log_error "$FAILLOCK_DIR : MANQUANT"

    # faillock.conf
    [ -f "$FAILLOCK_CONF" ] && \
        log_info "$FAILLOCK_CONF : OK" || \
        log_error "$FAILLOCK_CONF : MANQUANT"

    # common-auth
    grep -q "pam_faillock" "$COMMON_AUTH" && \
        log_info "$COMMON_AUTH contient pam_faillock : OK" || \
        log_error "$COMMON_AUTH ne contient pas pam_faillock"

    # init script
    [ -x "$INIT_SCRIPT" ] && \
        log_info "$INIT_SCRIPT exécutable : OK" || \
        log_error "$INIT_SCRIPT non exécutable"

    # lien rc.d
    [ -L "$RCD_LINK" ] && \
        log_info "$RCD_LINK : OK" || \
        log_error "$RCD_LINK : MANQUANT"
}

# =============================================================================
# Rollback
# =============================================================================

rollback() {
    log_warning "=== ROLLBACK ==="
    if [ -f "${COMMON_AUTH}.bak" ]; then
        mv "${COMMON_AUTH}.bak" "$COMMON_AUTH"
        log_info "common-auth restauré"
    fi
    log_warning "Rollback effectué — vérifier la connexion"
}

# =============================================================================
# Main
# =============================================================================

trap rollback ERR

echo "============================================="
echo " Installation pam_faillock — WAGO PFC200"
echo " Référence ANSSI-PG-078 R10"
echo "============================================="
echo ""
log_warning "ATTENTION : Maintenir une session SSH root ouverte en parallèle"
echo ""

check_root
check_user_authd
check_pam
install_package
install_init_script
create_tally_dir
configure_faillock
configure_pam
verify

echo ""
echo "============================================="
log_info "Installation terminée avec succès"
echo "============================================="
echo ""
echo "Pour tester :"
echo "  tail -f /var/log/messages | grep -iE 'faillock|authd|pam'"
echo ""
echo "Pour déverrouiller un utilisateur :"
echo "  rm -f /var/run/faillock/<utilisateur>"
echo ""
echo "Pour rollback manuel :"
echo "  mv ${COMMON_AUTH}.bak ${COMMON_AUTH}"
echo ""
