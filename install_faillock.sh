#!/bin/sh
# =============================================================================
# install_faillock.sh
# Installation and configuration of pam_faillock on WAGO Linux Controllers
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

# Colors — using printf for BusyBox compatibility
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()    { printf "${GREEN}[INFO]${NC} %s\n" "$1"; }
log_warning() { printf "${YELLOW}[WARN]${NC} %s\n" "$1"; }
log_error()   { printf "${RED}[ERROR]${NC} %s\n" "$1"; exit 1; }

# =============================================================================
# Pre-flight checks
# =============================================================================

check_root() {
    if [ "$(id -u)" != "0" ]; then
        log_error "This script must be run as root"
    fi
    log_info "Running as root: OK"
}

check_user_authd() {
    if ! grep -q "^authd:" /etc/passwd; then
        log_error "User authd not found — this script is intended for WAGO PFC200"
    fi
    log_info "User authd found: OK"
}

check_pam() {
    if [ ! -f /etc/pam.d/common-auth ]; then
        log_error "PAM not installed — /etc/pam.d/common-auth not found"
    fi
    log_info "PAM present: OK"
}

# =============================================================================
# Step 1 — Download and install package
# =============================================================================

install_package() {
    log_info "=== Step 1: PAM package installation ==="

    if [ -f /lib/security/pam_faillock.so ]; then
        log_warning "pam_faillock.so already present — reinstalling"
    fi

    log_info "Downloading from $IPK_URL"
    wget -q -O "$IPK_FILE" "$IPK_URL" || log_error "Download failed"

    log_info "Installing package"
    opkg install --force-reinstall -V3 "$IPK_FILE" || log_error "opkg installation failed"

    rm -f "$IPK_FILE"

    if [ ! -f /lib/security/pam_faillock.so ]; then
        log_error "pam_faillock.so not found after installation"
    fi
    log_info "pam_faillock.so installed: OK"
}

# =============================================================================
# Step 2 — Init script
# =============================================================================

install_init_script() {
    log_info "=== Step 2: Init script ==="

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
    log_info "Init script created: OK"

    ln -sf "$INIT_SCRIPT" "$RCD_LINK"
    log_info "rc.d symlink created: OK"
}

# =============================================================================
# Step 3 — Tally directory
# =============================================================================

create_tally_dir() {
    log_info "=== Step 3: Tally directory ==="

    "$INIT_SCRIPT" start

    if [ ! -d "$FAILLOCK_DIR" ]; then
        log_error "Directory $FAILLOCK_DIR was not created"
    fi

    OWNER=$(ls -la /var/run/ | grep faillock | awk '{print $3}')
    if [ "$OWNER" != "$FAILLOCK_USER" ]; then
        log_error "Wrong owner on $FAILLOCK_DIR: $OWNER (expected: $FAILLOCK_USER)"
    fi

    log_info "Directory $FAILLOCK_DIR: OK (owner: $OWNER)"
}

# =============================================================================
# Step 4 — faillock.conf
# =============================================================================

configure_faillock() {
    log_info "=== Step 4: faillock.conf ==="

    cat > "$FAILLOCK_CONF" << 'EOF'
# Lock account after 6 failed attempts within 60 seconds
# Account remains locked for 120 seconds
deny = 6
fail_interval = 60
unlock_time = 120
audit
silent
EOF

    chmod 644 "$FAILLOCK_CONF"
    log_info "faillock.conf created: OK"
}

# =============================================================================
# Step 5 — PAM common-auth
# =============================================================================

configure_pam() {
    log_info "=== Step 5: PAM configuration ==="

    # Backup original file
    cp "$COMMON_AUTH" "${COMMON_AUTH}.bak"
    log_info "Backup created: ${COMMON_AUTH}.bak"

    cat > "$COMMON_AUTH" << 'EOF'
#
# /etc/pam.d/common-auth; Linux-PAM configuration file
#
# pam_faillock wraps pam_unix to enforce brute-force protection
# Applies to all services including authd (WBM) and dropbear (SSH)
#

auth required                   pam_faillock.so preauth silent audit
auth [success=2 default=ignore] pam_unix.so nullok
auth [default=die]              pam_faillock.so authfail audit
auth requisite                  pam_deny.so
auth sufficient                 pam_faillock.so authsucc audit
auth required                   pam_permit.so
EOF

    log_info "common-auth configured: OK"
}

# =============================================================================
# Step 6 — Verification
# =============================================================================

verify() {
    log_info "=== Step 6: Verification ==="

    [ -f /lib/security/pam_faillock.so ] && \
        log_info "pam_faillock.so: OK" || \
        log_error "pam_faillock.so: MISSING"

    [ -d "$FAILLOCK_DIR" ] && \
        log_info "$FAILLOCK_DIR: OK" || \
        log_error "$FAILLOCK_DIR: MISSING"

    [ -f "$FAILLOCK_CONF" ] && \
        log_info "$FAILLOCK_CONF: OK" || \
        log_error "$FAILLOCK_CONF: MISSING"

    grep -q "pam_faillock" "$COMMON_AUTH" && \
        log_info "$COMMON_AUTH contains pam_faillock: OK" || \
        log_error "$COMMON_AUTH does not contain pam_faillock"

    [ -x "$INIT_SCRIPT" ] && \
        log_info "$INIT_SCRIPT executable: OK" || \
        log_error "$INIT_SCRIPT not executable"

    [ -L "$RCD_LINK" ] && \
        log_info "$RCD_LINK: OK" || \
        log_error "$RCD_LINK: MISSING"
}

# =============================================================================
# Rollback on error
# =============================================================================

rollback() {
    printf "${YELLOW}[WARN]${NC} %s\n" "=== ROLLBACK ==="
    if [ -f "${COMMON_AUTH}.bak" ]; then
        mv "${COMMON_AUTH}.bak" "$COMMON_AUTH"
        printf "${YELLOW}[WARN]${NC} %s\n" "common-auth restored from backup"
    fi
    printf "${YELLOW}[WARN]${NC} %s\n" "Rollback complete — please check connectivity"
}

# =============================================================================
# Main
# =============================================================================

trap rollback ERR

printf "=============================================\n"
printf " pam_faillock installation — WAGO PFC200\n"
printf " Reference: ANSSI-PG-078 R10\n"
printf "=============================================\n\n"

log_warning "Keep a root SSH session open in parallel before proceeding"
printf "\n"

check_root
check_user_authd
check_pam
install_package
install_init_script
create_tally_dir
configure_faillock
configure_pam
verify

printf "\n"
printf "=============================================\n"
log_info "Installation completed successfully"
printf "=============================================\n\n"
printf "Monitor logs:\n"
printf "  tail -f /var/log/messages | grep -iE 'faillock|authd|pam'\n\n"
printf "Unlock a user account manually:\n"
printf "  rm -f /var/run/faillock/<username>\n\n"
printf "Rollback manually:\n"
printf "  mv %s.bak %s\n\n" "$COMMON_AUTH" "$COMMON_AUTH"
