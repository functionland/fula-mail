#!/bin/bash
#
# Fula Mail — Production Installer
#
# Installs the fula-mail decentralized email gateway on an existing Fula system.
# Integrates with the running PostgreSQL (shared with pinning-service) and S3 gateway.
#
# Features:
#   - Idempotent: safe to re-run for updates or recovery
#   - Resumable: saves answers in .env; re-run pre-fills previous values
#   - Non-destructive: database migrations use IF NOT EXISTS / ADD COLUMN IF NOT EXISTS
#   - Atomic: builds in a staging directory, swaps only on success
#   - Rollback: keeps one previous binary so a failed update can be reverted
#
# Usage:
#   sudo bash install.sh              # fresh install or update
#   sudo bash install.sh --uninstall  # remove (preserves database tables)
#   sudo bash install.sh --status     # check service health
#
# Requires: an existing Fula system with Docker, PostgreSQL, and pinning-service.

set -euo pipefail

# ============================================
# Constants
# ============================================
readonly SCRIPT_VERSION="1.0.0"
readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly INSTALL_DIR="/opt/fula-mail"
readonly ENV_FILE="${INSTALL_DIR}/.env"
readonly BINARY_NAME="fula-mail"
readonly SERVICE_NAME="fula-mail"
readonly SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
readonly LOG_FILE="/var/log/fula-mail-install.log"
readonly BACKUP_DIR="${INSTALL_DIR}/backup"
readonly MIGRATIONS_DIR="${INSTALL_DIR}/migrations/postgres"
readonly TEMP_DIR="${INSTALL_DIR}/.install-tmp"
readonly MAIL_DATA_DIR="/var/lib/fula-mail"
readonly MAIL_USER="fulamail"
readonly NGINX_SITE_FILE="/etc/nginx/sites-available/${SERVICE_NAME}"
readonly NGINX_SITE_LINK="/etc/nginx/sites-enabled/${SERVICE_NAME}"

# Ports
readonly DEFAULT_HTTP_PORT=8080
readonly DEFAULT_SMTP_PORT=25
readonly DEFAULT_SUBMISSION_PORT=587
readonly DEFAULT_IMAP_PORT=993

# Color codes
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

# ============================================
# Logging
# ============================================
mkdir -p "$(dirname "$LOG_FILE")"

log() {
    local msg="[$(date +'%Y-%m-%d %H:%M:%S')] $1"
    echo -e "${GREEN}${msg}${NC}" | tee -a "$LOG_FILE"
}

log_warn() {
    local msg="[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1"
    echo -e "${YELLOW}${msg}${NC}" | tee -a "$LOG_FILE"
}

log_error() {
    local msg="[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1"
    echo -e "${RED}${msg}${NC}" | tee -a "$LOG_FILE"
}

# ============================================
# Error handling & cleanup
# ============================================
INSTALL_PHASE="initialization"
ROLLBACK_BINARY=""
ROLLBACK_SERVICE=false

cleanup_on_error() {
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        log_error "Installation failed during phase: ${INSTALL_PHASE}"
        log_error "Exit code: ${exit_code}"

        # Rollback binary if we replaced one
        if [ -n "$ROLLBACK_BINARY" ] && [ -f "$ROLLBACK_BINARY" ]; then
            log_warn "Rolling back binary to previous version..."
            cp "$ROLLBACK_BINARY" "${INSTALL_DIR}/${BINARY_NAME}" 2>/dev/null || true
        fi

        # Reload systemd if we modified the service file mid-install
        if [ "$ROLLBACK_SERVICE" = true ]; then
            log_warn "Reloading systemd after partial service file change..."
            systemctl daemon-reload 2>/dev/null || true
            # Try to restart with old binary
            systemctl start "${SERVICE_NAME}" 2>/dev/null || true
        fi

        # Clean up temp directory
        rm -rf "${TEMP_DIR}" 2>/dev/null || true

        log_error "Partial install state preserved at ${INSTALL_DIR}"
        log_error "Re-run this script to resume. Check log: ${LOG_FILE}"
    fi
}

trap cleanup_on_error EXIT

die() {
    log_error "$1"
    exit 1
}

# ============================================
# Root check
# ============================================
if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: This script must be run as root (use sudo)${NC}"
    exit 1
fi

# ============================================
# Prompt helper (pre-fills from existing .env)
# ============================================
# Reads an existing value from .env if present, shows it as default.
# User can press Enter to accept the default or type a new value.
prompt_with_default() {
    local var_name="$1"
    local prompt_text="$2"
    local default_value="$3"
    local is_secret="${4:-false}"

    # Check if already set in existing .env
    local existing=""
    if [ -f "$ENV_FILE" ]; then
        existing=$(grep "^${var_name}=" "$ENV_FILE" 2>/dev/null | head -1 | cut -d'=' -f2- | sed 's/^"//' | sed 's/"$//')
    fi

    # Prefer existing value over hard-coded default
    local show_default="${existing:-$default_value}"

    if [ "$is_secret" = "true" ] && [ -n "$existing" ]; then
        # Mask secrets: show first 4 chars + asterisks
        local masked
        if [ ${#existing} -gt 4 ]; then
            masked="${existing:0:4}$(printf '%*s' $((${#existing} - 4)) | tr ' ' '*')"
        else
            masked="****"
        fi
        read -rp "$(echo -e "${CYAN}${prompt_text}${NC} [${masked}]: ")" input
    elif [ -n "$show_default" ]; then
        read -rp "$(echo -e "${CYAN}${prompt_text}${NC} [${show_default}]: ")" input
    else
        read -rp "$(echo -e "${CYAN}${prompt_text}${NC}: ")" input
    fi

    # Use input if given, otherwise fall back to existing, then default
    local result="${input:-${existing:-$default_value}}"
    eval "$var_name=\"\$result\""
}

# Like prompt_with_default but requires non-empty
prompt_required() {
    local var_name="$1"
    local prompt_text="$2"
    local default_value="${3:-}"
    local is_secret="${4:-false}"

    while true; do
        prompt_with_default "$var_name" "$prompt_text" "$default_value" "$is_secret"
        eval "local val=\"\$$var_name\""
        if [ -n "$val" ]; then
            return
        fi
        echo -e "${RED}  This field is required.${NC}"
    done
}

# ============================================
# Save .env atomically
# ============================================
save_env() {
    mkdir -p "$INSTALL_DIR"
    local tmp_env="${ENV_FILE}.tmp.$$"

    cat > "$tmp_env" <<ENVEOF
# Fula Mail configuration
# Generated by install.sh v${SCRIPT_VERSION} on $(date -Iseconds)
# Re-run install.sh to update; previous answers are pre-filled.

# Server
MAIL_HOST="${CFG_MAIL_HOST}"
MAIL_HTTP_PORT=${CFG_MAIL_HTTP_PORT}
MAIL_SMTP_PORT=${CFG_MAIL_SMTP_PORT}
MAIL_SUBMISSION_PORT=${CFG_MAIL_SUBMISSION_PORT}
MAIL_IMAP_PORT=${CFG_MAIL_IMAP_PORT}

# Database (shared PostgreSQL — same instance as pinning-service)
POSTGRES_HOST="${CFG_POSTGRES_HOST}"
POSTGRES_PORT=${CFG_POSTGRES_PORT}
POSTGRES_DB="${CFG_POSTGRES_DB}"
POSTGRES_USER="${CFG_POSTGRES_USER}"
POSTGRES_PASSWORD="${CFG_POSTGRES_PASSWORD}"

# Auth (shared JWT secret — same as FxFiles / pinning-service)
JWT_SECRET="${CFG_JWT_SECRET}"

# MX hostname (the public DNS name that receives mail)
MX_HOSTNAME="${CFG_MX_HOSTNAME}"

# Pinning service integration
PINNING_SERVICE_URL="${CFG_PINNING_SERVICE_URL}"
PINNING_SYSTEM_KEY="${CFG_PINNING_SYSTEM_KEY}"

# TLS (optional — leave empty for plain HTTP/SMTP without STARTTLS)
TLS_CERT_PATH="${CFG_TLS_CERT_PATH}"
TLS_KEY_PATH="${CFG_TLS_KEY_PATH}"
TLS_CHAIN_PATH="${CFG_TLS_CHAIN_PATH}"

# Push notifications (optional — leave empty to disable)
FCM_SERVICE_ACCOUNT_KEY="${CFG_FCM_KEY_PATH}"

# Outbound relay (optional — for IP warming or shared relay)
OUTBOUND_RELAY_HOST="${CFG_OUTBOUND_RELAY_HOST}"
OUTBOUND_RELAY_PORT=${CFG_OUTBOUND_RELAY_PORT:-0}
OUTBOUND_RELAY_USER="${CFG_OUTBOUND_RELAY_USER}"
OUTBOUND_RELAY_PASSWORD="${CFG_OUTBOUND_RELAY_PASSWORD}"

# Path A settings
PATH_A_TTL_SECS=${CFG_PATH_A_TTL_SECS}

# Limits
MAX_MESSAGE_SIZE=${CFG_MAX_MESSAGE_SIZE}
MAX_RETRIES=${CFG_MAX_RETRIES}

# Encryption master key for secrets at rest (hex-encoded 32 bytes)
ENCRYPTION_MASTER_KEY="${CFG_ENCRYPTION_MASTER_KEY}"

# Logging
RUST_LOG="${CFG_RUST_LOG}"

# Installer settings (used on re-run to pre-fill choices)
CFG_SETUP_NGINX="${CFG_SETUP_NGINX}"
CFG_SETUP_CERTBOT="${CFG_SETUP_CERTBOT}"
CFG_CERTBOT_EMAIL="${CFG_CERTBOT_EMAIL:-}"
ENVEOF

    # Secure permissions before moving into place (contains secrets)
    chmod 600 "$tmp_env"
    mv "$tmp_env" "$ENV_FILE"
    log ".env saved to ${ENV_FILE}"
}

# ============================================
# Dependency checks
# ============================================
check_dependencies() {
    INSTALL_PHASE="dependency check"
    log "Checking dependencies..."

    local missing=()

    # Required system commands
    for cmd in curl docker psql openssl; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done

    if [ ${#missing[@]} -gt 0 ]; then
        log_warn "Missing commands: ${missing[*]}"
        log "Attempting to install missing dependencies..."

        apt-get update -qq || die "Failed to update package lists"

        for cmd in "${missing[@]}"; do
            case "$cmd" in
                curl)
                    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl || die "Failed to install curl"
                    ;;
                docker)
                    die "Docker is required but not installed. Install Docker first, or run the Fula OTA installer."
                    ;;
                psql)
                    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq postgresql-client || die "Failed to install postgresql-client"
                    ;;
                openssl)
                    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq openssl || die "Failed to install openssl"
                    ;;
            esac
        done

        log "Dependencies installed"
    else
        log "All dependencies present"
    fi

    # Verify Docker is running
    if ! docker info &>/dev/null; then
        die "Docker daemon is not running. Start it with: systemctl start docker"
    fi
}

# ============================================
# Detect existing installation
# ============================================
detect_existing() {
    INSTALL_PHASE="detection"

    EXISTING_INSTALL=false
    EXISTING_VERSION=""

    if [ -f "${INSTALL_DIR}/${BINARY_NAME}" ]; then
        EXISTING_INSTALL=true
        # Try to get version from the binary
        EXISTING_VERSION=$("${INSTALL_DIR}/${BINARY_NAME}" --version 2>/dev/null | awk '{print $NF}' || echo "unknown")
        log "Existing installation detected: version ${EXISTING_VERSION}"
    fi

    if [ -f "$ENV_FILE" ]; then
        log "Existing .env found — previous answers will be pre-filled"
    fi

    if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
        log "Service ${SERVICE_NAME} is currently running"
    fi
}

# ============================================
# Collect configuration from user
# ============================================
collect_config() {
    INSTALL_PHASE="configuration"

    echo ""
    echo -e "${GREEN}===== Fula Mail Configuration =====${NC}"
    echo "Press Enter to accept the default (shown in brackets)."
    echo ""

    # ---- Server ----
    echo -e "${CYAN}-- Server --${NC}"
    prompt_with_default CFG_MAIL_HOST      "Listen address"           "0.0.0.0"
    prompt_with_default CFG_MAIL_HTTP_PORT  "HTTP API port"            "$DEFAULT_HTTP_PORT"
    prompt_with_default CFG_MAIL_SMTP_PORT  "SMTP inbound port"        "$DEFAULT_SMTP_PORT"
    prompt_with_default CFG_MAIL_SUBMISSION_PORT "SMTP submission port" "$DEFAULT_SUBMISSION_PORT"
    prompt_with_default CFG_MAIL_IMAP_PORT  "IMAP port"                "$DEFAULT_IMAP_PORT"
    echo ""

    # ---- Database ----
    echo -e "${CYAN}-- Database (shared PostgreSQL) --${NC}"
    echo "  Uses the same PostgreSQL instance as the pinning-service."
    prompt_with_default CFG_POSTGRES_HOST     "PostgreSQL host"       "localhost"
    prompt_with_default CFG_POSTGRES_PORT     "PostgreSQL port"       "5432"
    prompt_with_default CFG_POSTGRES_DB       "Database name"         "pinning_service"
    prompt_with_default CFG_POSTGRES_USER     "Database user"         "pinning_user"
    prompt_required     CFG_POSTGRES_PASSWORD "Database password"     "" "true"
    echo ""

    # ---- Auth ----
    echo -e "${CYAN}-- Authentication --${NC}"
    echo "  Must match the JWT secret used by FxFiles / pinning-service."
    prompt_required CFG_JWT_SECRET "JWT secret (min 16 chars)" "" "true"
    if [ ${#CFG_JWT_SECRET} -lt 16 ]; then
        die "JWT secret must be at least 16 characters"
    fi
    echo ""

    # ---- Mail ----
    echo -e "${CYAN}-- Mail --${NC}"
    prompt_required CFG_MX_HOSTNAME "Public MX hostname (e.g. mail.example.com)" "mail.fula.net"
    echo ""

    # ---- Pinning service ----
    echo -e "${CYAN}-- Pinning Service Integration --${NC}"
    prompt_with_default CFG_PINNING_SERVICE_URL "Pinning service URL" "http://localhost:6000"
    prompt_with_default CFG_PINNING_SYSTEM_KEY  "Pinning system key"  "" "true"
    echo ""

    # ---- Nginx & TLS ----
    echo -e "${CYAN}-- Nginx Reverse Proxy & TLS --${NC}"
    echo "  Nginx proxies the HTTP API on ports 80/443."
    echo "  Certbot (Let's Encrypt) obtains the SSL certificate."
    echo "  The same cert is reused for SMTP STARTTLS."
    prompt_with_default CFG_SETUP_NGINX "Set up nginx reverse proxy? (yes/no)" "yes"
    if [[ "$CFG_SETUP_NGINX" =~ ^[Yy] ]]; then
        CFG_SETUP_NGINX="yes"
        prompt_with_default CFG_SETUP_CERTBOT "Set up SSL with certbot? (yes/no)" "yes"
        if [[ "$CFG_SETUP_CERTBOT" =~ ^[Yy] ]]; then
            CFG_SETUP_CERTBOT="yes"
            prompt_required CFG_CERTBOT_EMAIL "Email for Let's Encrypt notifications" ""
        else
            CFG_SETUP_CERTBOT="no"
        fi
    else
        CFG_SETUP_NGINX="no"
        CFG_SETUP_CERTBOT="no"
    fi

    # If certbot was already run, certs exist at well-known paths.
    # Pre-fill TLS paths from existing .env or from certbot default location.
    local le_cert="/etc/letsencrypt/live/${CFG_MX_HOSTNAME}/fullchain.pem"
    local le_key="/etc/letsencrypt/live/${CFG_MX_HOSTNAME}/privkey.pem"
    local le_chain="/etc/letsencrypt/live/${CFG_MX_HOSTNAME}/chain.pem"

    # Default: if certbot certs already exist, use them. Otherwise empty (filled after certbot runs).
    local default_cert="" default_key="" default_chain=""
    if [ -f "$le_cert" ]; then default_cert="$le_cert"; fi
    if [ -f "$le_key" ]; then default_key="$le_key"; fi
    if [ -f "$le_chain" ]; then default_chain="$le_chain"; fi

    # Only ask for manual TLS paths if user opted out of certbot
    if [ "$CFG_SETUP_CERTBOT" != "yes" ]; then
        echo ""
        echo -e "${CYAN}-- TLS (manual — leave empty to skip) --${NC}"
        prompt_with_default CFG_TLS_CERT_PATH  "TLS certificate path"  "$default_cert"
        prompt_with_default CFG_TLS_KEY_PATH   "TLS private key path"  "$default_key"
        prompt_with_default CFG_TLS_CHAIN_PATH "TLS chain path"        "$default_chain"

        if [ -n "$CFG_TLS_CERT_PATH" ] && [ ! -f "$CFG_TLS_CERT_PATH" ]; then
            log_warn "TLS cert file does not exist yet: ${CFG_TLS_CERT_PATH}"
        fi
        if [ -n "$CFG_TLS_KEY_PATH" ] && [ ! -f "$CFG_TLS_KEY_PATH" ]; then
            log_warn "TLS key file does not exist yet: ${CFG_TLS_KEY_PATH}"
        fi
    else
        # Will be filled after certbot runs
        CFG_TLS_CERT_PATH="${default_cert}"
        CFG_TLS_KEY_PATH="${default_key}"
        CFG_TLS_CHAIN_PATH="${default_chain}"
    fi
    echo ""

    # ---- Push notifications (optional) ----
    echo -e "${CYAN}-- Push Notifications (optional) --${NC}"
    prompt_with_default CFG_FCM_KEY_PATH "FCM service account key file" ""
    echo ""

    # ---- Outbound relay (optional) ----
    echo -e "${CYAN}-- Outbound Relay (optional — for IP warming) --${NC}"
    prompt_with_default CFG_OUTBOUND_RELAY_HOST     "Relay SMTP host"      ""
    prompt_with_default CFG_OUTBOUND_RELAY_PORT     "Relay SMTP port"      "0"
    prompt_with_default CFG_OUTBOUND_RELAY_USER     "Relay username"       ""
    prompt_with_default CFG_OUTBOUND_RELAY_PASSWORD "Relay password"       "" "true"
    echo ""

    # ---- Tuning ----
    echo -e "${CYAN}-- Tuning --${NC}"
    prompt_with_default CFG_PATH_A_TTL_SECS   "Path A TTL (seconds)"       "300"
    prompt_with_default CFG_MAX_MESSAGE_SIZE   "Max message size (bytes)"   "52428800"
    prompt_with_default CFG_MAX_RETRIES        "Max outbound retries"       "5"
    prompt_with_default CFG_RUST_LOG           "Log level"                  "info"
    echo ""

    # ---- Encryption master key ----
    echo -e "${CYAN}-- Encryption --${NC}"
    echo "  32-byte hex key for encrypting secrets at rest (DKIM keys, relay API keys)."
    echo "  Leave empty to auto-generate on first install."

    # Check existing
    local existing_key=""
    if [ -f "$ENV_FILE" ]; then
        existing_key=$(grep "^ENCRYPTION_MASTER_KEY=" "$ENV_FILE" 2>/dev/null | head -1 | cut -d'=' -f2- | sed 's/^"//' | sed 's/"$//')
    fi

    if [ -n "$existing_key" ]; then
        prompt_with_default CFG_ENCRYPTION_MASTER_KEY "Encryption master key" "$existing_key" "true"
    else
        prompt_with_default CFG_ENCRYPTION_MASTER_KEY "Encryption master key (Enter to auto-generate)" ""
        if [ -z "$CFG_ENCRYPTION_MASTER_KEY" ]; then
            CFG_ENCRYPTION_MASTER_KEY=$(openssl rand -hex 32)
            log "Auto-generated encryption master key"
        fi
    fi

    # Validate key format
    if [ -n "$CFG_ENCRYPTION_MASTER_KEY" ]; then
        if ! echo "$CFG_ENCRYPTION_MASTER_KEY" | grep -qE '^[0-9a-fA-F]{64}$'; then
            die "Encryption master key must be exactly 64 hex characters (32 bytes)"
        fi
    fi
    echo ""
}

# ============================================
# Test database connectivity
# ============================================
test_database() {
    INSTALL_PHASE="database connectivity test"
    log "Testing database connection..."

    if ! PGPASSWORD="$CFG_POSTGRES_PASSWORD" psql \
        -h "$CFG_POSTGRES_HOST" \
        -p "$CFG_POSTGRES_PORT" \
        -U "$CFG_POSTGRES_USER" \
        -d "$CFG_POSTGRES_DB" \
        -c "SELECT 1;" &>/dev/null; then
        die "Cannot connect to PostgreSQL at ${CFG_POSTGRES_HOST}:${CFG_POSTGRES_PORT}/${CFG_POSTGRES_DB}. Verify credentials and ensure PostgreSQL is running."
    fi

    log "Database connection OK"
}

# ============================================
# Run database migrations (safe, idempotent)
# ============================================
run_migrations() {
    INSTALL_PHASE="database migrations"
    log "Running database migrations..."

    # All migrations use IF NOT EXISTS / ADD COLUMN IF NOT EXISTS,
    # so they are inherently safe to re-run on an existing database.
    # We also track applied migrations by filename+checksum so unchanged
    # migrations are skipped entirely on re-runs.

    local migration_files=(
        "${SCRIPT_DIR}/migrations/postgres/001_mail_schema.sql"
        "${SCRIPT_DIR}/migrations/postgres/002_relay_config.sql"
        "${SCRIPT_DIR}/migrations/postgres/003_hardening.sql"
        "${SCRIPT_DIR}/migrations/postgres/004_outbound_queue.sql"
        "${SCRIPT_DIR}/migrations/postgres/005_cc_bcc.sql"
        "${SCRIPT_DIR}/migrations/postgres/006_tags.sql"
    )

    # Verify all migration files exist before starting
    for f in "${migration_files[@]}"; do
        if [ ! -f "$f" ]; then
            die "Migration file not found: $f (run install.sh from the fula-mail source directory)"
        fi
    done

    local psql_cmd=(
        env PGPASSWORD="$CFG_POSTGRES_PASSWORD" psql
        -h "$CFG_POSTGRES_HOST"
        -p "$CFG_POSTGRES_PORT"
        -U "$CFG_POSTGRES_USER"
        -d "$CFG_POSTGRES_DB"
        -v ON_ERROR_STOP=1
    )

    # Create migration tracking table (idempotent)
    "${psql_cmd[@]}" -c "
        CREATE TABLE IF NOT EXISTS mail_migration_log (
            id SERIAL PRIMARY KEY,
            filename TEXT NOT NULL,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
            checksum TEXT NOT NULL,
            UNIQUE(filename, checksum)
        );
    " 2>&1 | tee -a "$LOG_FILE" || die "Failed to create migration tracking table"

    # Apply each migration individually.
    # Each file runs as top-level SQL (not wrapped in PL/pgSQL) so DDL
    # statements like CREATE TABLE, ALTER TABLE work correctly.
    # Each migration runs in its own implicit transaction.
    local applied=0
    local skipped=0

    for f in "${migration_files[@]}"; do
        local fname
        fname=$(basename "$f")
        local checksum
        checksum=$(sha256sum "$f" | awk '{print $1}')

        # Check if this exact migration (file + checksum) was already applied
        local already_applied
        already_applied=$("${psql_cmd[@]}" -t -A -c "
            SELECT COUNT(*) FROM mail_migration_log
            WHERE filename = '${fname}' AND checksum = '${checksum}';
        " 2>/dev/null || echo "0")

        if [ "$already_applied" -gt 0 ] 2>/dev/null; then
            log "  Skipping (already applied): ${fname}"
            skipped=$((skipped + 1))
            continue
        fi

        log "  Applying: ${fname}..."

        # Run the migration file as-is (all statements are idempotent)
        if ! "${psql_cmd[@]}" -f "$f" 2>&1 | tee -a "$LOG_FILE"; then
            die "Migration failed: ${fname}. The migration uses IF NOT EXISTS guards, so no data was corrupted. Fix the issue and re-run."
        fi

        # Record successful application
        "${psql_cmd[@]}" -c "
            INSERT INTO mail_migration_log (filename, checksum)
            VALUES ('${fname}', '${checksum}')
            ON CONFLICT (filename, checksum) DO NOTHING;
        " 2>&1 | tee -a "$LOG_FILE" || log_warn "Failed to record migration ${fname} in tracking table (migration itself succeeded)"

        applied=$((applied + 1))
    done

    log "Database migrations complete (applied: ${applied}, skipped: ${skipped})"
}

# ============================================
# Create system user
# ============================================
create_user() {
    INSTALL_PHASE="system user"

    if id "$MAIL_USER" &>/dev/null; then
        log "System user '${MAIL_USER}' already exists"
        return
    fi

    log "Creating system user '${MAIL_USER}'..."
    useradd -r -s /bin/false -d "$MAIL_DATA_DIR" "$MAIL_USER" || die "Failed to create user ${MAIL_USER}"
    log "User '${MAIL_USER}' created"
}

# ============================================
# Create directories
# ============================================
create_directories() {
    INSTALL_PHASE="directories"

    mkdir -p "$INSTALL_DIR"
    mkdir -p "$BACKUP_DIR"
    mkdir -p "$MIGRATIONS_DIR"
    mkdir -p "$MAIL_DATA_DIR"
    mkdir -p "$TEMP_DIR"

    chown "$MAIL_USER":"$MAIL_USER" "$MAIL_DATA_DIR"
    chmod 750 "$MAIL_DATA_DIR"

    log "Directories created"
}

# ============================================
# Build the binary (Docker multi-stage)
# ============================================
build_binary() {
    INSTALL_PHASE="build"

    # Check if source code changed since last build
    local src_hash
    src_hash=$(find "$SCRIPT_DIR/src" "$SCRIPT_DIR/Cargo.toml" "$SCRIPT_DIR/Cargo.lock" \
        -type f 2>/dev/null | sort | xargs sha256sum 2>/dev/null | sha256sum | awk '{print $1}')

    local last_hash_file="${INSTALL_DIR}/.last-build-hash"
    local last_hash=""
    if [ -f "$last_hash_file" ]; then
        last_hash=$(cat "$last_hash_file")
    fi

    if [ "$src_hash" = "$last_hash" ] && [ -f "${INSTALL_DIR}/${BINARY_NAME}" ]; then
        log "Source unchanged since last build — skipping rebuild"
        return
    fi

    log "Building fula-mail binary (this may take several minutes)..."

    # Build using Docker multi-stage for reproducibility
    local build_tag="fula-mail-builder:install-$$"
    if ! docker build \
        --target runtime \
        -t "$build_tag" \
        -f "$SCRIPT_DIR/Dockerfile" \
        "$SCRIPT_DIR" 2>&1 | tee -a "$LOG_FILE"; then
        die "Docker build failed"
    fi

    # Extract binary from the built image
    local container_id
    container_id=$(docker create "$build_tag") || die "Failed to create container from build image"

    docker cp "${container_id}:/usr/local/bin/fula-mail" "${TEMP_DIR}/${BINARY_NAME}" || {
        docker rm "$container_id" &>/dev/null
        die "Failed to extract binary from build image"
    }
    docker rm "$container_id" &>/dev/null

    # Verify the extracted binary is executable
    if [ ! -f "${TEMP_DIR}/${BINARY_NAME}" ]; then
        die "Binary not found after extraction"
    fi
    chmod +x "${TEMP_DIR}/${BINARY_NAME}"

    # Sanity check: try running --help
    if ! "${TEMP_DIR}/${BINARY_NAME}" --help &>/dev/null; then
        die "Built binary failed sanity check (--help returned non-zero)"
    fi

    log "Binary built successfully"

    # Record source hash
    echo "$src_hash" > "$last_hash_file"

    # Clean up builder image (keep disk tidy)
    docker rmi "$build_tag" &>/dev/null || true
}

# ============================================
# Install binary (with backup of previous)
# ============================================
install_binary() {
    INSTALL_PHASE="install binary"

    local new_binary="${TEMP_DIR}/${BINARY_NAME}"

    if [ ! -f "$new_binary" ]; then
        # build_binary was skipped (no source change), nothing to install
        log "No new binary to install (source unchanged)"
        return
    fi

    # Stop service before replacing the binary
    if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
        log "Stopping ${SERVICE_NAME} for binary update..."
        systemctl stop "${SERVICE_NAME}" || log_warn "Failed to stop service (may not exist yet)"
    fi

    # Backup existing binary
    if [ -f "${INSTALL_DIR}/${BINARY_NAME}" ]; then
        local backup_name="${BINARY_NAME}.$(date +%Y%m%d%H%M%S).bak"
        cp "${INSTALL_DIR}/${BINARY_NAME}" "${BACKUP_DIR}/${backup_name}"
        ROLLBACK_BINARY="${BACKUP_DIR}/${backup_name}"
        log "Previous binary backed up to ${BACKUP_DIR}/${backup_name}"

        # Keep only the 3 most recent backups
        ls -t "${BACKUP_DIR}/${BINARY_NAME}".*.bak 2>/dev/null | tail -n +4 | xargs rm -f 2>/dev/null || true
    fi

    # Atomic move into place
    mv "$new_binary" "${INSTALL_DIR}/${BINARY_NAME}"
    chmod +x "${INSTALL_DIR}/${BINARY_NAME}"
    log "Binary installed to ${INSTALL_DIR}/${BINARY_NAME}"
}

# ============================================
# Copy migrations to install directory
# ============================================
install_migrations() {
    INSTALL_PHASE="migrations copy"

    if [ -d "$SCRIPT_DIR/migrations/postgres" ]; then
        cp -a "$SCRIPT_DIR/migrations/postgres/"*.sql "$MIGRATIONS_DIR/" 2>/dev/null || true
        log "Migration files copied to ${MIGRATIONS_DIR}"
    fi
}

# ============================================
# Install systemd service
# ============================================
install_service() {
    INSTALL_PHASE="systemd service"
    ROLLBACK_SERVICE=true

    cat > "$SERVICE_FILE" <<SVCEOF
[Unit]
Description=Fula Mail - Decentralized Email Gateway
Documentation=https://github.com/functionland/fula-mail
After=network-online.target postgresql.service docker.service
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=${MAIL_USER}
Group=${MAIL_USER}
EnvironmentFile=${ENV_FILE}
ExecStart=${INSTALL_DIR}/${BINARY_NAME} --config ${ENV_FILE}
WorkingDirectory=${INSTALL_DIR}

# Restart on failure with increasing delay
Restart=on-failure
RestartSec=10

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${MAIL_DATA_DIR}
PrivateTmp=true

# Allow binding to privileged ports (25, 587)
AmbientCapabilities=CAP_NET_BIND_SERVICE

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=fula-mail

[Install]
WantedBy=multi-user.target
SVCEOF

    chmod 644 "$SERVICE_FILE"
    systemctl daemon-reload
    systemctl enable "${SERVICE_NAME}" 2>/dev/null

    ROLLBACK_SERVICE=false
    log "Systemd service installed and enabled"
}

# ============================================
# Set file permissions
# ============================================
set_permissions() {
    INSTALL_PHASE="permissions"

    # .env contains secrets — only root and the service user should read it
    chown root:"$MAIL_USER" "$ENV_FILE"
    chmod 640 "$ENV_FILE"

    # Binary
    chown root:root "${INSTALL_DIR}/${BINARY_NAME}" 2>/dev/null || true
    chmod 755 "${INSTALL_DIR}/${BINARY_NAME}" 2>/dev/null || true

    # Data directory
    chown -R "$MAIL_USER":"$MAIL_USER" "$MAIL_DATA_DIR"

    log "Permissions set"
}

# ============================================
# Nginx reverse proxy
# ============================================
setup_nginx() {
    INSTALL_PHASE="nginx setup"

    if [ "${CFG_SETUP_NGINX}" != "yes" ]; then
        log "Nginx setup skipped (user opted out)"
        return
    fi

    # Install nginx if not present
    if ! command -v nginx &>/dev/null; then
        log "Installing nginx..."
        apt-get update -qq || die "Failed to update package lists"
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nginx || die "Failed to install nginx"
        log "Nginx installed"
    else
        log "Nginx already installed: $(nginx -v 2>&1)"
    fi

    # Ensure nginx is enabled
    systemctl enable nginx 2>/dev/null || true

    local server_name="${CFG_MX_HOSTNAME}"
    local upstream_port="${CFG_MAIL_HTTP_PORT}"

    # Check if nginx config already exists for this domain
    if [ -f "$NGINX_SITE_FILE" ]; then
        # Check if the upstream port matches
        if grep -q "proxy_pass http://127.0.0.1:${upstream_port}" "$NGINX_SITE_FILE"; then
            log "Nginx site config already exists and is current"
            # Still ensure it's enabled and nginx is reloaded
            if [ ! -L "$NGINX_SITE_LINK" ]; then
                ln -sf "$NGINX_SITE_FILE" "$NGINX_SITE_LINK"
            fi
            nginx -t 2>&1 | tee -a "$LOG_FILE" || die "Nginx config test failed"
            systemctl reload nginx || die "Failed to reload nginx"
            return
        else
            log "Nginx site config exists but upstream port changed — updating"
        fi
    fi

    log "Creating nginx site config for ${server_name}..."

    # Remove default site if it conflicts on port 80
    if [ -L /etc/nginx/sites-enabled/default ]; then
        rm -f /etc/nginx/sites-enabled/default
        log "Disabled default nginx site"
    fi

    # Write HTTP-only config (certbot will add the 443 section later)
    cat > "$NGINX_SITE_FILE" <<NGINXEOF
# Fula Mail — nginx reverse proxy
# Generated by install.sh v${SCRIPT_VERSION} on $(date -Iseconds)
# Certbot will add the SSL (port 443) server block automatically.

server {
    listen 80;
    listen [::]:80;
    server_name ${server_name};

    # Let's Encrypt ACME challenge (certbot needs this on port 80)
    location /.well-known/acme-challenge/ {
        root /var/www/html;
    }

    # Reverse proxy to fula-mail HTTP API
    location / {
        proxy_pass http://127.0.0.1:${upstream_port};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;

        # Timeouts for large message uploads
        proxy_read_timeout 120s;
        proxy_send_timeout 120s;

        # Match fula-mail's max message size (convert bytes to MB for nginx)
        client_max_body_size $(( CFG_MAX_MESSAGE_SIZE / 1048576 + 1 ))m;
    }

    # Health check shortcut (no buffering)
    location = /health {
        proxy_pass http://127.0.0.1:${upstream_port}/health;
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_buffering off;
        access_log off;
    }
}
NGINXEOF

    # Enable the site
    ln -sf "$NGINX_SITE_FILE" "$NGINX_SITE_LINK"

    # Test and reload
    if ! nginx -t 2>&1 | tee -a "$LOG_FILE"; then
        # Revert: remove the broken config
        rm -f "$NGINX_SITE_LINK"
        die "Nginx config test failed — site config removed. Check ${NGINX_SITE_FILE}"
    fi

    systemctl reload nginx || die "Failed to reload nginx"
    log "Nginx configured: ${server_name} → 127.0.0.1:${upstream_port}"
}

# ============================================
# Certbot (Let's Encrypt SSL)
# ============================================
setup_certbot() {
    INSTALL_PHASE="certbot SSL"

    if [ "${CFG_SETUP_CERTBOT}" != "yes" ]; then
        log "Certbot setup skipped (user opted out)"
        return
    fi

    if [ "${CFG_SETUP_NGINX}" != "yes" ]; then
        log_warn "Certbot requires nginx — skipping SSL setup"
        return
    fi

    local server_name="${CFG_MX_HOSTNAME}"
    local le_cert="/etc/letsencrypt/live/${server_name}/fullchain.pem"
    local le_key="/etc/letsencrypt/live/${server_name}/privkey.pem"
    local le_chain="/etc/letsencrypt/live/${server_name}/chain.pem"

    # Check if cert already exists and is valid
    if [ -f "$le_cert" ] && [ -f "$le_key" ]; then
        # Check expiry — renew only if within 30 days
        local expiry_epoch
        expiry_epoch=$(openssl x509 -in "$le_cert" -noout -enddate 2>/dev/null \
            | sed 's/notAfter=//' | xargs -I{} date -d {} +%s 2>/dev/null || echo "0")
        local now_epoch
        now_epoch=$(date +%s)
        local days_left=$(( (expiry_epoch - now_epoch) / 86400 ))

        if [ "$days_left" -gt 30 ]; then
            log "SSL cert exists and valid for ${days_left} more days — skipping certbot"
            # Ensure TLS paths are set
            CFG_TLS_CERT_PATH="$le_cert"
            CFG_TLS_KEY_PATH="$le_key"
            CFG_TLS_CHAIN_PATH="$le_chain"
            save_env
            return
        else
            log "SSL cert expires in ${days_left} days — will renew"
        fi
    fi

    # Install certbot if not present
    if ! command -v certbot &>/dev/null; then
        log "Installing certbot..."
        apt-get update -qq || die "Failed to update package lists"
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq certbot python3-certbot-nginx \
            || die "Failed to install certbot"
        log "Certbot installed"
    else
        log "Certbot already installed: $(certbot --version 2>&1)"
    fi

    # Verify port 80 is reachable by nginx (needed for ACME challenge)
    if ! curl -sf "http://127.0.0.1/.well-known/acme-challenge/" &>/dev/null && \
       ! curl -sf -o /dev/null -w "%{http_code}" "http://127.0.0.1/" 2>/dev/null | grep -qE '^[234]'; then
        log_warn "Nginx may not be serving port 80 yet — certbot might fail"
        log_warn "Ensure DNS for ${server_name} points to this server's public IP"
    fi

    log "Running certbot for ${server_name}..."
    echo ""
    echo -e "${YELLOW}  Certbot will verify domain ownership via HTTP challenge.${NC}"
    echo -e "${YELLOW}  Make sure DNS A/AAAA record for ${server_name} points to this server.${NC}"
    echo ""

    # Run certbot with --nginx plugin.
    # This will:
    # 1. Obtain the certificate via ACME HTTP-01 challenge
    # 2. Automatically modify the nginx config to add a listen 443 ssl block
    # 3. Add ssl_certificate and ssl_certificate_key directives
    # 4. Set up auto-renewal via systemd timer or cron
    if ! certbot --nginx \
        -d "$server_name" \
        --email "${CFG_CERTBOT_EMAIL}" \
        --agree-tos \
        --no-eff-email \
        --non-interactive \
        --redirect 2>&1 | tee -a "$LOG_FILE"; then
        log_error "Certbot failed. Common causes:"
        log_error "  - DNS A record for ${server_name} does not point to this server"
        log_error "  - Port 80 is blocked by firewall"
        log_error "  - Rate limit reached (max 5 certs per domain per week)"
        log_warn "Continuing without SSL. Re-run install.sh later to retry."
        return
    fi

    log "SSL certificate obtained successfully"

    # Verify cert files exist
    if [ ! -f "$le_cert" ] || [ ! -f "$le_key" ]; then
        log_warn "Certbot succeeded but cert files not found at expected paths"
        log_warn "Expected: ${le_cert}"
        return
    fi

    # Update TLS paths in .env so fula-mail uses same cert for SMTP STARTTLS
    CFG_TLS_CERT_PATH="$le_cert"
    CFG_TLS_KEY_PATH="$le_key"
    CFG_TLS_CHAIN_PATH="$le_chain"
    save_env

    # Grant fulamail user read access to Let's Encrypt certs
    # Certbot stores certs readable by root only. We add the service user
    # to a group that can traverse the directory.
    if ! getent group letsencrypt &>/dev/null; then
        groupadd letsencrypt 2>/dev/null || true
    fi
    usermod -aG letsencrypt "$MAIL_USER" 2>/dev/null || true

    # Allow group traversal of Let's Encrypt directories
    chmod 750 /etc/letsencrypt/live/ 2>/dev/null || true
    chmod 750 /etc/letsencrypt/archive/ 2>/dev/null || true
    chgrp letsencrypt /etc/letsencrypt/live/ 2>/dev/null || true
    chgrp letsencrypt /etc/letsencrypt/archive/ 2>/dev/null || true

    # Set up post-renewal hook to restart fula-mail (picks up new cert)
    local renewal_hook_dir="/etc/letsencrypt/renewal-hooks/post"
    mkdir -p "$renewal_hook_dir"
    cat > "${renewal_hook_dir}/fula-mail-restart.sh" <<'HOOKEOF'
#!/bin/bash
# Restart fula-mail after certbot renewal so SMTP STARTTLS uses the new cert.
systemctl restart fula-mail 2>/dev/null || true
# Nginx is restarted by certbot automatically.
HOOKEOF
    chmod +x "${renewal_hook_dir}/fula-mail-restart.sh"

    # Restart fula-mail so it picks up the new TLS paths
    if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
        log "Restarting ${SERVICE_NAME} to enable SMTP STARTTLS..."
        systemctl restart "${SERVICE_NAME}" || log_warn "Failed to restart service after TLS setup"
    fi

    log "SSL setup complete — HTTPS and SMTP STARTTLS enabled"
}

# ============================================
# Start service
# ============================================
start_service() {
    INSTALL_PHASE="service start"

    log "Starting ${SERVICE_NAME}..."
    systemctl start "${SERVICE_NAME}" || die "Failed to start ${SERVICE_NAME}"

    # Wait for health check
    log "Waiting for health check..."
    local retries=0
    local max_retries=15
    local health_url="http://127.0.0.1:${CFG_MAIL_HTTP_PORT}/health"

    while [ $retries -lt $max_retries ]; do
        if curl -sf "$health_url" &>/dev/null; then
            log "Health check passed"
            return
        fi
        retries=$((retries + 1))
        sleep 2
    done

    log_warn "Health check did not pass within 30 seconds"
    log_warn "Check logs: journalctl -u ${SERVICE_NAME} -n 50 --no-pager"

    # Don't die here — the service might still be starting up (slow DB, etc.)
    # The user can check manually.
}

# ============================================
# Print status
# ============================================
print_status() {
    echo ""
    echo -e "${GREEN}===== Fula Mail Status =====${NC}"

    # Service
    if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
        echo -e "  Service:  ${GREEN}running${NC}"
    elif systemctl is-enabled --quiet "${SERVICE_NAME}" 2>/dev/null; then
        echo -e "  Service:  ${YELLOW}stopped (enabled)${NC}"
    else
        echo -e "  Service:  ${RED}not installed${NC}"
    fi

    # Binary
    if [ -f "${INSTALL_DIR}/${BINARY_NAME}" ]; then
        local ver
        ver=$("${INSTALL_DIR}/${BINARY_NAME}" --version 2>/dev/null | awk '{print $NF}' || echo "unknown")
        echo -e "  Version:  ${ver}"
    else
        echo -e "  Binary:   ${RED}not found${NC}"
    fi

    # Database
    if [ -f "$ENV_FILE" ]; then
        source "$ENV_FILE"
        if PGPASSWORD="$POSTGRES_PASSWORD" psql \
            -h "$POSTGRES_HOST" \
            -p "$POSTGRES_PORT" \
            -U "$POSTGRES_USER" \
            -d "$POSTGRES_DB" \
            -c "SELECT COUNT(*) FROM mail_domains;" &>/dev/null 2>&1; then
            echo -e "  Database: ${GREEN}connected${NC}"

            local domain_count
            domain_count=$(PGPASSWORD="$POSTGRES_PASSWORD" psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" \
                -U "$POSTGRES_USER" -d "$POSTGRES_DB" -t -A \
                -c "SELECT COUNT(*) FROM mail_domains;" 2>/dev/null || echo "?")
            local addr_count
            addr_count=$(PGPASSWORD="$POSTGRES_PASSWORD" psql -h "$POSTGRES_HOST" -p "$POSTGRES_PORT" \
                -U "$POSTGRES_USER" -d "$POSTGRES_DB" -t -A \
                -c "SELECT COUNT(*) FROM mail_addresses;" 2>/dev/null || echo "?")
            echo "  Domains:  ${domain_count}"
            echo "  Addresses: ${addr_count}"
        else
            echo -e "  Database: ${RED}unreachable${NC}"
        fi
    fi

    # Health endpoint
    local http_port="${MAIL_HTTP_PORT:-$DEFAULT_HTTP_PORT}"
    if curl -sf "http://127.0.0.1:${http_port}/health" &>/dev/null; then
        echo -e "  Health:   ${GREEN}OK${NC}"
    else
        echo -e "  Health:   ${RED}unreachable${NC}"
    fi

    # Nginx
    if [ -f "$NGINX_SITE_FILE" ] && nginx -t 2>/dev/null; then
        echo -e "  Nginx:    ${GREEN}configured${NC}"
    elif command -v nginx &>/dev/null; then
        echo -e "  Nginx:    ${YELLOW}installed but not configured for fula-mail${NC}"
    else
        echo -e "  Nginx:    ${RED}not installed${NC}"
    fi

    # TLS
    if [ -f "$ENV_FILE" ]; then
        local cert_path="${TLS_CERT_PATH:-}"
        if [ -n "$cert_path" ] && [ -f "$cert_path" ]; then
            local expiry
            expiry=$(openssl x509 -in "$cert_path" -noout -enddate 2>/dev/null \
                | sed 's/notAfter=//' || echo "unknown")
            echo -e "  TLS:      ${GREEN}enabled${NC} (expires: ${expiry})"
        else
            echo -e "  TLS:      ${YELLOW}not configured${NC}"
        fi
    fi

    # Ports
    echo ""
    echo "  Ports:"
    echo "    HTTP API:   ${MAIL_HTTP_PORT:-$DEFAULT_HTTP_PORT} (internal)"
    if [ -f "$NGINX_SITE_FILE" ]; then
        echo "    HTTP/nginx: 80 → ${MAIL_HTTP_PORT:-$DEFAULT_HTTP_PORT}"
        if grep -q "listen 443" "$NGINX_SITE_FILE" 2>/dev/null; then
            echo "    HTTPS:      443 (certbot)"
        fi
    fi
    echo "    SMTP:       ${MAIL_SMTP_PORT:-$DEFAULT_SMTP_PORT}"
    echo ""
}

# ============================================
# Uninstall
# ============================================
do_uninstall() {
    echo -e "${YELLOW}===== Fula Mail Uninstall =====${NC}"
    echo ""
    echo "This will:"
    echo "  - Stop and disable the fula-mail service"
    echo "  - Remove the binary and configuration"
    echo "  - Remove the systemd service file"
    echo "  - Remove the nginx site config (nginx itself is kept)"
    echo ""
    echo -e "${YELLOW}Database tables and SSL certs will NOT be removed.${NC}"
    echo "To drop mail tables, do so manually in psql."
    echo "To revoke certs: sudo certbot delete --cert-name <domain>"
    echo ""
    read -rp "Continue? (y/N): " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        echo "Cancelled."
        exit 0
    fi

    if systemctl is-active --quiet "${SERVICE_NAME}" 2>/dev/null; then
        log "Stopping ${SERVICE_NAME}..."
        systemctl stop "${SERVICE_NAME}"
    fi
    if systemctl is-enabled --quiet "${SERVICE_NAME}" 2>/dev/null; then
        systemctl disable "${SERVICE_NAME}"
    fi
    rm -f "$SERVICE_FILE"
    systemctl daemon-reload

    # Remove nginx site config
    if [ -f "$NGINX_SITE_FILE" ] || [ -L "$NGINX_SITE_LINK" ]; then
        rm -f "$NGINX_SITE_LINK" "$NGINX_SITE_FILE"
        nginx -t 2>/dev/null && systemctl reload nginx 2>/dev/null || true
        log "Nginx site config removed"
    fi

    # Remove certbot renewal hook
    rm -f /etc/letsencrypt/renewal-hooks/post/fula-mail-restart.sh 2>/dev/null || true

    # Remove install dir but preserve .env as backup
    if [ -f "$ENV_FILE" ]; then
        cp "$ENV_FILE" "/tmp/fula-mail.env.backup.$(date +%s)"
        log ".env backed up to /tmp/"
    fi

    rm -rf "$INSTALL_DIR"
    rm -rf "$MAIL_DATA_DIR"

    if id "$MAIL_USER" &>/dev/null; then
        userdel "$MAIL_USER" 2>/dev/null || true
    fi

    log "Fula Mail uninstalled"
    log "Database tables preserved. Backup of .env in /tmp/"
}

# ============================================
# Print summary
# ============================================
print_summary() {
    echo ""
    echo -e "${GREEN}=====================================${NC}"
    if [ "$EXISTING_INSTALL" = true ]; then
        echo -e "${GREEN}  Fula Mail Updated Successfully${NC}"
    else
        echo -e "${GREEN}  Fula Mail Installed Successfully${NC}"
    fi
    echo -e "${GREEN}=====================================${NC}"
    echo ""
    echo "  Install dir:  ${INSTALL_DIR}"
    echo "  Config:       ${ENV_FILE}"
    echo "  Data dir:     ${MAIL_DATA_DIR}"
    echo "  Log file:     ${LOG_FILE}"
    echo "  Service:      ${SERVICE_NAME}"
    echo ""
    if [ -n "$CFG_TLS_CERT_PATH" ]; then
        echo "  HTTPS API:    https://${CFG_MX_HOSTNAME}"
    else
        echo "  HTTP API:     http://${CFG_MX_HOSTNAME}:${CFG_MAIL_HTTP_PORT}"
    fi
    echo "  SMTP inbound: ${CFG_MX_HOSTNAME}:${CFG_MAIL_SMTP_PORT}"
    if [ -n "$CFG_TLS_CERT_PATH" ]; then
        echo "  STARTTLS:     enabled"
    fi
    echo ""

    if [ "${CFG_SETUP_NGINX}" = "yes" ]; then
        echo "  Nginx:        port 80 → ${CFG_MAIL_HTTP_PORT}"
        if [ -n "$CFG_TLS_CERT_PATH" ]; then
            echo "                port 443 (TLS) → ${CFG_MAIL_HTTP_PORT}"
        fi
        echo ""
    fi

    echo "  Useful commands:"
    echo "    sudo systemctl status ${SERVICE_NAME}"
    echo "    sudo journalctl -u ${SERVICE_NAME} -f"
    echo "    sudo bash $0 --status"
    echo ""

    if [ -z "$CFG_TLS_CERT_PATH" ]; then
        echo -e "${YELLOW}  Note: TLS is not configured. SMTP STARTTLS and HTTPS are disabled.${NC}"
        if [ "${CFG_SETUP_CERTBOT}" != "yes" ]; then
            echo -e "${YELLOW}  Re-run install.sh and choose certbot, or set TLS paths in ${ENV_FILE}${NC}"
        else
            echo -e "${YELLOW}  Certbot may have failed — check log and re-run install.sh${NC}"
        fi
        echo ""
    fi
}

# ============================================
# Main
# ============================================
main() {
    case "${1:-}" in
        --uninstall)
            do_uninstall
            exit 0
            ;;
        --status)
            print_status
            exit 0
            ;;
        --help|-h)
            echo "Usage: sudo bash install.sh [--uninstall|--status|--help]"
            echo ""
            echo "  (no args)    Install or update fula-mail"
            echo "  --uninstall  Remove fula-mail (preserves database)"
            echo "  --status     Show service status"
            echo "  --help       Show this help"
            exit 0
            ;;
    esac

    echo -e "${GREEN}=====================================${NC}"
    echo -e "${GREEN}  Fula Mail Installer v${SCRIPT_VERSION}${NC}"
    echo -e "${GREEN}=====================================${NC}"
    echo ""

    # Phase 1: Pre-flight
    check_dependencies
    detect_existing

    if [ "$EXISTING_INSTALL" = true ]; then
        log "Update mode — existing installation will be upgraded in place"
        echo ""
        echo -e "${CYAN}Existing installation detected.${NC}"
        echo "The installer will update the binary and run any new migrations."
        echo "Your configuration and data will be preserved."
        echo ""
        read -rp "Continue with update? (Y/n): " confirm
        if [[ "$confirm" =~ ^[Nn]$ ]]; then
            echo "Cancelled."
            exit 0
        fi
    fi

    # Phase 2: Collect config (pre-filled from existing .env)
    collect_config

    # Phase 3: Save .env early (so if build fails, user's answers are preserved)
    save_env

    # Phase 4: Test database connectivity
    test_database

    # Phase 5: Create system user and directories
    create_user
    create_directories

    # Phase 6: Run migrations (transactional — rolls back on failure)
    run_migrations

    # Phase 7: Build binary (skipped if source is unchanged)
    build_binary

    # Phase 8: Install binary (with backup)
    install_binary

    # Phase 9: Copy migration files to install dir (for reference)
    install_migrations

    # Phase 10: Install systemd service
    install_service

    # Phase 11: Set file permissions
    set_permissions

    # Phase 12: Start service and health check
    start_service

    # Phase 13: Nginx reverse proxy (HTTP only initially)
    setup_nginx

    # Phase 14: Certbot SSL (adds 443 to nginx, sets TLS paths for SMTP STARTTLS)
    setup_certbot

    # Clean up temp
    rm -rf "$TEMP_DIR" 2>/dev/null || true

    # Done
    print_summary
}

main "$@"
