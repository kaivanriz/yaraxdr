#!/bin/bash
# =============================================================================
# Yara Rules - Initial Setup & Compiled File Creation
# Copyright (C) TangerangKota-CSIRT - 2025.
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License (version 2) as published
# by the FSF - Free Software Foundation.
# =============================================================================

set -euo pipefail

# =============================================================================
# STATIC PARAMETERS
# =============================================================================
readonly YARA_VERSION="4.1.3"
readonly YARA_TARBALL="v${YARA_VERSION}.tar.gz"
readonly YARA_SRC_DIR="yara-${YARA_VERSION}"
readonly YARA_DOWNLOAD_URL="https://github.com/VirusTotal/yara/archive/refs/tags/${YARA_TARBALL}"

readonly BASE_DIR="/usr/local/signature-base"
readonly REPO_NEO_URL="https://github.com/Neo23x0/signature-base.git"
readonly REPO_KOMINFO_URL="https://gitlab-kominfo.tangerangkota.go.id/sharing/yara_rulesv2.git"
readonly REPO_KOMINFO_DIR="${BASE_DIR}/yara_rulesv2"

readonly YARA_DIR="${BASE_DIR}/yara"
readonly YARA_RULES_LIST="${BASE_DIR}/yara_rules_list.yar"
readonly COMPILED_RULES="${BASE_DIR}/yara_base_ruleset_compiled.yar"
readonly LOG_FILE="/var/log/yara_install.log"

readonly -a YARA_BLACKLIST=(
    "gen_fake_amsi_dll.yar"
    "gen_vcruntime140_dll_sideloading.yar"
    "expl_connectwise_screenconnect_vuln_feb24.yar"
    "yara-rules_vuln_drivers_strict_renamed.yar"
    "gen_mal_3cx_compromise_mar23.yar"
    "expl_citrix_netscaler_adc_exploitation_cve_2023_3519.yar"
    "yara_mixed_ext_vars.yar"
    "thor_inverse_matches.yar"
    "generic_anomalies.yar"
    "gen_webshells_ext_vars.yar"
    "general_cloaking.yar"
    "configured_vulns_ext_vars.yar"
    "php_webshell_rules.yara"
    # Menggunakan external variable 'filepath' — tidak kompatibel tanpa LOKI/THOR
    "gen_susp_obfuscation.yar"
)

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

log_message() {
    local level="$1"
    local message="$2"
    echo "$(date '+%Y-%m-%d %H:%M:%S') [$level] $message" | tee -a "$LOG_FILE"
}

log_info()  { log_message "INFO " "$1"; }
log_warn()  { log_message "WARN " "$1"; }
log_error() { log_message "ERROR" "$1"; }

die() {
    log_error "$1"
    exit 1
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

require_root() {
    [ "$(id -u)" -eq 0 ] || die "Script ini harus dijalankan sebagai root atau dengan sudo."
}

# =============================================================================
# OS DETECTION
# =============================================================================

detect_os() {
    OS_FAMILY="unknown"

    if [ -f /etc/os-release ]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        OS_FAMILY="${ID:-unknown}"
    elif [ "$(uname -s)" = "Darwin" ]; then
        OS_FAMILY="macos"
    fi

    log_info "OS terdeteksi: $OS_FAMILY"
}

# =============================================================================
# DEPENDENCY INSTALLATION
# =============================================================================

install_build_dependencies() {
    log_info "Menginstall build dependencies untuk kompilasi YARA dari source..."

    case "$OS_FAMILY" in
        ubuntu|debian)
            apt-get update -qq
            apt-get install -y \
                build-essential automake libtool pkg-config \
                wget git libssl-dev libjansson-dev libmagic-dev
            ;;
        centos|rhel|fedora|almalinux|rocky)
            if command_exists dnf; then
                dnf groupinstall -y "Development Tools"
                dnf install -y automake libtool pkgconf-pkg-config wget git \
                    openssl-devel jansson-devel file-devel
            elif command_exists yum; then
                log_warn "dnf tidak ditemukan, menggunakan yum sebagai fallback..."
                yum groupinstall -y "Development Tools"
                yum install -y automake libtool pkgconfig wget git \
                    openssl-devel jansson-devel file-devel
            else
                die "Tidak ada package manager yang kompatibel (dnf/yum) ditemukan."
            fi
            ;;
        macos)
            command_exists brew || die "Homebrew tidak ditemukan. Install dari https://brew.sh terlebih dahulu."
            brew install automake libtool pkg-config wget jansson
            ;;
        *)
            die "OS '$OS_FAMILY' tidak didukung untuk instalasi build dependencies otomatis."
            ;;
    esac

    log_info "Build dependencies berhasil diinstall."
}

install_yara_package() {
    log_info "Menginstall YARA via package manager..."

    case "$OS_FAMILY" in
        ubuntu|debian)
            apt-get update -qq
            apt-get install -y yara
            ;;
        centos|rhel|fedora|almalinux|rocky)
            if command_exists dnf; then
                dnf install -y yara
            else
                yum install -y yara
            fi
            ;;
        macos)
            command_exists brew || die "Homebrew tidak ditemukan. Install dari https://brew.sh terlebih dahulu."
            brew install yara
            ;;
        *)
            log_warn "OS '$OS_FAMILY' tidak dikenal, mencoba kompilasi dari source..."
            install_yara_from_source
            return
            ;;
    esac

    log_info "YARA berhasil diinstall via package manager."
}

install_yara_from_source() {
    log_info "Menginstall YARA ${YARA_VERSION} dari source code..."

    install_build_dependencies

    local tmp_dir
    tmp_dir=$(mktemp -d)
    trap 'rm -rf "$tmp_dir"' EXIT

    cd "$tmp_dir" || die "Gagal masuk ke direktori temporary."

    log_info "Mengunduh YARA ${YARA_VERSION}..."
    wget -q --timeout=60 --tries=3 -O "$YARA_TARBALL" "$YARA_DOWNLOAD_URL" \
        || die "Gagal mengunduh YARA dari ${YARA_DOWNLOAD_URL}."

    tar -zxf "$YARA_TARBALL" \
        || die "Gagal mengekstrak ${YARA_TARBALL}."

    cd "$YARA_SRC_DIR" || die "Direktori source ${YARA_SRC_DIR} tidak ditemukan setelah ekstraksi."

    log_info "Mengkompilasi YARA..."
    autoreconf -fi
    ./configure --enable-magic --enable-cuckoo --enable-dotnet \
        || die "Konfigurasi YARA gagal."
    make -j"$(nproc)" \
        || die "Kompilasi YARA gagal."
    make check \
        || log_warn "make check gagal, melanjutkan instalasi..."
    make install \
        || die "Instalasi YARA gagal."

    # Normalkan path binary ke /usr/bin agar konsisten di semua distro
    for bin in yara yarac; do
        if [ -f "/usr/local/bin/${bin}" ] && [ ! -f "/usr/bin/${bin}" ]; then
            ln -sf "/usr/local/bin/${bin}" "/usr/bin/${bin}"
            log_info "Symlink dibuat: /usr/local/bin/${bin} -> /usr/bin/${bin}"
        fi
    done

    log_info "YARA ${YARA_VERSION} berhasil diinstall dari source."
}

# =============================================================================
# YARA INSTALLATION
# =============================================================================

install_yara() {
    if command_exists yara && command_exists yarac; then
        local version
        version=$(yara --version 2>/dev/null || echo "unknown")
        log_info "YARA sudah terinstall (versi: $version). Melewati instalasi."
        return 0
    fi

    log_info "YARA belum ditemukan. Memulai instalasi..."
    install_yara_package

    # Verifikasi instalasi berhasil
    command_exists yara  || die "Instalasi YARA gagal: binary 'yara' tidak ditemukan."
    command_exists yarac || die "Instalasi YARA gagal: binary 'yarac' tidak ditemukan."

    log_info "YARA berhasil diinstall: $(yara --version)"
}

# =============================================================================
# REPOSITORY SETUP
# =============================================================================

setup_repo_neo() {
    log_info "Menyiapkan repository Neo23x0/signature-base..."

    mkdir -p "$BASE_DIR"

    if [ -d "${BASE_DIR}/.git" ]; then
        log_info "Repository sudah ada, menarik update terbaru..."
        cd "$BASE_DIR" || die "Gagal masuk ke direktori $BASE_DIR."
        git remote set-url origin "$REPO_NEO_URL"

        # Deteksi branch default dari remote tanpa memicu fatal error di log
        local default_branch
        default_branch=$(git remote show origin 2>/dev/null | awk '/HEAD branch/ {print $NF}')
        default_branch="${default_branch:-master}"

        git pull origin "$default_branch" >> "$LOG_FILE" 2>&1 \
            || die "Gagal menarik update dari repository Neo23x0 (branch: $default_branch)."
    else
        log_info "Clone repository Neo23x0/signature-base..."
        git clone "$REPO_NEO_URL" "$BASE_DIR" >> "$LOG_FILE" 2>&1 \
            || die "Gagal clone repository Neo23x0."
    fi

    # Pastikan folder yara/ ada
    mkdir -p "$YARA_DIR"
    log_info "Repository Neo23x0 siap di ${BASE_DIR}."
}

setup_repo_kominfo() {
    log_info "Menyiapkan repository KOMINFO..."

    if [ -d "${REPO_KOMINFO_DIR}/.git" ]; then
        log_info "Repository KOMINFO sudah ada, menarik update terbaru..."
        cd "$REPO_KOMINFO_DIR" || die "Gagal masuk ke direktori $REPO_KOMINFO_DIR."

        local default_branch
        default_branch=$(git remote show origin 2>/dev/null | awk '/HEAD branch/ {print $NF}')
        default_branch="${default_branch:-main}"

        git pull origin "$default_branch" >> "$LOG_FILE" 2>&1 \
            || die "Gagal menarik update dari repository KOMINFO (branch: $default_branch)."
    else
        log_info "Clone repository KOMINFO..."
        git clone "$REPO_KOMINFO_URL" "$REPO_KOMINFO_DIR" >> "$LOG_FILE" 2>&1 \
            || die "Gagal clone repository KOMINFO."
    fi

    # Salin file .yar dari repo KOMINFO ke folder yara/ utama
    local copied=0
    for f in "${REPO_KOMINFO_DIR}"/*.yar "${REPO_KOMINFO_DIR}/yara"/*.yar; do
        [ -f "$f" ] || continue
        if cp "$f" "$YARA_DIR/"; then
            copied=$(( copied + 1 ))
        else
            log_warn "Gagal menyalin: $f"
        fi
    done

    log_info "Repository KOMINFO siap. $copied file disalin ke ${YARA_DIR}."
}

# =============================================================================
# CLEANUP & DOWNLOAD REPLACEMENT RULES
# =============================================================================

remove_blacklisted_rules() {
    log_info "Menghapus file Yara yang tidak kompatibel..."

    local removed=0
    for rule in "${YARA_BLACKLIST[@]}"; do
        local filepath="${YARA_DIR}/${rule}"
        if [ -f "$filepath" ]; then
            # Pastikan file writable sebelum dihapus (mengatasi permission mismatch)
            chmod u+w "$filepath" 2>/dev/null || true
            if rm -f "$filepath"; then
                removed=$(( removed + 1 ))
            else
                log_warn "Gagal menghapus: $filepath"
            fi
        fi
    done

    log_info "$removed file blacklist dihapus."
}

# =============================================================================
# BUILD & COMPILE YARA RULES
# =============================================================================

build_rules_list() {
    log_info "Membangun daftar Yara rules..."

    rm -f "$YARA_RULES_LIST"
    touch "$YARA_RULES_LIST"

    local count=0

    for f in "${YARA_DIR}"/*.yar "${YARA_DIR}"/*.yara; do
        [ -f "$f" ] || continue
        echo "include \"$f\"" >> "$YARA_RULES_LIST"
        count=$(( count + 1 ))
    done

    [ "$count" -gt 0 ] \
        || die "Tidak ada file Yara yang ditemukan di ${YARA_DIR}."

    log_info "$count file Yara dimasukkan ke rules list."
}

compile_rules() {
    log_info "Mengcompile Yara rules..."

    yarac "$YARA_RULES_LIST" "$COMPILED_RULES" >> "$LOG_FILE" 2>&1 \
        || die "Gagal mengcompile Yara rules. Periksa log di ${LOG_FILE}."

    [ -s "$COMPILED_RULES" ] \
        || die "File compiled rules kosong atau tidak terbentuk: ${COMPILED_RULES}."

    log_info "Yara rules berhasil dicompile ke ${COMPILED_RULES}."
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    # Inisialisasi log
    mkdir -p "$(dirname "$LOG_FILE")"
    touch "$LOG_FILE" 2>/dev/null \
        || die "Tidak dapat menulis ke log file: $LOG_FILE"

    log_info "========================================================"
    log_info "Memulai instalasi dan setup awal Yara rules..."
    log_info "========================================================"

    require_root
    detect_os
    install_yara
    setup_repo_neo
    setup_repo_kominfo
    remove_blacklisted_rules
    build_rules_list
    compile_rules

    log_info "========================================================"
    log_info "Setup awal Yara rules selesai dengan sukses."
    log_info "Compiled rules: ${COMPILED_RULES}"
    log_info "Log tersimpan di: ${LOG_FILE}"
    log_info "========================================================"
}

main "$@"