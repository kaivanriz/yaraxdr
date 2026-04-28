#!/bin/bash
# =============================================================================
# Yara Rules Update Script for Cronjob
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
readonly BASE_DIR="/usr/local/signature-base"
readonly REPO_NEO_URL="https://github.com/Neo23x0/signature-base.git"
readonly REPO_KOMINFO_URL="https://gitlab-kominfo.tangerangkota.go.id/sharing/yara_rulesv2.git"
readonly REPO_KOMINFO_DIR="${BASE_DIR}/yara_rulesv2"

readonly YARA_DIR="${BASE_DIR}/yara"
readonly YARA_RULES_LIST="${BASE_DIR}/yara_rules_list.yar"
readonly COMPILED_RULES="${BASE_DIR}/yara_base_ruleset_compiled.yar"
readonly LOG_FILE="/var/log/yara_rules_update.log"

# Yara rule files yang tidak kompatibel (akan dihapus setelah git pull)
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

# =============================================================================
# PREFLIGHT CHECKS
# =============================================================================

preflight_checks() {
    log_info "Menjalankan preflight checks..."

    # Cek tools yang dibutuhkan
    local -a required_tools=("git" "yarac" "wget")
    for tool in "${required_tools[@]}"; do
        command_exists "$tool" || die "Tool '$tool' tidak ditemukan. Install terlebih dahulu."
    done

    # Cek log file bisa ditulis
    touch "$LOG_FILE" 2>/dev/null \
        || die "Tidak dapat menulis ke log file: $LOG_FILE"

    # Cek repo utama (Neo23x0) sudah ada
    [ -d "${BASE_DIR}/.git" ] \
        || die "Git repository tidak ditemukan di ${BASE_DIR}. Jalankan script setup awal terlebih dahulu."

    # Cek folder yara/ ada
    [ -d "$YARA_DIR" ] \
        || die "Folder yara tidak ditemukan di ${YARA_DIR}."

    log_info "Preflight checks selesai."
}

# =============================================================================
# UPDATE REPOSITORIES
# =============================================================================

update_repo_neo() {
    log_info "Menarik update dari Neo23x0/signature-base..."

    cd "$BASE_DIR" || die "Gagal masuk ke direktori $BASE_DIR."

    # Pastikan remote 'origin' mengarah ke repo Neo23x0
    if ! git remote get-url origin &>/dev/null; then
        git remote add origin "$REPO_NEO_URL"
    else
        git remote set-url origin "$REPO_NEO_URL"
    fi

    # Deteksi branch default dari remote tanpa memicu fatal error di log
    local default_branch
    default_branch=$(git remote show origin 2>/dev/null | awk '/HEAD branch/ {print $NF}')
    default_branch="${default_branch:-master}"

    git pull origin "$default_branch" >> "$LOG_FILE" 2>&1 \
        || die "Gagal menarik update dari repository Neo23x0 (branch: $default_branch)."

    log_info "Update Neo23x0/signature-base berhasil."
}

update_repo_kominfo() {
    log_info "Menarik update dari GitLab KOMINFO..."

    # Repo KOMINFO diclone/pull ke subfolder terpisah agar tidak konflik
    if [ -d "${REPO_KOMINFO_DIR}/.git" ]; then
        cd "$REPO_KOMINFO_DIR" || die "Gagal masuk ke direktori $REPO_KOMINFO_DIR."

        local default_branch
        default_branch=$(git remote show origin 2>/dev/null | awk '/HEAD branch/ {print $NF}')
        default_branch="${default_branch:-main}"

        git pull origin "$default_branch" >> "$LOG_FILE" 2>&1 \
            || die "Gagal menarik update dari repository KOMINFO (branch: $default_branch)."
    else
        log_info "Repository KOMINFO belum ada, melakukan clone awal..."
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

    log_info "Update KOMINFO selesai. $copied file disalin ke ${YARA_DIR}."
}

# =============================================================================
# CLEANUP BLACKLISTED RULES
# =============================================================================

remove_blacklisted_rules() {
    log_info "Menghapus file Yara yang tidak kompatibel..."

    local removed=0
    for rule in "${YARA_BLACKLIST[@]}"; do
        local filepath="${YARA_DIR}/${rule}"
        if [ -f "$filepath" ]; then
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

    # Include semua .yar
    for f in "${YARA_DIR}"/*.yar; do
        [ -f "$f" ] || continue
        echo "include \"$f\"" >> "$YARA_RULES_LIST"
        count=$(( count + 1 ))
    done

    # Include semua .yara (ekstensi alternatif)
    for f in "${YARA_DIR}"/*.yara; do
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

    # Validasi output file terbentuk
    [ -s "$COMPILED_RULES" ] \
        || die "File compiled rules kosong atau tidak terbentuk: ${COMPILED_RULES}."

    log_info "Yara rules berhasil dicompile ke ${COMPILED_RULES}."
}

# =============================================================================
# MAIN
# =============================================================================

main() {
    log_info "========================================================"
    log_info "Memulai proses update Yara rules..."
    log_info "========================================================"

    preflight_checks
    update_repo_neo
    update_repo_kominfo
    remove_blacklisted_rules
    build_rules_list
    compile_rules

    log_info "========================================================"
    log_info "Update Yara rules selesai dengan sukses."
    log_info "========================================================"
}

main "$@"