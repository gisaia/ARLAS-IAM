#!/usr/bin/env bash

# generate_pkcs12.sh
# This script generates a private key, a self-signed certificate, and exports them to a PKCS#12 (.p12) file using OpenSSL.
# Usage:
#   ./generate_pkcs12.sh -o <output_dir> -n <common_name> -d <validity_days> -b <key_bits> -f <pkcs12_filename> -a <alias>
#
# Example:
#   ./generate_pkcs12.sh -o ./out -n example.com -d 365 -b 4096 -f mycert.p12 -a myalias

set -euo pipefail

# -----------------------
# Helper functions
# -----------------------
print_help() {
  echo "Usage: $0 -o <output_dir> -n <common_name> -d <validity_days> -b <key_bits> -f <pkcs12_filename> -a <alias>"
  echo
  echo "Options:"
  echo "  -o  Output directory for generated files"
  echo "  -n  Common Name (CN) for the certificate (e.g., example.com)"
  echo "  -d  Certificate validity in days"
  echo "  -b  Key size in bits (e.g., 2048, 4096)"
  echo "  -f  Output PKCS#12 filename (e.g., keystore.p12)"
  echo "  -a  Alias name (friendly name inside the PKCS#12)"
  echo
  exit 1
}

error() { echo "Error: $*" >&2; exit 1; }
info() { echo "[*] $*"; }

# -----------------------
# Parse command-line arguments
# -----------------------
while getopts ":o:n:d:b:f:a:" opt; do
  case $opt in
    o) OUT_DIR="$OPTARG" ;;
    n) CN="$OPTARG" ;;
    d) DAYS="$OPTARG" ;;
    b) KEY_BITS="$OPTARG" ;;
    f) PKCS12_FILENAME="$OPTARG" ;;
    a) PKCS12_ALIAS="$OPTARG" ;;
    *) print_help ;;
  esac
done

# Check required parameters
[[ -z "${OUT_DIR:-}" ]] && print_help
[[ -z "${CN:-}" ]] && print_help
[[ -z "${DAYS:-}" ]] && print_help
[[ -z "${KEY_BITS:-}" ]] && print_help
[[ -z "${PKCS12_FILENAME:-}" ]] && print_help
[[ -z "${PKCS12_ALIAS:-}" ]] && print_help

# -----------------------
# Set output file paths
# -----------------------
KEY_FILE="${OUT_DIR}/key.pem"
CERT_FILE="${OUT_DIR}/cert.pem"
PKCS12_FILE="${OUT_DIR}/${PKCS12_FILENAME}"

# -----------------------
# Check dependencies
# -----------------------
command -v openssl >/dev/null 2>&1 || error "openssl is not installed. Please install it and try again."

# -----------------------
# Confirm overwriting existing files
# -----------------------
if [[ -f "$KEY_FILE" || -f "$CERT_FILE" || -f "$PKCS12_FILE" ]]; then
  echo "Warning: One or more output files already exist:"
  [[ -f "$KEY_FILE" ]] && echo "  - Private Key : $KEY_FILE"
  [[ -f "$CERT_FILE" ]] && echo "  - Certificate : $CERT_FILE"
  [[ -f "$PKCS12_FILE" ]] && echo "  - PKCS#12     : $PKCS12_FILE"
  read -p "Do you want to overwrite them? (yes/no): " RESP
  case "$RESP" in
    y|Y|yes|YES) info "Overwriting files..." ;;
    *) error "Aborted." ;;
  esac
fi

# -----------------------
# Read PKCS#12 password securely
# -----------------------
read -r -s -p "Enter password for the PKCS#12 file: " PKCS12_PASS
echo
read -r -s -p "Confirm password: " PKCS12_PASS2
echo
[[ "$PKCS12_PASS" == "$PKCS12_PASS2" ]] || error "Passwords do not match."

# -----------------------
# Create output directory
# -----------------------
mkdir -p "$OUT_DIR"

# -----------------------
# Generate RSA private key
# -----------------------
info "Generating RSA private key (${KEY_BITS} bits) -> $KEY_FILE"
openssl genpkey -algorithm RSA -out "$KEY_FILE" -pkeyopt rsa_keygen_bits:$KEY_BITS
chmod 600 "$KEY_FILE"

# -----------------------
# Generate self-signed certificate
# -----------------------
SUBJ="/CN=${CN}"
info "Generating self-signed certificate (valid for $DAYS days) -> $CERT_FILE"
openssl req -new -x509 -key "$KEY_FILE" -out "$CERT_FILE" -days "$DAYS" -subj "$SUBJ"

# -----------------------
# Export to PKCS#12
# -----------------------
info "Exporting to PKCS#12 -> $PKCS12_FILE"
openssl pkcs12 -export \
  -inkey "$KEY_FILE" \
  -in "$CERT_FILE" \
  -out "$PKCS12_FILE" \
  -name "$PKCS12_ALIAS" \
  -passout "pass:${PKCS12_PASS}"

# -----------------------
# Done
# -----------------------
info "Done. Files generated:"
echo "  - Private Key : $KEY_FILE"
echo "  - Certificate : $CERT_FILE"
echo "  - PKCS#12     : $PKCS12_FILE"

#Exemple usage:
#./generate_pkcs12.sh -o ./output -n example.com -d 365 -b 4096 -f keystore.p12 -a arlas-iam