#!/bin/bash
# Stops commits and pushes that contain keys, tokens or signing files.
#   --staged  checks what is about to be committed
#   --full    checks every tracked file
set -euo pipefail

mode="${1:---full}"
case "$mode" in
  --staged) files=$(git diff --cached --name-only --diff-filter=ACMR) ;;
  --full) files=$(git ls-files) ;;
  *) echo "usage: $0 [--staged|--full]" >&2; exit 2 ;;
esac

secret_files='(^|/)(\.env(\..*)?|key\.properties|google-services\.json|GoogleService-Info\.plist)$|\.(jks|keystore|pem|p12|pfx|key)$'
secret_text='-----BEGIN [A-Z ]*PRIVATE KEY-----|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{22,}|AIza[0-9A-Za-z_-]{35}|sk-[A-Za-z0-9_-]{20,}|xox[abprs]-[A-Za-z0-9-]{10,}|(password|passwd|secret|api[_-]?key|token)["'"'"']?[[:space:]]*[:=][[:space:]]*["'"'"'][^"'"'"']{8,}'

read_file() {
  if [ "$mode" = --staged ]; then git show ":$1"; else cat "$1"; fi
}

found=0
while IFS= read -r file; do
  [ -n "$file" ] || continue
  if printf '%s\n' "$file" | grep -Eiq "$secret_files"; then
    echo "security-check: $file is a secret file" >&2
    found=1
    continue
  fi
  # Line numbers only, so the scan never prints the secret itself.
  lines=$(read_file "$file" | grep -EinI -- "$secret_text" | cut -d: -f1 | tr '\n' ' ' || true)
  if [ -n "$lines" ]; then
    echo "security-check: $file may contain a secret on line(s) $lines" >&2
    found=1
  fi
done <<< "$files"

if [ "$found" -ne 0 ]; then
  echo "security-check: blocked. Remove the secret, and revoke it if it was ever shared." >&2
  exit 1
fi
