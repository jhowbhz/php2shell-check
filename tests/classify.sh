#!/usr/bin/env bash
# Guarda a matriz publicada em 21 out 2026. Se estes casos mudarem de resultado,
# o script passa a dizer que um PHP corrigido está vulnerável, ou o contrário.
set -u

root="$(cd "$(dirname "$0")/.." && pwd)"
script="$root/php2shell-check.sh"
fail=0

check() {
  local version="$1"
  local expected="$2"
  local got
  got="$(bash "$script" --classify "$version" 2>/dev/null)" || true
  if [[ "$got" != "$expected" ]]; then
    printf 'FAIL %s: esperado %s, veio [%s]\n' "$version" "$expected" "$got"
    fail=1
  else
    printf 'ok %s -> %s\n' "$version" "$got"
  fi
}

check_package() {
  local package_version="$1"
  local expected="$2"
  local got
  got="$(bash "$script" --package-upstream "$package_version" 2>/dev/null)" || true
  if [[ "$got" != "$expected" ]]; then
    printf 'FAIL pacote %s: esperado %s, veio [%s]\n' "$package_version" "$expected" "$got"
    fail=1
  else
    printf 'ok pacote %s -> %s\n' "$package_version" "$got"
  fi
}

check "8.5.11" vulnerable
check "8.5.12" patched
check "8.5.12RC1" vulnerable
check "8.5.13" patched
check "8.4.26" vulnerable
check "8.4.27" patched
check "8.3.35" vulnerable
check "8.3.36" patched
check "8.2.34" vulnerable
check "8.2.35" patched
check "8.2.36" patched
check "8.1.33" eol
check "8.0.30" eol
check "7.4.33" eol
check "5.4.0" eol
check "5.3.29" below_range
check "8.6.0" unknown
check "8.5.12-dev" vulnerable
check "" unknown
check "nao-e-versao" unknown

check_package "1:8.2.10-2ubuntu1" "8.2.10"
check_package "8.1.2-1ubuntu2.22" "8.1.2"
check_package "8.3.36-1" "8.3.36"
check_package "8.4.27" "8.4.27"

check_banner() {
  local banner="$1"
  local expected="$2"
  local got
  got="$(printf '%s\n' "$banner" | bash "$script" --parse-version-text 2>/dev/null)" || true
  if [[ "$got" != "$expected" ]]; then
    printf 'FAIL banner [%s]: esperado [%s], veio [%s]\n' "$banner" "$expected" "$got"
    fail=1
  else
    printf 'ok banner %s\n' "$expected"
  fi
}

check_banner "PHP 8.5.10 (cli) (built: Aug 25 2026 21:23:48)" $'8.5.10\tcli'
check_banner "PHP 8.5.10 (cgi-fcgi) (built: Aug 25 2026 21:23:48)" $'8.5.10\tcgi-fcgi'
check_banner "PHP 8.3.36 (fpm-fcgi) (built: Oct 21 2026 12:00:00)" $'8.3.36\tfpm-fcgi'

check_evidence() {
  local payload="$1"
  local expected="$2"
  local got
  got="$(printf '%s' "$payload" | bash "$script" --changelog-evidence 2>/dev/null)" || true
  if [[ "$got" != "$expected" ]]; then
    printf 'FAIL changelog [%s]: esperado %s, veio [%s]\n' "$payload" "$expected" "$got"
    fail=1
  else
    printf 'ok changelog %s\n' "$expected"
  fi
}

check_evidence "" "unavailable"
check_evidence "Corrigido CVE-2026-109618." "partial"
check_evidence "CVE-2026-109618 CVE-2026-109619" "both"
check_evidence "GHSA-w8hw-w9fx-j79w GHSA-6wmf-4rv5-p3rp" "both"
check_evidence "security update" "none"

if [[ "$fail" -ne 0 ]]; then
  printf 'matriz de versao falhou\n'
  exit 1
fi

printf 'matriz de versao ok\n'
exit 0
