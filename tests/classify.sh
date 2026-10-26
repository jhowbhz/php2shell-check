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

if [[ "$fail" -ne 0 ]]; then
  printf 'matriz de versao falhou\n'
  exit 1
fi

printf 'matriz de versao ok\n'
exit 0
