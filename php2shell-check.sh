#!/usr/bin/env bash
# Inventário local de PHP2Shell (CVE-2026-109618 e CVE-2026-109619).
# A versão numérica não basta: distribuições aplicam backport sem lança
# o release upstream. Por isso o changelog do pacote também entra na conta.
# O aviso do PHP trata a atualização como a única correção completa, então
# configuração (memory_limit, ini, WAF) não muda o resultado daqui.
set -u

CVE_OOM="CVE-2026-109618"
CVE_UAF="CVE-2026-109619"
GHSA_OOM="GHSA-w8hw-w9fx-j79w"
GHSA_UAF="GHSA-6wmf-4rv5-p3rp"

VULN=0
UNKNOWN=0
FOUND=0
SEEN_KEYS=""
SEEN_VERSIONS=""

usage() {
  cat <<'EOF'
Uso: php2shell-check.sh [--self-test]

Lê os binários PHP, os processos PHP ainda em execução e os pacotes
instalados nesta máquina. Não recebe host, URL nem IP, e não envia requisição.

Códigos de saída:
  0  nenhuma versão vulnerável confirmada
  1  pelo menos uma instalação está na faixa afetada, sem evidência de correção
  2  nenhum PHP encontrado, ou a leitura ficou incompleta
EOF
}

is_prerelease() {
  local suffix="$1"
  [[ "$suffix" =~ ^[-.]?(dev|alpha|beta|rc|RC) ]]
}

classify_upstream() {
  local raw="${1-}"
  local major minor patch suffix fix

  if [[ ! "$raw" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(.*)$ ]]; then
    printf 'unknown\n'
    return 0
  fi

  major=$((10#${BASH_REMATCH[1]}))
  minor=$((10#${BASH_REMATCH[2]}))
  patch=$((10#${BASH_REMATCH[3]}))
  suffix="${BASH_REMATCH[4]}"

  # A faixa publicada começa em 5.4. Abaixo disso não dá para chamar de corrigido.
  if (( major < 5 || (major == 5 && minor < 4) )); then
    printf 'below_range\n'
    return 0
  fi

  # 8.5 é a última linha citada no aviso de 21 out 2026.
  if (( major > 8 || (major == 8 && minor > 5) )); then
    printf 'unknown\n'
    return 0
  fi

  case "$major.$minor" in
    8.2) fix=35 ;;
    8.3) fix=36 ;;
    8.4) fix=27 ;;
    8.5) fix=12 ;;
    *) fix="" ;;
  esac

  if [[ -n "$fix" ]]; then
    if (( patch > fix )); then
      printf 'patched\n'
      return 0
    fi
    # 8.5.12RC1 ainda não é o release 8.5.12.
    if (( patch == fix )) && ! is_prerelease "$suffix"; then
      printf 'patched\n'
      return 0
    fi
    printf 'vulnerable\n'
    return 0
  fi

  printf 'eol\n'
}

package_upstream() {
  local raw="${1-}"
  raw="${raw#*:}"
  if [[ "$raw" =~ ^([0-9]+\.[0-9]+\.[0-9]+) ]]; then
    printf '%s\n' "${BASH_REMATCH[1]}"
    return 0
  fi
  printf '\n'
  return 1
}

seen_has() {
  case "$SEEN_KEYS" in
    *"|$1|"*) return 0 ;;
    *) return 1 ;;
  esac
}

seen_add() {
  SEEN_KEYS="${SEEN_KEYS}|$1|"
}

version_seen() {
  case "$SEEN_VERSIONS" in
    *"|$1|"*) return 0 ;;
    *) return 1 ;;
  esac
}

version_mark() {
  SEEN_VERSIONS="${SEEN_VERSIONS}|$1|"
}

file_inode() {
  local target="$1"
  stat -c '%d:%i' "$target" 2>/dev/null || stat -f '%d:%i' "$target" 2>/dev/null || true
}

run_php() {
  if command -v timeout >/dev/null 2>&1; then
    timeout 5 "$@"
  else
    "$@"
  fi
}

parse_php_v() {
  local line
  # Parêntese da SAPI fica numa variável: dentro de [[ =~ ]] ele quebra o parser.
  local banner_re='^PHP[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+[^[:space:]]*)[[:space:]]+\(([^)]+)\)'
  while IFS= read -r line || [[ -n "$line" ]]; do
    line="${line//$'\r'/}"
    if [[ "$line" =~ $banner_re ]]; then
      printf '%s\t%s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
      return 0
    fi
  done
  return 1
}

read_php_identity() {
  local bin="$1"
  local out="" identity=""

  # php-cgi não aceita -r. O banner de -v traz versão e SAPI sem executar código.
  out="$(run_php "$bin" -n -v 2>&1)" || true
  identity="$(printf '%s\n' "$out" | parse_php_v)" || true
  if [[ -z "$identity" ]] && [[ "$(basename "$bin")" == frankenphp* ]]; then
    out="$(run_php "$bin" version 2>/dev/null)" || true
    identity="$(printf '%s\n' "$out" | parse_php_v)" || true
  fi
  [[ -n "$identity" ]] || return 1
  printf '%s\n' "$identity"
}

is_runtime_package() {
  case "$1" in
    php|php-cli|php-fpm|php-cgi|php-common|\
    php[0-9].[0-9]|php[0-9].[0-9]-cli|php[0-9].[0-9]-fpm|php[0-9].[0-9]-cgi|php[0-9].[0-9]-common|\
    libapache2-mod-php|libapache2-mod-php[0-9].[0-9]|\
    php[0-9][0-9]|php[0-9][0-9]-cli|php[0-9][0-9]-fpm|php[0-9][0-9]-cgi|php[0-9][0-9]-common|\
    php[0-9][0-9]-php-cli|php[0-9][0-9]-php-fpm|php[0-9][0-9]-php-common|\
    ea-php[0-9][0-9]-php-cli|ea-php[0-9][0-9]-php-fpm|ea-php[0-9][0-9]-php-common)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

is_php_comm() {
  case "$1" in
    php|php[0-9]*|php-*|lsphp|lsphp[0-9]*|frankenphp)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

read_doc() {
  local file="$1"
  if [[ "$file" == *.gz ]]; then
    if command -v gzip >/dev/null 2>&1; then
      gzip -dc -- "$file" 2>/dev/null || true
    fi
  else
    cat -- "$file" 2>/dev/null || true
  fi
}

changelog_text() {
  local pkg="$1"
  local sibling="" file
  local files=()

  if [[ -d "/usr/share/doc/$pkg" ]]; then
    files+=("/usr/share/doc/$pkg/changelog.Debian.gz" "/usr/share/doc/$pkg/changelog.gz" "/usr/share/doc/$pkg/changelog")
  fi
  if [[ "$pkg" =~ ^(php[0-9]+\.[0-9]+)- ]]; then
    sibling="${BASH_REMATCH[1]}-common"
    files+=("/usr/share/doc/$sibling/changelog.Debian.gz")
  fi

  for file in "${files[@]}"; do
    [[ -f "$file" ]] || continue
    read_doc "$file"
    printf '\n'
  done

  if command -v rpm >/dev/null 2>&1 && rpm -q "$pkg" >/dev/null 2>&1; then
    rpm -q --changelog "$pkg" 2>/dev/null || true
  fi
}

fix_evidence() {
  local text="$1"
  local has_oom=1 has_uaf=1

  if [[ -z "$text" ]]; then
    printf 'unavailable\n'
    return 0
  fi

  printf '%s' "$text" | grep -F -q -e "$CVE_OOM" -e "$GHSA_OOM" || has_oom=0
  printf '%s' "$text" | grep -F -q -e "$CVE_UAF" -e "$GHSA_UAF" || has_uaf=0

  if (( has_oom && has_uaf )); then
    printf 'both\n'
  elif (( has_oom || has_uaf )); then
    printf 'partial\n'
  else
    printf 'none\n'
  fi
}

package_for_path() {
  local bin="$1"
  local resolved="" line=""

  if command -v readlink >/dev/null 2>&1; then
    resolved="$(readlink -f "$bin" 2>/dev/null || true)"
    resolved="${resolved% (deleted)}"
  fi
  if [[ -n "$resolved" && "$resolved" != /proc/* && -e "$resolved" ]]; then
    bin="$resolved"
  fi

  if command -v dpkg >/dev/null 2>&1; then
    line="$(dpkg -S "$bin" 2>/dev/null | head -n 1 || true)"
    line="${line%%:*}"
    line="${line%%,*}"
    line="${line##* }"
    if [[ -n "$line" ]]; then
      printf '%s\n' "$line"
      return 0
    fi
  fi

  if command -v rpm >/dev/null 2>&1; then
    line="$(rpm -qf --qf '%{NAME}' "$bin" 2>/dev/null || true)"
    if [[ -n "$line" && "$line" != *"not owned"* && "$line" != *"no package provides"* ]]; then
      printf '%s\n' "$line"
      return 0
    fi
  fi

  return 1
}

evidence_phrase() {
  case "$1" in
    both) printf 'o changelog do pacote cita as duas correções' ;;
    partial) printf 'o changelog cita só uma das duas correções' ;;
    none) printf 'o changelog do pacote não cita essas correções' ;;
    *) printf 'não há changelog de pacote para confirmar um backport' ;;
  esac
}

fixed_release() {
  local version="$1"
  if [[ "$version" =~ ^([0-9]+)\.([0-9]+)\. ]]; then
    case "${BASH_REMATCH[1]}.${BASH_REMATCH[2]}" in
      8.2) printf '8.2.35' ;;
      8.3) printf '8.3.36' ;;
      8.4) printf '8.4.27' ;;
      8.5) printf '8.5.12' ;;
    esac
  fi
}

count_status() {
  FOUND=$((FOUND + 1))
  case "$1" in
    VULNERAVEL) VULN=$((VULN + 1)) ;;
    INDEFINIDO|ERRO) UNKNOWN=$((UNKNOWN + 1)) ;;
  esac
}

report() {
  local status="$1"
  local title="$2"
  local detail="$3"
  count_status "$status"
  printf '%s  %s\n' "$status" "$title"
  printf '  %s\n\n' "$detail"
}

judge_and_report() {
  local version="$1"
  local title="$2"
  local pkg="${3-}"
  local kind="${4-disco}"
  local class evidence detail fix extra=""

  class="$(classify_upstream "$version")"
  evidence="unavailable"
  if [[ "$class" == "vulnerable" || "$class" == "eol" ]]; then
    if [[ -n "$pkg" ]]; then
      evidence="$(fix_evidence "$(changelog_text "$pkg")")"
    fi
  fi

  if [[ "$kind" == "processo" ]]; then
    extra=" Processo ainda em execução; worker antigo continua ativo até o serviço ser reiniciado."
  fi

  case "$class" in
    patched)
      report "OK" "$title" "Versão igual ou posterior à correção upstream desta linha.${extra}"
      version_mark "$version"
      ;;
    below_range)
      report "FORA_DA_FAIXA" "$title" "A faixa publicada começa na série 5.4. Isso não atesta que esta instalação está segura.${extra}"
      version_mark "$version"
      ;;
    unknown)
      report "INDEFINIDO" "$title" "Versão fora da matriz publicada em 21 out 2026. Confira o aviso do PHP antes de tratá-la como corrigida.${extra}"
      version_mark "$version"
      ;;
    vulnerable|eol)
      if [[ "$evidence" == "both" ]]; then
        detail="A versão upstream ainda não é uma release oficial corrigida, mas $(evidence_phrase both)."
        detail="${detail} Reinicie os workers depois da atualização. Migrar para 8.2.35, 8.3.36, 8.4.27 ou 8.5.12 continua sendo o caminho durável.${extra}"
        report "BACKPORT" "$title" "$detail"
      else
        fix="$(fixed_release "$version")"
        if [[ -n "$fix" ]]; then
          detail="A correção upstream desta linha é ${fix}; $(evidence_phrase "$evidence")."
        else
          detail="O PHP não publicou release corrigida para esta linha. O caminho suportado é 8.2.35, 8.3.36, 8.4.27 ou 8.5.12; $(evidence_phrase "$evidence")."
        fi
        detail="${detail}${extra}"
        report "VULNERAVEL" "$title" "$detail"
      fi
      version_mark "$version"
      ;;
    *)
      report "ERRO" "$title" "Não foi possível classificar a versão ${version}."
      ;;
  esac
}

consider_directory() {
  local dir="$1"
  local candidate
  [[ -d "$dir" ]] || return 0

  for candidate in \
    "$dir"/php "$dir"/php.exe "$dir"/php-fpm "$dir"/php-cgi \
    "$dir"/php[0-9].[0-9] "$dir"/php[0-9].[0-9]-fpm "$dir"/php[0-9].[0-9]-cgi \
    "$dir"/php-fpm[0-9].[0-9] "$dir"/php[0-9][0-9] \
    "$dir"/lsphp "$dir"/lsphp[0-9][0-9] "$dir"/frankenphp
  do
    [[ -f "$candidate" && -x "$candidate" ]] || continue
    inspect_binary "$candidate" "disco"
  done
}

inspect_binary() {
  local bin="$1"
  local kind="$2"
  local inode="" key="" identity="" version="" sapi="" pkg="" title=""

  inode="$(file_inode "$bin")"
  if [[ -n "$inode" ]]; then
    key="inode:${inode}"
  else
    key="path:${bin}"
  fi
  if seen_has "$key"; then
    return 0
  fi
  seen_add "$key"

  identity="$(read_php_identity "$bin")" || {
    report "ERRO" "$bin" "O arquivo existe, mas não respondeu PHP_VERSION."
    return 0
  }
  version="${identity%%$'\t'*}"
  sapi="${identity#*$'\t'}"
  pkg="$(package_for_path "$bin" || true)"
  title="${bin}  ${version}  sapi=${sapi}"
  if [[ -n "$pkg" ]]; then
    title="${title}  pacote=${pkg}"
  fi
  if [[ "$kind" == "processo" ]]; then
    title="${title}  origem=processo"
  fi
  judge_and_report "$version" "$title" "$pkg" "$kind"
}

scan_path_and_known_roots() {
  local oldifs="$IFS"
  local di
  local -a dirs=()

  IFS=:
  read -ra dirs <<< "${PATH:-}"
  IFS="$oldifs"

  for dir in "${dirs[@]}"; do
    [[ -n "$dir" && "$dir" != "." ]] || continue
    consider_directory "$dir"
  done

  for dir in \
    /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin \
    /opt/plesk/php/*/bin \
    /opt/alt/php*/usr/bin \
    /opt/cpanel/ea-php*/root/usr/bin \
    /usr/local/lsws/lsphp*/bin \
    /opt/remi/php*/root/usr/bin
  do
    consider_directory "$dir"
  done
}

scan_running_processes() {
  local comm_path comm pid exe inode key
  [[ -d /proc ]] || return 0

  for comm_path in /proc/[0-9]*/comm; do
    [[ -r "$comm_path" ]] || continue
    comm="$(tr -d '[:space:]' < "$comm_path" 2>/dev/null || true)"
    is_php_comm "$comm" || continue
    pid="$(basename "$(dirname "$comm_path")")"
    exe="/proc/${pid}/exe"
    [[ -x "$exe" ]] || continue
    inode="$(file_inode "$exe")"
    if [[ -n "$inode" ]]; then
      key="inode:${inode}"
      if seen_has "$key"; then
        continue
      fi
    fi
    inspect_binary "$exe" "processo"
  done
}

list_dpkg() {
  command -v dpkg-query >/dev/null 2>&1 || return 0
  local name version status upstream
  while IFS=$'\t' read -r name version status; do
    [[ "$status" == "install ok installed" ]] || continue
    is_runtime_package "$name" || continue
    upstream="$(package_upstream "$version")"
    [[ -n "$upstream" ]] || continue
    printf '%s\t%s\n' "$name" "$upstream"
  done < <(dpkg-query -W -f='${Package}\t${Version}\t${Status}\n' 2>/dev/null || true)
}

list_rpm() {
  command -v rpm >/dev/null 2>&1 || return 0
  local name version upstream
  while IFS=$'\t' read -r name version; do
    [[ -n "$name" ]] || continue
    is_runtime_package "$name" || continue
    upstream="$(package_upstream "$version")"
    [[ -n "$upstream" ]] || continue
    printf '%s\t%s\n' "$name" "$upstream"
  done < <(rpm -qa --qf '%{NAME}\t%{VERSION}\n' 'php*' 'ea-php*' 2>/dev/null || true)
}

list_apk() {
  command -v apk >/dev/null 2>&1 || return 0
  local line token name upstream
  while IFS= read -r line; do
    token="${line%% *}"
    [[ "$token" =~ ^(.+)-([0-9]+\.[0-9]+\.[0-9]+) ]] || continue
    name="${BASH_REMATCH[1]}"
    upstream="${BASH_REMATCH[2]}"
    is_runtime_package "$name" || continue
    printf '%s\t%s\n' "$name" "$upstream"
  done < <(apk list -I 2>/dev/null || true)
}

scan_packages() {
  local name version
  while IFS=$'\t' read -r name version; do
    [[ -n "${name:-}" && -n "${version:-}" ]] || continue
    if version_seen "$version"; then
      continue
    fi
    judge_and_report "$version" "pacote ${name}  ${version}" "$name" "disco"
  done < <(list_dpkg; list_rpm; list_apk)
}

finish() {
  cat <<'EOF'
Correções upstream: 8.2.35, 8.3.36, 8.4.27 e 8.5.12.
PHP 8.1 e anteriores não têm release oficial corrigida.
O risco está no PHP que atende HTTP. Rode de novo dentro de cada container.
Este script não aciona a falha e não olha outros computadores.
EOF

  if (( FOUND == 0 )); then
    printf 'resultado: nenhum_php\n'
    exit 2
  fi
  if (( VULN > 0 )); then
    printf 'resultado: vulneravel\n'
    exit 1
  fi
  if (( UNKNOWN > 0 )); then
    printf 'resultado: incompleto\n'
    exit 2
  fi
  printf 'resultado: nenhuma_versao_vulneravel_confirmada\n'
  exit 0
}

main() {
  local shopt_state
  case "${1-}" in
    -h|--help)
      usage
      exit 0
      ;;
    --self-test)
      bash "$(cd "$(dirname "$0")" && pwd)/tests/classify.sh"
      exit $?
      ;;
    --classify)
      classify_upstream "${2-}"
      exit 0
      ;;
    --package-upstream)
      package_upstream "${2-}"
      exit $?
      ;;
    --parse-version-text)
      parse_php_v
      exit $?
      ;;
    --changelog-evidence)
      fix_evidence "$(cat)"
      exit 0
      ;;
    "")
      ;;
    *)
      printf 'Este script não recebe host, URL nem IP. Ele só lê o PHP desta máquina.\n' >&2
      usage >&2
      exit 2
      ;;
  esac

  shopt_state="$(shopt -p nullglob || true)"
  shopt -s nullglob

  printf 'PHP2Shell — checagem local\n'
  printf '%s e %s\n' "$CVE_OOM" "$CVE_UAF"
  printf 'Somente leitura nesta máquina. Nenhuma requisição é enviada.\n\n'

  scan_path_and_known_roots
  scan_running_processes
  scan_packages
  eval "$shopt_state"
  finish
}

main "$@"
