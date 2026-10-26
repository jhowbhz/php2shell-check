#!/usr/bin/env bash
# Caça defensiva pós-exploração para PHP2Shell.
# Sinal não é comprometimento confirmado: worker web com shell pendurado,
# por exemplo, também nasce de rotina legítima mal desenhada. Este script
# só junta o que merece investigação, sem apagar nem encerrar nada.
set -u

STRONG=0
REVIEW=0
INCOMPLETE=0

usage() {
  cat <<'EOF'
Uso: php2shell-hunt.sh

Procura, nesta máquina, sinais que pedem investigação depois de um PHP
vulnerável ao PHP2Shell: filhos estranhos de workers web/PHP, arquivos
recentes em pastas temporárias, trechos de log com quebra do worker e
conexões de saída desses workers.

Somente leitura. Não recebe host, URL nem IP, não envia requisição,
não encerra processo e não apaga arquivo.

Códigos de saída:
  0  nenhum sinal forte encontrado
  1  pelo menos um sinal forte para investiga
  2  leitura incompleta (ferramenta ou log indisponível)
EOF
}

comm_base() {
  local name="${1-}"
  name="${name##*/}"
  # Sem tr externo: esta funcao roda uma vez por processo e por arquivo.
  printf '%s' "${name,,}"
}

is_web_worker_comm() {
  local comm
  comm="$(comm_base "${1-}")"
  case "$comm" in
    php|php-*|php[0-9]*|lsphp*|frankenphp|apache2|apache|httpd|httpd-*)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

is_suspicious_child_comm() {
  local comm
  comm="$(comm_base "${1-}")"
  case "$comm" in
    sh|bash|dash|ash|zsh|ksh|mksh|\
    curl|wget|nc|ncat|netcat|socat|telnet|ftp|\
    python|python[0-9]*|perl|perl[0-9]*|ruby|ruby[0-9]*|node|nodejs|\
    base64|busybox)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

child_verdict() {
  if is_web_worker_comm "${1-}" && is_suspicious_child_comm "${2-}"; then
    printf 'suspicious\n'
  else
    printf 'normal\n'
  fi
}

file_verdict() {
  local path="${1-}"
  local exec_flag="${2-0}"
  local lowe

  case "$path" in
    /tmp/*|/var/tmp/*|/dev/shm/*) ;;
    *) printf 'normal\n'; return 0 ;;
  esac

  if [[ "$exec_flag" == "1" ]]; then
    printf 'suspicious\n'
    return 0
  fi

  lower="${path,,}"
  case "$lower" in
    *.sh|*.bash|*.php|*.phtml|*.phar|*.pl|*.py|*.rb|*.cgi|*.so)
      printf 'suspicious\n'
      ;;
    *)
      printf 'review\n'
      ;;
  esac
}

log_verdict() {
  local line=""
  IFS= read -r line || true
  case "$line" in
    *"Allowed memory size of"*"exhausted"*) printf 'review\n' ;;
    *"exited on signal 11"*) printf 'review\n' ;;
    *"Segmentation fault"*) printf 'review\n' ;;
    *"PHP Fatal error:"*) printf 'review\n' ;;
    *) printf 'normal\n' ;;
  esac
}

section() {
  printf '\n== %s ==\n' "$1"
}

hunt_processes() {
  local listing="" pid ppid comm rest
  local workers=" " found=0

  section "Processos filhos de workers web/PHP"
  if ! command -v ps >/dev/null 2>&1; then
    INCOMPLETE=1
    printf 'INDEFINIDO  ps nao encontrado; confira manualmente os filhos de php-fpm/apache.\n'
    return 0
  fi

  listing="$(ps -eo pid=,ppid=,comm= 2>/dev/null || true)"
  if [[ -z "$listing" ]]; then
    INCOMPLETE=1
    printf 'INDEFINIDO  ps nao retornou processos.\n'
    return 0
  fi

  while read -r pid ppid comm rest; do
    [[ "$pid" =~ ^[0-9]+$ ]] || continue
    if is_web_worker_comm "$comm"; then
      workers="${workers}${pid} "
    fi
  done <<< "$listing"

  while read -r pid ppid comm rest; do
    [[ "$pid" =~ ^[0-9]+$ && "$ppid" =~ ^[0-9]+$ ]] || continue
    case "$workers" in
      *" $ppid "*) ;;
      *) continue ;;
    esac
    if is_suspicious_child_comm "$comm"; then
      STRONG=$((STRONG + 1))
      found=1
      printf 'SINAL_FORTE  pid=%s ppid=%s processo=%s\n' "$pid" "$ppid" "$comm"
    fi
  done <<< "$listing"

  if (( found == 0 )); then
    printf 'nenhum shell, download ou interpretador filho direto de worker web/PHP.\n'
  fi
}

hunt_connections() {
  local out="" filtered=""

  section "Conexoes de saida de workers web/PHP"
  if command -v ss >/dev/null 2>&1; then
    out="$(ss -H -tpn state established 2>/dev/null || true)"
    filtered="$(printf '%s\n' "$out" | grep -i -e php -e apache -e httpd || true)"
  elif command -v netstat >/dev/null 2>&1; then
    out="$(netstat -tpn 2>/dev/null | grep -i ESTABLISHED || true)"
    filtered="$(printf '%s\n' "$out" | grep -i -e php -e apache -e httpd || true)"
  else
    INCOMPLETE=1
    printf 'INDEFINIDO  nem ss nem netstat encontrados.\n'
    return 0
  fi

  if [[ -n "$filtered" ]]; then
    REVIEW=$((REVIEW + 1))
    printf 'REVISAR  conexao de worker nao e, sozinha, sinal de invasao (banco e APIs sao legitimos):\n'
    printf '%s\n' "$filtered" | head -n 20
  else
    printf 'nenhuma conexao estabelecida atribuida a worker web/PHP.\n'
  fi
}

hunt_tmp() {
  local days="${PHP2SHELL_HUNT_DAYS:-7}"
  local dir file exec_flag verdict found_dir=0 found_file=0 printed=0

  section "Arquivos recentes em pastas temporarias (${days} dias)"
  [[ "$days" =~ ^[0-9]+$ ]] || days=7

  for dir in /tmp /var/tmp /dev/shm; do
    [[ -d "$dir" ]] || continue
    found_dir=1
    # Teto por pasta: /tmp de maquina de desenvolvimento tem milhares de
    # arquivos recentes, e a lista de conferencia nao precisa de todos.
    while IFS= read -r file; do
      [[ -n "$file" ]] || continue
      found_file=1
      exec_flag=0
      [[ -x "$file" ]] && exec_flag=1
      verdict="$(file_verdict "$file" "$exec_flag")"
      if [[ "$verdict" == "suspicious" ]]; then
        STRONG=$((STRONG + 1))
        # Sinal forte sempre aparece; quem tem teto de impressao e o REVISAR.
        (( STRONG <= 100 )) && printf 'SINAL_FORTE  %s\n' "$file"
      else
        REVIEW=$((REVIEW + 1))
        printed=$((printed + 1))
        (( printed <= 50 )) && printf 'REVISAR  %s\n' "$file"
      fi
    done < <(find "$dir" -maxdepth 3 -type f -mtime "-${days}" -print 2>/dev/null | head -n 500 || true)
  done

  if (( found_dir == 0 )); then
    INCOMPLETE=1
    printf 'INDEFINIDO  nenhuma pasta temporaria padrao encontrada.\n'
  elif (( found_file == 0 )); then
    printf 'nenhum arquivo recente em /tmp, /var/tmp ou /dev/shm.\n'
  fi
}

log_tail() {
  local file="$1"
  if [[ "$file" == *.gz ]]; then
    if command -v gzip >/dev/null 2>&1; then
      gzip -dc -- "$file" 2>/dev/null | tail -n 5000
    fi
  elif command -v tail >/dev/null 2>&1; then
    tail -n 5000 -- "$file" 2>/dev/null || true
  else
    cat -- "$file" 2>/dev/null || true
  fi
}

hunt_logs() {
  local file line verdict found_file=0 found_match=0 shown=0 seen=" "

  section "Trechos de log com quebra de worker"
  local candidates=(
    /var/log/apache2/error.log*
    /var/log/apache2/*error*log*
    /var/log/httpd/*
    /var/log/nginx/error.log*
    /var/log/php-fpm*
    /var/log/php-fpm/*
    /var/log/php/*
    /var/log/php_errors.log
  )

  for file in "${candidates[@]}"; do
    [[ -f "$file" ]] || continue
    case "$seen" in
      *" $file "*) continue ;;
    esac
    seen="${seen}${file} "
    if [[ ! -r "$file" ]]; then
      INCOMPLETE=1
      printf 'INDEFINIDO  sem leitura em %s (rode com permissao de leitura de log).\n' "$file"
      continue
    fi
    found_file=1
    shown=0
    while IFS= read -r line || [[ -n "$line" ]]; do
      verdict="$(printf '%s\n' "$line" | log_verdict)"
      [[ "$verdict" == "review" ]] || continue
      REVIEW=$((REVIEW + 1))
      found_match=1
      shown=$((shown + 1))
      if (( shown <= 10 )); then
        printf 'REVISAR  %s: %.220s\n' "$file" "$line"
      fi
    done < <(log_tail "$file")
  done

  if (( found_file == 0 )); then
    INCOMPLETE=1
    printf 'INDEFINIDO  nenhum log padrao de Apache, Nginx ou PHP-FPM encontrado.\n'
  elif (( found_match == 0 )); then
    printf 'nenhum trecho de quebra/OOM nas ultimas linhas dos logs encontrados.\n'
  fi
}

finish() {
  section "Resumo"
  printf 'sinais_fortes: %s\n' "$STRONG"
  printf 'itens_para_revisar: %s\n' "$REVIEW"
  printf 'Sinal forte nao confirma comprometimento. Preserve logs e horarios,\n'
  printf 'isole o servico se o sinal fizer sentido, atualize o PHP e investigue\n'
  printf 'antes de apagar arquivos ou encerrar processos. Veja HUNTING.md.\n'

  if (( STRONG > 0 )); then
    printf 'resultado: sinais_fortes_para_investigar\n'
    exit 1
  fi
  if (( INCOMPLETE > 0 )); then
    printf 'resultado: incompleto\n'
    exit 2
  fi
  printf 'resultado: nenhum_sinal_forte\n'
  exit 0
}

main() {
  case "${1-}" in
    -h|--help)
      usage
      exit 0
      ;;
    --child-verdict)
      child_verdict "${2-}" "${3-}"
      exit 0
      ;;
    --file-verdict)
      file_verdict "${2-}" "${3-0}"
      exit 0
      ;;
    --log-verdict)
      log_verdict
      exit 0
      ;;
    "")
      ;;
    *)
      printf 'Este script nao recebe host, URL nem IP. Ele so le esta maquina.\n' >&2
      usage >&2
      exit 2
      ;;
  esac

  printf 'PHP2Shell — deteccao pos-exploracao (php2shell-hunt)\n'
  printf 'Somente leitura nesta maquina. Nenhuma requisicao e enviada.\n'

  hunt_processes
  hunt_connections
  hunt_tmp
  hunt_logs
  finish
}

main "$@"
