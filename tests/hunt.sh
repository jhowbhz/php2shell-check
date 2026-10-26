#!/usr/bin/env bash
# Guarda o que a caça considera sinal. Sem estes casos, um worker PHP com um
# shell pendurado passaria batido, ou um fatal comum viraria "comprometimento".
set -u

root="$(cd "$(dirname "$0")/.." && pwd)"
hunt="$root/php2shell-hunt.sh"
main="$root/php2shell-check.sh"
fail=0

check_child() {
  local parent="$1"
  local child="$2"
  local expected="$3"
  local got
  got="$(bash "$hunt" --child-verdict "$parent" "$child" 2>/dev/null)" || true
  if [[ "$got" != "$expected" ]]; then
    printf 'FAIL filho %s>%s: esperado %s, veio [%s]\n' "$parent" "$child" "$expected" "$got"
    fail=1
  else
    printf 'ok filho %s>%s -> %s\n' "$parent" "$child" "$got"
  fi
}

check_file() {
  local path="$1"
  local exec_flag="$2"
  local expected="$3"
  local got
  got="$(bash "$hunt" --file-verdict "$path" "$exec_flag" 2>/dev/null)" || true
  if [[ "$got" != "$expected" ]]; then
    printf 'FAIL arquivo %s exec=%s: esperado %s, veio [%s]\n' "$path" "$exec_flag" "$expected" "$got"
    fail=1
  else
    printf 'ok arquivo %s exec=%s -> %s\n' "$path" "$exec_flag" "$got"
  fi
}

check_log() {
  local line="$1"
  local expected="$2"
  local got
  got="$(printf '%s\n' "$line" | bash "$hunt" --log-verdict 2>/dev/null)" || true
  if [[ "$got" != "$expected" ]]; then
    printf 'FAIL log [%s]: esperado %s, veio [%s]\n' "$line" "$expected" "$got"
    fail=1
  else
    printf 'ok log -> %s\n' "$expected"
  fi
}

check_child "php-fpm" "bash" "suspicious"
check_child "php-fpm" "curl" "suspicious"
check_child "php8.3-fpm" "wget" "suspicious"
check_child "apache2" "sh" "suspicious"
check_child "httpd" "python3" "suspicious"
check_child "php-fpm" "php" "normal"
check_child "php-fpm" "convert" "normal"
check_child "systemd" "bash" "normal"
check_child "sshd" "bash" "normal"
check_child "php-fpm" "" "normal"

check_file "/tmp/update.sh" "0" "suspicious"
check_file "/tmp/tool" "1" "suspicious"
check_file "/dev/shm/x.php" "0" "suspicious"
check_file "/var/tmp/job.py" "0" "suspicious"
check_file "/tmp/nota.txt" "0" "review"
check_file "/tmp/cache.bin" "0" "review"
check_file "/var/www/html/index.php" "0" "normal"
check_file "/srv/app/script.sh" "1" "normal"

check_log "PHP Fatal error: Allowed memory size of 134217728 bytes exhausted (tried to allocate 2048 bytes)" "review"
check_log "child 123 exited on signal 11 (SIGSEGV) after 12.345 seconds from start" "review"
check_log "PHP Fatal error: Uncaught Error: Call to a member function on null" "review"
check_log "Segmentation fault (core dumped)" "review"
check_log "GET /index.php HTTP/1.1 200 1234" "normal"
check_log "PHP Warning: Undefined array key in /var/www/html/index.php on line 10" "normal"

if bash "$main" --hunt --help 2>/dev/null | grep -q 'php2shell-hunt'; then
  printf 'ok main --hunt encaminha para o script de deteccao\n'
else
  printf 'FAIL main --hunt nao encaminhou para o script de deteccao\n'
  fail=1
fi

if [[ "$fail" -ne 0 ]]; then
  printf 'caca de sinais falhou\n'
  exit 1
fi

printf 'caca de sinais ok\n'
exit 0
