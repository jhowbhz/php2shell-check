# Detecção pós-exploração (defensiva)

Isto é caça a sinais, não prova de invasão. Um sinal forte manda investigar; ele não confirma comprometimento sozinho.

Rode no servidor:

```bash
bash php2shell-check.sh --hunt
```

ou direto:

```bash
bash php2shell-hunt.sh
```

Por padrão, arquivos temporários recentes são os dos últimos 7 dias. Para mudar a janela:

```bash
PHP2SHELL_HUNT_DAYS=30 bash php2shell-hunt.sh
```

## O que o script procura

| Sinal | Leitura |
| --- | --- |
| `SINAL_FORTE`: shell, `curl`, `wget`, interpretador ou ferramenta de rede como filho direto de `php-fpm`, Apache ou outro worker web/PHP | Worker web normalmente não abre shell. Investigue primeiro, mas lembre que rotina legítima mal desenhada também faz isso |
| `SINAL_FORTE`: arquivo executável ou script (`.sh`, `.php`, `.py`, `.pl`, `.cgi`, `.so`) recente em `/tmp`, `/var/tmp` ou `/dev/shm` | Pasta temporária com executável recente pede explicação |
| `REVISAR`: arquivo comum recente nessas pastas | Upload e cache legítimos também moram aí; serve como lista de conferência |
| `REVISAR`: `PHP Fatal error`, `Allowed memory size ... exhausted`, `exited on signal 11` ou `Segmentation fault` nas últimas linhas do log | Quebra/OOM é sinal fraco: bug de aplicação causa a mesma linha |
| `REVISAR`: conexão estabelecida atribuída a worker web/PHP | Banco de dados e API externa são legítimos; o que chama atenção é destino e porta sem relação com a aplicação |

## Conferência manual

```bash
ps auxf
ss -tpn state established
find /tmp /var/tmp /dev/shm -maxdepth 3 -type f -mtime -7 -ls
grep -E "Allowed memory size|PHP Fatal error|exited on signal 11" /var/log/apache2/error.log | tail -n 50
```

## Se aparecer sinal forte

1. Não apague o arquivo nem encerre o processo antes de registrar horário, PID, usuário, caminho e destino de rede.
2. Preserve os logs do servidor web, do PHP-FPM e de autenticação.
3. Atualize o PHP para 8.2.35, 8.3.36, 8.4.27 ou 8.5.12 e reinicie os workers.
4. Se o sinal não tiver explicação legítima, isole o serviço e trate como incidente: troque credenciais que esse servidor conhecia e revise contas e arquivos novos.

## Limites

- Sem `ps`, `ss`/`netstat` ou leitura dos logs, a seção sai como `INDEFINIDO` e o resultado vira incompleto.
- Processo encerrado antes da checagem não aparece. Arquivo com data antiga também fica fora da janela.
- Nada aqui substitui EDR, revisão de logs centralizados ou resposta a incidentes.
