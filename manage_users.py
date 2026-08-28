# manage_users.py
import sqlite3
import questionary
from werkzeug.security import generate_password_hash

DB_FILE = "c2_database.sqlite"

def create_users_table():
    """Cria a tabela de usuários se ela não existir."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('Administrator', 'Operator', 'Observer')),
        created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    ''')
    conn.commit()
    conn.close()
    print("[INFO] Tabela 'users' verificada/criada com sucesso.")

def list_users():
    """Lista todos os usuários cadastrados no banco de dados."""
    conn = sqlite3.connect(DB_FILE)
    users = conn.execute("SELECT id, username, role, created_at FROM users ORDER BY id").fetchall()
    conn.close()

    if not users:
        print("\n[INFO] Nenhum usuário cadastrado no banco de dados.")
        return

    print("\n--- Usuários Cadastrados ---")
    print(f"{'ID':<5} {'Usuário':<20} {'Função':<15} {'Criado em'}")
    print("-" * 65)
    for user in users:
        print(f"{user[0]:<5} {user[1]:<20} {user[2]:<15} {user[3]}")
    print()

def add_user():
    """Função interativa para adicionar um novo usuário."""
    print("--- Adicionar Novo Usuário ao C2 ---")

    username = questionary.text("Digite o nome do novo usuário:").ask()
    if not username:
        print("\nOperação cancelada.")
        return

    password = questionary.password("Digite a senha para o novo usuário:").ask()
    if not password:
        print("\nOperação cancelada.")
        return

    role = questionary.select(
        "Escolha a função (role) do usuário:",
        choices=['Administrator', 'Operator', 'Observer']
    ).ask()
    if not role:
        print("\nOperação cancelada.")
        return

    password_hash = generate_password_hash(password)

    try:
        conn = sqlite3.connect(DB_FILE)
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, password_hash, role)
        )
        conn.commit()
        conn.close()
        print(f"\n[SUCESSO] Usuário '{username}' com a função '{role}' foi criado!")
    except sqlite3.IntegrityError:
        print(f"\n[ERRO] O usuário '{username}' já existe no banco de dados.")
    except Exception as e:
        print(f"\n[ERRO] Ocorreu um erro inesperado: {e}")

def delete_user():
    """Função interativa para deletar um usuário."""
    print("--- Deletar Usuário do C2 ---")

    conn = sqlite3.connect(DB_FILE)
    users = conn.execute("SELECT username FROM users").fetchall()
    conn.close()

    if not users:
        print("Nenhum usuário encontrado no banco de dados.")
        return

    # CORREÇÃO: acesso por índice (tupla) em vez de chave string
    user_list = [user[0] for user in users]

    username_to_delete = questionary.select(
        "Qual usuário você deseja deletar?",
        choices=user_list
    ).ask()

    if not username_to_delete:
        print("\nOperação cancelada.")
        return

    if questionary.confirm(
        f"Você tem CERTEZA que deseja deletar permanentemente o usuário '{username_to_delete}'?"
    ).ask():
        conn = sqlite3.connect(DB_FILE)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE username = ?", (username_to_delete,))
        conn.commit()
        conn.close()
        print(f"\n[SUCESSO] Usuário '{username_to_delete}' foi deletado.")
    else:
        print("\nOperação de deleção cancelada.")

if __name__ == "__main__":
    create_users_table()

    action = questionary.select(
        "O que deseja fazer?",
        choices=['Adicionar usuário', 'Listar usuários', 'Deletar usuário', 'Sair']
    ).ask()

    if action == 'Adicionar usuário':
        add_user()
    elif action == 'Listar usuários':
        list_users()
    elif action == 'Deletar usuário':
        delete_user()
    else:
        print("\nSaindo...")