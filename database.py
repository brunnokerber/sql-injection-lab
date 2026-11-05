import os
import sqlite3

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "loja.db")


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(force_reset=False):
    """Inicializa o banco SQLite e popula com dados iniciais para demonstracao."""
    if force_reset and os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.executescript(
        """
        CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        );

        CREATE TABLE IF NOT EXISTS produtos (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nome TEXT NOT NULL,
            valor REAL NOT NULL,
            descricao TEXT NOT NULL,
            visivel INTEGER NOT NULL DEFAULT 1
        );
        """
    )

    # Verifica se ja existem usuarios cadastrados
    cursor.execute("SELECT COUNT(*) FROM usuarios")
    if cursor.fetchone()[0] == 0:
        usuarios_seed = [
            ("admin", "Admin@SuperSecreta2026!", "admin"),
            ("auditor", "Auditoria#Feevale9", "auditor"),
            ("cliente", "123456", "user"),
        ]
        cursor.executemany(
            "INSERT INTO usuarios (username, password, role) VALUES (?, ?, ?)",
            usuarios_seed,
        )

    # Verifica se ja existem produtos cadastrados
    cursor.execute("SELECT COUNT(*) FROM produtos")
    if cursor.fetchone()[0] == 0:
        produtos_seed = [
            ("Firewall Hardware UTM", 4500.00, "Appliance de seguranca de borda com IDS/IPS integrado", 1),
            ("Token USB FIDO2", 320.50, "Chave de autenticacao multifator fisica resistente a phishing", 1),
            ("Licenca SIEM Enterprise", 12800.00, "Monitoramento continuo e correlacao de logs de auditoria", 1),
            ("Cofre de Senhas Corporativo", 890.00, "Gerenciador de credenciais privilegiadas (PAM)", 1),
            ("[RESTRITO] Backup Master Key", 99999.99, "Chave mestra interna (Oculto: visivel=0)", 0),
        ]
        cursor.executemany(
            "INSERT INTO produtos (nome, valor, descricao, visivel) VALUES (?, ?, ?, ?)",
            produtos_seed,
        )

    conn.commit()
    conn.close()
