import sqlite3
import os

DB_PATH = os.path.join(os.path.dirname(__file__), 'vault.db')
DATABASE_URL = os.environ.get('DATABASE_URL')

def format_name_title_case(s):
    if not s:
        return ""
    words = str(s).strip().split()
    formatted = []
    for w in words:
        if len(w) > 0:
            formatted.append(w[0].upper() + w[1:].lower())
    return " ".join(formatted)

if DATABASE_URL:
    import psycopg2
    import psycopg2.extras

    class PostgreSQLConnectionWrapper:
        def __init__(self, conn):
            self.conn = conn

        def cursor(self):
            cur = self.conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
            return PostgreSQLCursorWrapper(cur)

        def execute(self, query, params=None):
            cur = self.cursor()
            cur.execute(query, params)
            return cur

        def commit(self):
            self.conn.commit()

        def rollback(self):
            self.conn.rollback()

        def close(self):
            self.conn.close()

    class PostgreSQLCursorWrapper:
        def __init__(self, cur):
            self.cur = cur
            self._lastrowid = None

        def execute(self, query, params=None):
            converted_query = query.replace('?', '%s')
            converted_query = converted_query.replace('datetime("now")', 'CURRENT_TIMESTAMP')
            converted_query = converted_query.replace("datetime('now')", 'CURRENT_TIMESTAMP')
            
            # Translate SQLite specific query constructs
            if "INSERT OR REPLACE INTO system_settings" in query:
                converted_query = "INSERT INTO system_settings (key, value) VALUES (%s, %s) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value"
            elif "INSERT OR IGNORE" in query:
                converted_query = query.replace("INSERT OR IGNORE", "INSERT").replace("?", "%s") + " ON CONFLICT DO NOTHING"
            
            # Capture lastrowid dynamically
            is_insert = converted_query.strip().upper().startswith('INSERT')
            if is_insert and 'RETURNING' not in converted_query.upper():
                converted_query += ' RETURNING id'

            try:
                self.cur.execute(converted_query, params)
                if is_insert:
                    try:
                        self._lastrowid = self.cur.fetchone()[0]
                    except Exception:
                        self._lastrowid = None
            except psycopg2.IntegrityError as e:
                # Rollback transaction to allow subsequent statement execution
                self.cur.connection.rollback()
                raise sqlite3.IntegrityError(str(e))
            return self

        def fetchone(self):
            try:
                row = self.cur.fetchone()
                return row # DictCursor row acts like a dictionary and supports numeric indexing
            except Exception:
                return None

        def fetchall(self):
            try:
                return self.cur.fetchall()
            except Exception:
                return []

        @property
        def lastrowid(self):
            return self._lastrowid

        def close(self):
            self.cur.close()

    def get_db_connection():
        # Parse postgres connection URL
        conn = psycopg2.connect(DATABASE_URL)
        return PostgreSQLConnectionWrapper(conn)
else:
    def get_db_connection():
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Create users table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            totp_secret TEXT,
            totp_enabled INTEGER DEFAULT 0,
            is_admin INTEGER DEFAULT 0,
            is_superuser INTEGER DEFAULT 0,
            status TEXT DEFAULT 'active',
            force_password_change INTEGER DEFAULT 0,
            current_session_id TEXT,
            password_hint TEXT,
            nombres TEXT,
            apellido_paterno TEXT,
            apellido_materno TEXT,
            ci TEXT,
            password_reset_token TEXT
        )
    ''')
    
    # Create invitations table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS invitations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            token TEXT UNIQUE NOT NULL,
            used INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            last_sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            nombres TEXT,
            apellido_paterno TEXT,
            apellido_materno TEXT,
            ci TEXT
        )
    ''')
    
    # Auto-migration of columns for existing databases
    # Users table migrations
    cursor.execute("PRAGMA table_info(users)")
    user_cols = [col[1] for col in cursor.fetchall()]
    new_user_cols = {
        'nombres': 'TEXT',
        'apellido_paterno': 'TEXT',
        'apellido_materno': 'TEXT',
        'ci': 'TEXT',
        'password_reset_token': 'TEXT'
    }
    for col_name, col_type in new_user_cols.items():
        if col_name not in user_cols:
            cursor.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_type}")
            print(f"Added column {col_name} to table users")
            
    # Invitations table migrations
    cursor.execute("PRAGMA table_info(invitations)")
    invite_cols = [col[1] for col in cursor.fetchall()]
    new_invite_cols = {
        'nombres': 'TEXT',
        'apellido_paterno': 'TEXT',
        'apellido_materno': 'TEXT',
        'ci': 'TEXT'
    }
    for col_name, col_type in new_invite_cols.items():
        if col_name not in invite_cols:
            cursor.execute(f"ALTER TABLE invitations ADD COLUMN {col_name} {col_type}")
            print(f"Added column {col_name} to table invitations")
    
    # Create password_history table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS password_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            password_hash TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')
    
    # Create vault_items table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS vault_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT NOT NULL,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            url TEXT,
            notes TEXT,
            is_favorite INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
        )
    ''')
    
    # Create audit_logs table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT NOT NULL,
            details TEXT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
        )
    ''')
    
    # Create system_settings table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS system_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    ''')
    
    # Seed default settings
    cursor.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('idle_timeout_minutes', '15')")
    cursor.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('smtp_host', 'smtp.gmail.com')")
    cursor.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('smtp_port', '587')")
    cursor.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('smtp_user', '')")
    cursor.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('smtp_pass', '')")
    cursor.execute("INSERT OR IGNORE INTO system_settings (key, value) VALUES ('smtp_from', 'operaciones@fiscalia.gob.bo')")
    
    # Convert existing names and surnames to Title Case (database integrity migration)
    users = cursor.execute("SELECT id, nombres, apellido_paterno, apellido_materno FROM users").fetchall()
    for u in users:
        formatted_n = format_name_title_case(u['nombres'])
        formatted_p = format_name_title_case(u['apellido_paterno'])
        formatted_m = format_name_title_case(u['apellido_materno'])
        cursor.execute("UPDATE users SET nombres = ?, apellido_paterno = ?, apellido_materno = ? WHERE id = ?", (formatted_n, formatted_p, formatted_m, u['id']))
        
    invitations = cursor.execute("SELECT id, nombres, apellido_paterno, apellido_materno FROM invitations").fetchall()
    for i in invitations:
        formatted_n = format_name_title_case(i['nombres'])
        formatted_p = format_name_title_case(i['apellido_paterno'])
        formatted_m = format_name_title_case(i['apellido_materno'])
        cursor.execute("UPDATE invitations SET nombres = ?, apellido_paterno = ?, apellido_materno = ? WHERE id = ?", (formatted_n, formatted_p, formatted_m, i['id']))
    
    conn.commit()
    conn.close()
    print("Database initialized successfully.")

if __name__ == '__main__':
    init_db()
