import sqlite3

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    # Таблица пользователей
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )''')
    # Таблица покупок
    c.execute('''CREATE TABLE IF NOT EXISTS purchases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        product TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users (id)
    )''')
    conn.commit()
    conn.close()

def add_user(username, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, password))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def check_user(username, password):
    from passlib.hash import pbkdf2_sha256
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT password FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()
    if result and pbkdf2_sha256.verify(password, result[0]):
        return True
    return False

def get_user_id(username):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    result = c.fetchone()
    conn.close()
    return result[0] if result else None

def add_purchase(user_id, product):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("INSERT INTO purchases (user_id, product) VALUES (?, ?)", (user_id, product))
    conn.commit()
    conn.close()

def get_purchases(user_id):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT product FROM purchases WHERE user_id = ?", (user_id,))
    purchases = [row[0] for row in c.fetchall()]
    conn.close()
    return purchases