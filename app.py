from flask import Flask, render_template, request, redirect, url_for, flash, session, send_file
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
import sqlite3
import hashlib
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-very-secret-key'  # Замени на свой секретный ключ
app.config['SESSION_COOKIE_SECURE'] = True  # Только HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Защита от XSS
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # Защита от CSRF

# Инициализация Talisman для заголовков безопасности
Talisman(app, force_https=True, strict_transport_security=True, session_cookie_secure=True)

# Инициализация Limiter для ограничения запросов (исправленный синтаксис)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def init_db():
    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (username TEXT PRIMARY KEY, password TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS user_products
                     (username TEXT, product TEXT, UNIQUE(username, product))''')
        conn.commit()
        print("База данных успешно инициализирована")
    except Exception as e:
        print(f"Ошибка при инициализации базы данных: {str(e)}")
    finally:
        conn.close()

# Инициализация базы данных при запуске
init_db()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/youtube')
def youtube():
    return render_template('youtube.html')

@app.route('/products', methods=['GET', 'POST'])
@limiter.limit("10 per minute")  # Ограничение: 10 запросов в минуту
def products():
    if 'username' not in session:
        flash('Пожалуйста, войдите в аккаунт!')
        print("Пользователь не авторизован, перенаправление на страницу входа")
        return redirect(url_for('login'))

    if request.method == 'POST':
        product = request.form.get('product')
        print(f"Получен POST-запрос: product={product}, username={session['username']}")

        if not product:
            flash('Ошибка: товар не выбран!')
            print("Товар не выбран в форме")
            return redirect(url_for('products'))

        if product != 'BOOST-PC':  # Ограничиваем покупку только BOOST-PC
            flash('Ошибка: этот товар недоступен!')
            print(f"Недопустимый товар: {product}")
            return redirect(url_for('products'))

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        try:
            c.execute('INSERT INTO user_products (username, product) VALUES (?, ?)',
                      (session['username'], product))
            conn.commit()
            flash(f'Товар {product} успешно куплен!')
            print(f"Товар {product} успешно добавлен для пользователя {session['username']}")
        except sqlite3.IntegrityError:
            flash(f'Товар {product} уже есть в вашем профиле!')
            print(f"Товар {product} уже существует для пользователя {session['username']}")
        except Exception as e:
            flash(f'Произошла ошибка при добавлении товара: {str(e)}')
            print(f"Ошибка при добавлении товара: {str(e)}")
        finally:
            conn.close()
        return redirect(url_for('account'))  # Перенаправляем в личный кабинет

    return render_template('products.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Ограничение: 5 запросов в минуту
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = hash_password(request.form.get('password'))
        print(f"Попытка входа: username={username}")
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
        user = c.fetchone()
        conn.close()
        if user:
            session['username'] = username
            flash('Вход выполнен успешно!')
            print(f"Вход успешен для пользователя {username}")
            return redirect(url_for('index'))
        else:
            flash('Неверное имя пользователя или пароль!')
            print("Неверное имя пользователя или пароль")
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")  # Ограничение: 5 запросов в минуту
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = hash_password(request.form.get('password'))
        print(f"Попытка регистрации: username={username}")
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
            conn.commit()
            flash('Регистрация прошла успешно! Теперь вы можете войти.')
            print(f"Регистрация успешна для пользователя {username}")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Имя пользователя уже занято!')
            print(f"Имя пользователя {username} уже занято")
        except Exception as e:
            flash(f'Произошла ошибка при регистрации: {str(e)}')
            print(f"Ошибка при регистрации: {str(e)}")
        finally:
            conn.close()
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    flash('Вы вышли из аккаунта!')
    print("Пользователь вышел из аккаунта")
    return redirect(url_for('index'))

@app.route('/account')
def account():
    if 'username' not in session:
        flash('Пожалуйста, войдите в аккаунт!')
        print("Пользователь не авторизован, перенаправление на страницу входа")
        return redirect(url_for('login'))
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT product FROM user_products WHERE username = ?', (session['username'],))
    products = [row[0] for row in c.fetchall()]
    conn.close()
    print(f"Товары пользователя {session['username']}: {products}")
    return render_template('account.html', products=products)

@app.route('/download/<product>')
def download(product):
    if 'username' not in session:
        flash('Пожалуйста, войдите в аккаунт!')
        print("Пользователь не авторизован, перенаправление на страницу входа")
        return redirect(url_for('login'))
    if product == 'BOOST-PC':
        file_path = 'static/files/boost-pc.exe'
    else:
        flash('Этот товар недоступен для скачивания!')
        print(f"Недопустимый товар для скачивания: {product}")
        return redirect(url_for('account'))

    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        flash('Файл не найден!')
        print(f"Файл не найден: {file_path}")
        return redirect(url_for('account'))

@app.route('/delete/<product>', methods=['POST'])
@limiter.limit("5 per minute")  # Ограничение: 5 запросов в минуту
def delete_product(product):
    if 'username' not in session:
        flash('Пожалуйста, войдите в аккаунт!')
        print("Пользователь не авторизован, перенаправление на страницу входа")
        return redirect(url_for('login'))

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT product FROM user_products WHERE username = ? AND product = ?',
              (session['username'], product))
    if not c.fetchone():
        conn.close()
        flash('У вас нет этого товара!')
        print(f"Товар {product} не найден у пользователя {session['username']}")
        return redirect(url_for('account'))

    password = hash_password(request.form.get('password'))
    c.execute('SELECT password FROM users WHERE username = ?', (session['username'],))
    user_password = c.fetchone()[0]
    if password == user_password:
        c.execute('DELETE FROM user_products WHERE username = ? AND product = ?',
                  (session['username'], product))
        conn.commit()
        flash(f'Товар {product} успешно удалён!')
        print(f"Товар {product} удалён для пользователя {session['username']}")
    else:
        flash('Неверный пароль!')
        print("Неверный пароль при попытке удаления товара")
    conn.close()
    return redirect(url_for('account'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)