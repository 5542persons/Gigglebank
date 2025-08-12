from flask import Flask, render_template, request, redirect, session, abort
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'supersecretkey'

THRESHOLD = 500  # Amount limit before requiring admin approval

def get_db_connection():
    conn = sqlite3.connect('gigglebux.db')
    conn.row_factory = sqlite3.Row
    return conn

def is_admin_user(username):
    if not username:
        return False
    conn = get_db_connection()
    row = conn.execute("SELECT is_admin FROM users WHERE username = ?", (username,)).fetchone()
    conn.close()
    return bool(row and row['is_admin'] == 1)

@app.route('/')
def dashboard():
    if 'username' not in session:
        return redirect('/login')
    conn = get_db_connection()
    users = conn.execute('SELECT * FROM users').fetchall()
    conn.close()
    return render_template('dashboard.html', users=users, username=session['username'])

@app.route('/send', methods=['POST'])
def send():
    if 'username' not in session:
        return redirect('/login')
    
    sender = session['username']
    receiver = request.form.get('receiver')
    amount_str = request.form.get('amount')
    password = request.form.get('password')  # you were missing this!

    # Validate amount input
    if not amount_str or not amount_str.isdigit():
        return "Invalid amount."

    amount = int(amount_str)
    
    if not receiver:
        return "Receiver username is required."

    if receiver == sender:
        return "You cannot send Gigglebux to yourself."

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE username = ?', (sender,)).fetchone()
    if not user:
        conn.close()
        return "Sender not found."

    # Check password from form input, not session
    if not password or not check_password_hash(user['password_hash'], password):
        conn.close()
        return "Authorization failed: Incorrect password."

    # Check sender balance for sufficient funds
    if user['balance'] < amount:
        conn.close()
        return "Insufficient balance."

    # Check if receiver exists
    receiver_user = conn.execute('SELECT * FROM users WHERE username = ?', (receiver,)).fetchone()
    if not receiver_user:
        conn.close()
        return "Receiver not found."

    if amount <= THRESHOLD:
        # Auto-approved transaction
        cur = conn.cursor()
        cur.execute('UPDATE users SET balance = balance - ? WHERE username = ?', (amount, sender))
        cur.execute('UPDATE users SET balance = balance + ? WHERE username = ?', (amount, receiver))
        cur.execute('INSERT INTO transactions (sender, receiver, amount, timestamp) VALUES (?, ?, ?, ?)',
                    (sender, receiver, amount, datetime.now()))
        conn.commit()
    else:
        # Needs admin approval: add to pending_transactions
        conn.execute('INSERT INTO pending_transactions (sender, receiver, amount, timestamp, status) VALUES (?, ?, ?, ?, ?)',
                     (sender, receiver, amount, datetime.now(), 'pending'))
        conn.commit()

    conn.close()
    return redirect('/')

@app.route("/admin")
def admin_dashboard():
    if "username" not in session:
        return redirect("/login")
    username = session['username']
    if not is_admin_user(username):
        return f"Access denied for user {username}"

    conn = sqlite3.connect("gigglebux.db")
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM pending_transactions")
    pending_transactions = cur.fetchall()
    conn.close()

    return render_template("admin_dashboard.html", pending_transactions=pending_transactions)

@app.route('/approve_transaction', methods=['POST'])
def approve_transaction():
    if 'username' not in session:
        return redirect('/login')
    if not is_admin_user(session['username']):
        return abort(403)  # Forbidden

    tx_id = request.form.get('tx_id')
    if not tx_id:
        return "Transaction ID missing.", 400

    conn = get_db_connection()
    tx = conn.execute('SELECT * FROM pending_transactions WHERE id = ?', (tx_id,)).fetchone()
    if not tx or tx['status'] != 'pending':
        conn.close()
        return "Transaction not found or already processed.", 404

    sender = tx['sender']
    receiver = tx['receiver']
    amount = tx['amount']

    # Check sender balance
    sender_data = conn.execute('SELECT balance FROM users WHERE username = ?', (sender,)).fetchone()
    if not sender_data or sender_data['balance'] < amount:
        conn.execute('UPDATE pending_transactions SET status = "rejected" WHERE id = ?', (tx_id,))
        conn.commit()
        conn.close()
        return "Sender does not have enough balance. Transaction rejected.", 400

    # Perform transaction
    cur = conn.cursor()
    cur.execute('UPDATE users SET balance = balance - ? WHERE username = ?', (amount, sender))
    cur.execute('UPDATE users SET balance = balance + ? WHERE username = ?', (amount, receiver))
    cur.execute('INSERT INTO transactions (sender, receiver, amount, timestamp) VALUES (?, ?, ?, datetime("now"))',
                (sender, receiver, amount))
    cur.execute('UPDATE pending_transactions SET status = "approved" WHERE id = ?', (tx_id,))
    conn.commit()
    conn.close()

    return redirect('/admin')

@app.route('/reject_transaction', methods=['POST'])
def reject_transaction():
    if 'username' not in session:
        return redirect('/login')
    if not is_admin_user(session['username']):
        return abort(403)

    tx_id = request.form.get('tx_id')
    if not tx_id:
        return "Transaction ID missing.", 400

    conn = get_db_connection()
    tx = conn.execute('SELECT * FROM pending_transactions WHERE id = ?', (tx_id,)).fetchone()
    if not tx or tx['status'] != 'pending':
        conn.close()
        return "Transaction not found or already processed.", 404

    conn.execute('UPDATE pending_transactions SET status = "rejected" WHERE id = ?', (tx_id,))
    conn.commit()
    conn.close()

    return redirect('/admin')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_hash = generate_password_hash(password)
        conn = get_db_connection()
        try:
            conn.execute('INSERT INTO users (username, password_hash, balance) VALUES (?, ?, ?)', 
                         (username, password_hash, 1000))
            conn.commit()
        except sqlite3.IntegrityError:
            return 'Username already exists.'
        finally:
            conn.close()
        return redirect('/login')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user['password_hash'], password):
            session['username'] = username
            return redirect('/')
        else:
            return 'Invalid credentials'
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect('/login')

conn = sqlite3.connect('gigglebux.db')
conn.row_factory = sqlite3.Row

rows = conn.execute("SELECT username, is_admin FROM users").fetchall()
for row in rows:
    print(f"{row['username']}: is_admin = {row['is_admin']}")

if __name__ == '__main__':
    app.run(debug=True)
