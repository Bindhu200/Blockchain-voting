import sqlite3
import os
import base64
import time
import hashlib
import jwt
from flask import Flask, render_template, request, redirect, url_for, session, flash
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# ==================== Database Setup ====================
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users 
                 (username TEXT UNIQUE, password TEXT)''')
    conn.commit()
    conn.close()

init_db()  # Creates the database if it doesn't exist

# ==================== Password Hashing ====================
def hash_password(password):
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(salt + key).decode('utf-8')

def verify_password(stored_password, provided_password):
    stored = base64.urlsafe_b64decode(stored_password.encode('utf-8'))
    salt = stored[:16]
    stored_key = stored[16:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(provided_password.encode())
    return key == stored_key

# ==================== JWT Authentication ====================
SECRET_KEY = 'change_this_to_a_strong_random_secret_key_2026'  # CHANGE THIS!

def generate_token(username):
    return jwt.encode({'username': username}, SECRET_KEY, algorithm='HS256')

def verify_token(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
    except:
        return None

# ==================== Blockchain Simulation ====================
class Block:
    def __init__(self, index, previous_hash, timestamp, data, hash):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.data = data
        self.hash = hash

def calculate_hash(index, previous_hash, timestamp, data):
    value = str(index) + str(previous_hash) + str(timestamp) + str(data)
    return hashlib.sha256(value.encode()).hexdigest()

class Blockchain:
    def __init__(self):
        self.chain = [self.create_genesis_block()]

    def create_genesis_block(self):
        return Block(0, "0", time.time(), "Genesis Block", calculate_hash(0, "0", time.time(), "Genesis Block"))

    def add_block(self, data):
        previous_block = self.chain[-1]
        new_index = previous_block.index + 1
        new_timestamp = time.time()
        new_hash = calculate_hash(new_index, previous_block.hash, new_timestamp, data)
        new_block = Block(new_index, previous_block.hash, new_timestamp, data, new_hash)
        self.chain.append(new_block)

    def is_valid(self):
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]
            if current.hash != calculate_hash(current.index, previous.hash, current.timestamp, current.data):
                return False
            if current.previous_hash != previous.hash:
                return False
        return True

# ==================== Flask App Setup ====================
app = Flask(__name__)
app.secret_key = 'super_strong_secret_key_for_session_2026'  # CHANGE THIS TOO
blockchain = Blockchain()

# ==================== Helper Functions ====================
def get_vote_counts():
    counts = {}
    for block in blockchain.chain[1:]:  # Skip genesis block
        if "Vote for" in block.data:
            parts = block.data.split("Vote for ")
            if len(parts) > 1:
                candidate_part = parts[1].split(" by ")[0]
                counts[candidate_part] = counts.get(candidate_part, 0) + 1
    return counts

def has_voted(username):
    for block in blockchain.chain[1:]:
        if username in block.data and "Vote for" in block.data:
            return True
    return False

# ==================== Routes ====================

@app.route('/')
def index():
    return render_template('index.html')  # Clean welcome page only

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if not username or not password:
            return "Please fill all fields"
        
        hashed_pw = hash_password(password)
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        try:
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_pw))
            conn.commit()
            flash("Registration successful! Please login.")
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            return "Username already taken!"
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT password FROM users WHERE username=?", (username,))
        stored = c.fetchone()
        conn.close()
        
        if stored and verify_password(stored[0], password):
            session['token'] = generate_token(username)
            flash("Login successful!")
            return redirect(url_for('dashboard'))
        else:
            return "Invalid username or password"
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if 'token' not in session or not verify_token(session['token']):
        return redirect(url_for('login'))
    
    user_data = verify_token(session['token'])
    username = user_data['username']
    counts = get_vote_counts()
    voted = has_voted(username)
    
    return render_template('dashboard.html', 
                         username=username, 
                         counts=counts, 
                         voted=voted, 
                         is_valid=blockchain.is_valid())

@app.route('/vote', methods=['GET', 'POST'])
def vote():
    if 'token' not in session or not verify_token(session['token']):
        return redirect(url_for('login'))
    
    user_data = verify_token(session['token'])
    username = user_data['username']
    
    if has_voted(username):
        flash("You have already voted. One vote per person.")
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        candidate = request.form['candidate']
        if candidate:
            blockchain.add_block(f"Vote for {candidate} by {username}")
            flash("Your vote has been recorded successfully!")
            return redirect(url_for('dashboard'))
    
    return render_template('vote.html')

@app.route('/logout')
def logout():
    session.pop('token', None)
    flash("You have been logged out.")
    return redirect(url_for('index'))

# ==================== Run App ====================
if __name__ == '__main__':
    app.run(debug=True)