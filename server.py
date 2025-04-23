"""Flask server providing secure user registration and JWT authentication."""

import os
import uuid
import base64
import sqlite3
import datetime

from flask import Flask, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from argon2 import PasswordHasher, exceptions
import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = Flask(__name__)

# --- Flask-Limiter Configuration ---
# Limit requests based on client IP to prevent abuse
limiter = Limiter(get_remote_address, app=app)

DB_FILE = "totally_not_my_privateKeys.db"  # SQLite database file
AES_KEY = base64.b64decode(os.environ.get("NOT_MY_KEY", "").encode())
assert len(AES_KEY) == 32, "NOT_MY_KEY must be 32 bytes after base64 decoding!"

ph = PasswordHasher()  # For secure password hashing (Argon2)

# --- AES Utility Functions ---
def aes_encrypt(data: bytes) -> bytes:
    """Encrypt data using AES in CFB mode."""
    iv = os.urandom(16)  # Initialization vector
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CFB(iv))
    encryptor = cipher.encryptor()
    return iv + encryptor.update(data) + encryptor.finalize()

def aes_decrypt(data: bytes) -> bytes:
    """Decrypt AES encrypted data."""
    iv = data[:16]
    cipher = Cipher(algorithms.AES(AES_KEY), modes.CFB(iv))
    decryptor = cipher.decryptor()
    return decryptor.update(data[16:]) + decryptor.finalize()

# --- DB Functions ---
def initialize_db():
    """Initialize the database by creating required tables."""
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)  # Start fresh if DB exists
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    # Create table for private keys
    c.execute('''CREATE TABLE IF NOT EXISTS keys (
                    kid INTEGER PRIMARY KEY AUTOINCREMENT,
                    key BLOB NOT NULL,
                    exp INTEGER NOT NULL)''')
    # Create table for users
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    email TEXT UNIQUE,
                    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP)''')
    # Create table for authentication logs
    c.execute('''CREATE TABLE IF NOT EXISTS auth_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_ip TEXT NOT NULL,
                    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    user_id INTEGER,
                    FOREIGN KEY(user_id) REFERENCES users(id))''')
    conn.commit()
    conn.close()

def save_private_key(private_key, exp):
    """Save a private key into the database, encrypted with AES."""
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    encrypted_pem = aes_encrypt(pem)  # Encrypt before storing
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('INSERT INTO keys (key, exp) VALUES (?, ?)', (encrypted_pem, exp))
    conn.commit()
    conn.close()

def generate_keys():
    """Generate one valid and one expired RSA private key."""
    valid = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    expired = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    save_private_key(valid, now + 3600)    # Expires in 1 hour
    save_private_key(expired, now - 3600)  # Expired 1 hour ago

def fetch_private_key(expired=False):
    """Fetch the most recent valid or expired private key from the database."""
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    if expired:
        c.execute('SELECT kid, key FROM keys WHERE exp < ? ORDER BY exp DESC LIMIT 1', (now,))
    else:
        c.execute('SELECT kid, key FROM keys WHERE exp > ? ORDER BY exp ASC LIMIT 1', (now,))
    row = c.fetchone()
    conn.close()
    if row:
        kid, enc_key = row
        private_key = serialization.load_pem_private_key(aes_decrypt(enc_key), password=None)
        return kid, private_key
    return None, None

# --- Flask Endpoints ---
@app.route('/register', methods=['POST'])
def register():
    """Register a new user with a random password."""
    data = request.get_json()
    username = data.get('username')
    email = data.get('email')
    password = str(uuid.uuid4())  # Generate random password
    password_hash = ph.hash(password)

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)',
                  (username, password_hash, email))
        conn.commit()
    except sqlite3.IntegrityError:
        # Username or email already exists
        return jsonify({'error': 'Username or email already exists'}), 400
    finally:
        conn.close()

    return jsonify({'password': password}), 201  # Return generated password

@app.route('/auth', methods=['POST'])
@limiter.limit("10/second")  # Rate limiting to 10 requests per second
def authenticate():
    """Authenticate user and return a signed JWT."""
    client_ip = request.remote_addr

    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('SELECT id, password_hash FROM users WHERE username = ?', (username,))
    row = c.fetchone()

    if not row:
        conn.close()
        return jsonify({'error': 'Invalid username or password'}), 401

    user_id, password_hash = row
    try:
        ph.verify(password_hash, password)  # Verify hashed password
    except exceptions.VerifyMismatchError:
        conn.close()
        return jsonify({'error': 'Invalid username or password'}), 401

    kid, private_key = fetch_private_key(
        expired=request.args.get('expired', 'false').lower() == 'true'
    )
    if not private_key:
        return jsonify({'message': 'No valid signing key'}), 500

    now = datetime.datetime.now(datetime.timezone.utc)
    payload = {
        'sub': username,
        'iat': now,
        'exp': now + datetime.timedelta(minutes=30)  # Token expires in 30 minutes
    }
    token = jwt.encode(payload, private_key, algorithm='RS256', headers={'kid': str(kid)})

    # Log successful authentication attempt
    c.execute('INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)',
              (client_ip, user_id))
    conn.commit()
    conn.close()

    return jsonify({'token': token})

@app.route('/.well-known/jwks.json', methods=['GET'])
def get_jwks():
    """Expose public keys in JWKS format."""
    keys = []
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    now = int(datetime.datetime.now(datetime.timezone.utc).timestamp())
    c.execute('SELECT kid, key FROM keys WHERE exp > ?', (now,))
    rows = c.fetchall()
    conn.close()
    for kid, enc_key in rows:
        private_key = serialization.load_pem_private_key(aes_decrypt(enc_key), password=None)
        public_key = private_key.public_key()
        public_numbers = public_key.public_numbers()
        # Prepare modulus (n) and exponent (e) for JWKS
        e = base64.urlsafe_b64encode(
            public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, byteorder='big')
        ).decode('utf-8').rstrip("=")
        n = base64.urlsafe_b64encode(
            public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, byteorder='big')
        ).decode('utf-8').rstrip("=")
        keys.append({
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": str(kid),
            "n": n,
            "e": e
        })
    return jsonify({"keys": keys})

# --- Main ---
if __name__ == '__main__':
    initialize_db()  # Reset and create new database tables
    generate_keys()  # Create initial signing keys
    app.run(port=8080, debug=True)  # Start Flask server
