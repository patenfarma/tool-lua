#!/usr/bin/env python3
# ══════════════════════════════════════════════════════════════════════════
#  KAPTEN 012 — AUTH SERVER DENGAN ENKRIPSI AES-256
#  Untuk mengelola autentikasi, user management, dan key distribution
# ══════════════════════════════════════════════════════════════════════════

import os
import sys
import json
import hashlib
import hmac
import time
import uuid
import sqlite3
import logging
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Tuple, Optional
from functools import wraps
from threading import Lock

# ──────────────────────────────────────────────────────────────────────────
#  ENCRYPTION MODULES
# ──────────────────────────────────────────────────────────────────────────
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("[ERROR] cryptography tidak terinstall!")
    print("Install: pip install cryptography")
    sys.exit(1)

try:
    from flask import Flask, request, jsonify
    from flask_cors import CORS
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
except ImportError:
    print("[ERROR] Flask dependencies tidak lengkap!")
    print("Install: pip install flask flask-cors flask-limiter")
    sys.exit(1)

# ──────────────────────────────────────────────────────────────────────────
#  LOGGING SETUP
# ──────────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('auth_server.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ──────────────────────────────────────────────────────────────────────────
#  ENCRYPTION UTILITY CLASS
# ──────────────────────────────────────────────────────────────────────────
class EncryptionManager:
    """
    Manage AES-256 encryption untuk data sensitif
    """
    def __init__(self, master_password: str = None):
        self.master_password = master_password or os.environ.get('AUTH_MASTER_PASSWORD', 'KAPTEN_012_DEFAULT')
        self.salt = os.environ.get('AUTH_SALT', 'kapten_012_salt_key').encode()
        self._key = self._derive_key()
        self.cipher_suite = Fernet(self._key)

    def _derive_key(self) -> bytes:
        """Derive encryption key dari master password"""
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(self.master_password.encode())
        return Fernet.generate_key() if not key else Fernet._URLSafeBase64._urlsafe_b64encode(key + b'\x00' * 8)

    def encrypt(self, data: str) -> str:
        """Encrypt data ke string"""
        try:
            encrypted = self.cipher_suite.encrypt(data.encode())
            return encrypted.decode()
        except Exception as e:
            logger.error(f"Encryption error: {e}")
            return None

    def decrypt(self, encrypted_data: str) -> str:
        """Decrypt data dari string"""
        try:
            decrypted = self.cipher_suite.decrypt(encrypted_data.encode())
            return decrypted.decode()
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            return None

    def hash_password(self, password: str) -> str:
        """Hash password dengan PBKDF2"""
        salt = os.urandom(32)
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        return (salt + key).hex()

    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password dengan hashed"""
        try:
            salt = bytes.fromhex(hashed[:64])
            stored_key = bytes.fromhex(hashed[64:])
            kdf = PBKDF2(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = kdf.derive(password.encode())
            return key == stored_key
        except Exception as e:
            logger.error(f"Password verification error: {e}")
            return False

    def generate_token(self, data: dict, expiry_hours: int = 24) -> str:
        """Generate JWT-like token dengan expiry"""
        payload = {
            'data': data,
            'issued_at': time.time(),
            'expires_at': time.time() + (expiry_hours * 3600)
        }
        token_json = json.dumps(payload)
        return self.encrypt(token_json)

    def verify_token(self, token: str) -> Optional[dict]:
        """Verify token dan extract data"""
        try:
            decrypted = self.decrypt(token)
            if not decrypted:
                return None
            payload = json.loads(decrypted)
            if time.time() > payload.get('expires_at', 0):
                logger.warning("Token expired")
                return None
            return payload.get('data')
        except Exception as e:
            logger.error(f"Token verification error: {e}")
            return None

# ──────────────────────────────────────────────────────────────────────────
#  DATABASE MANAGER
# ──────────────────────────────────────────────────────────────────────────
class DatabaseManager:
    """
    SQLite database untuk user, device, dan session tracking
    """
    def __init__(self, db_path: str = 'auth_database.db'):
        self.db_path = db_path
        self.lock = Lock()
        self._init_db()

    def _init_db(self):
        """Initialize database dengan schema"""
        with self.lock:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # Users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    email TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1
                )
            ''')

            # Devices table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS devices (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    device_id TEXT NOT NULL UNIQUE,
                    device_name TEXT,
                    device_key TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_seen TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
            ''')

            # License keys table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS license_keys (
                    id TEXT PRIMARY KEY,
                    device_id TEXT NOT NULL UNIQUE,
                    key TEXT NOT NULL,
                    expiry_date DATE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1,
                    FOREIGN KEY(device_id) REFERENCES devices(id)
                )
            ''')

            # Session tracking
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    device_id TEXT,
                    token TEXT,
                    login_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    logout_at TIMESTAMP,
                    ip_address TEXT,
                    user_agent TEXT,
                    is_active BOOLEAN DEFAULT 1,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
            ''')

            # Login attempts (anti brute force)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS login_attempts (
                    id TEXT PRIMARY KEY,
                    username TEXT NOT NULL,
                    ip_address TEXT,
                    success BOOLEAN,
                    attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')

            conn.commit()
            conn.close()
            logger.info("Database initialized")

    def execute(self, query: str, params: tuple = (), fetch: str = None):
        """Execute database query"""
        with self.lock:
            try:
                conn = sqlite3.connect(self.db_path)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute(query, params)
                
                if fetch == 'one':
                    result = cursor.fetchone()
                elif fetch == 'all':
                    result = cursor.fetchall()
                else:
                    result = None
                
                conn.commit()
                conn.close()
                return result
            except Exception as e:
                logger.error(f"Database error: {e}")
                return None

    def create_user(self, username: str, password: str, email: str = None) -> Tuple[bool, str]:
        """Create user baru"""
        try:
            user_id = str(uuid.uuid4())
            enc = EncryptionManager()
            password_hash = enc.hash_password(password)
            
            self.execute(
                'INSERT INTO users (id, username, password_hash, email) VALUES (?, ?, ?, ?)',
                (user_id, username, password_hash, email)
            )
            logger.info(f"User created: {username}")
            return True, user_id
        except Exception as e:
            logger.error(f"Create user error: {e}")
            return False, str(e)

    def verify_user(self, username: str, password: str) -> Tuple[bool, Optional[str]]:
        """Verify username & password"""
        try:
            user = self.execute(
                'SELECT id, password_hash FROM users WHERE username = ? AND is_active = 1',
                (username,),
                fetch='one'
            )
            if not user:
                return False, None
            
            enc = EncryptionManager()
            if enc.verify_password(password, user['password_hash']):
                return True, user['id']
            return False, None
        except Exception as e:
            logger.error(f"Verify user error: {e}")
            return False, None

    def register_device(self, user_id: str, device_id: str, device_name: str = None) -> Tuple[bool, str]:
        """Register device baru untuk user"""
        try:
            device_record_id = str(uuid.uuid4())
            enc = EncryptionManager()
            device_key = enc.encrypt(device_id)
            
            self.execute(
                'INSERT INTO devices (id, user_id, device_id, device_name, device_key) VALUES (?, ?, ?, ?, ?)',
                (device_record_id, user_id, device_id, device_name, device_key)
            )
            logger.info(f"Device registered: {device_id} for user {user_id}")
            return True, device_record_id
        except Exception as e:
            logger.error(f"Register device error: {e}")
            return False, str(e)

    def create_license_key(self, device_id: str, expiry_days: int = 365) -> Tuple[bool, str]:
        """Generate license key untuk device"""
        try:
            key_id = str(uuid.uuid4())
            enc = EncryptionManager()
            
            # Generate unique key
            key_data = f"{device_id}:{uuid.uuid4().hex}:{int(time.time())}"
            encrypted_key = enc.encrypt(key_data)
            
            expiry_date = (datetime.now() + timedelta(days=expiry_days)).strftime('%Y-%m-%d')
            
            self.execute(
                'INSERT INTO license_keys (id, device_id, key, expiry_date) VALUES (?, ?, ?, ?)',
                (key_id, device_id, encrypted_key, expiry_date)
            )
            logger.info(f"License key created for device {device_id}")
            return True, encrypted_key
        except Exception as e:
            logger.error(f"Create license key error: {e}")
            return False, str(e)

    def verify_license_key(self, device_id: str, key: str) -> Tuple[bool, str]:
        """Verify license key"""
        try:
            license_record = self.execute(
                'SELECT key, expiry_date, is_active FROM license_keys WHERE device_id = ?',
                (device_id,),
                fetch='one'
            )
            if not license_record or not license_record['is_active']:
                return False, "License tidak ditemukan atau tidak aktif"
            
            # Check expiry
            expiry_date = datetime.strptime(license_record['expiry_date'], '%Y-%m-%d')
            if datetime.now() > expiry_date:
                return False, "License telah expired"
            
            if license_record['key'] == key:
                return True, "License valid"
            return False, "License key tidak cocok"
        except Exception as e:
            logger.error(f"Verify license key error: {e}")
            return False, str(e)

    def log_login_attempt(self, username: str, ip_address: str, success: bool):
        """Log login attempt untuk tracking"""
        try:
            attempt_id = str(uuid.uuid4())
            self.execute(
                'INSERT INTO login_attempts (id, username, ip_address, success) VALUES (?, ?, ?, ?)',
                (attempt_id, username, ip_address, success)
            )
            logger.info(f"Login attempt: {username} from {ip_address} - {'SUCCESS' if success else 'FAILED'}")
        except Exception as e:
            logger.error(f"Log login attempt error: {e}")

    def check_brute_force(self, ip_address: str, max_attempts: int = 5, window_minutes: int = 15) -> bool:
        """Check untuk brute force attacks"""
        try:
            time_window = datetime.now() - timedelta(minutes=window_minutes)
            attempts = self.execute(
                'SELECT COUNT(*) as count FROM login_attempts WHERE ip_address = ? AND success = 0 AND attempted_at > ?',
                (ip_address, time_window),
                fetch='one'
            )
            return attempts['count'] >= max_attempts
        except Exception as e:
            logger.error(f"Check brute force error: {e}")
            return False

    def create_session(self, user_id: str, device_id: str, token: str, ip_address: str, user_agent: str) -> Tuple[bool, str]:
        """Create session baru"""
        try:
            session_id = str(uuid.uuid4())
            self.execute(
                'INSERT INTO sessions (id, user_id, device_id, token, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?)',
                (session_id, user_id, device_id, token, ip_address, user_agent)
            )
            logger.info(f"Session created for user {user_id} on device {device_id}")
            return True, session_id
        except Exception as e:
            logger.error(f"Create session error: {e}")
            return False, str(e)

# ──────────────────────────────────────────────────────────────────────────
#  FLASK APP
# ──────────────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.config['JSON_SORT_KEYS'] = False

CORS(app)
limiter = Limiter(app=app, key_func=get_remote_address)

db = DatabaseManager()
enc = EncryptionManager()

# ──────────────────────────────────────────────────────────────────────────
#  API ENDPOINTS
# ──────────────────────────────────────────────────────────────────────────

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'ok',
        'timestamp': datetime.now().isoformat(),
        'version': '1.0.0'
    }), 200

@app.route('/api/auth/register', methods=['POST'])
@limiter.limit("5 per hour")
def register():
    """Register user baru"""
    try:
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        email = data.get('email', '').strip()

        if not username or len(username) < 3:
            return jsonify({'status': 'error', 'message': 'Username minimal 3 karakter'}), 400
        if not password or len(password) < 6:
            return jsonify({'status': 'error', 'message': 'Password minimal 6 karakter'}), 400

        success, result = db.create_user(username, password, email)
        if success:
            return jsonify({
                'status': 'success',
                'message': 'User berhasil dibuat',
                'user_id': result
            }), 201
        else:
            return jsonify({'status': 'error', 'message': result}), 400

    except Exception as e:
        logger.error(f"Register error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("10 per hour")
def login():
    """Login user dan generate token"""
    try:
        ip_address = request.remote_addr
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        device_id = data.get('device_id', '').strip()
        device_name = data.get('device_name', 'Unknown')

        # Check brute force
        if db.check_brute_force(ip_address):
            db.log_login_attempt(username, ip_address, False)
            return jsonify({
                'status': 'error',
                'message': 'Terlalu banyak percobaan login gagal. Coba lagi nanti.'
            }), 429

        # Verify user
        success, user_id = db.verify_user(username, password)
        if not success:
            db.log_login_attempt(username, ip_address, False)
            return jsonify({'status': 'error', 'message': 'Username atau password salah'}), 401

        db.log_login_attempt(username, ip_address, True)

        # Register device jika belum ada
        if device_id:
            device_ok, device_record_id = db.register_device(user_id, device_id, device_name)
        else:
            device_record_id = None

        # Generate token
        token = enc.generate_token({
            'user_id': user_id,
            'username': username,
            'device_id': device_id
        }, expiry_hours=24)

        # Create session
        user_agent = request.headers.get('User-Agent', 'Unknown')
        db.create_session(user_id, device_id, token, ip_address, user_agent)

        return jsonify({
            'status': 'success',
            'message': 'Login berhasil',
            'token': token,
            'user_id': user_id,
            'username': username,
            'device_id': device_id,
            'expires_in': 86400
        }), 200

    except Exception as e:
        logger.error(f"Login error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/auth/verify-token', methods=['POST'])
def verify_token():
    """Verify token"""
    try:
        data = request.get_json()
        token = data.get('token', '').strip()

        if not token:
            return jsonify({'status': 'error', 'message': 'Token diperlukan'}), 400

        payload = enc.verify_token(token)
        if payload:
            return jsonify({
                'status': 'success',
                'message': 'Token valid',
                'data': payload
            }), 200
        else:
            return jsonify({'status': 'error', 'message': 'Token invalid atau expired'}), 401

    except Exception as e:
        logger.error(f"Verify token error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/device/register', methods=['POST'])
def register_device_endpoint():
    """Register device dengan user authentication"""
    try:
        data = request.get_json()
        user_id = data.get('user_id', '').strip()
        device_id = data.get('device_id', '').strip()
        device_name = data.get('device_name', 'Unknown')

        if not user_id or not device_id:
            return jsonify({'status': 'error', 'message': 'user_id dan device_id diperlukan'}), 400

        success, device_record_id = db.register_device(user_id, device_id, device_name)
        if success:
            # Generate license key
            key_success, license_key = db.create_license_key(device_id, expiry_days=365)
            if key_success:
                return jsonify({
                    'status': 'success',
                    'message': 'Device berhasil didaftarkan',
                    'device_record_id': device_record_id,
                    'license_key': license_key
                }), 201
            else:
                return jsonify({'status': 'error', 'message': license_key}), 400
        else:
            return jsonify({'status': 'error', 'message': device_record_id}), 400

    except Exception as e:
        logger.error(f"Register device error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/license/verify', methods=['POST'])
def verify_license():
    """Verify license key untuk device"""
    try:
        data = request.get_json()
        device_id = data.get('device_id', '').strip()
        key = data.get('key', '').strip()

        if not device_id or not key:
            return jsonify({'status': 'error', 'message': 'device_id dan key diperlukan'}), 400

        success, message = db.verify_license_key(device_id, key)
        if success:
            return jsonify({
                'status': 'success',
                'message': message,
                'valid': True
            }), 200
        else:
            return jsonify({
                'status': 'error',
                'message': message,
                'valid': False
            }), 401

    except Exception as e:
        logger.error(f"Verify license error: {e}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.errorhandler(429)
def rate_limit_handler(e):
    """Handle rate limit error"""
    return jsonify({
        'status': 'error',
        'message': 'Terlalu banyak request. Coba lagi nanti.'
    }), 429

@app.errorhandler(404)
def not_found(e):
    """Handle 404"""
    return jsonify({
        'status': 'error',
        'message': 'Endpoint tidak ditemukan'
    }), 404

@app.errorhandler(500)
def internal_error(e):
    """Handle 500"""
    logger.error(f"Internal error: {e}")
    return jsonify({
        'status': 'error',
        'message': 'Internal server error'
    }), 500

# ──────────────────────────────────────────────────────────────────────────
#  CLI SETUP
# ──────────────────────────────────────────────────────────────────────────
def cli_setup():
    """CLI untuk setup awal"""
    print("\n" + "="*60)
    print("  KAPTEN 012 — AUTH SERVER SETUP")
    print("="*60 + "\n")

    # Create admin user
    print("[1] Buat Admin User")
    username = input("  Username » ").strip()
    password = input("  Password » ").strip()
    email = input("  Email » ").strip()

    success, result = db.create_user(username, password, email)
    if success:
        print(f"\n  ✅ Admin user '{username}' berhasil dibuat!")
        print(f"  User ID: {result}\n")
    else:
        print(f"\n  ❌ Error: {result}\n")

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='KAPTEN 012 Auth Server')
    parser.add_argument('--setup', action='store_true', help='Run setup wizard')
    parser.add_argument('--host', default='0.0.0.0', help='Server host')
    parser.add_argument('--port', type=int, default=5000, help='Server port')
    parser.add_argument('--debug', action='store_true', help='Debug mode')

    args = parser.parse_args()

    if args.setup:
        cli_setup()
    else:
        logger.info(f"Starting Auth Server on {args.host}:{args.port}")
        app.run(host=args.host, port=args.port, debug=args.debug)
