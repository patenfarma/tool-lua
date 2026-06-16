#!/usr/bin/env python3
# ══════════════════════════════════════════════════════════════════════════
#  KAPTEN 012 — AUTH CLIENT LIBRARY (UNTUK v3.py)
#  Integrasi authentication dengan enkripsi ke tools Python Anda
# ══════════════════════════════════════════════════════════════════════════

import os
import sys
import json
import time
import uuid
import requests
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Tuple, Optional

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("[ERROR] cryptography tidak terinstall!")
    print("Install: pip install cryptography")
    sys.exit(1)

# ──────────────────────────────────────────────────────────────────────────
#  KAPTEN AUTH CLIENT
# ──────────────────────────────────────────────────────────────────────────
class KaptenAuthClient:
    """
    Client untuk authenticate dengan Kapten 012 Auth Server
    
    Usage:
        client = KaptenAuthClient('http://localhost:5000')
        success, result = client.login('username', 'password', 'device_id')
        if success:
            token = result['token']
    """
    
    def __init__(self, server_url: str, cache_dir: str = None):
        """
        Initialize auth client
        
        Args:
            server_url: URL ke auth server (e.g., 'http://localhost:5000')
            cache_dir: Directory untuk menyimpan cache (default: ~/.kapten_auth)
        """
        self.server_url = server_url.rstrip('/')
        self.cache_dir = Path(cache_dir or os.path.expanduser('~/.kapten_auth'))
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self.token_file = self.cache_dir / 'token.encrypted'
        self.session_file = self.cache_dir / 'session.json'
        
        self.current_token = None
        self.current_user = None
        self.current_device_id = None
        self._load_cached_token()

    def _get_encryption_key(self) -> bytes:
        """Derive encryption key untuk local token cache"""
        master_key = os.environ.get('KAPTEN_CLIENT_KEY', 'kapten_012_client').encode()
        salt = os.environ.get('KAPTEN_CLIENT_SALT', 'kapten_salt').encode()
        
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(master_key)
        return Fernet.generate_key() if not key else Fernet._URLSafeBase64._urlsafe_b64encode(key + b'\x00' * 8)

    def _encrypt_token(self, token: str) -> str:
        """Encrypt token untuk local storage"""
        try:
            key = self._get_encryption_key()
            cipher = Fernet(key)
            encrypted = cipher.encrypt(token.encode())
            return encrypted.decode()
        except Exception as e:
            print(f"[WARNING] Token encryption failed: {e}")
            return None

    def _decrypt_token(self, encrypted_token: str) -> Optional[str]:
        """Decrypt token dari local storage"""
        try:
            key = self._get_encryption_key()
            cipher = Fernet(key)
            decrypted = cipher.decrypt(encrypted_token.encode())
            return decrypted.decode()
        except Exception as e:
            print(f"[WARNING] Token decryption failed: {e}")
            return None

    def _load_cached_token(self):
        """Load cached token jika ada"""
        try:
            if self.token_file.exists() and self.session_file.exists():
                encrypted_token = self.token_file.read_text().strip()
                token = self._decrypt_token(encrypted_token)
                
                if token:
                    session_data = json.loads(self.session_file.read_text())
                    if self._verify_token_locally(token, session_data):
                        self.current_token = token
                        self.current_user = session_data.get('username')
                        self.current_device_id = session_data.get('device_id')
                        return True
        except Exception as e:
            pass
        return False

    def _verify_token_locally(self, token: str, session_data: dict) -> bool:
        """Verify token expiry locally"""
        try:
            expires_at = session_data.get('expires_at')
            if expires_at:
                if time.time() > expires_at:
                    return False
            return True
        except:
            return False

    def _save_cached_token(self, token: str, username: str, device_id: str, expires_in: int):
        """Save encrypted token dan session ke cache"""
        try:
            encrypted_token = self._encrypt_token(token)
            if encrypted_token:
                self.token_file.write_text(encrypted_token)
                
                session_data = {
                    'username': username,
                    'device_id': device_id,
                    'expires_at': time.time() + expires_in,
                    'cached_at': datetime.now().isoformat()
                }
                self.session_file.write_text(json.dumps(session_data, indent=2))
        except Exception as e:
            print(f"[WARNING] Failed to save cached token: {e}")

    def _clear_cache(self):
        """Clear cached token"""
        try:
            self.token_file.unlink(missing_ok=True)
            self.session_file.unlink(missing_ok=True)
        except:
            pass

    def register(self, username: str, password: str, email: str = None) -> Tuple[bool, Dict]:
        """
        Register user baru
        
        Returns:
            (success, result_dict)
        """
        try:
            response = requests.post(
                f'{self.server_url}/api/auth/register',
                json={
                    'username': username,
                    'password': password,
                    'email': email
                },
                timeout=10
            )
            
            if response.status_code == 201:
                data = response.json()
                return True, data
            else:
                data = response.json()
                return False, data
        except Exception as e:
            return False, {'error': str(e)}

    def login(self, username: str, password: str, device_id: str = None, device_name: str = None) -> Tuple[bool, Dict]:
        """
        Login dengan username & password
        
        Args:
            username: Username
            password: Password
            device_id: Device ID (optional, auto-generated if None)
            device_name: Device name (optional)
        
        Returns:
            (success, result_dict_with_token)
        """
        try:
            if not device_id:
                device_id = self._get_or_create_device_id()
            
            response = requests.post(
                f'{self.server_url}/api/auth/login',
                json={
                    'username': username,
                    'password': password,
                    'device_id': device_id,
                    'device_name': device_name or 'Python-Client'
                },
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                token = data.get('token')
                expires_in = data.get('expires_in', 86400)
                
                # Save ke cache
                self._save_cached_token(token, username, device_id, expires_in)
                
                # Store di memory
                self.current_token = token
                self.current_user = username
                self.current_device_id = device_id
                
                return True, data
            else:
                data = response.json()
                return False, data
        except Exception as e:
            return False, {'error': str(e)}

    def login_offline(self, license_key: str, device_id: str = None) -> Tuple[bool, Dict]:
        """
        Login dengan license key (offline mode)
        
        Returns:
            (success, result_dict)
        """
        try:
            if not device_id:
                device_id = self._get_or_create_device_id()
            
            response = requests.post(
                f'{self.server_url}/api/license/verify',
                json={
                    'device_id': device_id,
                    'key': license_key
                },
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                # Buat dummy token
                token = self._create_dummy_token()
                self._save_cached_token(token, 'offline_user', device_id, 86400)
                
                self.current_token = token
                self.current_device_id = device_id
                
                return True, {**data, 'token': token}
            else:
                data = response.json()
                return False, data
        except Exception as e:
            return False, {'error': str(e)}

    def verify_token(self, token: str = None) -> Tuple[bool, Dict]:
        """
        Verify token dengan server
        
        Args:
            token: Token to verify (default: current_token)
        
        Returns:
            (valid, data)
        """
        try:
            token_to_verify = token or self.current_token
            if not token_to_verify:
                return False, {'error': 'No token available'}
            
            response = requests.post(
                f'{self.server_url}/api/auth/verify-token',
                json={'token': token_to_verify},
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                return True, data
            else:
                data = response.json()
                return False, data
        except Exception as e:
            return False, {'error': str(e)}

    def is_authenticated(self) -> bool:
        """Check apakah currently authenticated"""
        return self.current_token is not None

    def get_current_user(self) -> Optional[str]:
        """Get current username"""
        return self.current_user

    def get_current_device_id(self) -> Optional[str]:
        """Get current device ID"""
        return self.current_device_id

    def get_current_token(self) -> Optional[str]:
        """Get current token"""
        return self.current_token

    def logout(self):
        """Logout dan clear cache"""
        self.current_token = None
        self.current_user = None
        self.current_device_id = None
        self._clear_cache()

    def _get_or_create_device_id(self) -> str:
        """Get device ID dari cache atau create baru"""
        device_id_file = self.cache_dir / 'device_id'
        
        if device_id_file.exists():
            return device_id_file.read_text().strip()
        
        device_id = str(uuid.uuid4())
        device_id_file.write_text(device_id)
        return device_id

    def _create_dummy_token(self) -> str:
        """Create dummy token untuk offline mode"""
        token_data = {
            'device_id': self.current_device_id,
            'mode': 'offline',
            'created_at': time.time()
        }
        return json.dumps(token_data)

    def health_check(self) -> Tuple[bool, Dict]:
        """Check server health"""
        try:
            response = requests.get(
                f'{self.server_url}/api/health',
                timeout=5
            )
            
            if response.status_code == 200:
                return True, response.json()
            else:
                return False, {'error': f'HTTP {response.status_code}'}
        except Exception as e:
            return False, {'error': str(e)}


# ──────────────────────────────────────────────────────────────────────────
#  DECORATOR UNTUK REQUIRE AUTH
# ──────────────────────────────────────────────────────────────────────────
def require_auth(auth_client: KaptenAuthClient):
    """
    Decorator untuk function yang require authentication
    
    Usage:
        @require_auth(auth_client)
        def my_function():
            pass
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            if not auth_client.is_authenticated():
                raise PermissionError("Authentication required!")
            return func(*args, **kwargs)
        return wrapper
    return decorator


# ──────────────────────────────────────────────────────────────────────────
#  HELPER FUNCTION
# ──────────────────────────────────────────────────────────────────────────
def create_client(server_url: str = None) -> KaptenAuthClient:
    """
    Create auth client dengan default settings
    
    Args:
        server_url: Auth server URL (default: env var KAPTEN_AUTH_SERVER)
    
    Returns:
        KaptenAuthClient instance
    """
    server = server_url or os.environ.get('KAPTEN_AUTH_SERVER', 'http://localhost:5000')
    return KaptenAuthClient(server)


# ──────────────────────────────────────────────────────────────────────────
#  CLI TEST
# ──────────────────────────────────────────────────────────────────────────
if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Kapten Auth Client CLI')
    parser.add_argument('--server', default='http://localhost:5000', help='Auth server URL')
    parser.add_argument('--test', action='store_true', help='Run test')
    parser.add_argument('--login', action='store_true', help='Interactive login')
    
    args = parser.parse_args()
    
    client = KaptenAuthClient(args.server)
    
    if args.test:
        print(f"\n[*] Testing connection to {args.server}...")
        ok, result = client.health_check()
        if ok:
            print(f"[✓] Server is healthy: {result}")
        else:
            print(f"[✗] Server error: {result}")
    
    elif args.login:
        print("\n=== Kapten Auth Client - Login ===\n")
        username = input("Username: ").strip()
        password = input("Password: ").strip()
        
        print("\n[*] Logging in...")
        ok, result = client.login(username, password)
        
        if ok:
            print(f"[✓] Login successful!")
            print(f"  User: {client.get_current_user()}")
            print(f"  Device ID: {client.get_current_device_id()}")
            print(f"  Token: {client.get_current_token()[:50]}...")
        else:
            print(f"[✗] Login failed: {result.get('message')}")
    
    else:
        print("\nKapten Auth Client - Available Options:")
        print("  --test              : Test server connection")
        print("  --login             : Interactive login")
        print("  --server <url>      : Auth server URL (default: http://localhost:5000)")
