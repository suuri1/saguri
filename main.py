import psutil
import subprocess
import os
import time
import json
import logging
import hashlib
import requests
import socket
from datetime import datetime, timedelta
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading
import sys
from urllib.parse import urlparse, parse_qs
from collections import defaultdict
import secrets
import re
import signal

# Байгууллагын нэр
APP_NAME = "Process Clinic Pro"
VERSION = "2.0.0"

# Лог тохиргоо - хэрэглэгчийн гэрийн директорт хадгалах
USER_HOME = os.path.expanduser("~")
LOG_DIR = os.path.join(USER_HOME, ".process_clinic")
os.makedirs(LOG_DIR, exist_ok=True)

# Бүртгэлийн тохиргоо
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(LOG_DIR, 'process_clinic.log')),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(APP_NAME)

# Тохиргооны файл
CONFIG_FILE = os.path.join(LOG_DIR, 'config.json')

class Config:
    """Тохиргооны класс"""
    def __init__(self):
        self.default_config = {
            "port": 8080,
            "host": "localhost",
            "virustotal_api_key": "",
            "rate_limit": 100,
            "session_secret": secrets.token_hex(32),
            "allowed_commands": [
                "python3", "python", "echo", "ls", "pwd",
                "whoami", "date", "uptime", "ps", "top"
            ],
            "banned_ips": [],
            "max_file_size_mb": 10,
            "enable_authentication": False,
            "admin_username": "admin",
            "admin_password": "admin123",
            "ssl_enabled": False,
            "ssl_cert": "",
            "ssl_key": "",
            "auto_clean_logs_days": 7
        }
        self.config = self.load_config()
    
    def load_config(self):
        """Тохиргооны файлыг унших"""
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    loaded_config = json.load(f)
                    # Анхны утгуудтай нэгтгэх
                    config = self.default_config.copy()
                    config.update(loaded_config)
                    return config
            else:
                # Шинэ тохиргооны файл үүсгэх
                self.save_config(self.default_config)
                return self.default_config
        except Exception as e:
            logger.error(f"Тохиргоо уншихад алдаа: {e}")
            return self.default_config
    
    def save_config(self, config=None):
        """Тохиргооны файлыг хадгалах"""
        try:
            if config is None:
                config = self.config
            
            with open(CONFIG_FILE, 'w') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
            logger.info("Тохиргоо хадгалагдлаа")
            return True
        except Exception as e:
            logger.error(f"Тохиргоо хадгалахад алдаа: {e}")
            return False
    
    def get(self, key, default=None):
        """Тохиргооны утга авах"""
        return self.config.get(key, default)
    
    def set(self, key, value):
        """Тохиргооны утга өөрчлөх"""
        self.config[key] = value
        return self.save_config()

config = Config()

class RateLimiter:
    """Хандалтын хязгаарлагч"""
    def __init__(self, max_requests=100, window=60):
        self.max_requests = max_requests
        self.window = window  # секундэд
        self.access_log = defaultdict(list)
        self.lock = threading.Lock()
    
    def is_allowed(self, ip):
        """IP хаяг хандах эрхтэй эсэхийг шалгах"""
        with self.lock:
            now = time.time()
            # Хуучин бүртгэлүүдийг устгах
            if ip in self.access_log:
                self.access_log[ip] = [
                    timestamp for timestamp in self.access_log[ip]
                    if now - timestamp < self.window
                ]
            
            # Хандалтын тоог шалгах
            if len(self.access_log[ip]) >= self.max_requests:
                return False
            
            # Шинэ бүртгэл нэмэх
            self.access_log[ip].append(now)
            return True
    
    def get_stats(self, ip):
        """IP хаягны статистик авах"""
        with self.lock:
            now = time.time()
            if ip in self.access_log:
                recent = [t for t in self.access_log[ip] if now - t < self.window]
                return {
                    "requests": len(recent),
                    "max_requests": self.max_requests,
                    "window": self.window
                }
            return {"requests": 0, "max_requests": self.max_requests, "window": self.window}

class SecurityValidator:
    """Аюулгүй байдлын баталгаажуулагч"""
    
    @staticmethod
    def validate_command(command):
        """Командыг баталгаажуулах"""
        # Хориглосон командууд
        dangerous_patterns = [
            r'rm\s+-rf\s+/', r'mkfs\.', r'dd\s+if=', r'chmod\s+777',
            r'wget\s+', r'curl\s+', r'python\s+-c\s+[\'"].*[\'"]',
            r'nc\s+', r'telnet\s+', r'ssh\s+', r'scp\s+', r'bash\s+-i',
            r'>\s+/dev/', r'&\s*$', r'\|\s*bash', r'`.*`', r'\$\(.*\)'
        ]
        
        command_lower = command.lower()
        
        # Хэв маягийн шалгалт
        for pattern in dangerous_patterns:
            if re.search(pattern, command_lower):
                logger.warning(f"Аюултай команд илрүүлэв: {command}")
                return False
        
        # Зөвшөөрсөн командын жагсаалтаар шалгах
        allowed_commands = config.get("allowed_commands", [])
        first_word = command.split()[0] if command.split() else ""
        
        if allowed_commands and first_word not in allowed_commands:
            # Команд дахь файлын зам шалгах
            if '/' in first_word or '..' in first_word:
                logger.warning(f"Зөвшөөрөгдөөгүй команд эсвэл файлын зам: {command}")
                return False
        
        return True
    
    @staticmethod
    def validate_file_path(file_path):
        """Файлын замыг баталгаажуулах"""
        # Хориглосон замнууд
        forbidden_paths = [
            '/etc/passwd', '/etc/shadow', '/root', '/boot',
            '/dev', '/proc', '/sys', '/var/log'
        ]
        
        try:
            # Бодит зам шалгах
            real_path = os.path.realpath(file_path)
            
            # Хориглосон замнуудыг шалгах
            for forbidden in forbidden_paths:
                if real_path.startswith(forbidden):
                    logger.warning(f"Хориглосон файлын зам: {file_path}")
                    return False
            
            # Хэрэглэгчийн гэрийн директор л хүртээмжтэй
            if not real_path.startswith(USER_HOME) and not real_path.startswith('/tmp'):
                logger.warning(f"Хандах эрхгүй файлын зам: {file_path}")
                return False
            
            return True
        except Exception:
            return False
    
    @staticmethod
    def sanitize_input(input_str):
        """Оролтын мөрийг цэвэрлэх"""
        if not input_str:
            return ""
        
        # Хортой тэмдэгтүүдийг арилгах
        dangerous_chars = [';', '|', '&', '$', '`', '>', '<', '\n', '\r']
        sanitized = input_str
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        
        return sanitized.strip()

class SessionManager:
    """Хэрэглэгчийн сессийн менежер"""
    def __init__(self):
        self.sessions = {}
        self.session_timeout = 3600  # 1 цаг
        self.lock = threading.Lock()
    
    def create_session(self, username):
        """Шинэ сессийг үүсгэх"""
        with self.lock:
            session_id = secrets.token_hex(32)
            self.sessions[session_id] = {
                "username": username,
                "created": time.time(),
                "last_activity": time.time(),
                "ip": None
            }
            return session_id
    
    def validate_session(self, session_id, ip=None):
        """Сессийг шалгах"""
        with self.lock:
            if session_id not in self.sessions:
                return False
            
            session = self.sessions[session_id]
            
            # Хугацаа дууссан эсэх
            if time.time() - session["last_activity"] > self.session_timeout:
                del self.sessions[session_id]
                return False
            
            # IP хаяг шалгах (сонголттой)
            if ip and session["ip"] and session["ip"] != ip:
                logger.warning(f"Сессийн IP өөрчлөгдсөн: {session['ip']} -> {ip}")
                # IP өөрчлөгдсөн тохиолдолд сессийг устгах
                del self.sessions[session_id]
                return False
            
            # Сүүлийн үйлдлийн цагийг шинэчлэх
            session["last_activity"] = time.time()
            return True
    
    def destroy_session(self, session_id):
        """Сессийг устгах"""
        with self.lock:
            if session_id in self.sessions:
                del self.sessions[session_id]
    
    def cleanup_expired(self):
        """Хугацаа нь дууссан сессийг цэвэрлэх"""
        with self.lock:
            now = time.time()
            expired = [
                sid for sid, session in self.sessions.items()
                if now - session["last_activity"] > self.session_timeout
            ]
            for sid in expired:
                del self.sessions[sid]
            return len(expired)

class ProcessClinicHandler(BaseHTTPRequestHandler):
    """HTTP Handler"""
    
    # Классын хувьсагчууд
    rate_limiter = RateLimiter(
        max_requests=config.get("rate_limit", 100),
        window=60
    )
    session_manager = SessionManager()
    access_count = defaultdict(int)
    banned_ips = set(config.get("banned_ips", []))
    
    # CORS header
    CORS_HEADERS = {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
        'Access-Control-Max-Age': '86400'
    }
    
    def log_request(self, code='-', size='-'):
        """HTTP хүсэлтийг логлох"""
        if code != 200:  # Зөвхөн алдааг логлох
            logger.info(f'{self.client_address[0]} - "{self.requestline}" {code}')
    
    def do_OPTIONS(self):
        """CORS preflight хүсэлтийг боловсруулах"""
        self.send_response(200)
        for key, value in self.CORS_HEADERS.items():
            self.send_header(key, value)
        self.end_headers()
    
    def send_json_response(self, data, status=200):
        """JSON хариу илгээх"""
        self.send_response(status)
        self.send_header('Content-type', 'application/json; charset=utf-8')
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        self.send_header('Pragma', 'no-cache')
        self.send_header('Expires', '0')
        
        # CORS header нэмэх
        for key, value in self.CORS_HEADERS.items():
            self.send_header(key, value)
        
        self.end_headers()
        
        try:
            json_data = json.dumps(data, ensure_ascii=False, default=str)
            self.wfile.write(json_data.encode('utf-8'))
        except Exception as e:
            logger.error(f"JSON хариу илгээхэд алдаа: {e}")
    
    def send_error_response(self, message, status=400):
        """Алдааны хариу илгээх"""
        response = {
            "success": False,
            "message": message,
            "timestamp": datetime.now().isoformat()
        }
        self.send_json_response(response, status)
    
    def authenticate_request(self):
        """Хүсэлтийг баталгаажуулах"""
        if not config.get("enable_authentication", False):
            return True
        
        # Session cookie шалгах
        cookies = self.headers.get('Cookie', '')
        session_id = None
        
        for cookie in cookies.split(';'):
            if 'session_id' in cookie:
                session_id = cookie.split('=')[1].strip()
                break
        
        if session_id and self.session_manager.validate_session(session_id, self.client_address[0]):
            return True
        
        # Basic authentication шалгах
        auth_header = self.headers.get('Authorization', '')
        if auth_header.startswith('Basic '):
            import base64
            try:
                auth_decoded = base64.b64decode(auth_header[6:]).decode('utf-8')
                username, password = auth_decoded.split(':', 1)
                
                if (username == config.get("admin_username") and 
                    password == config.get("admin_password")):
                    return True
            except:
                pass
        
        return False
    
    def do_GET(self):
        """GET хүсэлтийг боловсруулах"""
        try:
            # Хандалтын хязгаарлалт шалгах
            client_ip = self.client_address[0]
            
            if client_ip in self.banned_ips:
                self.send_error_response("Таны IP хаяг хориглосон", 403)
                return
            
            if not self.rate_limiter.is_allowed(client_ip):
                self.send_error_response("Хандах хязгаар хэтэрсэн байна", 429)
                return
            
            # Баталгаажуулалт шалгах
            if not self.authenticate_request():
                self.send_error_response("Нэвтрэх шаардлагатай", 401)
                return
            
            # Хандалтын тоог бүртгэх
            self.access_count[client_ip] += 1
            
            # Path-ээр боловсруулах
            parsed_path = urlparse(self.path)
            path = parsed_path.path
            
            if path == '/':
                self.serve_home_page()
            elif path == '/api/processes':
                self.get_process_data()
            elif path == '/api/system':
                self.get_system_info()
            elif path == '/api/stats':
                self.get_access_stats()
            elif path == '/api/logs':
                self.get_logs()
            elif path.startswith('/api/scan/'):
                pid = path.split('/')[-1]
                self.scan_process(pid)
            else:
                self.send_error_response("Хүсэлт олдсонгүй", 404)
                
        except Exception as e:
            logger.error(f"GET хүсэлт боловсруулах алдаа: {e}")
            self.send_error_response("Дотоод серверийн алдаа", 500)
    
    def do_POST(self):
        """POST хүсэлтийг боловсруулах"""
        try:
            # Хандалтын хязгаарлалт шалгах
            client_ip = self.client_address[0]
            
            if client_ip in self.banned_ips:
                self.send_error_response("Таны IP хаяг хориглосон", 403)
                return
            
            if not self.rate_limiter.is_allowed(client_ip):
                self.send_error_response("Хандах хязгаар хэтэрсэн байна", 429)
                return
            
            # Баталгаажуулалт шалгах
            if not self.authenticate_request():
                self.send_error_response("Нэвтрэх шаардлагатай", 401)
                return
            
            # POST өгөгдлийг унших
            content_length = int(self.headers.get('Content-Length', 0))
            if content_length > 10 * 1024 * 1024:  # 10MB хязгаар
                self.send_error_response("Файлын хэмжээ хэтэрсэн", 413)
                return
            
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8')) if post_data else {}
            
            # Path-ээр боловсруулах
            path = urlparse(self.path).path
            
            if path == '/api/login':
                self.handle_login(data)
            elif path == '/api/logout':
                self.handle_logout()
            elif path == '/api/process/start':
                self.start_process(data)
            elif path == '/api/process/kill':
                self.kill_process(data)
            elif path == '/api/scan/file':
                self.scan_file(data)
            elif path == '/api/config':
                self.update_config(data)
            else:
                self.send_error_response("Хүсэлт олдсонгүй", 404)
                
        except json.JSONDecodeError:
            self.send_error_response("JSON формат буруу", 400)
        except Exception as e:
            logger.error(f"POST хүсэлт боловсруулах алдаа: {e}")
            self.send_error_response("Дотоод серверийн алдаа", 500)
    
    def serve_home_page(self):
        """Нүүр хуудас үйлчлэх"""
        try:
            with open('templates/index.html', 'r', encoding='utf-8') as f:
                html_content = f.read()
            
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(html_content.encode('utf-8'))
        except FileNotFoundError:
            # Хэрэв template файл байхгүй бол энгийн HTML үүсгэх
            html_content = '''
            <!DOCTYPE html>
            <html>
            <head>
                <title>Process Clinic</title>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <style>
                    body { font-family: Arial, sans-serif; margin: 40px; }
                    .container { max-width: 800px; margin: 0 auto; }
                    .status { padding: 20px; background: #f0f0f0; border-radius: 5px; }
                </style>
            </head>
            <body>
                <div class="container">
                    <h1>Process Clinic Pro</h1>
                    <div class="status">
                        <p>Сервер ажиллаж байна</p>
                        <p>API endpoint: /api/processes</p>
                        <p><a href="/api/docs">API documentation</a></p>
                    </div>
                </div>
            </body>
            </html>
            '''
            self.send_response(200)
            self.send_header('Content-type', 'text/html; charset=utf-8')
            self.end_headers()
            self.wfile.write(html_content.encode('utf-8'))
    
    def get_process_data(self):
        """Процессуудын мэдээлэл авах"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 
                                           'create_time', 'status', 'connections']):
                try:
                    pinfo = proc.info
                    connections = pinfo.get('connections', [])
                    
                    process_info = {
                        'pid': pinfo['pid'],
                        'name': SecurityValidator.sanitize_input(pinfo['name']),
                        'user': pinfo.get('username', 'N/A'),
                        'cpu': round(pinfo.get('cpu_percent', 0), 1),
                        'memory': round(pinfo.get('memory_percent', 0), 1),
                        'memory_mb': round(proc.memory_info().rss / (1024 * 1024), 1),
                        'created': datetime.fromtimestamp(pinfo.get('create_time', 0)).isoformat() 
                                   if pinfo.get('create_time') else 'N/A',
                        'status': pinfo.get('status', 'N/A'),
                        'connections': len(connections),
                        'exe': SecurityValidator.sanitize_input(proc.exe() if hasattr(proc, 'exe') else 'N/A')
                    }
                    processes.append(process_info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # CPU ачааллаар эрэмбэлэх
            processes.sort(key=lambda x: x['cpu'], reverse=True)
            
            response = {
                "success": True,
                "count": len(processes),
                "processes": processes[:50],  # Эхний 50 процесс
                "timestamp": datetime.now().isoformat()
            }
            
            self.send_json_response(response)
            
        except Exception as e:
            logger.error(f"Процесс мэдээлэл авахад алдаа: {e}")
            self.send_error_response("Процесс мэдээлэл авахад алдаа гарлаа")
    
    def get_system_info(self):
        """Системийн мэдээлэл авах"""
        try:
            # CPU мэдээлэл
            cpu_percent = psutil.cpu_percent(interval=0.1)
            cpu_percent_per_core = psutil.cpu_percent(interval=0.1, percpu=True)
            
            # Санах ойн мэдээлэл
            memory = psutil.virtual_memory()
            swap = psutil.swap_memory()
            
            # Дискний мэдээлэл
            disk = psutil.disk_usage('/')
            
            # Сүлжээний мэдээлэл
            net_io = psutil.net_io_counters()
            
            # Системийн ачаалал
            load_avg = os.getloadavg() if hasattr(os, 'getloadavg') else [0, 0, 0]
            
            response = {
                "success": True,
                "cpu": {
                    "percent": cpu_percent,
                    "cores": psutil.cpu_count(),
                    "physical_cores": psutil.cpu_count(logical=False),
                    "per_core": cpu_percent_per_core,
                    "frequency": psutil.cpu_freq().current if psutil.cpu_freq() else 0,
                    "load_average": load_avg
                },
                "memory": {
                    "total": memory.total,
                    "available": memory.available,
                    "used": memory.used,
                    "percent": memory.percent,
                    "swap_total": swap.total,
                    "swap_used": swap.used,
                    "swap_percent": swap.percent
                },
                "disk": {
                    "total": disk.total,
                    "used": disk.used,
                    "free": disk.free,
                    "percent": disk.percent
                },
                "network": {
                    "bytes_sent": net_io.bytes_sent,
                    "bytes_recv": net_io.bytes_recv,
                    "packets_sent": net_io.packets_sent,
                    "packets_recv": net_io.packets_recv
                },
                "boot_time": datetime.fromtimestamp(psutil.boot_time()).isoformat(),
                "timestamp": datetime.now().isoformat()
            }
            
            self.send_json_response(response)
            
        except Exception as e:
            logger.error(f"Системийн мэдээлэл авахад алдаа: {e}")
            self.send_error_response("Системийн мэдээлэл авахад алдаа гарлаа")
    
    def get_access_stats(self):
        """Хандалтын статистик авах"""
        try:
            stats = self.rate_limiter.get_stats(self.client_address[0])
            
            response = {
                "success": True,
                "ip": self.client_address[0],
                "rate_limit": stats,
                "total_accesses": self.access_count[self.client_address[0]],
                "active_sessions": len(self.session_manager.sessions),
                "banned_ips": len(self.banned_ips),
                "timestamp": datetime.now().isoformat()
            }
            
            self.send_json_response(response)
            
        except Exception as e:
            logger.error(f"Статистик авахад алдаа: {e}")
            self.send_error_response("Статистик авахад алдаа гарлаа")
    
    def get_logs(self):
        """Лог файлыг авах"""
        try:
            log_file = os.path.join(LOG_DIR, 'process_clinic.log')
            
            if os.path.exists(log_file):
                with open(log_file, 'r', encoding='utf-8') as f:
                    logs = f.readlines()[-100:]  # Сүүлийн 100 мөр
                
                response = {
                    "success": True,
                    "logs": logs,
                    "total_lines": len(logs),
                    "file_size": os.path.getsize(log_file)
                }
            else:
                response = {
                    "success": True,
                    "logs": ["Лог файл байхгүй байна"],
                    "total_lines": 0,
                    "file_size": 0
                }
            
            self.send_json_response(response)
            
        except Exception as e:
            logger.error(f"Лог уншихад алдаа: {e}")
            self.send_error_response("Лог уншихад алдаа гарлаа")
    
    def scan_process(self, pid):
        """Процессыг VirusTotal-ээр шалгах"""
        try:
            pid = int(pid)
            
            if not psutil.pid_exists(pid):
                self.send_error_response("Процесс олдсонгүй", 404)
                return
            
            proc = psutil.Process(pid)
            exe_path = proc.exe()
            
            if not os.path.exists(exe_path):
                self.send_error_response("Гүйцэтгэх файл олдсонгүй")
                return
            
            # Файлын замыг баталгаажуулах
            if not SecurityValidator.validate_file_path(exe_path):
                self.send_error_response("Файлын зам хандах эрхгүй")
                return
            
            result = self.virustotal_check(exe_path)
            self.send_json_response(result)
            
        except ValueError:
            self.send_error_response("PID тоо биш байна")
        except Exception as e:
            logger.error(f"Процесс сканердах алдаа: {e}")
            self.send_error_response("Процесс сканердах алдаа гарлаа")
    
    def start_process(self, data):
        """Процесс эхлүүлэх"""
        try:
            command = SecurityValidator.sanitize_input(data.get('command', ''))
            
            if not command:
                self.send_error_response("Комманд оруулна уу")
                return
            
            # Командыг баталгаажуулах
            if not SecurityValidator.validate_command(command):
                self.send_error_response("Аюултай команд илрүүлэв")
                return
            
            # Процесс эхлүүлэх
            env = os.environ.copy()
            
            # Безопас орчны хувьсагч
            env['PATH'] = '/usr/local/bin:/usr/bin:/bin'
            env['PYTHONPATH'] = ''
            
            proc = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                start_new_session=True  # Шинэ сессид эхлүүлэх
            )
            
            response = {
                "success": True,
                "pid": proc.pid,
                "command": command,
                "message": f"Процесс {proc.pid} амжилттай эхлэв"
            }
            
            logger.info(f"Процесс эхлэв: {command} (PID: {proc.pid})")
            self.send_json_response(response)
            
        except Exception as e:
            logger.error(f"Процесс эхлүүлэх алдаа: {e}")
            self.send_error_response(f"Процесс эхлүүлэх алдаа: {str(e)}")
    
    def kill_process(self, data):
        """Процесс устгах"""
        try:
            pid = int(data.get('pid', 0))
            
            if pid <= 0:
                self.send_error_response("Буруу PID")
                return
            
            if not psutil.pid_exists(pid):
                self.send_error_response("Процесс олдсонгүй")
                return
            
            proc = psutil.Process(pid)
            proc_name = proc.name()
            
            # Өөрөө өөрийгөө устгахыг хориглох
            if pid == os.getpid():
                self.send_error_response("Өөрийгөө устгах боломжгүй")
                return
            
            # Системийн чухал процессуудыг хориглох
            protected_pids = [1, os.getppid()]  # init process болон эцэг процесс
            if pid in protected_pids:
                self.send_error_response("Энэ процессыг устгах боломжгүй")
                return
            
            # Процессыг устгах
            try:
                proc.terminate()
                gone, alive = psutil.wait_procs([proc], timeout=3)
                
                if alive:
                    proc.kill()
                    gone, alive = psutil.wait_procs([proc], timeout=1)
                
                if alive:
                    response = {
                        "success": False,
                        "message": f"Процесс {pid} устгагдаагүй"
                    }
                else:
                    response = {
                        "success": True,
                        "message": f"Процесс {pid} ({proc_name}) амжилттай устгагдлаа"
                    }
                    logger.info(f"Процесс устгагдлаа: {proc_name} (PID: {pid})")
                    
            except psutil.NoSuchProcess:
                response = {
                    "success": True,
                    "message": f"Процесс {pid} аль хэдийн устгагдсан"
                }
            
            self.send_json_response(response)
            
        except ValueError:
            self.send_error_response("PID тоо биш байна")
        except Exception as e:
            logger.error(f"Процесс устгах алдаа: {e}")
            self.send_error_response(f"Процесс устгах алдаа: {str(e)}")
    
    def scan_file(self, data):
        """Файлыг VirusTotal-ээр шалгах"""
        try:
            file_path = data.get('file_path', '')
            
            if not file_path:
                self.send_error_response("Файлын зам оруулна уу")
                return
            
            # Файлын замыг баталгаажуулах
            if not SecurityValidator.validate_file_path(file_path):
                self.send_error_response("Файлын зам хандах эрхгүй")
                return
            
            if not os.path.exists(file_path):
                self.send_error_response("Файл олдсонгүй")
                return
            
            # Файлын хэмжээг шалгах
            max_size = config.get("max_file_size_mb", 10) * 1024 * 1024
            file_size = os.path.getsize(file_path)
            
            if file_size > max_size:
                self.send_error_response(f"Файлын хэмжээ хэтэрсэн (дээд хязгаар: {max_size/1024/1024}MB)")
                return
            
            result = self.virustotal_check(file_path)
            self.send_json_response(result)
            
        except Exception as e:
            logger.error(f"Файл сканердах алдаа: {e}")
            self.send_error_response(f"Файл сканердах алдаа: {str(e)}")
    
    def handle_login(self, data):
        """Нэвтрэх хүсэлт боловсруулах"""
        try:
            username = data.get('username', '')
            password = data.get('password', '')
            
            if (username == config.get("admin_username") and 
                password == config.get("admin_password")):
                
                session_id = self.session_manager.create_session(username)
                
                response = {
                    "success": True,
                    "message": "Амжилттай нэвтэрлээ",
                    "session_id": session_id,
                    "username": username
                }
                
                # Session cookie тохируулах
                self.send_response(200)
                self.send_header('Content-type', 'application/json; charset=utf-8')
                self.send_header('Set-Cookie', f'session_id={session_id}; HttpOnly; Path=/; Max-Age=3600')
                self.end_headers()
                
                self.wfile.write(json.dumps(response, ensure_ascii=False).encode('utf-8'))
            else:
                self.send_error_response("Нэвтрэх нэр эсвэл нууц үг буруу", 401)
                
        except Exception as e:
            logger.error(f"Нэвтрэх алдаа: {e}")
            self.send_error_response("Нэвтрэх алдаа гарлаа")
    
    def handle_logout(self):
        """Гарах хүсэлт боловсруулах"""
        try:
            cookies = self.headers.get('Cookie', '')
            session_id = None
            
            for cookie in cookies.split(';'):
                if 'session_id' in cookie:
                    session_id = cookie.split('=')[1].strip()
                    break
            
            if session_id:
                self.session_manager.destroy_session(session_id)
            
            response = {
                "success": True,
                "message": "Амжилттай гарлаа"
            }
            
            # Cookie устгах
            self.send_response(200)
            self.send_header('Content-type', 'application/json; charset=utf-8')
            self.send_header('Set-Cookie', 'session_id=; HttpOnly; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT')
            self.end_headers()
            
            self.wfile.write(json.dumps(response, ensure_ascii=False).encode('utf-8'))
            
        except Exception as e:
            logger.error(f"Гарах алдаа: {e}")
            self.send_error_response("Гарах алдаа гарлаа")
    
    def update_config(self, data):
        """Тохиргоо шинэчлэх"""
        try:
            # Зөвхөн зарим тохиргоог шинэчлэх
            updatable_keys = ['rate_limit', 'allowed_commands', 'max_file_size_mb']
            
            for key in updatable_keys:
                if key in data:
                    config.set(key, data[key])
            
            response = {
                "success": True,
                "message": "Тохиргоо амжилттай шинэчлэгдлээ",
                "config": {k: config.get(k) for k in updatable_keys}
            }
            
            self.send_json_response(response)
            
        except Exception as e:
            logger.error(f"Тохиргоо шинэчлэх алдаа: {e}")
            self.send_error_response(f"Тохиргоо шинэчлэх алдаа: {str(e)}")
    
    def virustotal_check(self, file_path):
        """VirusTotal API ашиглан шалгалт хийх"""
        api_key = config.get("virustotal_api_key", "")
        
        if not api_key:
            return {
                "success": False,
                "message": "VirusTotal API түлхүүр тохируулаагүй байна",
                "file_path": file_path,
                "requires_api_key": True
            }
        
        try:
            # Файлын hash тооцоолох
            sha256_hash = hashlib.sha256()
            with open(file_path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            file_hash = sha256_hash.hexdigest()
            
            # VirusTotal API дуудах
            headers = {"x-apikey": api_key}
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                stats = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                
                return {
                    "success": True,
                    "message": "VirusTotal шалгалт амжилттай",
                    "file_path": file_path,
                    "file_hash": file_hash,
                    "malicious": stats.get('malicious', 0),
                    "suspicious": stats.get('suspicious', 0),
                    "undetected": stats.get('undetected', 0),
                    "harmless": stats.get('harmless', 0),
                    "total": sum(stats.values()),
                    "scan_date": result.get('data', {}).get('attributes', {}).get('last_analysis_date', '')
                }
            elif response.status_code == 404:
                return {
                    "success": True,
                    "message": "Файл VirusTotal-д бүртгэгдээгүй байна",
                    "file_path": file_path,
                    "file_hash": file_hash,
                    "requires_upload": True
                }
            else:
                return {
                    "success": False,
                    "message": f"VirusTotal API алдаа: {response.status_code}",
                    "file_path": file_path,
                    "file_hash": file_hash
                }
                
        except requests.exceptions.Timeout:
            return {
                "success": False,
                "message": "VirusTotal API холболтын timeout",
                "file_path": file_path
            }
        except Exception as e:
            logger.error(f"VirusTotal шалгалтын алдаа: {e}")
            return {
                "success": False,
                "message": f"VirusTotal шалгалтын алдаа: {str(e)}",
                "file_path": file_path
            }


def cleanup_old_logs():
    """Хуучин лог файлуудыг устгах"""
    try:
        auto_clean_days = config.get("auto_clean_logs_days", 7)
        cutoff_time = time.time() - (auto_clean_days * 24 * 3600)
        
        for filename in os.listdir(LOG_DIR):
            filepath = os.path.join(LOG_DIR, filename)
            if os.path.isfile(filepath):
                if filename.endswith('.log') or filename.endswith('.txt'):
                    if os.path.getmtime(filepath) < cutoff_time:
                        os.remove(filepath)
                        logger.info(f"Хуучин лог устгагдлаа: {filename}")
        
        # Session cleanup
        expired = ProcessClinicHandler.session_manager.cleanup_expired()
        if expired > 0:
            logger.info(f"{expired} хуучин сессийг устгалаа")
            
    except Exception as e:
        logger.error(f"Лог цэвэрлэх алдаа: {e}")


def signal_handler(signum, frame):
    """Сигнал боловсруулагч"""
    logger.info(f"Сигнал хүлээн авлаа: {signum}")
    sys.exit(0)


def start_server():
    """Сервер эхлүүлэх"""
    port = config.get("port", 8080)
    host = config.get("host", "localhost")
    
    server_address = (host, port)
    httpd = HTTPServer(server_address, ProcessClinicHandler)
    
    # Сигнал бүртгэх
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print(f"╔{'═' * 60}╗")
    print(f"║{'PROCESS CLINIC PRO - Кибер Аюулгүй Байдлын Систем':^60}║")
    print(f"║{'Version ' + VERSION:^60}║")
    print(f"╚{'═' * 60}╝")
    print(f"\n🚀 Сервер эхэллээ: http://{host}:{port}")
    print(f"📁 Лог директор: {LOG_DIR}")
    print(f"🔧 Тохиргооны файл: {CONFIG_FILE}")
    
    # Мэдээлэл харуулах
    if config.get("enable_authentication"):
        print(f"🔒 Нэвтрэх шаардлагатай: {config.get('admin_username')}")
    else:
        print("🔓 Нэвтрэх шаардлагагүй")
    
    if config.get("virustotal_api_key"):
        print("🦠 VirusTotal интеграц идэвхтэй")
    else:
        print("⚠️  VirusTotal API түлхүүр тохируулаагүй")
        print("   Тохиргоонд нэмэх эсвэл дараах коммандаар тохируулна уу:")
        print(f"   echo '{{\"virustotal_api_key\": \"YOUR_KEY\"}}' >> {CONFIG_FILE}")
    
    print(f"\n📊 Тохиргоо:")
    print(f"   • Хандалтын хязгаар: {config.get('rate_limit')} хүсэлт/минут")
    print(f"   • Зөвшөөрсөн командууд: {len(config.get('allowed_commands', []))} ширхэг")
    print(f"   • Автомат лог цэвэрлэх: {config.get('auto_clean_logs_days')} хоног")
    
    print("\n🛑 Зогсоох: Ctrl+C")
    print("=" * 60)
    
    try:
        # Лог цэвэрлэгч эхлүүлэх
        cleanup_thread = threading.Thread(target=cleanup_old_logs, daemon=True)
        cleanup_thread.start()
        
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n\n👋 Сервер зогслоо. Баяртай!")
        logger.info("Сервер зогссон")
        httpd.server_close()
    except Exception as e:
        logger.error(f"Сервер алдаа: {e}")
        print(f"Алдаа гарлаа: {e}")
        sys.exit(1)


if __name__ == '__main__':
    # Шинэчлэгдсэн HTML template файл үүсгэх
    templates_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
    os.makedirs(templates_dir, exist_ok=True)
    
    html_template = os.path.join(templates_dir, 'index.html')
    
    if not os.path.exists(html_template):
        # Энгийн веб интерфэйс үүсгэх
        simple_html = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Process Clinic Pro</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
               background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
               min-height: 100vh; padding: 20px; }
        .container { max-width: 1200px; margin: 0 auto; background: white; 
                    border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); 
                    overflow: hidden; }
        header { background: #2d3748; color: white; padding: 30px; text-align: center; }
        h1 { font-size: 2.5em; margin-bottom: 10px; }
        .subtitle { opacity: 0.8; font-size: 1.1em; }
        .main-content { display: flex; min-height: 500px; }
        .sidebar { width: 250px; background: #f7fafc; padding: 20px; border-right: 1px solid #e2e8f0; }
        .content { flex: 1; padding: 30px; }
        .nav-item { padding: 15px; margin: 5px 0; background: white; border-radius: 8px; 
                   cursor: pointer; transition: all 0.3s; border-left: 4px solid #4299e1; }
        .nav-item:hover { background: #edf2f7; transform: translateX(5px); }
        .nav-item.active { background: #4299e1; color: white; }
        .card { background: #f7fafc; padding: 25px; margin-bottom: 20px; 
               border-radius: 10px; border-left: 5px solid #4299e1; }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); 
                gap: 15px; margin: 20px 0; }
        .stat-card { background: white; padding: 20px; border-radius: 8px; 
                    text-align: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .stat-value { font-size: 2em; font-weight: bold; color: #4299e1; margin: 10px 0; }
        button { padding: 12px 24px; background: #4299e1; color: white; border: none; 
                border-radius: 6px; cursor: pointer; font-size: 16px; font-weight: 600; 
                transition: all 0.3s; margin: 5px; }
        button:hover { background: #3182ce; transform: translateY(-2px); }
        .btn-danger { background: #e53e3e; }
        .btn-danger:hover { background: #c53030; }
        .btn-success { background: #38a169; }
        .btn-success:hover { background: #2f855a; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; background: white; 
               border-radius: 8px; overflow: hidden; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        th { background: #4a5568; color: white; padding: 15px; text-align: left; }
        td { padding: 12px 15px; border-bottom: 1px solid #e2e8f0; }
        .notification { position: fixed; top: 20px; right: 20px; padding: 15px 25px; 
                      background: #38a169; color: white; border-radius: 8px; 
                      display: none; z-index: 1000; box-shadow: 0 5px 15px rgba(0,0,0,0.2); }
        .login-form { max-width: 400px; margin: 50px auto; }
        input { width: 100%; padding: 12px; margin: 10px 0; border: 2px solid #e2e8f0; 
               border-radius: 6px; font-size: 16px; }
        .loading { text-align: center; padding: 50px; color: #718096; }
        .error { background: #fed7d7; color: #c53030; padding: 10px; border-radius: 5px; 
                margin: 10px 0; }
        .success { background: #c6f6d5; color: #276749; padding: 10px; border-radius: 5px; 
                  margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🏥 Process Clinic Pro</h1>
            <div class="subtitle">Кибер Аюулгүй Байдлын Профессиональ Хяналт</div>
        </header>
        
        <div class="main-content">
            <div class="sidebar" id="sidebar">
                <!-- Навигацийг JavaScript-ээр үүсгэнэ -->
            </div>
            
            <div class="content" id="content">
                <div class="loading" id="loading">
                    <h2>Түр хүлээнэ үү...</h2>
                    <p>Апп ачаалж байна</p>
                </div>
            </div>
        </div>
    </div>
    
    <div class="notification" id="notification"></div>
    
    <script>
        // API суурь URL
        const API_BASE = '/api';
        
        // Веб аппын үндсэн логик
        class ProcessClinicApp {
            constructor() {
                this.currentView = 'dashboard';
                this.views = {
                    dashboard: 'Хянах Самбар',
                    processes: 'Процессууд',
                    system: 'Систем',
                    security: 'Аюулгүй Байдал',
                    logs: 'Логууд',
                    settings: 'Тохиргоо'
                };
                
                this.init();
            }
            
            async init() {
                await this.checkAuth();
                this.renderNavigation();
                this.loadView(this.currentView);
                this.setupEventListeners();
            }
            
            async checkAuth() {
                try {
                    const response = await fetch(`${API_BASE}/stats`);
                    if (response.status === 401) {
                        this.showLogin();
                        return false;
                    }
                    return true;
                } catch (error) {
                    console.error('Auth check failed:', error);
                    this.showLogin();
                    return false;
                }
            }
            
            showLogin() {
                const content = document.getElementById('content');
                content.innerHTML = `
                    <div class="login-form">
                        <div class="card">
                            <h2>🔐 Нэвтрэх</h2>
                            <div id="login-error" class="error" style="display: none;"></div>
                            <input type="text" id="username" placeholder="Нэвтрэх нэр" value="admin">
                            <input type="password" id="password" placeholder="Нууц үг" value="admin123">
                            <button onclick="app.login()" class="btn-success">Нэвтрэх</button>
                        </div>
                    </div>
                `;
            }
            
            async login() {
                const username = document.getElementById('username').value;
                const password = document.getElementById('password').value;
                
                try {
                    const response = await fetch(`${API_BASE}/login`, {
                        method: 'POST',
                        headers: {'Content-Type': 'application/json'},
                        body: JSON.stringify({username, password})
                    });
                    
                    if (response.ok) {
                        this.showNotification('Амжилттай нэвтэрлээ', 'success');
                        setTimeout(() => {
                            this.init();
                        }, 1000);
                    } else {
                        const error = await response.json();
                        this.showNotification(error.message || 'Нэвтрэх алдаа', 'error');
                    }
                } catch (error) {
                    this.showNotification('Сүлжээний алдаа', 'error');
                }
            }
            
            renderNavigation() {
                const sidebar = document.getElementById('sidebar');
                let navHTML = '';
                
                for (const [viewId, viewName] of Object.entries(this.views)) {
                    navHTML += `
                        <div class="nav-item ${viewId === this.currentView ? 'active' : ''}" 
                             onclick="app.loadView('${viewId}')">
                            ${viewName}
                        </div>
                    `;
                }
                
                navHTML += `
                    <div style="margin-top: auto; padding-top: 20px;">
                        <div class="nav-item" onclick="app.logout()">
                            🔓 Гарах
                        </div>
                    </div>
                `;
                
                sidebar.innerHTML = navHTML;
            }
            
            async loadView(viewId) {
                this.currentView = viewId;
                this.renderNavigation();
                
                const content = document.getElementById('content');
                content.innerHTML = '<div class="loading">Ачаалж байна...</div>';
                
                try {
                    switch(viewId) {
                        case 'dashboard':
                            await this.loadDashboard();
                            break;
                        case 'processes':
                            await this.loadProcesses();
                            break;
                        case 'system':
                            await this.loadSystemInfo();
                            break;
                        case 'security':
                            await this.loadSecurity();
                            break;
                        case 'logs':
                            await this.loadLogs();
                            break;
                        case 'settings':
                            await this.loadSettings();
                            break;
                    }
                } catch (error) {
                    content.innerHTML = `<div class="error">Алдаа гарлаа: ${error.message}</div>`;
                }
            }
            
            async loadDashboard() {
                const [processes, system, stats] = await Promise.all([
                    this.fetchData('/processes'),
                    this.fetchData('/system'),
                    this.fetchData('/stats')
                ]);
                
                const content = document.getElementById('content');
                content.innerHTML = `
                    <div class="card">
                        <h2>📊 Системийн Тойм</h2>
                        <div class="stats">
                            <div class="stat-card">
                                <div>CPU Ачаалал</div>
                                <div class="stat-value">${system?.cpu?.percent?.toFixed(1) || 0}%</div>
                                <div>Системийн ачаалал</div>
                            </div>
                            <div class="stat-card">
                                <div>Санах Ой</div>
                                <div class="stat-value">${system?.memory?.percent?.toFixed(1) || 0}%</div>
                                <div>Ашиглалт</div>
                            </div>
                            <div class="stat-card">
                                <div>Процессууд</div>
                                <div class="stat-value">${processes?.count || 0}</div>
                                <div>Идэвхтэй</div>
                            </div>
                            <div class="stat-card">
                                <div>Диск</div>
                                <div class="stat-value">${system?.disk?.percent?.toFixed(1) || 0}%</div>
                                <div>Ашиглалт</div>
                            </div>
                        </div>
                    </div>
                    
                    <div class="card">
                        <h2>🚨 Шуурхай Үйлдлүүд</h2>
                        <div>
                            <button onclick="app.killHighCpu()" class="btn-danger">Өндөр CPU Процессууд</button>
                            <button onclick="app.scanSystem()" class="btn-success">Систем Сканердах</button>
                            <button onclick="app.refreshAll()" class="btn-success">Шинэчлэх</button>
                        </div>
                    </div>
                `;
            }
            
            async killHighCpu() {
                const processes = await this.fetchData('/processes');
                const highCpu = processes.processes.filter(p => p.cpu > 50);
                
                for (const proc of highCpu.slice(0, 5)) {
                    await this.killProcess(proc.pid);
                    await new Promise(resolve => setTimeout(resolve, 500));
                }
                
                this.showNotification(`${highCpu.length} процесс устгагдлаа`, 'success');
                this.loadView('processes');
            }
            
            async scanSystem() {
                this.showNotification('Системийн процессуудыг сканердаж байна...', 'info');
                // Сканердах логик нэмэх
            }
            
            async refreshAll() {
                await this.loadView(this.currentView);
                this.showNotification('Шинэчлэгдлээ', 'success');
            }
            
            showNotification(message, type = 'success') {
                const notification = document.getElementById('notification');
                notification.textContent = message;
                notification.style.background = type === 'error' ? '#e53e3e' : 
                                              type === 'warning' ? '#ed8936' : '#38a169';
                notification.style.display = 'block';
                
                setTimeout(() => {
                    notification.style.display = 'none';
                }, 3000);
            }
            
            async fetchData(endpoint) {
                const response = await fetch(`${API_BASE}${endpoint}`);
                if (!response.ok) {
                    throw new Error(`API алдаа: ${response.status}`);
                }
                return await response.json();
            }
        }
        
        // Глобал апп объект үүсгэх
        window.app = new ProcessClinicApp();
    </script>
</body>
</html>'''
        
        with open(html_template, 'w', encoding='utf-8') as f:
            f.write(simple_html)
    
    # Сервер эхлүүлэх
    start_server()