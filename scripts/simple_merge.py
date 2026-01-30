#!/usr/bin/env python3
"""
Скрипт для парсинга.
Разрешается только некоммерческое использование.
(если вы будете продавать конфиги из парсера - это будет нарушение лицензии)
Сам парсер является полностью переписанным парсером goida-vpn-configs.
"""

from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from collections import defaultdict
from github import GithubException
from github import Github, Auth
from datetime import datetime
import concurrent.futures
import urllib.parse
import threading
import ipaddress
import zoneinfo
import requests
import urllib3
import calendar
import base64
import json
import re
import os

LOGS_BY_FILE: dict[int, list[str]] = defaultdict(list)
_LOG_LOCK = threading.Lock()

def log(message: str):
    """Добавляет сообщение в общий словарь логов потокобезопасно."""
    with _LOG_LOCK:
        LOGS_BY_FILE[0].append(message)

zone = zoneinfo.ZoneInfo("Europe/Moscow")
thistime = datetime.now(zone)
offset = thistime.strftime("%H:%M | %d.%m.%Y")

GITHUB_TOKEN = os.environ.get("MY_TOKEN", "")
REPO_NAME = os.environ.get("GITHUB_REPOSITORY", "bywarm/wlrusparser")

# Cloud.ru S3 конфигурация
CLOUD_RU_ENDPOINT = os.environ.get("CLOUD_RU_ENDPOINT", "https://s3.cloud.ru/bucket-93b250")
CLOUD_RU_ACCESS_KEY = os.environ.get("CLOUD_RU_ACCESS_KEY", "28a54be8-b238-4edf-8079-7cee88d2ab3c:d103f9e8c17b5d760f0d713ca4af063c")
CLOUD_RU_SECRET_KEY = os.environ.get("CLOUD_RU_SECRET_KEY", "")
CLOUD_RU_BUCKET = os.environ.get("CLOUD_RU_BUCKET", "bucket-93b250")
CLOUD_RU_REGION = os.environ.get("CLOUD_RU_REGION", "ru-central-1")

# GitVerse API конфигурация (только токен в секретах)
GITVERSE_TOKEN = os.environ.get("GITVERSE_TOKEN", "")

# Остальные параметры GitVerse заданы явно в коде
if GITVERSE_TOKEN:
    # Настройки по умолчанию - замените на ваши
    GITVERSE_ENDPOINT = "https://api.gitverse.ru"  # Основной endpoint согласно документации
    GITVERSE_REPO_OWNER = "bywarm"  # ВАШ логин на GitVerse
    GITVERSE_REPO_NAME = "rser"  # ВАШ репозиторий
    GITVERSE_BRANCH = "master"
else:
    # Если токен не задан, параметры не важны
    GITVERSE_ENDPOINT = ""
    GITVERSE_REPO_OWNER = ""
    GITVERSE_REPO_NAME = ""
    GITVERSE_BRANCH = ""

if GITHUB_TOKEN:
    g = Github(auth=Auth.Token(GITHUB_TOKEN))
else:
    g = Github()

try:
    REPO = g.get_repo(REPO_NAME)
except Exception as e:
    log("Ошибка подключения к GitHub: " + str(e)[:100])
    REPO = None


OUTPUT_DIR = os.environ.get("OUTPUT_DIR", "confs")

CONFIG = {
    "output_dir": OUTPUT_DIR,
    "merged_file": "merged.txt",
    "wl_file": "wl.txt",
    "selected_file": "selected.txt",
    "custom_prefix": "",
    "use_date_suffix": False,
    "rotate_folders": False,
}

if CONFIG["rotate_folders"]:
    month = datetime.now().month
    year_short = datetime.now().strftime("%y")
    CONFIG["output_dir_suffix"] = f"_{year_short}{month:02d}"

def get_paths():
    """Возвращает актуальные пути к файлам"""
    base_dir = CONFIG["output_dir"]
    
    paths = {
        "base_dir": base_dir,
        "merged": f"{base_dir}/{CONFIG['merged_file']}",
        "wl": f"{base_dir}/{CONFIG['wl_file']}",
        "selected": f"{base_dir}/{CONFIG['selected_file']}",
        "gh_pages_merged": "merged.txt",
        "gh_pages_wl": "wl.txt",
    }
    return paths

PATHS = get_paths()

EXCLUDE_PATTERNS = [
    "rootface-@pwn1337-telegram",
    "01010101",
    "9292929",
    "38388282",
    "star_test1",
]

# Дополнительные настройки
EXCLUDE_SETTINGS = {
    "case_sensitive": False,  # Регистрозависимость
    "log_excluded": True,     # Логировать исключенные конфиги
    "save_excluded": True,    # Сохранять исключенные в отдельный файл
}

WHITELIST_SUBNETS = [
    "5.188.0.0/16",
    "37.18.0.0/16",
    "37.139.0.0/16",
    "45.15.0.0/16",
    "45.129.0.0/16",
    "51.250.0.0/16", 
    "51.250.0.0/17", 
    "77.88.21.0/24", 
    "78.159.0.0/16",
    "78.159.247.0/24", 
    "79.174.91.0/24",  
    "79.174.92.0/24",  
    "79.174.93.0/24",  
    "79.174.94.0/24", 
    "79.174.95.0/24",  
    "83.166.0.0/16",
    "84.201.0.0/16",   
    "84.201.128.0/18", 
    "87.250.247.0/24", 
    "87.250.250.0/24",
    "87.250.251.0/24", 
    "87.250.254.0/24", 
    "89.208.0.0/16",
    "89.253.200.0/21", 
    "91.219.0.0/16",
    "91.222.239.0/24", 
    "95.163.0.0/16",
    "95.163.248.0/22", 
    "95.181.182.0/24", 
    "103.111.114.0/24", 
    "109.120.0.0/16",
    "109.73.201.0/24", 
    "130.193.0.0/16",
    "134.17.94.0/24",  
    "158.160.0.0/16",
    "176.32.0.0/16",
    "176.108.0.0/16",
    "176.109.0.0/16",
    "176.122.0.0/16",
    "178.154.0.0/16",
    "185.39.206.0/24",
    "185.130.0.0/16",
    "185.141.216.0/24", 
    "185.177.0.0/16",
    "185.177.73.0/24", 
    "185.241.192.0/22", 
    "193.53.0.0/16",
    "212.233.72.0/21",
    "217.12.0.0/16",
    "217.16.0.0/16",    
    "217.16.24.0/21",  
    "37.9.38.0/24",
    "37.220.166.0/24",
    "77.41.174.0/24",
    "79.126.125.0/24",
    "81.22.206.0/24",
    "81.177.73.0/24",
    "81.211.48.0/24",
    "82.208.79.0/24",
    "82.209.65.0/24",
    "85.26.166.0/24",
    "85.234.38.0/24",
    "89.248.230.0/24",
    "91.233.216.0/24",
    "91.233.217.0/24",
    "91.233.218.0/24",
    "92.223.43.0/24",
    "94.229.232.0/24",
    "95.142.205.0/24",
    "95.163.43.0/24",
    "95.167.222.0/24",
    "95.181.181.0/24",
    "109.120.190.0/24",
    "128.75.235.0/24",
    "128.75.253.0/24",
    "128.140.170.0/24",
    "146.185.209.0/24",
    "151.236.75.0/24",
    "151.236.87.0/24",
    "151.236.90.0/24",
    "151.236.96.0/24",
    "151.236.99.0/24",
    "155.212.192.0/24",
    "176.211.118.0/24",
    "178.176.128.0/24",
    "178.176.145.0/24",
    "178.178.103.0/24",
    "178.237.22.0/24",
    "178.248.232.0/24",
    "178.248.233.0/24",
    "178.248.234.0/24",
    "178.248.235.0/24",
    "178.248.238.0/24",
    "178.248.239.0/24",
    "185.9.230.0/24",
    "185.16.150.0/24",
    "185.27.192.0/24",
    "185.32.187.0/24",
    "185.32.251.0/24",
    "185.45.82.0/24",
    "185.62.201.0/24",
    "185.65.148.0/24",
    "185.65.149.0/24",
    "185.72.228.0/24",
    "185.72.229.0/24",
    "185.72.231.0/24",
    "185.73.192.0/24",
    "185.73.193.0/24",
    "185.73.194.0/24",
    "185.73.195.0/24",
    "185.163.159.0/24",
    "185.226.55.0/24",
    "185.241.193.0/24",
    "185.242.16.0/24",
    "188.43.2.0/24",
    "188.43.3.0/24",
    "188.43.5.0/24",
    "188.170.146.0/24",
    "194.67.49.0/24",
    "194.85.149.0/24",
    "194.154.70.0/24",
    "194.154.71.0/24",
    "194.154.73.0/24",
    "194.154.76.0/24",
    "194.154.80.0/24",
    "194.186.16.0/24",
    "194.186.17.0/24",
    "194.186.26.0/24",
    "194.186.31.0/24",
    "194.186.81.0/24",
    "194.186.86.0/24",
    "194.186.91.0/24",
    "194.186.96.0/24",
    "194.186.158.0/24",
    "194.186.168.0/24",
    "194.186.172.0/24",
    "194.186.174.0/24",
    "194.186.244.0/24",
    "194.186.249.0/24",
    "194.186.250.0/24",
    "195.34.36.0/24",
    "195.34.37.0/24",
    "195.34.38.0/24",
    "195.34.58.0/24",
    "195.239.1.0/24",
    "195.239.7.0/24",
    "195.239.9.0/24",
    "195.239.13.0/24",
    "195.239.38.0/24",
    "195.239.57.0/24",
    "195.239.67.0/24",
    "195.239.68.0/24",
    "195.239.94.0/24",
    "195.239.109.0/24",
    "195.239.156.0/24",
    "195.239.158.0/24",
    "195.239.159.0/24",
    "212.46.197.0/24",
    "212.46.198.0/24",
    "212.46.200.0/24",
    "212.46.208.0/24",
    "212.46.210.0/24",
    "212.46.254.0/24",
    "212.188.4.0/24",
    "212.188.6.0/24",
    "212.188.8.0/24",
    "212.188.12.0/24",
    "212.188.15.0/24",
    "212.188.16.0/24",
    "212.193.146.0/24",
    "212.193.147.0/24",
    "213.87.71.0/24",
    "213.184.156.0/24",
    "217.20.158.0/24",
    "217.118.183.0/24",
    "217.174.188.0/24",
    "80.68.251.0/24",
    "91.208.84.0/24",
    "91.232.131.0/24",
    "109.207.4.0/24",
]

WHITELIST_NETWORKS = [ipaddress.ip_network(subnet) for subnet in WHITELIST_SUBNETS]

URLS = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
    "https://raw.githubusercontent.com/vsevjik/OBSpiskov/refs/heads/main/wwh",
    "https://fsub.flux.2bd.net/githubmirror/bypass/bypass-all.txt",
    "https://storage.yandexcloud.net/cid-vpn/whitelist.txt",
    "https://raw.githubusercontent.com/koteey/Ms.Kerosin-VPN/refs/heads/main/proxies.txt",
    "https://raw.githubusercontent.com/SilentGhostCodes/WhiteListVpn/refs/heads/main/config.txt",
    "https://raw.githubusercontent.com/HikaruApps/WhiteLattice/refs/heads/main/subscriptions/main-sub.txt",
    "https://raw.githubusercontent.com/avbak/sturdy-octo-tribble1/refs/heads/main/VLESS-RU-MOBILE-CIDR-WHITELIST-filtered.txt",
    "https://raw.githubusercontent.com/FalerChannel/FalerChannel/refs/heads/main/configs",
    "https://raw.githubusercontent.com/officialdakari/psychic-octo-tribble/refs/heads/main/subwl.txt",
    "https://raw.githubusercontent.com/RKPchannel/RKP_bypass_configs/refs/heads/main/configs",
    "https://raw.githubusercontent.com/Ai123999/WhiteeListSub/refs/heads/main/whitelistkeys",
    "https://raw.githubusercontent.com/EtoNeYaProject/etoneyaproject.github.io/refs/heads/main/whitelist",
    "https://s3c3.001.gpucloud.ru/dixsm/htxml",
    "https://gitverse.ru/api/repos/LowiK/LowiKLive/raw/branch/main/WhiteList-Bypass_Ru.txt",
    "https://rstnnl.gitverse.site/sb/dev.txt",
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-CIDR-RU-checked.txt",
]
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/138.0.0.0 Safari/537.36"
)

DEFAULT_MAX_WORKERS = int(os.environ.get("MAX_WORKERS", "10"))

def _build_session(max_pool_size: int) -> requests.Session:
    session = requests.Session()
    adapter = HTTPAdapter(
        pool_connections=max_pool_size,
        pool_maxsize=max_pool_size,
        max_retries=Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("HEAD", "GET", "OPTIONS"),
        ),
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({"User-Agent": CHROME_UA})
    return session

REQUESTS_SESSION = _build_session(max_pool_size=min(DEFAULT_MAX_WORKERS, len(URLS)))

def fetch_url(url: str, timeout: int = 15, max_attempts: int = 3) -> str:
    """Загружает данные с URL"""
    for attempt in range(1, max_attempts + 1):
        try:
            modified_url = url
            verify = True

            if attempt == 2:
                verify = False
            elif attempt == 3:
                parsed = urllib.parse.urlparse(url)
                if parsed.scheme == "https":
                    modified_url = parsed._replace(scheme="http").geturl()
                verify = False

            response = REQUESTS_SESSION.get(modified_url, timeout=timeout, verify=verify)
            response.raise_for_status()
            return response.text

        except requests.exceptions.RequestException as exc:
            last_exc = exc
            if attempt < max_attempts:
                continue
            error_msg = str(exc)
            if len(error_msg) > 100:
                error_msg = error_msg[:100]
            log("Ошибка загрузки " + url + ": " + error_msg)
            return ""
    
    return ""

def extract_host_port(config: str) -> tuple[str, int] | None:
    """Извлекает хост и порт из конфигурационной строки для дедупликации"""
    if not config:
        return None
    
    try:
        if config.startswith("vmess://"):
            try:
                payload = config[8:]
                rem = len(payload) % 4
                if rem:
                    payload += '=' * (4 - rem)
                
                decoded = base64.b64decode(payload).decode('utf-8', errors='ignore')
                
                if decoded.startswith('{'):
                    j = json.loads(decoded)
                    host = j.get('add') or j.get('host') or j.get('ip')
                    port = j.get('port')
                    
                    if host and port:
                        return str(host), int(port)
            except Exception:
                pass
        
        patterns = [
            r'@([\w\.-]+):(\d{1,5})',
            r'host=([\w\.-]+).*?port=(\d{1,5})',
            r'address=([\w\.-]+).*?port=(\d{1,5})',
            r'//([\w\.-]+):(\d{1,5})',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, config, re.IGNORECASE)
            if match:
                host = match.group(1)
                port = int(match.group(2))
                return host, port
        
        match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})', config)
        if match:
            return match.group(1), int(match.group(2))
        
        match = re.search(r'([\w\.-]+):(\d{1,5})', config)
        if match:
            host = match.group(1)
            port = int(match.group(2))
            if len(host) > 1 and ('.' in host or host.replace('.', '').replace('-', '').isalnum()):
                return host, port
                
    except Exception:
        pass
    
    return None

def generate_config_key(config: str) -> str:
    """Генерирует уникальный ключ для конфига на основе всех параметров"""
    if not config:
        return ""
    
    try:
        # Для VLESS
        if config.startswith("vless://"):
            parsed = urllib.parse.urlparse(config)
            
            # Извлекаем основные параметры
            username = parsed.username or ""
            host = parsed.hostname or ""
            port = parsed.port or 443
            
            # Парсим query параметры
            query_params = urllib.parse.parse_qs(parsed.query)
            
            # Собираем ключевые параметры для уникальности
            key_parts = [
                username,  # UUID
                host,
                str(port),
                query_params.get('security', [''])[0],
                query_params.get('sni', [''])[0],
                query_params.get('sid', [''])[0],
                query_params.get('pbk', [''])[0],
                query_params.get('type', [''])[0],
                query_params.get('flow', [''])[0],
                query_params.get('fp', [''])[0],
                query_params.get('encryption', [''])[0],
            ]
            
            # Фильтруем пустые значения и объединяем
            return "|".join([part for part in key_parts if part])
        
        # Для VMESS
        elif config.startswith("vmess://"):
            try:
                payload = config[8:]
                rem = len(payload) % 4
                if rem:
                    payload += '=' * (4 - rem)
                
                decoded = base64.b64decode(payload).decode('utf-8', errors='ignore')
                
                if decoded.startswith('{'):
                    j = json.loads(decoded)
                    key_parts = [
                        j.get('id', ''),  # UUID
                        j.get('add', ''),  # Host
                        str(j.get('port', '')),  # Port
                        j.get('net', ''),  # Network type
                        j.get('host', ''),  # Host header
                        j.get('path', ''),  # Path
                        j.get('tls', ''),  # TLS
                        j.get('sni', ''),  # SNI
                        j.get('type', ''),  # Type
                        j.get('ps', ''),  # Remark/name
                    ]
                    return "|".join([part for part in key_parts if part])
            except Exception:
                pass
        
        # Для Trojan
        elif config.startswith("trojan://"):
            parsed = urllib.parse.urlparse(config)
            username = parsed.username or ""  # Password for Trojan
            host = parsed.hostname or ""
            port = parsed.port or 443
            
            query_params = urllib.parse.parse_qs(parsed.query)
            key_parts = [
                username,
                host,
                str(port),
                query_params.get('security', [''])[0],
                query_params.get('sni', [''])[0],
                query_params.get('type', [''])[0],
                query_params.get('flow', [''])[0],
                query_params.get('fp', [''])[0],
            ]
            return "|".join([part for part in key_parts if part])
        
        # Для других протоколов используем полную строку как ключ
        else:
            return config[:200]  # Используем начало конфига
        
    except Exception as e:
        # В случае ошибки используем начало конфига
        return config[:100]
    
    # Фолбэк
    return config[:100]

def is_ip_in_subnets(ip_str: str) -> bool:
    """Проверяет, принадлежит ли IP-адрес одной из разрешенных подсетей"""
    try:
        ip = ipaddress.ip_address(ip_str)
        
        if ip.version != 4:
            return False
            
        for network in WHITELIST_NETWORKS:
            if ip in network:
                return True
        return False
    except ValueError:
        return False


def download_and_process_url(url: str) -> list[str]:
    """Загружает и обрабатывает конфиги с одного URL"""
    try:
        data = fetch_url(url)
        if not data:
            return []
        
        data = re.sub(r'(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2)://', r'\n\1://', data)
        lines = data.splitlines()
        
        configs = []
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#') and len(line) > 10:
                if any(line.startswith(p) for p in ['vmess://', 'vless://', 'trojan://', 
                                                     'ss://', 'ssr://', 'tuic://', 
                                                     'hysteria://', 'hysteria2://']):
                    configs.append(line)
                elif '@' in line and ':' in line and line.count(':') >= 2:
                    configs.append(line)
        
        try:
            repo_name = url.split('/')[3] if '/' in url else 'unknown'
        except:
            repo_name = 'unknown'
        log("✅ " + repo_name + ": " + str(len(configs)) + " конфигов")
        return configs
        
    except Exception as e:
        error_msg = str(e)
        if len(error_msg) > 100:
            error_msg = error_msg[:100]
        log("Ошибка обработки " + url + ": " + error_msg)
        return []
    

def add_numbering_to_name(config: str, number: int) -> str:
    """Добавляет нумерацию и вотермарк в поле name конфига"""
    try:
        if config.startswith("vmess://"):
            try:
                payload = config[8:]
                rem = len(payload) % 4
                if rem:
                    payload += '=' * (4 - rem)
                
                decoded = base64.b64decode(payload).decode('utf-8', errors='ignore')
                
                if decoded.startswith('{'):
                    j = json.loads(decoded)
                    existing_ps = j.get('ps', '')
                    
                    flag = ""
                    flag_match = re.search(r'[\U0001F1E6-\U0001F1FF]{2}', existing_ps)
                    if flag_match:
                        flag = flag_match.group(0) + " "
                    
                    new_name = f"{number}. {flag}VMESS | TG: @wlrustg"
                    j['ps'] = new_name
                    
                    new_json = json.dumps(j, separators=(',', ':'))
                    encoded = base64.b64encode(new_json.encode()).decode()
                    return f"vmess://{encoded}"
            except Exception:
                pass
            return config
            
        elif config.startswith("vless://"):
            parsed = urllib.parse.urlparse(config)
            
            existing_fragment = urllib.parse.unquote(parsed.fragment) if parsed.fragment else ""
            
            flag = ""
            flag_match = re.search(r'[\U0001F1E6-\U0001F1FF]{2}', existing_fragment)
            if flag_match:
                flag = flag_match.group(0) + " "
            
            new_name = f"{number}. {flag}VLESS | TG: @wlrustg"
            
            new_fragment = urllib.parse.quote(new_name, safe='')
            
            new_parsed = parsed._replace(fragment=new_fragment)
            new_config = urllib.parse.urlunparse(new_parsed)
            
            return new_config
            
        elif config.startswith("trojan://"):
            parsed = urllib.parse.urlparse(config)
            
            existing_fragment = urllib.parse.unquote(parsed.fragment) if parsed.fragment else ""
            
            flag = ""
            flag_match = re.search(r'[\U0001F1E6-\U0001F1FF]{2}', existing_fragment)
            if flag_match:
                flag = flag_match.group(0) + " "
            
            new_name = f"{number}. {flag}TROJAN | TG: @wlrustg"
            
            new_fragment = urllib.parse.quote(new_name, safe='')
            
            new_parsed = parsed._replace(fragment=new_fragment)
            new_config = urllib.parse.urlunparse(new_parsed)
            
            return new_config
            
        elif config.startswith("ss://"):
            parsed = urllib.parse.urlparse(config)
            
            existing_fragment = urllib.parse.unquote(parsed.fragment) if parsed.fragment else ""
            
            name_from_query = ""
            if not existing_fragment and parsed.query:
                params = urllib.parse.parse_qs(parsed.query)
                if 'name' in params:
                    name_from_query = urllib.parse.unquote(params['name'][0])
            
            existing_name = existing_fragment or name_from_query
            
            flag = ""
            flag_match = re.search(r'[\U0001F1E6-\U0001F1FF]{2}', existing_name)
            if flag_match:
                flag = flag_match.group(0) + " "
            
            new_name = f"{number}. {flag}SS | TG: @wlrustg"
            
            new_fragment = urllib.parse.quote(new_name, safe='')
            
            new_parsed = parsed._replace(fragment=new_fragment)
            new_config = urllib.parse.urlunparse(new_parsed)
            
            return new_config
            
        else:
            if '#' in config:
                base_part, fragment = config.rsplit('#', 1)
                existing_fragment = urllib.parse.unquote(fragment)
                
                flag = ""
                flag_match = re.search(r'[\U0001F1E6-\U0001F1FF]{2}', existing_fragment)
                if flag_match:
                    flag = flag_match.group(0) + " "
                
                config_type = "CONFIG"
                if config.startswith("ssr://"):
                    config_type = "SSR"
                elif config.startswith("tuic://"):
                    config_type = "TUIC"
                elif config.startswith("hysteria://"):
                    config_type = "HYSTERIA"
                elif config.startswith("hysteria2://"):
                    config_type = "HYSTERIA2"
                
                new_name = f"{number}. {flag}{config_type} | TG: @wlrustg"
                new_fragment = urllib.parse.quote(new_name, safe='')
                
                return f"{base_part}#{new_fragment}"
            else:
                config_type = "CONFIG"
                if config.startswith("ssr://"):
                    config_type = "SSR"
                elif config.startswith("tuic://"):
                    config_type = "TUIC"
                elif config.startswith("hysteria://"):
                    config_type = "HYSTERIA"
                elif config.startswith("hysteria2://"):
                    config_type = "HYSTERIA2"
                
                new_name = f"{number}. {config_type} | TG: @wlrustg"
                new_fragment = urllib.parse.quote(new_name, safe='')
                
                return f"{config}#{new_fragment}"
                
    except Exception as e:
        log(f"Ошибка добавления нумерации к конфигу: {str(e)[:100]}")
        return config


def extract_existing_info(config: str) -> tuple:
    """Извлекает существующие информацию из конфига: номер, флаг, вотермарк"""
    config_clean = config.strip()
    
    number_match = re.search(r'(?:#?\s*)(\d{1,3})(?:\.|\s+|$)', config_clean)
    number = number_match.group(1) if number_match else None
    
    flag_match = re.search(r'[\U0001F1E6-\U0001F1FF]{2}', config_clean)
    flag = flag_match.group(0) if flag_match else ""
    
    tg_match = re.search(r'TG\s*:\s*@wlrustg', config_clean, re.IGNORECASE)
    tg = tg_match.group(0) if tg_match else ""
    
    return number, flag, tg


def process_configs_with_numbering(configs: list[str]) -> list[str]:
    """Добавляет нумерацию и вотермарк в поле name конфигов"""
    processed_configs = []
    
    for i, config in enumerate(configs, 1):
        existing_number, _, existing_tg = extract_existing_info(config)
        
        # Если уже есть номер и наш вотермарк, не меняем
        if existing_number and "TG: @wlrustg" in config:
            processed_configs.append(config)
        else:
            # Добавляем нумерацию
            processed = add_numbering_to_name(config, i)
            processed_configs.append(processed)
    
    return processed_configs


def merge_and_deduplicate(all_configs: list[str]) -> tuple[list[str], list[str]]:
    """Объединяет и дедуплицирует конфиги, возвращает два списка: все конфиги и whitelist конфиги"""
    if not all_configs:
        return [], []
    
    seen_full = set()
    seen_config_keys = set()  # Уникальные ключи конфигов (по параметрам)
    unique_configs = []
    whitelist_configs = []
    duplicate_count = 0
    
    for config in all_configs:
        config = config.strip()
        if not config or config in seen_full:
            duplicate_count += 1
            continue
        seen_full.add(config)
        
        # Генерируем уникальный ключ конфига на основе его параметров
        config_key = generate_config_key(config)
        if config_key and config_key in seen_config_keys:
            duplicate_count += 1
            continue
        seen_config_keys.add(config_key)
        
        unique_configs.append(config)
        
        # Проверка на whitelist (по IP)
        host_port = extract_host_port(config)
        if host_port:
            host = host_port[0]
            try:
                ip = ipaddress.ip_address(host)
                if ip.version == 4 and is_ip_in_subnets(str(ip)):
                    whitelist_configs.append(config)
            except ValueError:
                pass
    
    if duplicate_count > 0:
        log(f"🔍 Удалено {duplicate_count} дубликатов (полных или по параметрам)")
    
    return unique_configs, whitelist_configs

def save_to_file(configs: list[str], file_type: str, description: str = "", add_numbering: bool = False):
    """Сохраняет конфиги в файл с динамическим именем"""
    if file_type == "merged":
        filepath = PATHS["merged"]
        filename = os.path.basename(filepath)
    elif file_type == "wl":
        filepath = PATHS["wl"]
        filename = os.path.basename(filepath)
    else:
        filepath = file_type  # Прямой путь
        filename = os.path.basename(filepath)
    
    try:
        os.makedirs(PATHS["base_dir"], exist_ok=True)
        
        with open(filepath, "w", encoding="utf-8", errors="replace") as f:
            if 'Whitelist' in description:
               f.write("#profile-title: WL RUS (wl.txt)\n")
            else:
               f.write("#profile-title: WL RUS (all)\n")
        
        
            f.write("#profile-update-interval: 24\n")
            f.write("#announce: Сервера из подписки должны использоваться ТОЛЬКО при белых списках!\n")
            f.write(f"# Обновлено: {offset}\n")
            f.write(f"# Всего конфигов: {len(configs)}\n")
            f.write("#" * 50 + "\n\n")
            
            # Обработка конфигов
            if add_numbering:
                processed_configs = process_configs_with_numbering(configs)
            else:
                processed_configs = configs
            
            for config in processed_configs:
                f.write(config + "\n")
        
        log(f"💾 Сохранено {len(configs)} конфигов в {filename}")
        
    except Exception as e:
        log(f"Ошибка сохранения файла {filename}: {str(e)}")

def upload_to_github(filename: str, remote_path: str = None, branch: str = "main"):
    """Загружает файл на GitHub в указанную ветку"""
    if not REPO:
        log("Пропускаю загрузку на GitHub (нет подключения)")
        return
    
    if not os.path.exists(filename):
        log(f"Файл {filename} не найден для загрузки")
        return
    
    try:
        # Читаем файл в бинарном режиме, затем декодируем
        with open(filename, "rb") as f:
            binary_content = f.read()
        
        # Декодируем содержимое с обработкой ошибок
        try:
            content = binary_content.decode("utf-8")
        except UnicodeDecodeError:
            # Если не удается декодировать как UTF-8, пробуем другие кодировки
            log(f"⚠️  Ошибка декодирования UTF-8 в файле {filename}, пробую другие кодировки...")
            try:
                content = binary_content.decode("utf-8-sig")  # UTF-8 с BOM
            except UnicodeDecodeError:
                try:
                    content = binary_content.decode("cp1251")  # Windows-1251
                except UnicodeDecodeError:
                    try:
                        content = binary_content.decode("latin-1")  # Latin-1
                    except UnicodeDecodeError:
                        # В крайнем случае игнорируем ошибки
                        content = binary_content.decode("utf-8", errors="replace")
                        log(f"⚠️  Использована замена некорректных символов в файле {filename}")
        
        if remote_path is None:
            remote_path = filename
        
        try:
            file_in_repo = REPO.get_contents(remote_path, ref=branch)
            current_sha = file_in_repo.sha
            
            remote_content = file_in_repo.decoded_content.decode("utf-8", errors="replace")
            if remote_content == content:
                log(f"Файл {remote_path} не изменился в ветке {branch}")
                return
            
            REPO.update_file(
                path=remote_path,
                message="🤖 Авто-обновление: " + offset,
                content=content,
                sha=current_sha,
                branch=branch
            )
            log(f"⬆️ Файл {remote_path} обновлён на GitHub в ветке {branch}")
            
        except GithubException as e:
            if e.status == 404:
                REPO.create_file(
                    path=remote_path,
                    message="🤖 Первое создание: " + offset,
                    content=content,
                    branch=branch
                )
                log(f"🆕 Файл {remote_path} создан на GitHub в ветке {branch}")
            else:
                error_msg = e.data.get('message', str(e))
                log("Ошибка GitHub: " + error_msg)
                
    except Exception as e:
        log("Ошибка при загрузке на GitHub: " + str(e))

def update_readme(total_configs: int, wl_configs_count: int):
    """Обновляет README.md со статистикой"""
    if not REPO:
        log("Пропускаю обновление README (нет подключения)")
        return
    
    try:
        try:
            readme_file = REPO.get_contents("README.md")
            old_content = readme_file.decoded_content.decode("utf-8")
        except GithubException:
            old_content = "# Объединенные конфиги VPN\n\n"
        
        # Формируем ссылки на файлы
        raw_url_merged = "https://github.com/" + REPO_NAME + "/raw/main/merged.txt"
        raw_url_wl = "https://github.com/" + REPO_NAME + "/raw/main/githubmirror/wl.txt"
        raw_url_selected = "https://github.com/" + REPO_NAME + "/raw/main/githubmirror/selected.txt"
        
        # Разделяем время и дату
        time_parts = offset.split(" | ")
        time_part = time_parts[0] if len(time_parts) > 0 else ""
        date_part = time_parts[1] if len(time_parts) > 1 else ""
        
        new_section = "\n## 📊 Статус обновления\n\n"
        new_section += "| Файл | Описание | Конфигов | Время обновления | Дата |\n"
        new_section += "|------|----------|----------|------------------|------|\n"
        new_section += f"| [`merged.txt`]({raw_url_merged}) | Все конфиги из {len(URLS)} источников | {total_configs} | {time_part} | {date_part} |\n"
        new_section += f"| [`wl.txt`]({raw_url_wl}) | Только конфиги из {len(WHITELIST_SUBNETS)} подсетей | {wl_configs_count} | {time_part} | {date_part} |\n"
        new_section += f"| [`selected.txt`]({raw_url_selected}) | Отборные админами конфиги, самый надежный список | не знаю | {time_part} | {date_part} |\n\n"
        
        # Обновляем файл
        sha = readme_file.sha if 'readme_file' in locals() else None
        REPO.update_file(
            path="README.md",
            message="📝 Обновление README: " + str(total_configs) + " конфигов, " + str(wl_configs_count) + " в whitelist",
            content=new_section,
            sha=sha
        )
        log("📝 README.md обновлён")
        
    except Exception as e:
        log("Ошибка обновления README: " + str(e))

def process_selected_file():
    """Обрабатывает файл selected.txt с ручными серверами, включая дедупликацию"""
    selected_file = PATHS["selected"]
    
    if os.path.exists(selected_file):
        try:
            with open(selected_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
        except Exception as e:
            log(f"❌ Ошибка чтения selected.txt: {str(e)}")
            return []
        
        configs = []
        manual_comments = []
        
        skip_auto_header = False
        for line in lines:
            stripped = line.strip()
            
            if stripped.startswith("#profile-title: WL RUS (selected)"):
                skip_auto_header = True
                continue
            
            if skip_auto_header:
                if stripped.startswith("#") or not stripped:
                    continue
                else:
                    skip_auto_header = False
            
            if not stripped:
                if manual_comments and manual_comments[-1] != "":
                    manual_comments.append("")
            elif stripped.startswith('#'):
                manual_comments.append(stripped)
            else:
                if any(stripped.startswith(p) for p in ['vmess://', 'vless://', 'trojan://', 
                                                         'ss://', 'ssr://', 'tuic://', 
                                                         'hysteria://', 'hysteria2://']):
                    configs.append((len(configs), stripped))
                elif '@' in stripped and ':' in stripped and stripped.count(':') >= 2:
                    configs.append((len(configs), stripped))
        
        if configs:
            try:
                # ДЕДУПЛИКАЦИЯ С УЧЕТОМ ВСЕХ ПАРАМЕТРОВ КОНФИГА
                config_indices = [idx for idx, _ in configs]
                raw_configs = [config for _, config in configs]
                
                seen_full = set()
                seen_config_keys = set()  # Уникальные ключи конфигов (по параметрам)
                unique_configs_with_index = []
                duplicates_count = 0
                
                for idx, config in zip(config_indices, raw_configs):
                    if config in seen_full:
                        duplicates_count += 1
                        continue
                    seen_full.add(config)
                    
                    # Генерируем уникальный ключ конфига на основе его параметров
                    config_key = generate_config_key(config)
                    if config_key and config_key in seen_config_keys:
                        duplicates_count += 1
                        continue
                    seen_config_keys.add(config_key)
                    
                    unique_configs_with_index.append((idx, config))
                
                if duplicates_count > 0:
                    log(f"🔍 Найдено {duplicates_count} дубликатов в selected.txt")
                
                # Обрабатываем конфиги с нумерацией
                unique_configs = [config for _, config in unique_configs_with_index]
                processed_configs = process_configs_with_numbering(unique_configs)
                
                processed_by_index = {}
                for (idx, _), processed in zip(unique_configs_with_index, processed_configs):
                    processed_by_index[idx] = processed
                
                # Сохраняем с одним заголовком
                with open(selected_file, "w", encoding="utf-8") as f:
                    f.write("#profile-title: WL RUS (selected)\n")
                    f.write("#profile-update-interval: 24\n")
                    f.write("#announce: Сервера из подписки должны использоваться ТОЛЬКО при белых списках!\n")
                    
                    if manual_comments:
                        f.write("\n")
                        for comment in manual_comments:
                            if comment == "":
                                f.write("\n")
                            else:
                                f.write(comment + "\n")
                    
                    if processed_configs:
                        if manual_comments:
                            f.write("\n")
                        
                        for i in range(len(processed_configs)):
                            if i in processed_by_index:
                                f.write(processed_by_index[i] + "\n")
                                if i < len(processed_configs) - 1:
                                    f.write("\n")
                
                log(f"✅ Обработан selected.txt: {len(processed_configs)} конфигов (удалено {duplicates_count} дубликатов)")
                return processed_configs
                
            except Exception as e:
                log(f"❌ Ошибка обработки конфигов в selected.txt: {str(e)}")
                return []
        else:
            log("ℹ️ В selected.txt нет конфигов для обработки")
            return []
    else:
        log("ℹ️ Файл selected.txt не найден")
        return []

def filter_excluded_configs(configs, exclude_patterns=None, settings=None, excluded_file=None):
    """
    Фильтрует конфиги по паттернам исключения
    """
    if exclude_patterns is None:
        exclude_patterns = EXCLUDE_PATTERNS
    
    if settings is None:
        settings = EXCLUDE_SETTINGS.copy()
    else:
        settings = settings.copy()
    
    if excluded_file:
        settings["excluded_file"] = excluded_file
    
    filtered_configs = []
    excluded_configs = []
    exclusion_stats = {}
    
    # Подготовка паттернов (регистр)
    if not settings.get("case_sensitive", False):
        exclude_patterns = [p.lower() for p in exclude_patterns]
    
    for config in configs:
        config_for_check = config if settings.get("case_sensitive", False) else config.lower()
        excluded = False
        reason = ""
        
        # Проверка каждого паттерна
        for pattern in exclude_patterns:
            # Разные типы проверок в зависимости от паттерна
            if pattern.startswith("#"):  # Исключение по remark
                remark_pattern = pattern[1:]  # Убираем #
                if f"#{remark_pattern}" in config_for_check:
                    excluded = True
                    reason = f"remark содержит: {pattern}"
                    break
                    
            elif pattern.startswith("@"):  # Исключение по адресу
                addr_pattern = pattern[1:]  # Убираем @
                # Ищем адрес после @ и до : или ?
                if f"@{addr_pattern}" in config_for_check:
                    excluded = True
                    reason = f"адрес содержит: {pattern}"
                    break
                    
            elif pattern.startswith("/"):  # Исключение по path
                if f"path={pattern}" in config_for_check or f"path%3D{pattern}" in config_for_check:
                    excluded = True
                    reason = f"path содержит: {pattern}"
                    break
                    
            else:  # Общая проверка по подстроке
                if pattern in config_for_check:
                    excluded = True
                    reason = f"содержит: {pattern}"
                    break
        
        if excluded:
            excluded_configs.append(config)
            # Статистика по причинам
            if reason in exclusion_stats:
                exclusion_stats[reason] += 1
            else:
                exclusion_stats[reason] = 1
        else:
            filtered_configs.append(config)
    
    # Вывод статистики
    if settings.get("log_excluded", True):
        log(f"🚫 Фильтрация исключений:")
        log(f"   Всего конфигов до фильтрации: {len(configs)}")
        log(f"   Исключено: {len(excluded_configs)}")
        log(f"   Осталось после исключений: {len(filtered_configs)}")
        
        if exclusion_stats:
            log(f"   Причины исключений:")
            for reason, count in exclusion_stats.items():
                log(f"     • {reason}: {count}")
    
    # Сохранение исключенных конфигов
    if settings.get("save_excluded", True) and excluded_configs:
        excluded_filename = settings.get("excluded_file", "excluded.txt")
        with open(excluded_filename, 'w', encoding='utf-8') as f:
            f.write('\n'.join(excluded_configs))
        log(f"💾 Исключенные конфиги сохранены в {excluded_filename} ({len(excluded_configs)} шт.)")
    
    return filtered_configs, excluded_configs

def upload_to_cloud_ru(file_path: str, s3_path: str = None):
    """Загружает файл в bucket Cloud.ru по S3 API"""
    if not all([CLOUD_RU_ENDPOINT, CLOUD_RU_ACCESS_KEY, CLOUD_RU_SECRET_KEY, CLOUD_RU_BUCKET]):
        log("❌ Пропускаю загрузку в Cloud.ru: отсутствуют необходимые переменные окружения")
        return
    
    try:
        # Пробуем импортировать boto3
        try:
            import boto3
            from botocore.config import Config
        except ImportError:
            log("❌ Модуль boto3 не установлен. Установите: pip install boto3")
            return
        
        if not os.path.exists(file_path):
            log(f"❌ Файл {file_path} не найден для загрузки в Cloud.ru")
            return
        
        # Определяем имя файла в bucket
        if s3_path is None:
            s3_path = os.path.basename(file_path)
        
        log(f"☁️  Загружаю {file_path} в Cloud.ru bucket {CLOUD_RU_BUCKET} как {s3_path}")
        
        # Настройка клиента S3 для Cloud.ru
        s3_client = boto3.client(
            's3',
            endpoint_url=CLOUD_RU_ENDPOINT,
            aws_access_key_id=CLOUD_RU_ACCESS_KEY,
            aws_secret_access_key=CLOUD_RU_SECRET_KEY,
            region_name=CLOUD_RU_REGION,
            config=Config(
                signature_version='s3v4',
                s3={'addressing_style': 'path'}
            )
        )
        
        # Загружаем файл
        with open(file_path, 'rb') as f:
            s3_client.put_object(
                Bucket=CLOUD_RU_BUCKET,
                Key=s3_path,
                Body=f,
                ContentType='text/plain; charset=utf-8',
            )
        
        log(f"✅ Файл успешно загружен в Cloud.ru: {s3_path}")
        
        # Формируем ссылку на файл
        file_url = f"{CLOUD_RU_ENDPOINT}/{CLOUD_RU_BUCKET}/{s3_path}"
        log(f"🔗 Ссылка на файл: {file_url}")
        
    except Exception as e:
        error_msg = str(e)
        # Более подробное логирование ошибки
        if "AuthorizationHeaderMalformed" in error_msg:
            log(f"❌ Ошибка авторизации Cloud.ru: неверный регион или endpoint. Убедитесь, что регион: {CLOUD_RU_REGION}")
        else:
            log(f"❌ Ошибка при загрузке в Cloud.ru: {error_msg[:200]}")
        
def upload_to_gitverse(filename: str, remote_path: str = None):
    """Загружает файл на GitVerse через API с корректным версионированием"""
    if not GITVERSE_TOKEN:
        log("❌ Пропускаю загрузку на GitVerse: отсутствует токен")
        return
    
    if not os.path.exists(filename):
        log(f"❌ Файл {filename} не найден для загрузки на GitVerse")
        return
    
    try:
        # 1. Чтение файла
        with open(filename, "r", encoding="utf-8") as f:
            content = f.read()
        
        remote_path = remote_path or os.path.basename(filename)
        
        # 2. Определение базового URL и первичных заголовков
        base_url = "https://api.gitverse.ru"
        
        # 3. ОСНОВНОЕ ИСПРАВЛЕНИЕ: правильный формат Accept-заголовка
        primary_headers = {
            "Authorization": f"Bearer {GITVERSE_TOKEN}",
            "Accept": "application/vnd.gitverse.object+json;version=1",  # <-- ИСПРАВЛЕНО
            "Content-Type": "application/json"
        }
        
        # 4. Проверка доступности API и получение актуальной версии
        log(f"🔍 Проверяю доступ к API GitVerse...")
        latest_version = None
        
        try:
            test_response = requests.get(
                f"{base_url}/user",
                headers=primary_headers,
                timeout=10
            )
            
            # Если получили 400, возможно, версия устарела
            if test_response.status_code == 400:
                latest_version = test_response.headers.get('Gitverse-Api-Latest-Version')
                if latest_version:
                    log(f"⚠️  Версия 1 устарела. Актуальная версия: {latest_version}")
                    # Обновляем заголовок с актуальной версией
                    primary_headers["Accept"] = f"application/vnd.gitverse.object+json;version={latest_version}"
                    
                    # Повторяем проверку с новой версией
                    test_response = requests.get(
                        f"{base_url}/user",
                        headers=primary_headers,
                        timeout=10
                    )
            
            if test_response.status_code == 200:
                user_info = test_response.json()
                log(f"✅ Аутентифицирован как: {user_info.get('login', 'Unknown')}")
                log(f"✅ Версия API: {primary_headers['Accept'].split('version=')[1]}")
            elif test_response.status_code in [401, 403]:
                log(f"❌ Ошибка доступа ({test_response.status_code}). Проверьте токен.")
                return
            else:
                log(f"⚠️  Неожиданный ответ от API: {test_response.status_code}")
                
        except requests.exceptions.RequestException as e:
            log(f"❌ Ошибка подключения: {str(e)[:100]}")
            return
        
        # 5. Формируем URL для работы с файлом (согласно п.6 документации)
        content_url = f"{base_url}/repos/{GITVERSE_REPO_OWNER}/{GITVERSE_REPO_NAME}/contents/{remote_path}"
        
        # 6. Кодируем содержимое
        content_b64 = base64.b64encode(content.encode('utf-8')).decode('utf-8')
        
        # 7. Проверяем существование файла и получаем SHA
        sha = None
        try:
            params = {'ref': GITVERSE_BRANCH} if GITVERSE_BRANCH else {}
            get_response = requests.get(
                content_url,
                headers=primary_headers,
                params=params,
                timeout=10
            )
            
            if get_response.status_code == 200:
                existing_file = get_response.json()
                sha = existing_file.get('sha', '')
                log(f"📄 Файл существует. SHA: {sha[:8]}...")
            elif get_response.status_code != 404:
                log(f"⚠️  Не удалось проверить файл ({get_response.status_code})")
                
        except requests.exceptions.RequestException:
            pass  # Пропускаем ошибку проверки
        
        # 8. Подготовка данных для PUT запроса
        data = {
            "message": f"🤖 Авто-обновление: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "content": content_b64,
        }
        
        if GITVERSE_BRANCH:
            data["branch"] = GITVERSE_BRANCH
        if sha:
            data["sha"] = sha  # Обязательно для обновления существующего файла
        
        # 9. Выполняем основной запрос (PUT)
        log(f"📤 {'Обновляю' if sha else 'Создаю'} файл '{remote_path}'...")
        try:
            put_response = requests.put(content_url, headers=primary_headers, json=data, timeout=15)
            
            if put_response.status_code in [200, 201]:
                action = "обновлён" if sha else "создан"
                log(f"✅ Файл успешно {action}!")
                
                # Проверяем, не устарела ли используемая версия API
                if put_response.headers.get('Gitverse-Api-Deprecation') == 'true':
                    latest = put_response.headers.get('Gitverse-Api-Latest-Version')
                    decommission = put_response.headers.get('Gitverse-Api-Decommissioning')
                    log(f"⚠️  ВНИМАНИЕ: Используемая версия API устарела!")
                    log(f"    Актуальная версия: {latest}")
                    log(f"    Отключение: {decommission}")
                    
            elif put_response.status_code == 400:
                error_text = put_response.text[:200]
                log(f"❌ Ошибка 400: {error_text}")
                
                # Если в ответе есть указание на последнюю версию
                latest_in_response = put_response.headers.get('Gitverse-Api-Latest-Version')
                if latest_in_response and latest_in_response != latest_version:
                    log(f"🔄 Обнаружена новая актуальная версия: {latest_in_response}")
                    
            elif put_response.status_code == 403:
                log(f"❌ Ошибка 403: Доступ запрещён")
                log(f"   Проверьте:")
                log(f"   1. Существует ли репозиторий '{GITVERSE_REPO_OWNER}/{GITVERSE_REPO_NAME}'")
                log(f"   2. Имеет ли токен права на запись (scope 'repo' или 'write:repo')")
                log(f"   Полный ответ: {put_response.text[:300]}")
                
            elif put_response.status_code == 409:
                log(f"❌ Конфликт: SHA файла изменился. Обновите локальный SHA.")
                
            else:
                log(f"❌ Ошибка {put_response.status_code}: {put_response.text[:200]}")
                
        except requests.exceptions.RequestException as e:
            log(f"❌ Сетевая ошибка: {str(e)[:100]}")
            
    except Exception as e:
        log(f"❌ Общая ошибка: {str(e)}")
    
def main():
    """Основная функция"""

    log("📥 Загрузка конфигов...")
    
    all_configs = []
    max_workers = min(DEFAULT_MAX_WORKERS, len(URLS))
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {}
        for url in URLS:
            future = executor.submit(download_and_process_url, url)
            futures[future] = url
        
        for future in concurrent.futures.as_completed(futures):
            url = futures[future]
            try:
                configs = future.result(timeout=30)
                if configs:
                    all_configs.extend(configs)
            except Exception as e:
                error_msg = str(e)
                if len(error_msg) > 50:
                    error_msg = error_msg[:50]
                log("Таймаут или ошибка для " + url + ": " + error_msg)
    
    log("📊 Скачано всего: " + str(len(all_configs)) + " конфигов")
    
    # 2. Обрабатываем selected.txt (ручные серверы)
    log("🔧 Обработка selected.txt...")
    selected_configs = process_selected_file()
    
    if not all_configs:
        log("❌ Не удалось загрузить ни одного конфига")
        return
    
    # 3. Добавляем selected конфиги в общий список
    all_configs.extend(selected_configs)
    
    # 4. Дедупликация и сортировка по подсетям
    log("🔄 Дедупликация и фильтрация...")
    unique_configs, whitelist_configs = merge_and_deduplicate(all_configs)
    log("🔄 После дедупликации: " + str(len(unique_configs)) + " конфигов")
    log("🛡️ Whitelist конфигов: " + str(len(whitelist_configs)))
    
    # 5. ФИЛЬТРАЦИЯ ИСКЛЮЧЕНИЙ - НОВЫЙ ЭТАП
    log("🚫 Применение списка исключений...")
    
    # Фильтруем основной список (merged)
    filtered_unique_configs, excluded_unique = filter_excluded_configs(
        unique_configs, 
        excluded_file="excluded_merged.txt"
    )
    
    # Фильтруем whitelist список
    filtered_whitelist_configs, excluded_whitelist = filter_excluded_configs(
        whitelist_configs,
        excluded_file="excluded_wl.txt"
    )
    
    # Обновляем переменные для дальнейшего использования
    unique_configs = filtered_unique_configs
    whitelist_configs = filtered_whitelist_configs
    
    log(f"✅ После исключений:")
    log(f"   • merged: {len(unique_configs)} конфигов (исключено {len(excluded_unique)})")
    log(f"   • whitelist: {len(whitelist_configs)} конфигов (исключено {len(excluded_whitelist)})")
    
    # 6. Сохраняем локально
    os.makedirs("confs", exist_ok=True)
    
    # СОХРАНЯЕМ merged.txt С НУМЕРАЦИЕЙ (включая конфиги из selected.txt)
    save_to_file(unique_configs, "merged", "Объединенные конфиги (после исключений)", add_numbering=True)
    save_to_file(whitelist_configs, "wl", "Whitelist конфиги (после исключений)", add_numbering=True)
    
    # 7. Загружаем на GitHub
    log("🌐 Загрузка на GitHub...")
    upload_to_github(PATHS["merged"])
    upload_to_github(PATHS["wl"])
    upload_to_github(PATHS["selected"])
    
    # 8. Загружаем в Cloud.ru
    log("☁️  Начинаю загрузку в Cloud.ru...")
    files_to_upload = {
        "merged.txt": PATHS["merged"],
        "wl.txt": PATHS["wl"],
        "selected.txt": PATHS["selected"]
    }
    
    for s3_name, local_path in files_to_upload.items():
        if os.path.exists(local_path):
            upload_to_cloud_ru(local_path, s3_name)
        else:
            log(f"⚠️  Файл {local_path} не найден, пропускаю загрузку в Cloud.ru")

    if GITVERSE_TOKEN:
        log("🚀 Начинаю загрузку на GitVerse...")
        gitverse_files = {
            "merged.txt": PATHS["merged"],
            "wl.txt": PATHS["wl"],
            "selected.txt": PATHS["selected"]
        }
    
        # Создаем сессию для повторного использования соединений
        for remote_name, local_path in gitverse_files.items():
            if os.path.exists(local_path):
                upload_to_gitverse(local_path, remote_name)
            else:
                log(f"⚠️  Файл {local_path} не найден, пропускаю загрузку на GitVerse")
    else:
        log("ℹ️  Токен GitVerse не задан, пропускаю загрузку")
    
    # 9. Обновляем README
    update_readme(len(unique_configs), len(whitelist_configs))
    
    # 10. Выводим итоги
    log("=" * 60)
    log("📊 ИТОГИ:")
    log("   🌐 Источников: " + str(len(URLS)))
    log("   📥 Скачано из URL: " + str(len(all_configs) - len(selected_configs)))
    log("   🔧 Из selected.txt: " + str(len(selected_configs)))
    log("   🔄 Уникальных (после дедупликации): " + str(len(filtered_unique_configs)))
    log("   🚫 Исключено паттернами: " + str(len(excluded_unique) + len(excluded_whitelist)))
    log("   🛡️ Whitelist (после исключений): " + str(len(filtered_whitelist_configs)))
    log("   💾 Основные файлы:")
    log(f"      • {PATHS['merged']} ({len(unique_configs)} конфигов)")
    log(f"      • {PATHS['wl']} ({len(whitelist_configs)} конфигов)")
    log(f"      • {PATHS['selected']}")
    log(f"      • excluded_merged.txt ({len(excluded_unique)} конфигов)")
    log(f"      • excluded_wl.txt ({len(excluded_whitelist)} конфигов)")
    log("   ☁️  Cloud.ru bucket: " + (CLOUD_RU_BUCKET if CLOUD_RU_BUCKET else "не настроен"))
    log("   🚀 GitVerse: " + ("настроен" if GITVERSE_TOKEN else "не настроен"))
    log("=" * 60)
    
    # Проверяем изменения для GitHub Actions
    log("💾 Проверка изменений...")
    log(f"📊 Конфигов в merged.txt: {len(unique_configs)}")
    log(f"🛡️ Конфигов в wl.txt: {len(whitelist_configs)}")
    
    # Выводим логи
    print("\n📋 ЛОГИ ВЫПОЛНЕНИЯ (" + offset + "):")
    print("=" * 60)
    for line in LOGS_BY_FILE[0]:
        print(line)


if __name__ == "__main__":
    main()
