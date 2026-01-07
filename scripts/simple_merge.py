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

# Получение текущего времени по часовому поясу Европа/Москва
zone = zoneinfo.ZoneInfo("Europe/Moscow")
thistime = datetime.now(zone)
offset = thistime.strftime("%H:%M | %d.%m.%Y")

# Получение GitHub токена из переменных окружения
GITHUB_TOKEN = os.environ.get("MY_TOKEN", "")
REPO_NAME = os.environ.get("GITHUB_REPOSITORY", "bywarm/wlrusparser")

if GITHUB_TOKEN:
    g = Github(auth=Auth.Token(GITHUB_TOKEN))
else:
    g = Github()

try:
    REPO = g.get_repo(REPO_NAME)
except Exception as e:
    log("Ошибка подключения к GitHub: " + str(e)[:100])
    REPO = None


CONFIG = {
    "output_dir": "githubmirror",          # Основная папка
    "output_dir_suffix": "",               # Суффикс папки
    "merged_file": "merged.txt",           # Все конфиги
    "wl_file": "wl.txt",                   # Whitelist конфиги
    "selected_file": "selected.txt",       # Ручные серверы
    "custom_prefix": "wlrus_",             # Префикс для файлов
    "use_date_suffix": False,              # Добавлять дату к именам?
    "rotate_folders": False,               # Ротировать папки каждый месяц?
}


if CONFIG["rotate_folders"]:
    month = datetime.now().month
    year_short = datetime.now().strftime("%y")
    CONFIG["output_dir_suffix"] = f"_{year_short}{month:02d}"

def get_paths():
    """Возвращает актуальные пути к файлам"""
    base_dir = CONFIG["output_dir"] + CONFIG["output_dir_suffix"]
    
    # Суффикс для файлов (если нужно)
    file_suffix = ""
    if CONFIG["use_date_suffix"]:
        file_suffix = f"_{datetime.now().strftime('%d%m')}"
    
    paths = {
        "base_dir": base_dir,
        "merged": f"{base_dir}/{CONFIG['custom_prefix']}{CONFIG['merged_file'].replace('.txt', '')}{file_suffix}.txt",
        "wl": f"{base_dir}/{CONFIG['custom_prefix']}{CONFIG['wl_file'].replace('.txt', '')}{file_suffix}.txt",
        "selected": f"{base_dir}/{CONFIG['selected_file']}",
        "gh_pages_merged": f"{CONFIG['custom_prefix']}merged{file_suffix}.txt",
        "gh_pages_wl": f"{CONFIG['custom_prefix']}wl{file_suffix}.txt",
    }
    return paths

WHITELIST_SUBNETS = [
    "95.163.0.0/16",
    "89.208.0.0/16",
    "217.16.0.0/16",
    "5.188.0.0/16",
    "109.120.0.0/16",
    "217.12.0.0/16",
    "176.108.0.0/16",
    "178.154.0.0/16",
    "176.109.0.0/16",
    "176.32.0.0/16",
    "193.53.0.0/16",
    "45.129.0.0/16",
    "37.18.0.0/16",
    "78.159.0.0/16",
    "185.177.0.0/16",
    "45.15.0.0/16",
    "176.122.0.0/16",
    "185.130.0.0/16",
    "37.139.0.0/16",
    "83.166.0.0/16",
    "91.219.0.0/16",
    "51.250.0.0/16",
    "84.201.0.0/16",
    "158.160.0.0/16",
    "130.193.0.0/16"
]
# Преобразуем подсети в объекты ipaddress для быстрой проверки
WHITELIST_NETWORKS = [ipaddress.ip_network(subnet) for subnet in WHITELIST_SUBNETS]

# Источники конфигов
URLS = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
    "https://raw.githubusercontent.com/AvenCores/goida-vpn-configs/refs/heads/main/githubmirror/26.txt",
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
        # VMESS
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
        
        # VLESS / TROJAN / SS
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
        
        # Прямой IP:PORT
        match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})', config)
        if match:
            return match.group(1), int(match.group(2))
        
        # Ищем хост и порт в любой комбинации
        match = re.search(r'([\w\.-]+):(\d{1,5})', config)
        if match:
            host = match.group(1)
            port = int(match.group(2))
            if len(host) > 1 and ('.' in host or host.replace('.', '').replace('-', '').isalnum()):
                return host, port
                
    except Exception:
        pass
    
    return None

def is_ip_in_subnets(ip_str: str) -> bool:
    """Проверяет, принадлежит ли IP-адрес одной из разрешенных подсетей"""
    try:
        ip = ipaddress.ip_address(ip_str)
        
        # Проверяем только IPv4
        if ip.version != 4:
            return False
            
        # Проверяем принадлежность к любой из подсетей
        for network in WHITELIST_NETWORKS:
            if ip in network:
                return True
        return False
    except ValueError:
        # Невалидный IP адрес
        return False


def download_and_process_url(url: str) -> list[str]:
    """Загружает и обрабатывает конфиги с одного URL"""
    try:
        data = fetch_url(url)
        if not data:
            return []
        
        # Разделяем слипшиеся конфиги
        data = re.sub(r'(vmess|vless|trojan|ss|ssr|tuic|hysteria|hysteria2)://', r'\n\1://', data)
        lines = data.splitlines()
        
        configs = []
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#') and len(line) > 10:
                # Проверяем, что это похоже на конфиг
                if any(line.startswith(p) for p in ['vmess://', 'vless://', 'trojan://', 
                                                     'ss://', 'ssr://', 'tuic://', 
                                                     'hysteria://', 'hysteria2://']):
                    configs.append(line)
                # Также принимаем строки, содержащие @host:port
                elif '@' in line and ':' in line and line.count(':') >= 2:
                    configs.append(line)
        
        # Безопасный способ извлечения имени репозитория
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
        # Определяем тип протокола
        if config.startswith("vmess://"):
            # Для VMESS: парсим JSON и меняем поле "ps"
            try:
                payload = config[8:]
                rem = len(payload) % 4
                if rem:
                    payload += '=' * (4 - rem)
                
                decoded = base64.b64decode(payload).decode('utf-8', errors='ignore')
                
                if decoded.startswith('{'):
                    j = json.loads(decoded)
                    # Получаем существующий ps
                    existing_ps = j.get('ps', '')
                    
                    # Извлекаем флаг из существующего ps
                    flag = ""
                    flag_match = re.search(r'[\U0001F1E6-\U0001F1FF]{2}', existing_ps)
                    if flag_match:
                        flag = flag_match.group(0) + " "
                    
                    # Формируем новое имя
                    new_name = f"{number}. {flag}VMESS | TG: @wlrustg"
                    j['ps'] = new_name
                    
                    # Кодируем обратно
                    new_json = json.dumps(j, separators=(',', ':'))
                    encoded = base64.b64encode(new_json.encode()).decode()
                    return f"vmess://{encoded}"
            except Exception:
                pass
            return config
            
        elif config.startswith("vless://"):
            # Для VLESS: имя задается через # (фрагмент)
            parsed = urllib.parse.urlparse(config)
            
            # Извлекаем существующий фрагмент
            existing_fragment = urllib.parse.unquote(parsed.fragment) if parsed.fragment else ""
            
            # Извлекаем флаг из существующего фрагмента
            flag = ""
            flag_match = re.search(r'[\U0001F1E6-\U0001F1FF]{2}', existing_fragment)
            if flag_match:
                flag = flag_match.group(0) + " "
            
            # Формируем новое имя
            new_name = f"{number}. {flag}VLESS | TG: @wlrustg"
            
            # Создаем новый фрагмент
            new_fragment = urllib.parse.quote(new_name, safe='')
            
            # Собираем URL с новым фрагментом
            new_parsed = parsed._replace(fragment=new_fragment)
            new_config = urllib.parse.urlunparse(new_parsed)
            
            return new_config
            
        elif config.startswith("trojan://"):
            # Для Trojan: имя также может быть в фрагменте
            parsed = urllib.parse.urlparse(config)
            
            # Извлекаем существующий фрагмент
            existing_fragment = urllib.parse.unquote(parsed.fragment) if parsed.fragment else ""
            
            # Извлекаем флаг
            flag = ""
            flag_match = re.search(r'[\U0001F1E6-\U0001F1FF]{2}', existing_fragment)
            if flag_match:
                flag = flag_match.group(0) + " "
            
            # Формируем новое имя
            new_name = f"{number}. {flag}TROJAN | TG: @wlrustg"
            
            # Создаем новый фрагмент
            new_fragment = urllib.parse.quote(new_name, safe='')
            
            # Собираем URL
            new_parsed = parsed._replace(fragment=new_fragment)
            new_config = urllib.parse.urlunparse(new_parsed)
            
            return new_config
            
        elif config.startswith("ss://"):
            # Для SS: имя может быть в фрагменте или в параметрах
            parsed = urllib.parse.urlparse(config)
            
            # Сначала проверяем фрагмент
            existing_fragment = urllib.parse.unquote(parsed.fragment) if parsed.fragment else ""
            
            # Если нет фрагмента, проверяем query параметры
            name_from_query = ""
            if not existing_fragment and parsed.query:
                params = urllib.parse.parse_qs(parsed.query)
                if 'name' in params:
                    name_from_query = urllib.parse.unquote(params['name'][0])
            
            existing_name = existing_fragment or name_from_query
            
            # Извлекаем флаг
            flag = ""
            flag_match = re.search(r'[\U0001F1E6-\U0001F1FF]{2}', existing_name)
            if flag_match:
                flag = flag_match.group(0) + " "
            
            # Формируем новое имя
            new_name = f"{number}. {flag}SS | TG: @wlrustg"
            
            # Предпочитаем использовать фрагмент
            new_fragment = urllib.parse.quote(new_name, safe='')
            
            # Собираем URL
            new_parsed = parsed._replace(fragment=new_fragment)
            new_config = urllib.parse.urlunparse(new_parsed)
            
            return new_config
            
        else:
            # Для других протоколов пытаемся добавить через # в конец
            # Проверяем, есть ли уже фрагмент
            if '#' in config:
                # Разделяем на основную часть и фрагмент
                base_part, fragment = config.rsplit('#', 1)
                existing_fragment = urllib.parse.unquote(fragment)
                
                # Извлекаем флаг
                flag = ""
                flag_match = re.search(r'[\U0001F1E6-\U0001F1FF]{2}', existing_fragment)
                if flag_match:
                    flag = flag_match.group(0) + " "
                
                # Определяем тип протокола по началу
                config_type = "CONFIG"
                if config.startswith("ssr://"):
                    config_type = "SSR"
                elif config.startswith("tuic://"):
                    config_type = "TUIC"
                elif config.startswith("hysteria://"):
                    config_type = "HYSTERIA"
                elif config.startswith("hysteria2://"):
                    config_type = "HYSTERIA2"
                
                # Формируем новое имя
                new_name = f"{number}. {flag}{config_type} | TG: @wlrustg"
                new_fragment = urllib.parse.quote(new_name, safe='')
                
                return f"{base_part}#{new_fragment}"
            else:
                # Добавляем фрагмент в конец
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
    
    # Ищем номер в формате #123, 123., #123.
    number_match = re.search(r'(?:#?\s*)(\d{1,3})(?:\.|\s+|$)', config_clean)
    number = number_match.group(1) if number_match else None
    
    # Ищем флаг эмодзи
    flag_match = re.search(r'[\U0001F1E6-\U0001F1FF]{2}', config_clean)
    flag = flag_match.group(0) if flag_match else ""
    
    # Ищем вотермарк TG: @wlrustg
    tg_match = re.search(r'TG\s*:\s*@wlrustg', config_clean, re.IGNORECASE)
    tg = tg_match.group(0) if tg_match else ""
    
    return number, flag, tg


def process_configs_with_numbering(configs: list[str]) -> list[str]:
    """Добавляет нумерацию и вотермарк в поле name конфигов"""
    processed_configs = []
    
    for i, config in enumerate(configs, 1):
        # Проверяем, есть ли уже нумерация и наш вотермарк
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
    seen_hostport = set()
    unique_configs = []
    whitelist_configs = []
    
    for config in all_configs:
        config = config.strip()
        if not config or config in seen_full:
            continue
        seen_full.add(config)
        
        # Дедупликация по хосту и порту
        host_port = extract_host_port(config)
        if host_port:
            key = host_port[0].lower() + ":" + str(host_port[1])
            if key in seen_hostport:
                continue
            seen_hostport.add(key)
        
        unique_configs.append(config)
        
        # Проверяем, принадлежит ли хост к whitelist подсетям
        if host_port:
            host = host_port[0]
            # Пытаемся распарсить как IP адрес
            try:
                ip = ipaddress.ip_address(host)
                if ip.version == 4 and is_ip_in_subnets(str(ip)):
                    whitelist_configs.append(config)
            except ValueError:
                # Если это не IP адрес (доменное имя), пропускаем для whitelist
                pass
    
    return unique_configs, whitelist_configs


def save_to_file(configs: list[str], file_type: str, description: str = "", add_numbering: bool = False):
    """Сохраняет конфиги в файл с динамическим именем"""
    # Определяем путь по типу файла
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
        
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(f"# {description}\n")
            f.write(f"# Папка: {PATHS['base_dir']}\n")
            f.write(f"# Файл: {filename}\n")
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
        

def upload_to_github(filepath: str, remote_path: str = None, branch: str = "main"):
    """Загружает файл на GitHub с динамическими путями"""
    if not REPO:
        return
    
    if not os.path.exists(filepath):
        log(f"Файл {filepath} не найден")
        return
    
    # Если remote_path не указан, формируем автоматически
    if remote_path is None:
        filename = os.path.basename(filepath)
        remote_path = f"{PATHS['base_dir']}/{filename}"
    
    try:
        with open(filename, "r", encoding="utf-8") as f:
            content = f.read()
        
        try:
            # Пытаемся получить существующий файл
            file_in_repo = REPO.get_contents(remote_path, ref=branch)
            current_sha = file_in_repo.sha
            
            # Проверяем, изменился ли контент
            remote_content = file_in_repo.decoded_content.decode("utf-8", errors="replace")
            if remote_content == content:
                log(f"Файл {remote_path} не изменился в ветке {branch}")
                return
            
            # Обновляем файл
            REPO.update_file(
                path=remote_path,
                message="🤖 Авто-обновление: " + offset,
                content=content,
                sha=current_sha,
                branch=branch
            )
            log(f"⬆️ Файл {os.path.basename(filepath)} → {remote_path} в ветке {branch}")
            
        except GithubException as e:
            if e.status == 404:
                # Файл не существует, создаем новый
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
        # Получаем текущий README
        try:
            readme_file = REPO.get_contents("README.md")
            old_content = readme_file.decoded_content.decode("utf-8")
        except GithubException:
            # Если README не существует, создаем новый
            old_content = "# Объединенные конфиги VPN\n\n"
        
        # Формируем ссылки на файлы
        raw_url_merged = "https://github.com/" + REPO_NAME + "/raw/main/githubmirror/merged.txt"
        raw_url_wl = "https://github.com/" + REPO_NAME + "/raw/main/githubmirror/wl.txt"
        raw_url_selected = "https://github.com/" + REPO_NAME + "/raw/main/githubmirror/selected.txt"
        
        
        
        # Разделяем время и дату
        time_part = offset.split(" | ")[0]
        date_part = offset.split(" | ")[1] if " | " in offset else ""
        
        # Создаем новую таблицу
        new_section = "\n## 📊 Статус обновления\n\n"
        new_section += "| Файл | Описание | Конфигов | Время обновления | Дата |\n"
        new_section += "|------|----------|----------|------------------|------|\n"
        new_section += f"| [`merged.txt`]({raw_url_merged}) | Все конфиги из {len(URLS)} источников | {total_configs} | {time_part} | {date_part} |\n"
        new_section += f"| [`wl.txt`]({raw_url_wl}) | Только конфиги из {len(WHITELIST_SUBNETS)} подсетей | {wl_configs_count} | {time_part} | {date_part} |\n"
        new_section += f"| [`selected.txt`]({raw_url_selected}) | Отборные админами конфиги, самый надежный список | не знаю | {time_part} | {date_part} |\n\n"
        
        # Добавляем информацию о подсетях
        new_section += "## 📋 Whitelist подсети\n"
        new_section += f"Файл `wl.txt` содержит только конфиги из {len(WHITELIST_SUBNETS)} проверенных подсетей:\n\n"
        
        # Группируем подсети по строкам для лучшей читаемости
        for i in range(0, len(WHITELIST_SUBNETS), 4):
            subnet_line = WHITELIST_SUBNETS[i:i+4]
            new_section += "`" + "` `".join(subnet_line) + "`  \n"
        
        new_section += "\n## 🌐 Варианты доступа\n"
        
        
        new_section += "### Прямые ссылки GitHub\n"
        new_section += f"- Все конфиги: [{raw_url_merged}]({raw_url_merged})\n"
        new_section += f"- Только whitelist: [{raw_url_wl}]({raw_url_wl})\n\n"
        
        
        new_section += "## ⚙️ Авто-обновление\n"
        new_section += "Конфиги автоматически обновляются каждый час через GitHub Actions.\n\n"
        
        new_section += "## 📢 Контакты\n"
        new_section += "Telegram канал: [@wlrustg](https://t.me/wlrustg)\n"
        
        # Заменяем или добавляем секцию статуса
        status_pattern = r'## 📊 Статус обновления[\s\S]*?(?=## |$)'
        if re.search(status_pattern, old_content):
            new_content = re.sub(status_pattern, new_section.strip(), old_content)
        else:
            new_content = old_content.strip() + "\n\n" + new_section
        
        # Обновляем файл
        sha = readme_file.sha if 'readme_file' in locals() else None
        REPO.update_file(
            path="README.md",
            message="📝 Обновление README: " + str(total_configs) + " конфигов, " + str(wl_configs_count) + " в whitelist",
            content=new_content,
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
            
            configs = []
            manual_comments = []  # Только ручные комментарии пользователя
            
            # Пропускаем автоматические заголовки при чтении
            skip_auto_header = False
            for line in lines:
                stripped = line.strip()
                
                # Определяем начало автоматического заголовка
                if stripped.startswith("#profile-title: WL RUS (selected)"):
                    skip_auto_header = True
                    continue
                
                # Пропускаем все строки автоматического заголовка
                if skip_auto_header:
                    if stripped.startswith("#") or not stripped:
                        continue
                    else:
                        skip_auto_header = False
                
                # Теперь обрабатываем обычные строки
                if not stripped:
                    if manual_comments and manual_comments[-1] != "":
                        manual_comments.append("")
                elif stripped.startswith('#'):
                    # Игнорируем автоматические заголовки, но сохраняем ручные комментарии
                    if not any(stripped.startswith(p) for p in [
                        "#profile-title:", 
                        "#profile-update-interval:", 
                        "#announce:",
                        "# Обновлено:",
                        "# Всего конфигов:",
                        "# Вотермарк:",
                        "##################################################"
                    ]):
                        manual_comments.append(stripped)
                else:
                    # Это конфиг
                    if any(stripped.startswith(p) for p in ['vmess://', 'vless://', 'trojan://', 
                                                             'ss://', 'ssr://', 'tuic://', 
                                                             'hysteria://', 'hysteria2://']):
                        configs.append((len(configs), stripped))
                    elif '@' in stripped and ':' in stripped and stripped.count(':') >= 2:
                        configs.append((len(configs), stripped))
            
            if configs:
                # Дедупликация
                config_indices = [idx for idx, _ in configs]
                raw_configs = [config for _, config in configs]
                
                seen_full = set()
                seen_hostport = set()
                unique_configs_with_index = []
                
                for idx, config in zip(config_indices, raw_configs):
                    if config in seen_full:
                        continue
                    seen_full.add(config)
                    
                    host_port = extract_host_port(config)
                    if host_port:
                        key = host_port[0].lower() + ":" + str(host_port[1])
                        if key in seen_hostport:
                            continue
                        seen_hostport.add(key)
                    
                    unique_configs_with_index.append((idx, config))
                
                duplicates_count = len(configs) - len(unique_configs_with_index)
                if duplicates_count > 0:
                    log(f"🔍 Найдено {duplicates_count} дубликатов в selected.txt")
                
                # Обрабатываем конфиги с нумерацией
                unique_configs = [config for _, config in unique_configs_with_index]
                processed_configs = process_configs_with_numbering(unique_configs)
                
                processed_by_index = {}
                for (idx, _), processed in zip(unique_configs_with_index, processed_configs):
                    processed_by_index[idx] = processed
                
         
        
        with open(selected_file, "w", encoding="utf-8") as f:
            f.write(f"#profile-title: WL RUS (selected)\n")
            f.write(f"#profile-update-interval: 1\n")
            f.write("#announce: Сервера из подписки должны использоваться ТОЛЬКО при белых списках!\n")
                    
                    # Добавляем ручные комментарии пользователя
                    if manual_comments:
                        f.write("\n")
                        for comment in manual_comments:
                            if comment == "":
                                f.write("\n")
                            else:
                                f.write(comment + "\n")
                    
                    # Добавляем конфиги
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
            else:
                log("ℹ️ В selected.txt нет конфигов для обработки")
                return []
                
        except Exception as e:
            log(f"❌ Ошибка обработки selected.txt: {str(e)}")
            return []
    else:
        log("ℹ️ Файл selected.txt не найден")
        return []

def main():
    """Основная функция"""
log("🚀 Конфигурация запуска:")
    log(f"   📁 Папка: {PATHS['base_dir']}")
    log(f"   📄 Merged: {PATHS['merged'].replace(PATHS['base_dir']+'/', '')}")
    log(f"   🛡️ Whitelist: {PATHS['wl'].replace(PATHS['base_dir']+'/', '')}")
    log(f"   🔧 Selected: {PATHS['selected'].replace(PATHS['base_dir']+'/', '')}")

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
    
    # 4. Дедупликация и сортировка по подсетям
    log("🔄 Дедупликация и фильтрация...")
    unique_configs, whitelist_configs = merge_and_deduplicate(all_configs)
    log("🔄 После дедупликации: " + str(len(unique_configs)) + " конфигов")
    log("🛡️ Whitelist конфигов: " + str(len(whitelist_configs)))
    
    # 5. Сохраняем локально
    os.makedirs("githubmirror", exist_ok=True)
    output_file_merged = "githubmirror/merged.txt"
    output_file_wl = "githubmirror/wl.txt"
    
    # СОХРАНЯЕМ merged.txt С НУМЕРАЦИЕЙ (включая конфиги из selected.txt)
    save_to_file(unique_configs, "merged", "Объединенные конфиги", add_numbering=True)
    save_to_file(whitelist_configs, "wl", "Whitelist конфиги", add_numbering=True)
    
    # Загружаем на GitHub
    upload_to_github(PATHS["merged"])
    upload_to_github(PATHS["wl"])
    upload_to_github(PATHS["selected"])
    
   # Загружаем selected.txt на GitHub, если он существует
   # selected_file = "githubmirror/selected.txt"
   # if os.path.exists(selected_file):
   #     upload_to_github(selected_file, "githubmirror/selected.txt", "main")
    
    
    # 8. Обновляем README
    update_readme(len(unique_configs), len(whitelist_configs))
    
    # 9. Выводим итоги
    log("=" * 60)
    log("📊 ИТОГИ:")
    log("   🌐 Источников: " + str(len(URLS)))
    log("   📥 Скачано из URL: " + str(len(all_configs) - len(selected_configs)))
    log("   🔧 Из selected.txt: " + str(len(selected_configs)))
    log("   🔄 Уникальных: " + str(len(unique_configs)))
    total_duplicates = (len(all_configs) - len(selected_configs)) + len(selected_configs) - len(unique_configs)
    log("   📊 Дубликатов: " + str(total_duplicates))
    log("   🛡️ Whitelist: " + str(len(whitelist_configs)))
    log("   💾 Основные файлы:")
    log("      • githubmirror/merged.txt (с нумерацией)")
    log("      • githubmirror/wl.txt (с нумерацией)")
    log("      • githubmirror/selected.txt (дедуплицирован и обработан)")
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
