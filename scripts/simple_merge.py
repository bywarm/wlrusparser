#!/usr/bin/env python3
"""
Упрощенный скрипт для объединения конфигов без проверки пинга
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
import base64
import json
import re
import os

# -------------------- ЛОГИРОВАНИЕ --------------------
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

# Список подсетей для whitelist
WHITELIST_SUBNETS = [
    "95.163.0.0/24",
    "89.208.0.0/24",
    "217.16.0.0/24",
    "5.188.0.0/24",
    "109.120.188.0/24",
    "217.12.40.0/24",
    "176.108.242.0/24",
    "178.154.221.0/24",
    "176.109.105.0/24",
    "176.109.109.0/24",
    "51.250.0.0/24",
    "176.32.0.0/24",
    "193.53.126.0/24",
    "45.129.2.0/24",
    "37.18.15.0/24",
    "78.159.131.0/24",
    "185.177.238.0/24",
    "45.15.0.0/24",
    "176.122.25.0/24",
    "185.130.114.0/24",
    "37.139.35.0/24",
    "83.166.251.0/24",
    "91.219.227.0/24"
]

# Преобразуем подсети в объекты ipaddress для быстрой проверки
WHITELIST_NETWORKS = [ipaddress.ip_network(subnet) for subnet in WHITELIST_SUBNETS]

# Источники конфигов
URLS = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    "https://raw.githubusercontent.com/zieng2/wl/refs/heads/main/vless_universal.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
    "https://jsnegsukavsos.hb.ru-msk.vkcloud-storage.ru/love",
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

def add_numbering_and_watermark(configs: list[str], watermark: str = "TG: @wlrustg") -> list[str]:
    """Добавляет нумерацию и вотермарк к конфигам"""
    numbered_configs = []
    
    for i, config in enumerate(configs, 1):
        # Извлекаем хост для более информативного отображения
        host_port = extract_host_port(config)
        if host_port:
            host_info = f" | {host_port[0]}:{host_port[1]}"
        else:
            host_info = ""
        
        # Определяем тип конфига
        if config.startswith("vmess://"):
            config_type = "VMESS"
        elif config.startswith("vless://"):
            config_type = "VLESS"
        elif config.startswith("trojan://"):
            config_type = "TROJAN"
        elif config.startswith("ss://"):
            config_type = "SS"
        else:
            config_type = "CONFIG"
        
        # Добавляем нумерацию и вотермарк как комментарий
        numbered_config = f"# {i}. {config_type}{host_info} | {watermark}\n{config}"
        numbered_configs.append(numbered_config)
    
    return numbered_configs

def save_to_file(configs: list[str], filename: str, description: str = "", add_numbering: bool = False):
    """Сохраняет конфиги в файл с опциональной нумерацией"""
    try:
        with open(filename, "w", encoding="utf-8") as f:
            # Заголовок файла
            f.write("# " + description + "\n")
            f.write("# Обновлено: " + offset + "\n")
            f.write("# Всего конфигов: " + str(len(configs)) + "\n")
            
            if description == "Whitelist конфиги (только подсети из списка)":
                f.write("# Подсети: " + str(len(WHITELIST_SUBNETS)) + "\n")
                f.write("# Вотермарк: TG: @wlrustg\n")
                f.write("#" * 50 + "\n")
                for subnet in WHITELIST_SUBNETS:
                    f.write("# " + subnet + "\n")
            else:
                f.write("# Источников: " + str(len(URLS)) + "\n")
                if add_numbering:
                    f.write("# Вотермарк: TG: @wlrustg\n")
            
            f.write("#" * 50 + "\n\n")
            
            # Обрабатываем конфиги в зависимости от необходимости нумерации
            if add_numbering:
                processed_configs = add_numbering_and_watermark(configs)
            else:
                processed_configs = configs
            
            # Записываем конфиги
            for config in processed_configs:
                f.write(config + "\n\n")
        
        log("💾 Сохранено " + str(len(configs)) + " конфигов в " + filename)
        
    except Exception as e:
        log("Ошибка сохранения файла " + filename + ": " + str(e))

def create_working_servers_file(configs: list[str]):
    """Создает файл с проверенными рабочими серверами для Cloudflare Pages"""
    try:
        # Создаем отдельную папку для Cloudflare Pages
        os.makedirs("cloudflare-pages", exist_ok=True)
        output_file = "cloudflare-pages/working-servers.txt"
        
        # Отсортировать конфиги по типу для удобства
        vmess_configs = [c for c in configs if c.startswith("vmess://")]
        vless_configs = [c for c in configs if c.startswith("vless://")]
        trojan_configs = [c for c in configs if c.startswith("trojan://")]
        other_configs = [c for c in configs if not c.startswith(("vmess://", "vless://", "trojan://"))]
        
        with open(output_file, "w", encoding="utf-8") as f:
            # Красивый заголовок
            f.write("=" * 60 + "\n")
            f.write("РАБОЧИЕ VPN СЕРВЕРА - РУЧНАЯ ПРОВЕРКА\n")
            f.write("=" * 60 + "\n\n")
            
            f.write("📅 Последнее обновление: " + offset + "\n")
            f.write("📊 Всего конфигов доступно: " + str(len(configs)) + "\n")
            f.write("👨‍💻 Проверено вручную: [ЗДЕСЬ БУДЕТ КОЛИЧЕСТВО]\n")
            f.write("📢 Канал поддержки: TG: @wlrustg\n")
            f.write("-" * 60 + "\n\n")
            
            f.write("ℹ️ ИНСТРУКЦИЯ:\n")
            f.write("1. Сервера проверяются вручную на работоспособность\n")
            f.write("2. ✅ - работает, ❌ - не работает, ⚠️ - нестабильно\n")
            f.write("3. Статус обновляется по мере проверки\n")
            f.write("4. Для добавления в клиент скопируйте строку БЕЗ комментариев\n")
            f.write("-" * 60 + "\n\n")
            
            # Счетчики для статистики
            total_checked = 0
            working_count = 0
            
            # VLESS сервера
            if vless_configs:
                f.write("🔷 VLESS СЕРВЕРА (" + str(len(vless_configs)) + "):\n")
                f.write("-" * 40 + "\n")
                
                for i, config in enumerate(vless_configs[:20], 1):  # Ограничим 20 для ручной проверки
                    host_port = extract_host_port(config)
                    if host_port:
                        host_info = f"{host_port[0]}:{host_port[1]}"
                    else:
                        host_info = "Неизвестный хост"
                    
                    # Добавляем место для ручной пометки статуса
                    f.write(f"#{i:03d} VLESS | {host_info}\n")
                    f.write("# Статус: [ ] ✅ [ ] ❌ [ ] ⚠️\n")
                    f.write("# Скорость: _____ Мбит/с\n")
                    f.write("# Пинг: _____ мс\n")
                    f.write("# Комментарий: ____________________\n")
                    f.write(config + "\n")
                    f.write("-" * 40 + "\n")
                    total_checked += 1
            
            # VMESS сервера
            if vmess_configs:
                f.write("\n🔶 VMESS СЕРВЕРА (" + str(len(vmess_configs)) + "):\n")
                f.write("-" * 40 + "\n")
                
                for i, config in enumerate(vmess_configs[:15], 1):  # Ограничим 15
                    host_port = extract_host_port(config)
                    if host_port:
                        host_info = f"{host_port[0]}:{host_port[1]}"
                    else:
                        host_info = "Неизвестный хост"
                    
                    f.write(f"#{i+20:03d} VMESS | {host_info}\n")
                    f.write("# Статус: [ ] ✅ [ ] ❌ [ ] ⚠️\n")
                    f.write("# Скорость: _____ Мбит/с\n")
                    f.write("# Пинг: _____ мс\n")
                    f.write("# Комментарий: ____________________\n")
                    f.write(config + "\n")
                    f.write("-" * 40 + "\n")
                    total_checked += 1
            
            # Trojan сервера
            if trojan_configs:
                f.write("\n🔺 TROJAN СЕРВЕРА (" + str(len(trojan_configs)) + "):\n")
                f.write("-" * 40 + "\n")
                
                for i, config in enumerate(trojan_configs[:10], 1):  # Ограничим 10
                    host_port = extract_host_port(config)
                    if host_port:
                        host_info = f"{host_port[0]}:{host_port[1]}"
                    else:
                        host_info = "Неизвестный хост"
                    
                    f.write(f"#{i+35:03d} TROJAN | {host_info}\n")
                    f.write("# Статус: [ ] ✅ [ ] ❌ [ ] ⚠️\n")
                    f.write("# Скорость: _____ Мбит/с\n")
                    f.write("# Пинг: _____ мс\n")
                    f.write("# Комментарий: ____________________\n")
                    f.write(config + "\n")
                    f.write("-" * 40 + "\n")
                    total_checked += 1
            
            # Статистика в конце
            f.write("\n" + "=" * 60 + "\n")
            f.write("📈 СТАТИСТИКА:\n")
            f.write("=" * 60 + "\n")
            f.write(f"Всего доступно: {len(configs)} конфигов\n")
            f.write(f"Отобрано для проверки: {total_checked}\n")
            f.write(f"Проверено вручную: {working_count}\n")
            f.write(f"Рабочих: {working_count}\n")
            f.write(f"Процент рабочих: {working_count/max(total_checked,1)*100:.1f}%\n")
            f.write("\n📢 Поддержка и обновления: TG: @wlrustg\n")
            f.write("=" * 60 + "\n")
        
        log("📋 Создан файл для ручной проверки: cloudflare-pages/working-servers.txt")
        log("ℹ️  Файл содержит шаблон для отметки работоспособности серверов")
        
        # Также создаем простую версию с нумерацией
        simple_file = "cloudflare-pages/simple-list.txt"
        with open(simple_file, "w", encoding="utf-8") as f:
            f.write("# Пронумерованный список серверов\n")
            f.write("# Обновлено: " + offset + "\n")
            f.write("# TG: @wlrustg\n")
            f.write("#" * 50 + "\n\n")
            
            numbered_configs = add_numbering_and_watermark(configs[:50])  # Ограничим 50
            for config in numbered_configs:
                f.write(config + "\n\n")
        
        log("📝 Создан упрощенный список: cloudflare-pages/simple-list.txt")
        
    except Exception as e:
        log("Ошибка создания файла для Cloudflare Pages: " + str(e))

def upload_to_github(filename: str, remote_path: str, branch: str = "main"):
    """Загружает файл на GitHub в указанную ветку"""
    if not REPO:
        log("Пропускаю загрузку на GitHub (нет подключения)")
        return
    
    if not os.path.exists(filename):
        log("Файл " + filename + " не найден для загрузки")
        return
    
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
    
