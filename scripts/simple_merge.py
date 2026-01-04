#!/usr/bin/env python3

from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from collections import defaultdict
from github import GithubException
from github import Github, Auth
from datetime import datetime
import concurrent.futures
import urllib.parse
import threading
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
    log(f"⚠️ Ошибка подключения к GitHub: {e}")
    REPO = None

# Источники конфигов
URLS = [
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_lite.txt",
    "https://raw.githubusercontent.com/zieng2/wl/main/vless_universal.txt"
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
            log(f"❌ Ошибка загрузки {url}: {str(exc)[:100]}")
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
        
        log(f"✅ {url.split('/')[3] if '/' in url else 'unknown'}: {len(configs)} конфигов")
        return configs
        
    except Exception as e:
        log(f"❌ Ошибка обработки {url}: {str(e)[:100]}")
        return []

def merge_and_deduplicate(all_configs: list[str]) -> list[str]:
    """Объединяет и дедуплицирует конфиги"""
    if not all_configs:
        return []
    
    seen_full = set()
    seen_hostport = set()
    unique_configs = []
    
    for config in all_configs:
        config = config.strip()
        if not config or config in seen_full:
            continue
        seen_full.add(config)
        
        # Дедупликация по хосту и порту
        host_port = extract_host_port(config)
        if host_port:
            key = f"{host_port[0].lower()}:{host_port[1]}"
            if key in seen_hostport:
                continue
            seen_hostport.add(key)
        
        unique_configs.append(config)
    
    return unique_configs

def save_to_file(configs: list[str], filename: str):
    """Сохраняет конфиги в файл"""
    try:
        with open(filename, "w", encoding="utf-8") as f:
            # Заголовок файла
            f.write(f"# Объединенные конфиги (источников: {len(URLS)})\n")
            f.write(f"# Обновлено: {offset}\n")
            f.write(f"# Всего конфигов: {len(configs)}\n")
            f.write("#" * 50 + "\n\n")
            
            # Записываем конфиги
            for config in configs:
                f.write(config + "\n")
        
        log(f"💾 Сохранено {len(configs)} конфигов в {filename}")
        
    except Exception as e:
        log(f"❌ Ошибка сохранения файла {filename}: {e}")

def upload_to_github(filename: str, remote_path: str):
    """Загружает файл на GitHub"""
    if not REPO:
        log("⚠️ Пропускаю загрузку на GitHub (нет подключения)")
        return
    
    if not os.path.exists(filename):
        log(f"❌ Файл {filename} не найден для загрузки")
        return
    
    try:
        with open(filename, "r", encoding="utf-8") as f:
            content = f.read()
        
        try:
            # Пытаемся получить существующий файл
            file_in_repo = REPO.get_contents(remote_path)
            current_sha = file_in_repo.sha
            
            # Проверяем, изменился ли контент
            remote_content = file_in_repo.decoded_content.decode("utf-8", errors="replace")
            if remote_content == content:
                log(f"🔄 Файл {remote_path} не изменился")
                return
            
            # Обновляем файл
            REPO.update_file(
                path=remote_path,
                message=f"🤖 Авто-обновление: {offset}",
                content=content,
                sha=current_sha
            )
            log(f"⬆️ Файл {remote_path} обновлён на GitHub")
            
        except GithubException as e:
            if e.status == 404:
                # Файл не существует, создаем новый
                REPO.create_file(
                    path=remote_path,
                    message=f"🤖 Первое создание: {offset}",
                    content=content
                )
                log(f"🆕 Файл {remote_path} создан на GitHub")
            else:
                log(f"⚠️ Ошибка GitHub: {e.data.get('message', str(e))}")
                
    except Exception as e:
        log(f"❌ Ошибка при загрузке на GitHub: {e}")

def update_readme(total_configs: int):
    """Обновляет README.md со статистикой"""
    if not REPO:
        log("⚠️ Пропускаю обновление README (нет подключения)")
        return
    
    try:
        # Получаем текущий README
        try:
            readme_file = REPO.get_contents("README.md")
            old_content = readme_file.decoded_content.decode("utf-8")
        except GithubException:
            # Если README не существует, создаем новый
            old_content = "# Объединенные конфиги VPN\n\n"
        
        # Формируем ссылку на raw-файл
        raw_url = f"https://github.com/{REPO_NAME}/raw/main/confs/merged.txt"
        
        # Создаем новую таблицу
        new_section = f"""
## 📊 Статус обновления

| Файл | Описание | Конфигов | Время обновления | Дата |
|------|----------|----------|------------------|------|
| [`merged.txt`]({raw_url}) | Объединенные конфиги из {len(URLS)} источников | {total_configs} | {offset.split(' \| ')[0]} | {offset.split(' \| ')[1]} |

## 📥 Скачать
- [merged.txt]({raw_url}) - все конфиги в одном файле

## ⚙️ Авто-обновление
Конфиги автоматически обновляются каждый час через GitHub Actions.
"""
        
        # Заменяем или добавляем секцию статуса
        status_pattern = r'## 📊 Статус обновления[\s\S]*?(?=## |$)'
        if re.search(status_pattern, old_content):
            new_content = re.sub(status_pattern, new_section.strip(), old_content)
        else:
            new_content = old_content.strip() + "\n\n" + new_section
        
        # Обновляем файл
        REPO.update_file(
            path="README.md",
            message=f"📝 Обновление README: {total_configs} конфигов",
            content=new_content,
            sha=readme_file.sha if 'readme_file' in locals() else None
        )
        log("📝 README.md обновлён")
        
    except Exception as e:
        log(f"⚠️ Ошибка обновления README: {e}")

def main():
    """Основная функция"""
    log("🚀 Начало объединения конфигов")
    log(f"📅 Время: {offset}")
    log(f"🌐 Источников: {len(URLS)}")
    
    # 1. Скачиваем конфиги из всех источников
    log("📥 Загрузка конфигов...")
    
    all_configs = []
    max_workers = min(DEFAULT_MAX_WORKERS, len(URLS))
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(download_and_process_url, url): url for url in URLS}
        
        for future in concurrent.futures.as_completed(futures):
            url = futures[future]
            try:
                configs = future.result(timeout=30)
                if configs:
                    all_configs.extend(configs)
            except Exception as e:
                log(f"❌ Таймаут или ошибка для {url}: {str(e)[:50]}")
    
    log(f"📊 Скачано всего: {len(all_configs)} конфигов")
    
    if not all_configs:
        log("❌ Не удалось загрузить ни одного конфига")
        return
    
    # 2. Дедупликация
    log("🔄 Дедупликация...")
    unique_configs = merge_and_deduplicate(all_configs)
    log(f"🔄 После дедупликации: {len(unique_configs)} конфигов")
    
    # 3. Сохраняем локально
    os.makedirs("confs", exist_ok=True)
    output_file = "confs/merged.txt"
    save_to_file(unique_configs, output_file)
    
    # 4. Загружаем на GitHub
    log("📤 Загрузка на GitHub...")
    upload_to_github(output_file, "confs/merged.txt")
    
    # 5. Обновляем README
    update_readme(len(unique_configs))
    
    # 6. Выводим итоги
    log("=" * 50)
    log("📊 ИТОГИ:")
    log(f"   🌐 Источников: {len(URLS)}")
    log(f"   📥 Скачано: {len(all_configs)}")
    log(f"   🔄 Уникальных: {len(unique_configs)}")
    log(f"   📊 Дубликатов: {len(all_configs) - len(unique_configs)}")
    log(f"   💾 Файл: {output_file}")
    log("=" * 50)
    
    # Выводим логи
    print(f"\n📋 ЛОГИ ВЫПОЛНЕНИЯ ({offset}):")
    print("=" * 50)
    for line in LOGS_BY_FILE[0]:
        print(line)

if __name__ == "__main__":
    main()
