import json
import base64
import re
import os
import socket
import time
import subprocess
import requests
import concurrent.futures
from datetime import datetime

# --- CONFIGURATION & PATHS ---
RAW_FILES = ['sub_raw.txt', 'my_personal_links.txt']
# Поиск бинарника в разных местах
LST_BINARY_NAMES = ["./lite-speedtest", "lite-speedtest", "./bin/lite-speedtest"]
STATUS_FILE = 'status.json'

# Output Files
SUBS = {
    'elite': 'sub_elite.txt',   
    'fast': 'sub_fast.txt',    
    'gemini': 'sub_gemini.txt', 
    'kz': 'sub_kz.txt',         
    'by': 'sub_by.txt',         
    'brave': 'sub_brave.txt',   
    'slow': 'sub_slow.txt'      
}

class EliteFactoryLST:
    """
    Elite Proxy Factory - LiteSpeedTest Edition with Smart Fetch.
    Handles recursive link downloading, TCP pre-checks, and L7 validation.
    """
    def __init__(self):
        self.stats = {
            "input_files_processed": 0,
            "external_links_followed": 0,
            "total_lines_found": 0,
            "unique_nodes": 0,
            "tcp_alive": 0,
            "google_ok": 0,
            "elite_count": 0,
            "last_run": datetime.now().isoformat(),
            "errors": []
        }
        self.unique_map = {} # host:port -> original_url
        self.final_results = {k: [] for k in SUBS.keys()}
        self.binary_path = None

    def log(self, msg):
        """Standardized logger for GitHub Actions console."""
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ⚙️ {msg}")

    def find_binary(self):
        """Находит путь к бинарнику LST и проверяет права."""
        for name in LST_BINARY_NAMES:
            if os.path.exists(name) or subprocess.call(f"command -v {name}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0:
                self.binary_path = name
                # Пытаемся дать права на выполнение на всякий случай
                try:
                    if os.path.exists(name):
                        os.chmod(name, 0o755)
                except: pass
                self.log(f"System: Найден бинарник {name}")
                return True
        
        self.log("❌ ERROR: Бинарник LiteSpeedTest не найден!")
        self.log(f"Files in current dir: {os.listdir('.')}")
        return False

    def fetch_remote_content(self, url):
        """
        Downloads content from external URLs found in input files.
        Handles timeout and basic HTTP errors.
        """
        try:
            url = url.strip()
            self.log(f"Remote: Попытка загрузки из {url}...")
            response = requests.get(url, timeout=15)
            if response.status_code == 200:
                self.stats["external_links_followed"] += 1
                lines = response.text.splitlines()
                self.log(f"Remote: Получено {len(lines)} строк.")
                return lines
            else:
                self.log(f"Remote Warning: Ошибка HTTP {response.status_code} для {url}")
        except Exception as e:
            self.log(f"Remote Error: Сбой загрузки {url} -> {e}")
        return []

    def extract_host_port(self, url):
        """Decodes proxy URL to get host and port for deduplication."""
        try:
            url = url.strip()
            if not url or url.startswith('http'): return None, None
            if url.startswith('vmess://'):
                try:
                    # Remove 'vmess://' and decode
                    decoded = base64.b64decode(url[8:]).decode('utf-8')
                    data = json.loads(decoded)
                    return str(data.get('add')), str(data.get('port'))
                except: return None, None
            
            # Pattern for vless, trojan, ss, hy2
            pattern = r'://(?:[^@]+@)?(?:\[([a-fA-F0-9:]+)\]|([^:/?#]+)):([0-9]+)'
            match = re.search(pattern, url)
            if match:
                host = match.group(1) or match.group(2)
                port = match.group(3)
                return str(host), str(port)
        except: return None, None
        return None, None

    def parse_country(self, url):
        """Extracts [CC] country code from the remark part of the URL."""
        try:
            remark = url.split('#')[-1] if '#' in url else ""
            match = re.search(r'\[([A-Z]{2})\]', remark)
            return match.group(1) if match else "UN"
        except: return "UN"

    def fast_tcp_check(self, url):
        """Non-blocking TCP handshake to filter dead servers."""
        host, port = self.extract_host_port(url)
        if not host: return None
        try:
            with socket.create_connection((host, int(port)), timeout=2.5):
                return url
        except: return None

    def run_lst_check(self, links):
        """Runs LiteSpeedTest binary to check real internet access (Google)."""
        if not links: return []
        if not self.binary_path:
            self.log("LST: Пропуск теста (бинарник отсутствует)")
            return []
        
        with open("batch.txt", "w", encoding='utf-8') as f:
            f.write("\n".join(links))
        
        self.log(f"LST: Запуск ядра для {len(links)} узлов...")
        
        try:
            # LST Command: -sub (input file), -test (target), -out (output format)
            cmd = [self.binary_path, "-sub", "batch.txt", "-test", "google", "-out", "json"]
            subprocess.run(cmd, capture_output=True, timeout=360)
            
            if os.path.exists("output.json"):
                with open("output.json", "r", encoding='utf-8') as f:
                    return json.load(f)
            else:
                self.log("LST: Файл output.json не был создан.")
        except Exception as e:
            self.log(f"LST Core Error: {e}")
            self.stats["errors"].append(str(e))
        return []

    def start_process(self):
        """Main execution flow: Load -> Fetch -> Dedupe -> Test -> Sort."""
        self.log("--- СТАРТ ЗАВОДА ELITE LST (Smart Fetch) ---")
        
        # 0. Поиск бинарника
        self.find_binary()

        # 1. Loading & Recursive Fetching
        all_raw_lines = []
        for f_path in RAW_FILES:
            if os.path.exists(f_path):
                self.stats["input_files_processed"] += 1
                self.log(f"Loader: Чтение локального файла {f_path}...")
                with open(f_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if not line: continue
                        if line.startswith('http'):
                            all_raw_lines.extend(self.fetch_remote_content(line))
                        else:
                            all_raw_lines.append(line)
        
        self.stats["total_lines_found"] = len(all_raw_lines)

        # 2. Deduplication (Strict Host:Port match)
        unique_list = []
        for url in all_raw_lines:
            h, p = self.extract_host_port(url)
            if h and f"{h}:{p}" not in self.unique_map:
                self.unique_map[f"{h}:{p}"] = url
                unique_list.append(url)
        
        self.stats["unique_nodes"] = len(unique_list)
        self.log(f"Dedupe: Найдено {len(unique_list)} уникальных конфигов.")

        if not unique_list:
            self.log("System: Данных для теста нет. Выход.")
            return

        # 3. Fast TCP Pre-filter
        with concurrent.futures.ThreadPoolExecutor(max_workers=60) as executor:
            alive_results = list(executor.map(self.fast_tcp_check, unique_list))
        
        alive_links = [l for l in alive_results if l]
        self.stats["tcp_alive"] = len(alive_links)
        self.log(f"TCP: Живых портов: {len(alive_links)}")

        # 4. LiteSpeedTest L7 Validation
        results = self.run_lst_check(alive_links)
        
        # 5. Advanced Sorting & Tiering
        if results:
            for node in results:
                url = node.get('url')
                speed = node.get('speed', 0) # Mbps
                google_ping = node.get('google_ping', 0)
                google_ok = google_ping > 0
                country = self.parse_country(url)
                
                if country == 'KZ': self.final_results['kz'].append(url)
                elif country == 'BY': self.final_results['by'].append(url)
                
                if google_ok:
                    self.stats["google_ok"] += 1
                    self.final_results['gemini'].append(url)
                    if speed > 50:
                        self.final_results['elite'].append(url)
                        self.stats["elite_count"] += 1
                    elif speed > 10:
                        self.final_results['fast'].append(url)
                    
                    if 100 <= google_ping <= 165:
                        self.final_results['brave'].append(url)
                else:
                    self.final_results['slow'].append(url)
        else:
            # Fallback: если LST не сработал, просто кладем живые TCP в Brave/Slow по странам
            self.log("System: Работа в режиме Fallback (только TCP данные)")
            for url in alive_links:
                country = self.parse_country(url)
                if country == 'KZ': self.final_results['kz'].append(url)
                elif country == 'BY': self.final_results['by'].append(url)
                self.final_results['brave'].append(url)

        # 6. Save & Export
        for tier, filename in SUBS.items():
            content = "\n".join(self.final_results[tier])
            with open(filename, "w", encoding='utf-8') as f:
                f.write(content)
            with open(f"b64_{filename}", "w", encoding='utf-8') as f:
                f.write(base64.b64encode(content.encode()).decode())

        # Update Status JSON
        with open(STATUS_FILE, "w", encoding='utf-8') as f:
            json.dump(self.stats, f, indent=4)
            
        self.log("--- ПРОИЗВОДСТВЕННЫЙ ЦИКЛ ЗАВЕРШЕН ---")
        self.log(f"✅ Успешно: {self.stats['google_ok']} | 💎 Elite: {self.stats['elite_count']}")
        self.log(f"🇰🇿 KZ: {len(self.final_results['kz'])} | 🇧🇾 BY: {len(self.final_results['by'])}")

if __name__ == "__main__":
    factory = EliteFactoryLST()
    factory.start_process()
