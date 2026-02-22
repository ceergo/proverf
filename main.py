import json
import base64
import re
import os
import socket
import time
import subprocess
import concurrent.futures
from datetime import datetime

# --- CONFIGURATION & PATHS ---
RAW_FILES = ['sub_raw.txt', 'my_personal_links.txt']
LST_BINARY = "./lite-speedtest"  # Должен быть скачан в Workflow
LST_CONFIG = "config.json"
LST_OUTPUT = "output.json"
STATUS_FILE = 'status.json'

# Output Files
SUBS = {
    'elite': 'sub_elite.txt',   # Speed > 50 Mbps + Google OK
    'fast': 'sub_fast.txt',    # Speed 10-50 Mbps + Google OK
    'gemini': 'sub_gemini.txt', # All Google-accessible (AI Ready)
    'kz': 'sub_kz.txt',         # Kazakhstan
    'by': 'sub_by.txt',         # Belarus
    'brave': 'sub_brave.txt',   # Working Mix (Ping 100-160ms)
    'slow': 'sub_slow.txt'      # Everything else
}

class EliteFactoryLST:
    """
    Elite Proxy Factory - LiteSpeedTest Edition.
    Uses LST binary for real L7 validation (Google/Gemini) and Speed tests.
    """
    def __init__(self):
        self.stats = {
            "input_count": 0,
            "tcp_alive": 0,
            "google_ok": 0,
            "elite": 0,
            "gemini": 0,
            "kz": 0,
            "by": 0,
            "dead": 0,
            "start_time": datetime.now().isoformat()
        }
        self.unique_map = {} # host:port -> original_url
        self.final_results = {k: [] for k in SUBS.keys()}

    def log(self, msg):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] ⚙️ {msg}")

    def extract_host_port(self, url):
        """Парсинг параметров для дедупликации"""
        try:
            url = url.strip()
            if not url: return None, None
            if url.startswith('vmess://'):
                try:
                    decoded = base64.b64decode(url[8:]).decode('utf-8')
                    data = json.loads(decoded)
                    return str(data.get('add')), str(data.get('port'))
                except: return None, None
            pattern = r'://(?:[^@]+@)?(?:\[([a-fA-F0-9:]+)\]|([^:/?#]+)):([0-9]+)'
            match = re.search(pattern, url)
            if match:
                host = match.group(1) or match.group(2)
                port = match.group(3)
                return str(host), str(port)
        except: return None, None
        return None, None

    def parse_country(self, url):
        """Извлечение кода страны из Remark"""
        try:
            remark = url.split('#')[-1] if '#' in url else ""
            match = re.search(r'\[([A-Z]{2})\]', remark)
            return match.group(1) if match else "UN"
        except: return "UN"

    def fast_tcp_check(self, url):
        """Быстрый отсев мертвецов перед тяжелым тестом LST"""
        host, port = self.extract_host_port(url)
        if not host: return None
        try:
            with socket.create_connection((host, int(port)), timeout=2.5):
                return url
        except:
            return None

    def run_lst_check(self, links):
        """Запуск бинарника LiteSpeedTest для проверки Google и Скорости"""
        if not links: return []
        
        # Создаем временный файл со списком ссылок для LST
        with open("batch.txt", "w") as f:
            f.write("\n".join(links))
        
        self.log(f"LST: Начинаю проверку {len(links)} ссылок на доступ к Google...")
        
        try:
            # Команда запуска LST (настройки зависят от версии бинарника)
            # -test google: проверяет доступность google
            # -out json: выводит результат в файл
            cmd = [LST_BINARY, "-sub", "batch.txt", "-test", "google", "-out", "json"]
            subprocess.run(cmd, capture_output=True, timeout=300)
            
            if os.path.exists("output.json"):
                with open("output.json", "r") as f:
                    return json.load(f)
        except Exception as e:
            self.log(f"LST Error: {e}")
        return []

    def start_process(self):
        self.log("--- СТАРТ ЗАВОДА ELITE LST ---")
        
        # 1. Сбор данных и дедупликация
        raw_links = []
        for f_path in RAW_FILES:
            if os.path.exists(f_path):
                with open(f_path, 'r') as f:
                    raw_links.extend([l.strip() for l in f if l.strip()])
        
        self.stats["input_count"] = len(raw_links)
        
        clean_links = []
        for url in raw_links:
            h, p = self.extract_host_port(url)
            if h and f"{h}:{p}" not in self.unique_map:
                self.unique_map[f"{h}:{p}"] = url
                clean_links.append(url)
        
        self.log(f"Dedupe: Очищено до {len(clean_links)} уникальных узлов.")

        # 2. Быстрый TCP Фильтр (чтобы не грузить LST мертвечиной)
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            alive_results = list(executor.map(self.fast_tcp_check, clean_links))
        
        alive_links = [l for l in alive_results if l]
        self.stats["tcp_alive"] = len(alive_links)
        self.log(f"TCP: Живых портов обнаружено: {len(alive_links)}")

        # 3. Основной тест через LiteSpeedTest
        # Примечание: В реальном GitHub Actions тут вызывается бинарник.
        # Для примера логики парсим результаты теста.
        lst_results = self.run_lst_check(alive_links)
        
        # 4. Сортировка по папкам на основе данных LST
        for node in lst_results:
            url = node.get('url')
            speed = node.get('speed', 0) # Mbps
            google_ping = node.get('google_ping', 0)
            google_ok = google_ping > 0
            
            country = self.parse_country(url)
            
            # Логика Босса
            if country == 'KZ':
                self.final_results['kz'].append(url)
            elif country == 'BY':
                self.final_results['by'].append(url)
            elif google_ok:
                self.stats["google_ok"] += 1
                if speed > 50:
                    self.final_results['elite'].append(url)
                elif speed > 10:
                    self.final_results['fast'].append(url)
                
                # Все, кто открыл Google, идут в Gemini
                self.final_results['gemini'].append(url)
                
                if 100 <= google_ping <= 160:
                    self.final_results['brave'].append(url)
            else:
                self.final_results['slow'].append(url)

        # 5. Сохранение результатов
        for tier, filename in SUBS.items():
            content = "\n".join(self.final_results[tier])
            with open(filename, "w") as f:
                f.write(content)
            # Base64 версия
            with open(f"b64_{filename}", "w") as f:
                f.write(base64.b64encode(content.encode()).decode())

        self.stats["elite"] = len(self.final_results['elite'])
        self.stats["gemini"] = len(self.final_results['gemini'])
        
        # Финальный отчет
        with open(STATUS_FILE, "w") as f:
            json.dump(self.stats, f, indent=4)
            
        self.log("--- ОТЧЕТ ЗАВЕРШЕН ---")
        self.log(f"📥 Вход: {self.stats['input_count']} | 🚀 Elite: {self.stats['elite']}")
        self.log(f"🤖 Gemini: {self.stats['gemini']} | 🇰🇿 KZ: {len(self.final_results['kz'])}")
        self.log(f"💀 Dead/Filtered: {self.stats['input_count'] - self.stats['google_ok']}")

if __name__ == "__main__":
    factory = EliteFactoryLST()
    factory.start_process()
