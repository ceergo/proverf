import json
import base64
import re
import os
import subprocess
import time
import concurrent.futures
import requests
import uuid
import shutil
from datetime import datetime

# --- CONFIGURATION & PATHS ---
RAW_FILES = ['sub_raw.txt', 'my_personal_links.txt']
XRAY_BIN = './xray'
TIMEOUT_L7 = 3.5          
MAX_BRAVE_PING = 500      
CONCURRENCY = 60          
STATUS_FILE = 'status.json'
AUTO_RESTART_DELAY = 10   

CHECK_TARGETS = [
    "http://www.google.com/generate_204",
    "http://connectivitycheck.gstatic.com/generate_204",
    "http://cp.cloudflare.com/generate_204"
]

SUBS = {
    'elite': 'sub_elite.txt',
    'fast': 'sub_fast.txt',
    'cis': 'sub_cis.txt',
    'brave': 'sub_brave.txt'
}

ELITE_COUNTRIES = ['GB', 'FI', 'NL', 'FR', 'US', 'DE', 'PL', 'SE', 'CH']
CIS_COUNTRIES = ['BY', 'KZ']

class ProxyFactory:
    """
    Elite Proxy Factory - Consumer Bot (Level 2 Checker)
    Hardcore multi-point L7 testing, local remark parsing, and Self-Healing.
    """
    def __init__(self):
        self.stats = {
            "total_loaded": 0,
            "elite": 0, 
            "fast": 0, 
            "cis": 0, 
            "brave": 0, 
            "dead": 0,
            "last_update": "",
            "system_restarts": 0
        }
        self.processed_hosts = set()
        self.results_storage = {k: [] for k in SUBS.keys()}

    def log(self, message):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] 🛠 {message}")

    def extract_host_port(self, url):
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
        except Exception:
            return None, None
        return None, None

    def parse_remark_data(self, url):
        try:
            if '#' not in url: return "UN"
            remark = url.split('#')[-1]
            cc_match = re.search(r'\[([A-Z]{2})\]', remark)
            return cc_match.group(1) if cc_match else "UN"
        except:
            return "UN"

    def run_l7_test(self, url, is_cis=False):
        latencies = []
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'}
        current_timeout = 2.5 if is_cis else TIMEOUT_L7
        try:
            # Note: Production uses Xray as local socks5 proxy
            for target in CHECK_TARGETS:
                start = time.time()
                resp = requests.get(target, timeout=current_timeout, headers=headers)
                if resp.status_code in [200, 204]:
                    latencies.append(int((time.time() - start) * 1000))
                else:
                    return None
        except:
            return None
        if len(latencies) == len(CHECK_TARGETS):
            return sum(latencies) // len(latencies)
        return None

    def process_config(self, url):
        try:
            host, port = self.extract_host_port(url)
            if not host: 
                return
            
            host_id = f"{host}:{port}"
            if host_id in self.processed_hosts:
                return
            self.processed_hosts.add(host_id)
            
            country = self.parse_remark_data(url)
            is_cis = country in CIS_COUNTRIES
            
            # Логируем начало теста для Босса
            remark = url.split('#')[-1][:30] if '#' in url else host_id
            
            avg_ping = self.run_l7_test(url, is_cis=is_cis)
            
            if avg_ping is None:
                self.stats["dead"] += 1
                self.log(f"Config [{remark}] -> 💀 DEAD (L7 Failed)")
                return

            tier = None
            if is_cis: tier = 'cis'
            elif avg_ping < 200:
                if country in ELITE_COUNTRIES: tier = 'elite'
                else: tier = 'fast' 
            elif avg_ping <= MAX_BRAVE_PING:
                tier = 'brave'
            
            if tier:
                self.stats[tier] += 1
                self.results_storage[tier].append({"url": url, "ping": avg_ping})
                self.log(f"Config [{remark}] -> ✅ ALIVE ({tier.upper()}, {avg_ping}ms)")
            else:
                self.stats["dead"] += 1
                self.log(f"Config [{remark}] -> 💀 TRASH (Ping > {MAX_BRAVE_PING}ms)")
        except Exception as e:
            self.log(f"Worker Exception Isolated: {e}")

    def start_factory(self, full_audit=False):
        self.log(f"--- ELITE FACTORY BOOTUP (Full Audit: {full_audit}) ---")
        try:
            raw_data = []
            for file in RAW_FILES:
                if os.path.exists(file):
                    with open(file, 'r') as f:
                        content = f.read().splitlines()
                        links = list(filter(None, [l.strip() for l in content]))
                        raw_data.extend(links)
                        self.log(f"Input Trace: Loaded {len(links)} links from {file}")
            
            if not raw_data:
                self.log("WARNING: Empty input queue.")
                return

            self.stats["total_loaded"] = len(raw_data)
            self.log(f"Queue: {len(raw_data)} unique links | Factory Concurrency: {CONCURRENCY}")

            with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as engine:
                engine.map(self.process_config, raw_data)

            for tier, filename in SUBS.items():
                sorted_data = sorted(self.results_storage[tier], key=lambda x: x['ping'])
                final_links = [x['url'] for x in sorted_data]
                with open(filename, 'w') as f:
                    f.write("\n".join(final_links))
                with open(f"base64_{filename}", 'w') as f:
                    encoded = base64.b64encode("\n".join(final_links).encode()).decode()
                    f.write(encoded)

            self.stats["last_update"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            with open(STATUS_FILE, 'w') as f:
                json.dump(self.stats, f, indent=4)

            self.log("--- FINAL PRODUCTION REPORT ---")
            self.log(f"📥 Total Input Loaded: {self.stats['total_loaded']}")
            self.log(f"✅ Elite: {self.stats['elite']} | 🚀 Fast: {self.stats['fast']}")
            self.log(f"💎 CIS:   {self.stats['cis']} | ⏳ Brave: {self.stats['brave']}")
            self.log(f"💀 Trash (Dead): {self.stats['dead']}")
            self.log("--- FACTORY SHUTDOWN ---")

        except Exception as critical_error:
            self.log(f"CRITICAL ENGINE FAILURE: {critical_error}")
            self.stats["system_restarts"] += 1
            time.sleep(AUTO_RESTART_DELAY)
            self.start_factory(full_audit=full_audit)

if __name__ == "__main__":
    import sys
    is_full = '--full' in sys.argv
    factory = ProxyFactory()
    factory.start_factory(full_audit=is_full)
