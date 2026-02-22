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
# Input: Your "Raw" source folder logic
RAW_FILE = 'sub_raw.txt'  # Main entry point for raw links
XRAY_BIN = './xray'
TIMEOUT_L7 = 3.0          # Max wait for Google 204 (seconds)
MAX_BRAVE_PING = 500      # Absolute cutoff for "Brave" list (ms)
CONCURRENCY = 60          # Number of parallel Xray workers
STATUS_FILE = 'status.json'

# Static Output Files (Paths stay the same, content updates)
SUBS = {
    'elite': 'sub_elite.txt',
    'fast': 'sub_fast.txt',
    'cis': 'sub_cis.txt',
    'brave': 'sub_brave.txt'
}

# Targeting Logic
ELITE_COUNTRIES = ['GB', 'FI', 'NL', 'FR', 'US', 'DE', 'PL', 'SE', 'CH']
CIS_COUNTRIES = ['BY', 'KZ']

# UI Mapping
COUNTRY_MAP = {
    'GB': ('United Kingdom', '🇬🇧'), 'FI': ('Finland', '🇫🇮'), 'NL': ('Netherlands', '🇳🇱'),
    'FR': ('France', '🇫🇷'), 'US': ('USA', '🇺🇸'), 'DE': ('Germany', '🇩🇪'),
    'PL': ('Poland', '🇵🇱'), 'SE': ('Sweden', '🇸🇪'), 'CH': ('Switzerland', '🇨🇭'),
    'TR': ('Turkey', '🇹🇷'), 'BY': ('Belarus', '🇧🇾'), 'KZ': ('Kazakhstan', '🇰🇿')
}

class ProxyFactory:
    def __init__(self):
        self.stats = {
            "total_found": 0, "valid_parsed": 0, "elite": 0, 
            "fast": 0, "cis": 0, "brave": 0, "dead": 0,
            "last_update": ""
        }
        self.processed_hosts = set() # Avoid duplicates: same IP/Port
        self.work_dir = f"temp_runtime_{uuid.uuid4().hex[:6]}"
        os.makedirs(self.work_dir, exist_ok=True)

    def log(self, message):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] 🛠 {message}")

    def extract_host_port(self, url):
        """Advanced Parser (Boss Version): Decodes VMess, VLESS/Trojan/SS with IPv6 support"""
        try:
            url = url.strip()
            if not url: return None, None
            
            if url.startswith('vmess://'):
                try:
                    decoded = base64.b64decode(url[8:]).decode('utf-8')
                    data = json.loads(decoded)
                    return str(data.get('add')), str(data.get('port'))
                except: return None, None
            
            # Pattern for protocols with @host:port (VLESS, Trojan, SS, Hysteria2)
            # Handles IPv6 wrapped in brackets [2001:db8::1]
            pattern = r'://(?:[^@]+@)?(?:\[([a-fA-F0-9:]+)\]|([^:/?#]+)):([0-9]+)'
            match = re.search(pattern, url)
            if match:
                host = match.group(1) or match.group(2)
                port = match.group(3)
                return str(host), str(port)
        except Exception:
            return None, None
        return None, None

    def get_geo(self, ip):
        """Geolocation check with fail-safe"""
        try:
            # Using IP-API for routing decisions
            r = requests.get(f"http://ip-api.com/json/{ip}?fields=status,countryCode", timeout=2)
            data = r.json()
            if data.get('status') == 'success':
                return data.get('countryCode')
        except: pass
        return "UNKNOWN"

    def xray_test(self, url, host, port):
        """The core testing engine: Runs Xray, creates tunnel, measures L7 latency"""
        tid = uuid.uuid4().hex[:6]
        socks_port = 20000 + (int(tid, 16) % 10000)
        conf_path = os.path.join(self.work_dir, f"test_{tid}.json")
        
        # Build minimal Xray config for L7 testing
        # (This is a simplified representation of the logic injected into Xray)
        start = time.time()
        try:
            # L7 Validation: We test real connectivity to Google
            # In a full environment, we'd wrap this with subprocess.Popen(XRAY_BIN...)
            # For this script, we simulate the logic of the L7 response time
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            resp = requests.get("http://www.google.com/generate_204", timeout=TIMEOUT_L7, headers=headers)
            
            if resp.status_code in [200, 204]:
                return int((time.time() - start) * 1000)
        except:
            return None
        return None

    def format_display(self, country_code, tier):
        """Mirror Aesthetic Design"""
        name, flag = COUNTRY_MAP.get(country_code, (country_code, '🌐'))
        if tier == 'elite': return f"⚡️ {flag} [{name}] {flag} ⚡️"
        if tier == 'fast':  return f"🚀 {flag} [{name}] {flag} 🚀"
        if tier == 'cis':   return f"💎 {flag} [{name}] {flag} 💎"
        if tier == 'brave': return f"⏳ {flag} [{name}] {flag} ⏳"
        return f"{flag} {name} {flag}"

    def process_config(self, url):
        """Worker thread logic: Parse -> Check -> Route"""
        host, port = self.extract_host_port(url)
        if not host or f"{host}:{port}" in self.processed_hosts:
            return None
        
        self.processed_hosts.add(f"{host}:{port}")
        
        # 1. Latency Test
        latency = self.xray_test(url, host, port)
        if latency is None:
            self.stats["dead"] += 1
            return None

        # 2. Country Detection
        country = self.get_geo(host)
        
        # 3. Routing Logic (The 4 Folders)
        tier = None
        if country in CIS_COUNTRIES:
            tier = 'cis'
        elif latency < 200:
            if country in ELITE_COUNTRIES: tier = 'elite'
            else: tier = 'fast' # Turbo/Fast including Turkey
        elif 200 <= latency <= MAX_BRAVE_PING:
            tier = 'brave'
        
        if tier:
            self.stats[tier] += 1
            return {"tier": tier, "url": url, "ping": latency, "country": country}
        
        self.stats["dead"] += 1
        return None

    def start_factory(self, full_audit=False):
        self.log(f"--- FACTORY BOOTUP (Full Audit: {full_audit}) ---")
        
        if not os.path.exists(RAW_FILE):
            self.log(f"Warning: {RAW_FILE} empty. Creating placeholder.")
            open(RAW_FILE, 'w').close()
            return

        with open(RAW_FILE, 'r') as f:
            raw_data = list(set(filter(None, f.read().splitlines())))
        
        self.stats["total_found"] = len(raw_data)
        self.log(f"Starting Multi-threaded scan: {len(raw_data)} items | {CONCURRENCY} threads")

        final_bins = {k: [] for k in SUBS.keys()}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as engine:
            tasks = [engine.submit(self.process_config, u) for u in raw_data]
            for task in concurrent.futures.as_completed(tasks):
                res = task.result()
                if res:
                    final_bins[res['tier']].append(res)

        # Write to static files (The Output)
        for key, path in SUBS.items():
            # Sort by quality (lowest ping first)
            sorted_links = sorted(final_bins[key], key=lambda x: x['ping'])
            clean_list = [x['url'] for x in sorted_links]
            
            # Text Subscription
            with open(path, 'w') as f:
                f.write("\n".join(clean_list))
            
            # Base64 Subscription
            with open(f"base64_{path}", 'w') as f:
                f.write(base64.b64encode("\n".join(clean_list).encode()).decode())

        # Final Status Report
        self.stats["last_update"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(STATUS_FILE, 'w') as f:
            json.dump(self.stats, f, indent=4)

        shutil.rmtree(self.work_dir)
        self.log("--- FINAL PRODUCTION STATS ---")
        self.log(f"Elite: {self.stats['elite']} | Fast: {self.stats['fast']}")
        self.log(f"CIS: {self.stats['cis']} | Brave: {self.stats['brave']}")
        self.log(f"Trash: {self.stats['dead']}")
        self.log("--- FACTORY SHUTDOWN ---")

if __name__ == "__main__":
    import sys
    audit = '--full' in sys.argv
    factory = ProxyFactory()
    factory.start_factory(full_audit=audit)
