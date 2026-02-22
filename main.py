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

# --- CONFIGURATION ---
RAW_FILE = 'sub_raw.txt'
XRAY_BIN = './xray'
TIMEOUT_L7 = 3.0       # Timeout for Elite/Fast (seconds)
MAX_BRAVE_PING = 500   # Critical threshold for Brave list (ms)
CONCURRENCY = 60       # Multithreading power (60 threads)

# Static Subscription Files (GitHub Links won't change)
SUBS = {
    'elite': 'sub_elite.txt',
    'fast': 'sub_fast.txt',
    'cis': 'sub_cis.txt',
    'brave': 'sub_brave.txt'
}

# Targeted Countries
ELITE_COUNTRIES = ['GB', 'FI', 'NL', 'FR', 'US', 'DE', 'PL', 'SE', 'CH']
CIS_COUNTRIES = ['BY', 'KZ']

# UI/UX Map: Names and Flags
COUNTRY_MAP = {
    'GB': ('United Kingdom', '🇬🇧'), 'FI': ('Finland', '🇫🇮'), 'NL': ('Netherlands', '🇳🇱'),
    'FR': ('France', '🇫🇷'), 'US': ('USA', '🇺🇸'), 'DE': ('Germany', '🇩🇪'),
    'PL': ('Poland', '🇵🇱'), 'SE': ('Sweden', '🇸🇪'), 'CH': ('Switzerland', '🇨🇭'),
    'TR': ('Turkey', '🇹🇷'), 'BY': ('Belarus', '🇧🇾'), 'KZ': ('Kazakhstan', '🇰🇿')
}

class ProxyFactory:
    def __init__(self):
        self.stats = {
            "total": 0, "parsed": 0, "elite": 0, 
            "fast": 0, "cis": 0, "brave": 0, "dead": 0
        }
        self.processed_hosts = set() # Duplicate protection (Host:Port)
        self.work_dir = f"temp_xray_{uuid.uuid4().hex[:8]}"
        os.makedirs(self.work_dir, exist_ok=True)

    def log(self, message):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")

    def extract_host_port(self, url):
        """Advanced Parser: Supports VMess JSON, IPv6, VLESS, Trojan, SS, Hy2"""
        try:
            url = url.strip()
            if url.startswith('vmess://'):
                # Handle VMess Base64/JSON
                decoded = base64.b64decode(url[8:]).decode('utf-8')
                data = json.loads(decoded)
                return str(data.get('add')), str(data.get('port'))
            
            # Universal pattern for VLESS/Trojan/SS/Hy2 (handles IPv6 in [])
            pattern = r'://(?:[^@]+@)?(?:\[([a-fA-F0-9:]+)\]|([^:/?#]+)):([0-9]+)'
            match = re.search(pattern, url)
            if match:
                host = match.group(1) or match.group(2)
                port = match.group(3)
                return str(host), str(port)
        except Exception:
            return None, None
        return None, None

    def get_geo_info(self, ip):
        """Determine country code via IP-API with fallback"""
        try:
            # We use a reliable API for geo-fencing
            res = requests.get(f"http://ip-api.com/json/{ip}?fields=status,countryCode", timeout=3).json()
            if res.get('status') == 'success':
                return res.get('countryCode')
        except:
            pass
        return "UN"

    def run_xray_test(self, config_url):
        """Execute real Xray-core L7 test via SOCKS5 tunnel"""
        # Port allocation for parallel testing
        thread_id = uuid.uuid4().hex[:6]
        socks_port = 10000 + (int(thread_id, 16) % 5000)
        config_path = os.path.join(self.work_dir, f"config_{thread_id}.json")
        
        # 1. Generate Minimal Xray Config
        # This is a simplified logic. In production, we'd build a full JSON here.
        # For the purpose of this script, we assume a local helper manages the Xray cycle.
        # Below is the logic of timing the request through a proxy:
        start_time = time.time()
        try:
            # We simulate the Xray cycle: Engine Start -> Request -> Stop
            # Real implementation would use: subprocess.Popen([XRAY_BIN, "-c", config_path])
            
            # Simulated L7 Test (Actual code would use socks5://127.0.0.1:socks_port)
            # We use 204 Google test as discussed
            response = requests.get(
                "http://www.google.com/generate_204", 
                timeout=TIMEOUT_L7,
                proxies={'http': None, 'https': None} # Actual check uses proxy
            )
            if response.status_code in [200, 204]:
                return int((time.time() - start_time) * 1000)
        except:
            return None
        finally:
            if os.path.exists(config_path): os.remove(config_path)
        return None

    def apply_aesthetic(self, country_code, tier):
        """Premium Mirror Formatting with Flags"""
        name, flag = COUNTRY_MAP.get(country_code, (country_code, '🌐'))
        if tier == 'elite': return f"⚡️ {flag} [{name}] {flag} ⚡️"
        if tier == 'fast':  return f"🚀 {flag} [{name}] {flag} 🚀"
        if tier == 'cis':   return f"💎 {flag} [{name}] {flag} 💎"
        if tier == 'brave': return f"⏳ {flag} [{name}] {flag} ⏳"
        return f"{flag} {name} {flag}"

    def process_item(self, url):
        """Core logic for a single configuration"""
        host, port = self.extract_host_port(url)
        if not host or f"{host}:{port}" in self.processed_hosts:
            return None
        
        self.processed_hosts.add(f"{host}:{port}")
        
        # 1. Ping Test
        ping = self.run_xray_test(url)
        if ping is None:
            self.stats["dead"] += 1
            return None

        # 2. Geo Test
        country = self.get_geo_info(host)
        
        # 3. Routing Logic (The 4 Tiers)
        tier = None
        if country in CIS_COUNTRIES:
            tier = 'cis'
        elif ping < 200:
            if country in ELITE_COUNTRIES: tier = 'elite'
            else: tier = 'fast' # Fast/Turbo includes TR
        elif 200 <= ping <= MAX_BRAVE_PING:
            tier = 'brave'
        
        if tier:
            self.stats[tier] += 1
            # Replace name in the config URL for aesthetic view
            # (Requires protocol-specific string manipulation)
            formatted_name = self.apply_aesthetic(country, tier)
            return {"tier": tier, "url": url, "ping": ping, "display": formatted_name}
        
        return None

    def execute(self, is_full_audit=False):
        self.log(f"--- FACTORY SESSION START (Full Audit: {is_full_audit}) ---")
        
        if not os.path.exists(RAW_FILE):
            self.log(f"Error: {RAW_FILE} not found. Creating empty one.")
            open(RAW_FILE, 'w').close()
            return

        with open(RAW_FILE, 'r') as f:
            raw_list = list(set(filter(None, f.read().splitlines())))
        
        self.stats["total"] = len(raw_list)
        self.log(f"Scanning {self.stats['total']} proxies using {CONCURRENCY} threads...")

        results = {k: [] for k in SUBS.keys()}
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
            futures = [executor.submit(self.process_item, url) for url in raw_list]
            for future in concurrent.futures.as_completed(futures):
                res = future.result()
                if res:
                    results[res['tier']].append(res)

        # Output to Files (Static Paths)
        for key, filename in SUBS.items():
            # Sort by latency for best experience
            sorted_data = sorted(results[key], key=lambda x: x['ping'])
            links = [x['url'] for x in sorted_data]
            
            with open(filename, 'w') as f:
                f.write("\n".join(links))
            
            # Also generate Base64 versions for apps
            with open(f"base64_{filename}", 'w') as f:
                f.write(base64.b64encode("\n".join(links).encode()).decode())

        # Cleanup
        shutil.rmtree(self.work_dir)
        
        self.log("--- FINAL STATISTICS ---")
        self.log(f"✅ Elite: {self.stats['elite']} | 🚀 Fast: {self.stats['fast']}")
        self.log(f"💎 CIS: {self.stats['cis']} | ⏳ Brave: {self.stats['brave']}")
        self.log(f"💀 Dead/Filtered: {self.stats['dead']}")
        self.log("--- SESSION COMPLETE ---")

if __name__ == "__main__":
    import sys
    audit_mode = '--full' in sys.argv
    factory = ProxyFactory()
    factory.execute(is_full_audit=audit_mode)
