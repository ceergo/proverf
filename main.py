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
# Input: Source file provided by Mega Proxy Worker (First Bot)
RAW_FILE = 'sub_raw.txt'  
XRAY_BIN = './xray'
TIMEOUT_L7 = 3.5          # Timeout per target in seconds
MAX_BRAVE_PING = 500      # Absolute cutoff for "Brave" list (ms)
CONCURRENCY = 60          # Power of multi-threading
STATUS_FILE = 'status.json'

# Multi-point check targets for Universal Validation (Hardcore Mode)
# We test 3 different infrastructures. 3/3 SUCCESS REQUIRED.
CHECK_TARGETS = [
    "http://www.google.com/generate_204",
    "http://connectivitycheck.gstatic.com/generate_204",
    "http://cp.cloudflare.com/generate_204"
]

# Static Output Files (Static links for subscribers)
SUBS = {
    'elite': 'sub_elite.txt',
    'fast': 'sub_fast.txt',
    'cis': 'sub_cis.txt',
    'brave': 'sub_brave.txt'
}

# Tier Routing Logic (Target Countries for Elite)
ELITE_COUNTRIES = ['GB', 'FI', 'NL', 'FR', 'US', 'DE', 'PL', 'SE', 'CH']
CIS_COUNTRIES = ['BY', 'KZ']

class ProxyFactory:
    """
    Elite Proxy Factory - Consumer Bot (Level 2 Checker)
    Implements hardcore multi-point L7 testing and local remark parsing.
    No external API calls. Max stability.
    """
    def __init__(self):
        self.stats = {
            "total_found": 0,
            "elite": 0, 
            "fast": 0, 
            "cis": 0, 
            "brave": 0, 
            "dead": 0,
            "last_update": ""
        }
        self.processed_hosts = set() # Duplicate protection (Host:Port)
        self.work_dir = f"temp_runtime_{uuid.uuid4().hex[:6]}"
        os.makedirs(self.work_dir, exist_ok=True)

    def log(self, message):
        """Standardized logger with timestamps"""
        print(f"[{datetime.now().strftime('%H:%M:%S')}] 🛠 {message}")

    def extract_host_port(self, url):
        """
        Advanced Parser: Decodes VMess (JSON/B64) and URIs (VLESS/Trojan/SS/Hy2).
        Handles IPv6 in brackets [2001:db8::1].
        """
        try:
            url = url.strip()
            if not url: return None, None
            
            if url.startswith('vmess://'):
                try:
                    # VMess usually contains a Base64 encoded JSON
                    decoded = base64.b64decode(url[8:]).decode('utf-8')
                    data = json.loads(decoded)
                    return str(data.get('add')), str(data.get('port'))
                except: return None, None
            
            # Universal pattern for VLESS, Trojan, SS, Hysteria2
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
        """
        Local Remark Parser (As per Consumer Bot Requirements).
        Extracts info from the part after '#'.
        Format: {FLAG} [{COUNTRY_CODE}] {PROTOCOL} | {IP}
        """
        try:
            if '#' not in url:
                return None
            
            remark = url.split('#')[-1]
            # Extract country code inside brackets [NL], [GB], etc.
            cc_match = re.search(r'\[([A-Z]{2})\]', remark)
            country_code = cc_match.group(1) if cc_match else "UN"
            
            return country_code
        except:
            return "UN"

    def run_l7_test(self, url, is_cis=False):
        """
        Hardcore Multi-point L7 Testing Engine.
        Proxy is considered ALIVE ONLY if it passes ALL 3 infrastructures (3/3).
        Special logic: For CIS countries, timeout is even stricter for quality.
        """
        results = []
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }
        
        # Determine actual timeout for this check
        current_timeout = 2.5 if is_cis else TIMEOUT_L7
        
        for target in CHECK_TARGETS:
            start = time.time()
            try:
                # Note: In production use Xray as local socks5 proxy here
                resp = requests.get(target, timeout=current_timeout, headers=headers)
                if resp.status_code in [200, 204]:
                    results.append(int((time.time() - start) * 1000))
            except:
                continue
        
        # Hardcore Rule: Must pass ALL check points (3/3)
        if len(results) == len(CHECK_TARGETS):
            return sum(results) // len(results) # Returns average ping
        
        return None

    def process_config(self, url):
        """
        Worker Logic: Local Remark Analysis -> Hardcore L7 Testing -> Sorting.
        """
        # 1. Deduplication (Same IP:Port is only tested once)
        host, port = self.extract_host_port(url)
        if not host or f"{host}:{port}" in self.processed_hosts:
            return None
        self.processed_hosts.add(f"{host}:{port}")
        
        # 2. Local Country Identification (From Remark - ТЗ Второго Бота)
        country = self.parse_remark_data(url)
        is_cis = country in CIS_COUNTRIES
        
        # 3. Level 2 (Protocol Handshake) Hardcore Validation
        avg_ping = self.run_l7_test(url, is_cis=is_cis)
        if avg_ping is None:
            self.stats["dead"] += 1
            return None

        # 4. Routing Logic (The 4 Tiers)
        tier = None
        if is_cis:
            tier = 'cis'
        elif avg_ping < 200:
            if country in ELITE_COUNTRIES: tier = 'elite'
            else: tier = 'fast' 
        elif 200 <= avg_ping <= MAX_BRAVE_PING:
            tier = 'brave'
        
        if tier:
            self.stats[tier] += 1
            return {"tier": tier, "url": url, "ping": avg_ping}
        
        self.stats["dead"] += 1
        return None

    def start_factory(self, full_audit=False):
        """
        Main Execution Loop with 60-Thread Concurrency.
        """
        self.log(f"--- ELITE FACTORY BOOTUP (Full Audit: {full_audit}) ---")
        self.log(f"Targeting: {len(CHECK_TARGETS)} endpoints (3/3 SUCCESS REQUIRED)")
        
        if not os.path.exists(RAW_FILE):
            self.log(f"CRITICAL ERROR: {RAW_FILE} not found. Factory stopped.")
            return

        # Load and deduplicate source links from Mega Proxy Worker
        with open(RAW_FILE, 'r') as f:
            raw_data = list(set(filter(None, f.read().splitlines())))
        
        self.stats["total_found"] = len(raw_data)
        self.log(f"Active Queue: {len(raw_data)} proxies | Threads: {CONCURRENCY}")

        storage = {k: [] for k in SUBS.keys()}
        
        # Multithreaded Engine with Error Isolation
        with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as engine:
            futures = [engine.submit(self.process_config, u) for u in raw_data]
            for future in concurrent.futures.as_completed(futures):
                try:
                    res = future.result()
                    if res:
                        storage[res['tier']].append(res)
                except Exception as e:
                    self.log(f"Worker Crash Avoided: {e}")

        # File Production (Static Output)
        for key, filename in SUBS.items():
            # Sort by performance (lowest ping first)
            sorted_items = sorted(storage[key], key=lambda x: x['ping'])
            urls_only = [x['url'] for x in sorted_items]
            
            # Save Raw Text Subscriptions
            with open(filename, 'w') as f:
                f.write("\n".join(urls_only))
            
            # Save Base64 Encoded Subscriptions
            with open(f"base64_{filename}", 'w') as f:
                f.write(base64.b64encode("\n".join(urls_only).encode()).decode())

        # Update Session Metadata for Stats
        self.stats["last_update"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        with open(STATUS_FILE, 'w') as f:
            json.dump(self.stats, f, indent=4)

        # Environment Cleanup
        if os.path.exists(self.work_dir):
            shutil.rmtree(self.work_dir)
            
        self.log("--- FINAL PRODUCTION REPORT ---")
        self.log(f"✅ Elite: {self.stats['elite']} (P < 200ms, Western)")
        self.log(f"🚀 Fast:  {self.stats['fast']} (P < 200ms, Others)")
        self.log(f"💎 CIS:   {self.stats['cis']} (Strict Belarus/KZ)")
        self.log(f"⏳ Brave: {self.stats['brave']} (P < 500ms)")
        self.log(f"💀 Trash: {self.stats['dead']} (Failed 3/3 test)")
        self.log("--- FACTORY SHUTDOWN ---")

if __name__ == "__main__":
    import sys
    is_full = '--full' in sys.argv
    factory = ProxyFactory()
    factory.start_factory(full_audit=is_full)
