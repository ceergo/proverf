import os
import json
import subprocess
import hashlib
import time
import asyncio
import re
from datetime import datetime, timedelta

# --- CONFIGURATION ---
RAW_LINKS_FILE = "raw_links.txt"
DEAD_CACHE_FILE = "dead_cache.txt"
CLEANUP_LOG = "last_cleanup.txt"

# Output files
ELITE_GEMINI = "Elite_Gemini.txt"
STABLE_CHAT = "Stable_Chat.txt"
FAST_NO_GOOGLE = "Fast_NoGoogle.txt"

RESULT_FILES = [ELITE_GEMINI, STABLE_CHAT, FAST_NO_GOOGLE]

# Verification Rules
CHECK_RULES = [
    {
        "name": "AI_STUDIO",
        "url": "https://aistudio.google.com/",
        "must_not_contain": ["ai.google.dev", "available-regions"],
    },
    {
        "name": "SPOTIFY",
        "url": "https://open.spotify.com/",
        "must_not_contain": ["why-not-available"],
    }
]

MAIN_GEMINI_APP = "https://gemini.google.com/app"
SPEED_TEST_URL = "https://cachefly.cachefly.net/1mb.test" 

MAX_CONCURRENT_PROXIES = 100 

def get_md5(text):
    return hashlib.md5(text.encode()).hexdigest()

def remove_proxy_from_all_files(proxy_link):
    for file_path in RESULT_FILES:
        if not os.path.exists(file_path): continue
        try:
            with open(file_path, "r") as f:
                lines = f.readlines()
            new_lines = [l for l in lines if proxy_link not in l]
            if len(lines) != len(new_lines):
                with open(file_path, "w") as f:
                    f.writelines(new_lines)
        except: pass

def manage_cache_lifecycle():
    now = datetime.now()
    if os.path.exists(CLEANUP_LOG):
        with open(CLEANUP_LOG, "r") as f:
            try:
                last_run = datetime.fromisoformat(f.read().strip())
                if now - last_run > timedelta(hours=72):
                    print(f"[{now.strftime('%H:%M:%S')}] [CLEANUP] 72h reached. Wiping old data...")
                    if os.path.exists(DEAD_CACHE_FILE): os.remove(DEAD_CACHE_FILE)
                    for f_name in RESULT_FILES:
                        if os.path.exists(f_name): open(f_name, 'w').close()
                    with open(CLEANUP_LOG, "w") as f_out: f_out.write(now.isoformat())
            except: pass
    else:
        with open(CLEANUP_LOG, "w") as f_out: f_out.write(now.isoformat())

def extract_configs_from_text(text):
    """
    Parses raw text to find proxy-like strings (vmess, vless, ss, trojan, etc.)
    """
    # Regex for common proxy protocols
    pattern = r'(vless|vmess|ss|trojan|ssr)://[^\s|#]+'
    found = re.findall(pattern, text, re.IGNORECASE)
    return list(set(found))

async def load_and_expand_links():
    """
    Reads raw_links.txt, follows URLs if needed, and extracts individual configs.
    """
    if not os.path.exists(RAW_LINKS_FILE):
        print(f"[ERROR] {RAW_LINKS_FILE} missing!")
        return []

    print(f"[{datetime.now().strftime('%H:%M:%S')}] [PARSER] Reading {RAW_LINKS_FILE}...")
    
    with open(RAW_LINKS_FILE, "r") as f:
        raw_lines = [line.strip() for line in f if line.strip()]

    all_configs = []
    
    for entry in raw_lines:
        if entry.startswith("http"):
            print(f"  > [FETCHING] {entry} ...")
            try:
                # Use curl to fetch the subscription content
                cmd = ["curl", "-s", "-L", "-m", "15", entry]
                proc = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, _ = await proc.communicate()
                content = stdout.decode(errors='ignore')
                
                configs = extract_configs_from_text(content)
                print(f"    - Found {len(configs)} configs in this URL.")
                all_configs.extend(configs)
            except Exception as e:
                print(f"    - [ERROR] Failed to fetch {entry}: {e}")
        else:
            # It's a direct config line
            all_configs.append(entry)

    # Filtering through dead cache
    dead_ids = set()
    if os.path.exists(DEAD_CACHE_FILE):
        with open(DEAD_CACHE_FILE, "r") as f:
            dead_ids = set(line.strip() for line in f)

    unique_configs = list(set(all_configs))
    final_list = [c for c in unique_configs if get_md5(c) not in dead_ids]
    
    print(f"[{datetime.now().strftime('%H:%M:%S')}] [PARSER] Total unique: {len(unique_configs)} | Active: {len(final_list)} (Banned: {len(unique_configs)-len(final_list)})")
    return final_list

async def check_url_anchor(link, rule):
    start = time.time()
    try:
        cmd = [
            "curl", "-s", "-L", "--proxy", link, rule["url"],
            "--connect-timeout", "6", "-m", "10",
            "-A", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "-w", "%{url_effective}"
        ]
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = await proc.communicate()
        final_url = stdout.decode(errors='ignore').strip().lower()
        latency = round((time.time() - start) * 1000, 0)
        
        if not final_url or len(final_url) < 5: 
            return {"status": "FAIL", "url": "TIMEOUT", "ms": latency}
        
        is_blocked = any(marker in final_url for marker in rule.get("must_not_contain", []))
        return {"status": "BLOCK" if is_blocked else "OK", "url": final_url, "ms": latency}
    except:
        return {"status": "FAIL", "url": "ERROR", "ms": 0}

async def measure_speed(link):
    start = time.time()
    try:
        cmd = [
            "curl", "-L", "--proxy", link, SPEED_TEST_URL,
            "-o", "/dev/null", "-s", "--max-time", "12", "-w", "%{http_code}"
        ]
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = await proc.communicate()
        duration = time.time() - start
        
        if stdout.decode().strip() == "200":
            return round(8 / duration, 2)
        return 0
    except: return 0

async def async_headless_audit(link):
    """
    Real-time detailed trace of each proxy's journey.
    """
    trace = []
    
    # Speed check
    speed = await measure_speed(link)
    trace.append(f"SPEED: {speed} Mbps")
    
    # Burst Anchors
    tasks = [check_url_anchor(link, rule) for rule in CHECK_RULES]
    results = await asyncio.gather(*tasks)
    
    ai_studio = results[0]
    spotify = results[1]
    
    trace.append(f"AI_STUDIO: {ai_studio['status']} ({ai_studio['ms']}ms) -> {ai_studio['url']}")
    trace.append(f"SPOTIFY: {spotify['status']} ({spotify['ms']}ms) -> {spotify['url']}")

    # Gemini Validation
    gemini_res = await check_url_anchor(link, {"url": MAIN_GEMINI_APP, "must_not_contain": ["unsupported"]})
    gemini_ok = (gemini_res["status"] == "OK" and "/app" in gemini_res["url"])
    trace.append(f"GEMINI_APP: {'SUCCESS' if gemini_ok else 'FAILED'} ({gemini_res['ms']}ms) -> {gemini_res['url']}")

    # Decision logic
    category = "DEAD"
    if gemini_ok and ai_studio['status'] == "OK" and speed >= 15:
        category = "ELITE"
    elif gemini_ok and speed >= 0.5:
        category = "STABLE"
    elif speed >= 15:
        category = "FAST_NO_GOOGLE"

    # Real-time console report
    print(f"--- [PROBING] {link[:50]}... ---")
    for step in trace: print(f"  [>] {step}")
    print(f"  [!!!] RESULT: {category}\n")

    return link, category, speed

async def main_orchestrator():
    print(f"[{datetime.now().strftime('%H:%M:%S')}] --- STARTING REAL-TIME SIERRA AUDIT ---")
    
    manage_cache_lifecycle()
    # Step 1: Expand subscriptions and raw configs
    links = await load_and_expand_links()
    total = len(links)
    
    if total == 0:
        print("No configs found to check.")
        return

    # Process chunks
    for i in range(0, total, MAX_CONCURRENT_PROXIES):
        chunk = links[i : i + MAX_CONCURRENT_PROXIES]
        print(f"--- Processing Batch {i//MAX_CONCURRENT_PROXIES + 1} ({len(chunk)} nodes) ---")
        
        tasks = [async_headless_audit(link) for link in chunk]
        results = await asyncio.gather(*tasks)
        
        for link, cat, speed in results:
            if cat == "DEAD":
                with open(DEAD_CACHE_FILE, "a") as f: f.write(get_md5(link) + "\n")
                remove_proxy_from_all_files(link)
            else:
                target = {"ELITE": ELITE_GEMINI, "STABLE": STABLE_CHAT, "FAST_NO_GOOGLE": FAST_NO_GOOGLE}.get(cat)
                remove_proxy_from_all_files(link)
                with open(target, "a") as f:
                    f.write(f"{link} # [{cat}] {speed}Mbps | {datetime.now().strftime('%H:%M')}\n")

    print(f"[{datetime.now().strftime('%H:%M:%S')}] --- AUDIT COMPLETE ---")

if __name__ == "__main__":
    asyncio.run(main_orchestrator())
