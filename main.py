import os
import json
import subprocess
import hashlib
import time
import asyncio
import re
import sys
import base64
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

def log_event(msg):
    """Real-time logging for GitHub Actions."""
    timestamp = datetime.now().strftime('%H:%M:%S')
    print(f"[{timestamp}] {msg}", flush=True)

def get_md5(text):
    return hashlib.md5(text.encode()).hexdigest()

def remove_proxy_from_all_files(proxy_link):
    for file_path in RESULT_FILES:
        if not os.path.exists(file_path): continue
        try:
            with open(file_path, "r") as f:
                lines = f.readlines()
            # Фильтруем строку, если она содержит прокси-ссылку
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
                    log_event("[CLEANUP] 72h cycle! Wiping dead_cache and starting fresh audit...")
                    if os.path.exists(DEAD_CACHE_FILE): os.remove(DEAD_CACHE_FILE)
                    for f_name in RESULT_FILES:
                        if os.path.exists(f_name): open(f_name, 'w').close()
                    with open(CLEANUP_LOG, "w") as f_out: f_out.write(now.isoformat())
            except: pass
    else:
        with open(CLEANUP_LOG, "w") as f_out: f_out.write(now.isoformat())

def extract_configs_from_text(text):
    # Regex to find proxy links
    pattern = r'(vless|vmess|ss|trojan|ssr)://[^\s|#]+(?:#[^\s]*)?'
    found = re.findall(pattern, text, re.IGNORECASE)
    return list(set(found))

async def load_and_expand_links():
    if not os.path.exists(RAW_LINKS_FILE):
        log_event(f"[ERROR] {RAW_LINKS_FILE} not found!")
        return []

    log_event(f"[PARSER] Opening {RAW_LINKS_FILE}...")
    with open(RAW_LINKS_FILE, "r") as f:
        raw_lines = [line.strip() for line in f if line.strip()]

    all_configs = []
    for entry in raw_lines:
        if entry.startswith("http"):
            log_event(f"[FETCH] Requesting: {entry}")
            try:
                # Using curl with follow-redirects and insecure flags
                cmd = ["curl", "-s", "-L", "-k", "-m", "20", entry]
                proc = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                stdout, _ = await proc.communicate()
                content = stdout.decode(errors='ignore')
                
                # Check for Base64 (many subs use it)
                if not content.startswith(('vless', 'vmess', 'ss', 'trojan')):
                    try:
                        content = base64.b64decode(content).decode('utf-8')
                        log_event("  ├─ Base64 detected and decoded successfully.")
                    except: pass

                configs = extract_configs_from_text(content)
                log_event(f"  └─ Success! Extracted {len(configs)} nodes.")
                all_configs.extend(configs)
            except Exception as e:
                log_event(f"  └─ [ERROR] Fetch failed: {e}")
        else:
            extracted = extract_configs_from_text(entry)
            all_configs.extend(extracted if extracted else [entry])

    dead_ids = set()
    if os.path.exists(DEAD_CACHE_FILE):
        with open(DEAD_CACHE_FILE, "r") as f:
            dead_ids = set(line.strip() for line in f)

    unique_configs = list(set(all_configs))
    final_list = []
    
    for c in unique_configs:
        if get_md5(c) in dead_ids:
            continue
        final_list.append(c)
    
    log_event(f"[PARSER] Unique: {len(unique_configs)} | Fresh: {len(final_list)} | Banned: {len(unique_configs)-len(final_list)}")
    return final_list

async def check_url_anchor(link, rule):
    start = time.time()
    try:
        cmd = [
            "curl", "-s", "-L", "-k", "--proxy", link, rule["url"],
            "--connect-timeout", "10", "-m", "15",
            "-A", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
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
        # Добавили флаг -w для проверки размера и кода ответа
        cmd = [
            "curl", "-L", "-k", "--proxy", link, SPEED_TEST_URL,
            "-o", "/dev/null", "-s", "--max-time", "20", 
            "-w", "%{http_code}:%{size_download}"
        ]
        proc = await asyncio.create_subprocess_exec(*cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        stdout, _ = await proc.communicate()
        res_data = stdout.decode().strip().split(':')
        
        if len(res_data) == 2:
            code, size = res_data[0], int(res_data[1])
            duration = time.time() - start
            if code == "200" and size > 100000: # Минимум 100КБ для засчета скорости
                return round((size * 8) / (duration * 1000000), 2) # Mbps
        return 0
    except: return 0

async def async_headless_audit(link):
    proxy_id = get_md5(link)[:8]
    log_event(f"[AUDIT:{proxy_id}] >>> PROBING: {link[:50]}...")
    
    # 1. Speed (First check, if 0 - likely dead/fake)
    speed = await measure_speed(link)
    log_event(f"  [>] Speed: {speed} Mbps")
    
    # 2. Regional Anchors
    tasks = [check_url_anchor(link, rule) for rule in CHECK_RULES]
    results = await asyncio.gather(*tasks)
    ai_studio, spotify = results[0], results[1]
    log_event(f"  [>] AI_Studio: {ai_studio['status']} ({ai_studio['ms']}ms)")
    log_event(f"  [>] Spotify: {spotify['status']} ({spotify['ms']}ms)")

    # 3. Gemini App Test
    gemini_res = await check_url_anchor(link, {"url": MAIN_GEMINI_APP, "must_not_contain": ["unsupported"]})
    gemini_ok = (gemini_res["status"] == "OK" and "/app" in gemini_res["url"])
    log_event(f"  [>] Gemini_Web: {'PASSED' if gemini_ok else 'FAILED'} ({gemini_res['ms']}ms)")

    # Final Verdict
    category = "DEAD"
    if gemini_ok and ai_studio['status'] == "OK" and speed >= 10:
        category = "ELITE"
    elif gemini_ok and speed >= 0.1:
        category = "STABLE"
    elif speed >= 5:
        category = "FAST_NO_GOOGLE"

    log_event(f"[AUDIT:{proxy_id}] VERDICT: {category}\n")
    return link, category, speed

async def main_orchestrator():
    log_event("--- SIERRA ORCHESTRATOR ONLINE ---")
    
    # Init files
    for f_name in RESULT_FILES:
        if not os.path.exists(f_name): open(f_name, 'a').close()

    manage_cache_lifecycle()
    links = await load_and_expand_links()
    
    if not links:
        log_event("No fresh nodes to audit. Check dead_cache.txt or raw_links.txt content.")
        return

    # Process chunks
    for i in range(0, len(links), MAX_CONCURRENT_PROXIES):
        chunk = links[i : i + MAX_CONCURRENT_PROXIES]
        log_event(f"--- Processing Batch {i//MAX_CONCURRENT_PROXIES + 1} ---")
        
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
                    f.write(f"{link} # [{cat}] {speed}Mbps | {datetime.now().strftime('%Y-%m-%d %H:%M')}\n")

    log_event("--- AUDIT COMPLETE ---")

if __name__ == "__main__":
    asyncio.run(main_orchestrator())
