import os
import json
import subprocess
import hashlib
import time
import asyncio
from datetime import datetime, timedelta

# --- CONFIGURATION ---
RAW_LINKS_FILE = "raw_links.txt"
DEAD_CACHE_FILE = "dead_cache.txt"
CLEANUP_LOG = "last_cleanup.txt"

# Output files (The Sieve)
ELITE_GEMINI = "Elite_Gemini.txt"     # Full access to AI Studio & Gemini App + High Speed
STABLE_CHAT = "Stable_Chat.txt"      # Limited access or Slower speed
FAST_NO_GOOGLE = "Fast_NoGoogle.txt" # Google blocked, but proxy is fast and alive

RESULT_FILES = [ELITE_GEMINI, STABLE_CHAT, FAST_NO_GOOGLE]

# The "Anchor" Logic: Reliable markers provided by Boss
CHECK_RULES = [
    {
        "name": "AI_STUDIO",
        "url": "https://aistudio.google.com/",
        "must_not_contain": ["ai.google.dev", "available-regions"],
        "weight": "high"
    },
    {
        "name": "SPOTIFY",
        "url": "https://open.spotify.com/",
        "must_not_contain": ["why-not-available"],
        "weight": "medium"
    }
]

MAIN_GEMINI_APP = "https://gemini.google.com/app"
SPEED_TEST_URL = "https://cachefly.cachefly.net/1mb.test" 

# Concurrency settings
MAX_CONCURRENT_PROXIES = 100 

def get_md5(text):
    """Generates a stable MD5 hash for each proxy link."""
    return hashlib.md5(text.encode()).hexdigest()

def remove_proxy_from_all_files(proxy_link):
    """Removes a proxy from all result files to ensure data integrity."""
    for file_path in RESULT_FILES:
        if not os.path.exists(file_path):
            continue
        try:
            with open(file_path, "r") as f:
                lines = f.readlines()
            new_lines = [l for l in lines if proxy_link not in l]
            if len(lines) != len(new_lines):
                with open(file_path, "w") as f:
                    f.writelines(new_lines)
        except:
            pass

def manage_cache_lifecycle():
    """Wipes dead cache and results every 72 hours."""
    now = datetime.now()
    if os.path.exists(CLEANUP_LOG):
        with open(CLEANUP_LOG, "r") as f:
            try:
                last_run = datetime.fromisoformat(f.read().strip())
                if now - last_run > timedelta(hours=72):
                    print(f"[{now.strftime('%H:%M:%S')}] 72h Cleanup Triggered. Wiping caches...")
                    if os.path.exists(DEAD_CACHE_FILE): os.remove(DEAD_CACHE_FILE)
                    for f_name in RESULT_FILES:
                        if os.path.exists(f_name): open(f_name, 'w').close()
                    with open(CLEANUP_LOG, "w") as f_out: f_out.write(now.isoformat())
            except:
                with open(CLEANUP_LOG, "w") as f_out: f_out.write(now.isoformat())
    else:
        with open(CLEANUP_LOG, "w") as f_out: f_out.write(now.isoformat())

def load_and_filter_input():
    """Loads links and filters via MD5 ban-list."""
    if not os.path.exists(RAW_LINKS_FILE):
        return []
    with open(RAW_LINKS_FILE, "r") as f:
        links = list(set(line.strip() for line in f if line.strip()))
    dead_ids = set()
    if os.path.exists(DEAD_CACHE_FILE):
        with open(DEAD_CACHE_FILE, "r") as f:
            dead_ids = set(line.strip() for line in f)
    filtered = [l for l in links if get_md5(l) not in dead_ids]
    print(f"Loaded: {len(links)} | Filtered (already dead): {len(links) - len(filtered)} | To check: {len(filtered)}")
    return filtered

async def check_url_anchor(link, rule):
    """Checks URL access and logs the final redirect path."""
    try:
        cmd = [
            "curl", "-s", "-L", "--proxy", link, rule["url"],
            "--connect-timeout", "6", "-m", "10",
            "-A", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
            "-w", "%{url_effective}"
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        final_url = stdout.decode(errors='ignore').strip().lower()
        
        if not final_url or len(final_url) < 5: 
            return {"name": rule["name"], "status": "FAIL", "final_url": "TIMEOUT/NO_RESPONSE"}
        
        is_blocked = any(marker in final_url for marker in rule["must_not_contain"])
        return {
            "name": rule["name"], 
            "status": "BLOCK" if is_blocked else "OK", 
            "final_url": final_url
        }
    except:
        return {"name": rule["name"], "status": "FAIL", "final_url": "ERROR"}

async def measure_speed(link):
    """Measures speed and returns Mbps."""
    try:
        start_time = time.time()
        cmd = [
            "curl", "-L", "--proxy", link, SPEED_TEST_URL,
            "-o", "/dev/null", "-s", "--max-time", "12", "-w", "%{http_code}"
        ]
        proc = await asyncio.create_subprocess_exec(
            *cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        end_time = time.time()
        
        if stdout.decode().strip() == "200":
            duration = end_time - start_time
            return round(8 / duration, 2) if duration > 0 else 0
        return 0
    except:
        return 0

async def async_headless_audit(link):
    """
    Detailed Audit with Trace Logging.
    Each step is recorded to explain the final decision.
    """
    trace = []
    
    # STEP 1: Speed
    speed = await measure_speed(link)
    trace.append(f"Speed: {speed}Mbps")
    
    # STEP 2: Anchors (Burst)
    burst_tasks = [check_url_anchor(link, rule) for rule in CHECK_RULES]
    burst_results = await asyncio.gather(*burst_tasks)
    
    ai_studio_res = next((r for r in burst_results if r["name"] == "AI_STUDIO"), None)
    spotify_res = next((r for r in burst_results if r["name"] == "SPOTIFY"), None)
    
    ai_studio_ok = ai_studio_res["status"] == "OK" if ai_studio_res else False
    any_block = any(r["status"] == "BLOCK" for r in burst_results)
    all_failed = all(r["status"] == "FAIL" for r in burst_results)

    trace.append(f"AI_Studio: {ai_studio_res['status']} ({ai_studio_res['final_url']})")
    trace.append(f"Spotify: {spotify_res['status']} ({spotify_res['final_url']})")

    # STEP 3: Gemini Main
    res_gemini = await check_url_anchor(link, {"url": MAIN_GEMINI_APP, "must_not_contain": ["unsupported"], "name": "GEMINI_APP"})
    gemini_app_working = (res_gemini["status"] == "OK" and "/app" in res_gemini.get("final_url", ""))
    trace.append(f"Gemini_App: {'WORKING' if gemini_app_working else 'BLOCKED'} (Final: {res_gemini['final_url']})")

    # --- DECISION LOGIC ---
    decision = "DEAD"
    
    # ELITE Criteria
    if gemini_app_working and ai_studio_ok and not any_block and speed >= 15:
        decision = "ELITE"
    # STABLE Criteria
    elif gemini_app_working and speed >= 0.5:
        decision = "STABLE"
    # FAST_NO_GOOGLE Criteria
    elif speed >= 15:
        decision = "FAST_NO_GOOGLE"
    
    # Log the full trace to console
    print(f"--- [AUDIT] {link} ---")
    for step in trace:
        print(f"  > {step}")
    print(f"  [!] FINAL DECISION: {decision}\n")

    return link, decision, speed

async def main_orchestrator():
    print(f"[{datetime.now().strftime('%H:%M:%S')}] --- STARTING DETAILED PURGE AUDIT ---")
    
    manage_cache_lifecycle()
    links = load_and_filter_input()
    total = len(links)
    
    for i in range(0, total, MAX_CONCURRENT_PROXIES):
        chunk = links[i : i + MAX_CONCURRENT_PROXIES]
        tasks = [async_headless_audit(link) for link in chunk]
        results = await asyncio.gather(*tasks)
        
        for link, category, speed in results:
            if category == "DEAD":
                with open(DEAD_CACHE_FILE, "a") as f: 
                    f.write(get_md5(link) + "\n")
                remove_proxy_from_all_files(link)
                continue
                
            target_file = {
                "ELITE": ELITE_GEMINI,
                "STABLE": STABLE_CHAT,
                "FAST_NO_GOOGLE": FAST_NO_GOOGLE
            }.get(category)

            if target_file:
                remove_proxy_from_all_files(link)
                with open(target_file, "a") as f:
                    f.write(f"{link} # [{category}] {speed}Mbps\n")

        print(f"Batch Progress: {min(i + MAX_CONCURRENT_PROXIES, total)} / {total}")

    print(f"[{datetime.now().strftime('%H:%M:%S')}] --- DEEP AUDIT COMPLETE ---")

if __name__ == "__main__":
    asyncio.run(main_orchestrator())
