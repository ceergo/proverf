import os
import json
import subprocess
import hashlib
import time
import asyncio
from datetime import datetime, timedelta

# --- CONFIGURATION (Boss, do not touch these paths) ---
RAW_LINKS_FILE = "raw_links.txt"
DEAD_CACHE_FILE = "dead_cache.txt"
CLEANUP_LOG = "last_cleanup.txt"

# Output files
ELITE_GEMINI = "Elite_Gemini.txt"     # Full access + High Speed
STABLE_CHAT = "Stable_Chat.txt"      # Working Gemini + Normal Speed
FAST_NO_GOOGLE = "Fast_NoGoogle.txt" # High Speed, but Google is blocked

RESULT_FILES = [ELITE_GEMINI, STABLE_CHAT, FAST_NO_GOOGLE]

# Verification Rules (The "Anchors")
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

# Concurrency Management
MAX_CONCURRENT_PROXIES = 100 

def get_md5(text):
    """Generates a stable MD5 hash for unique proxy identification."""
    return hashlib.md5(text.encode()).hexdigest()

def remove_proxy_from_all_files(proxy_link):
    """Ensures a proxy doesn't exist in any output file before re-categorizing or banning."""
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
        except Exception as e:
            pass # Silent error to maintain loop stability

def manage_cache_lifecycle():
    """Wipes dead cache and fresh results every 72 hours based on last_cleanup timestamp."""
    now = datetime.now()
    if os.path.exists(CLEANUP_LOG):
        with open(CLEANUP_LOG, "r") as f:
            try:
                last_run = datetime.fromisoformat(f.read().strip())
                if now - last_run > timedelta(hours=72):
                    print(f"[{now.strftime('%H:%M:%S')}] [CLEANUP] 72h limit reached. Cleaning database...")
                    if os.path.exists(DEAD_CACHE_FILE): os.remove(DEAD_CACHE_FILE)
                    for f_name in RESULT_FILES:
                        if os.path.exists(f_name): open(f_name, 'w').close()
                    with open(CLEANUP_LOG, "w") as f_out: f_out.write(now.isoformat())
            except:
                with open(CLEANUP_LOG, "w") as f_out: f_out.write(now.isoformat())
    else:
        with open(CLEANUP_LOG, "w") as f_out: f_out.write(now.isoformat())

def load_and_filter_input():
    """Loads proxies from raw_links.txt and skips those already in dead_cache."""
    if not os.path.exists(RAW_LINKS_FILE):
        print(f"[ERROR] {RAW_LINKS_FILE} not found!")
        return []
    with open(RAW_LINKS_FILE, "r") as f:
        links = list(set(line.strip() for line in f if line.strip()))
    
    dead_ids = set()
    if os.path.exists(DEAD_CACHE_FILE):
        with open(DEAD_CACHE_FILE, "r") as f:
            dead_ids = set(line.strip() for line in f)
            
    filtered = [l for l in links if get_md5(l) not in dead_ids]
    print(f"--- [LOADER] ---")
    print(f"Total links: {len(links)}")
    print(f"Ignored (Banned): {len(links) - len(filtered)}")
    print(f"Active queue: {len(filtered)}")
    return filtered

async def check_url_anchor(link, rule):
    """Executes curl with redirect tracking and logs final destination URL."""
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
            return {"name": rule["name"], "status": "FAIL", "final_url": "NO_RESPONSE"}
        
        # Checking for forbidden patterns in final URL
        is_blocked = any(marker in final_url for marker in rule["must_not_contain"])
        return {
            "name": rule["name"], 
            "status": "BLOCK" if is_blocked else "OK", 
            "final_url": final_url
        }
    except:
        return {"name": rule["name"], "status": "FAIL", "final_url": "SYSTEM_ERROR"}

async def measure_speed(link):
    """Measures raw download speed for 1MB file."""
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
            # 8 bits per byte -> Mbps calculation
            return round(8 / duration, 2) if duration > 0 else 0
        return 0
    except:
        return 0

async def async_headless_audit(link):
    """
    Core Logic: Step-by-step trace of proxy performance.
    Outputs detailed logs for real-time monitoring.
    """
    trace = []
    
    # 1. Speed Test
    speed = await measure_speed(link)
    trace.append(f"SPEED: {speed} Mbps")
    
    # 2. Burst Anchors (Parallel)
    burst_tasks = [check_url_anchor(link, rule) for rule in CHECK_RULES]
    burst_results = await asyncio.gather(*burst_tasks)
    
    # Extract results for logic
    ai_studio_res = next((r for r in burst_results if r["name"] == "AI_STUDIO"), None)
    spotify_res = next((r for r in burst_results if r["name"] == "SPOTIFY"), None)
    
    ai_studio_ok = ai_studio_res["status"] == "OK" if ai_studio_res else False
    any_block = any(r["status"] == "BLOCK" for r in burst_results)
    all_failed = all(r["status"] == "FAIL" for r in burst_results)

    trace.append(f"ANCHOR AI_STUDIO: {ai_studio_res['status']} -> {ai_studio_res['final_url']}")
    trace.append(f"ANCHOR SPOTIFY: {spotify_res['status']} -> {spotify_res['final_url']}")

    # 3. Gemini App Validation (Final Path /app check)
    res_gemini = await check_url_anchor(link, {"url": MAIN_GEMINI_APP, "must_not_contain": ["unsupported"], "name": "GEMINI_APP"})
    gemini_app_working = (res_gemini["status"] == "OK" and "/app" in res_gemini.get("final_url", ""))
    
    trace.append(f"GEMINI_APP_AUTH: {'SUCCESS' if gemini_app_working else 'FAILED'} -> {res_gemini['final_url']}")

    # --- DECISION ENGINE ---
    decision = "DEAD"
    
    # Priority 1: Elite (Full Access + Speed)
    if gemini_app_working and ai_studio_ok and not any_block and speed >= 15:
        decision = "ELITE"
    # Priority 2: Stable (Functional Gemini)
    elif gemini_app_working and speed >= 0.5:
        decision = "STABLE"
    # Priority 3: Fast No Google (Just fast pipe)
    elif speed >= 15:
        decision = "FAST_NO_GOOGLE"
    
    # Print Trace to Console for Boss
    print(f"--- [AUDIT START] {link} ---")
    for step in trace:
        print(f"  {step}")
    print(f"  [>>>] FINAL CATEGORY: {decision}\n")

    return link, decision, speed

async def main_orchestrator():
    """Manages the lifecycle of the Sieve audit."""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] --- INITIATING SIERRA MASTER AUDIT ---")
    
    manage_cache_lifecycle()
    links = load_and_filter_input()
    total = len(links)
    
    if total == 0:
        print("No work to do. Exiting.")
        return

    # Processing in concurrent chunks
    for i in range(0, total, MAX_CONCURRENT_PROXIES):
        chunk = links[i : i + MAX_CONCURRENT_PROXIES]
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Processing Batch {i//MAX_CONCURRENT_PROXIES + 1}...")
        
        tasks = [async_headless_audit(link) for link in chunk]
        results = await asyncio.gather(*tasks)
        
        for link, category, speed in results:
            if category == "DEAD":
                # Permanent Ban for this cycle
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
                # Clean up existing entry before adding updated one
                remove_proxy_from_all_files(link)
                with open(target_file, "a") as f:
                    f.write(f"{link} # [{category}] {speed}Mbps | Date: {datetime.now().strftime('%d.%m %H:%M')}\n")

    print(f"[{datetime.now().strftime('%H:%M:%S')}] --- MASTER AUDIT COMPLETE ---")

if __name__ == "__main__":
    try:
        asyncio.run(main_orchestrator())
    except KeyboardInterrupt:
        print("\nAudit interrupted by Boss.")
