import json
import os
import time
import subprocess
import asyncio
import aiohttp

# --- CONFIGURATION (Boss, you can tune these) ---
INPUT_FILE = "raw_links.txt"   # Where the primary bot stores raw links
CACHE_FILE = "dead_cache.txt"   # IDs of nodes that failed tests
CLEANUP_LOG = "last_cleanup.txt"

# Thresholds for sorting
MAX_PING = 300       # Max allowed ping for "Stable Reserve"
ELITE_PING = 150     # Max ping for "Elite"
SPEED_MIN = 3.0      # Min speed in Mbps for "Speed Master"

# --- 1. CACHE MANAGEMENT (72-hour cycle) ---
def manage_cache_lifecycle():
    """Removes cache and old files every 3 days to refresh the pool."""
    now = time.time()
    three_days = 259200 # seconds
    
    if os.path.exists(CLEANUP_LOG):
        with open(CLEANUP_LOG, "r") as f:
            last_clean = float(f.read().strip())
    else:
        last_clean = 0
        
    if now - last_clean > three_days:
        print("[System] 72h Cleanup triggered. Clearing cache...")
        if os.path.exists(CACHE_FILE): os.remove(CACHE_FILE)
        # Clear output files to ensure fresh overwrite
        for f in ["Elite_Gemini.txt", "Speed_Master.txt", "Stable_Reserve.txt"]:
            if os.path.exists(f): os.remove(f)
            
        with open(CLEANUP_LOG, "w") as f:
            f.write(str(now))

# --- 2. INPUT PROCESSING ---
def load_and_filter_input():
    """Reads raw links and filters out duplicates and cached dead nodes."""
    if not os.path.exists(INPUT_FILE):
        return []
    
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        links = list(set(line.strip() for line in f if line.strip()))
    
    dead_pool = set()
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f:
            dead_pool = set(line.strip() for line in f if line.strip())
            
    # Filter: keep only links not in the dead pool
    # We use a simple hash of the link as an ID
    filtered = [l for l in links if str(hash(l)) not in dead_pool]
    return filtered

# --- 3. LITESPEEDTEST CORE INTEGRATION ---
def execute_lite_benchmark():
    """Runs the LiteSpeedTest binary and parses JSON results."""
    # We create a temporary file for LiteSpeedTest to read
    temp_input = "temp_batch.txt"
    links = load_and_filter_input()
    
    if not links:
        print("[System] No new links to process.")
        return []

    with open(temp_input, "w") as f:
        f.write("\n".join(links))

    print(f"[System] Starting LiteSpeedTest for {len(links)} nodes...")
    
    # Run the binary. 
    # -f: input file, -p: test url, -o: output format
    subprocess.run([
        "./lite-speedtest",
        "-f", temp_input,
        "-p", "https://gemini.google.com",
        "-o", "json"
    ], capture_output=True)

    results_file = "result.json"
    if not os.path.exists(results_file):
        return []

    with open(results_file, "r", encoding="utf-8") as f:
        try:
            return json.load(f)
        except:
            return []

# --- 4. CLASSIFICATION & OVERWRITE ---
def triple_tier_classifier():
    """Sorts tested nodes into 3 files based on performance and Gemini access."""
    nodes = execute_lite_benchmark()
    
    elite_gemini = []
    speed_master = []
    stable_reserve = []
    dead_ids = []

    for node in nodes:
        link = node.get("link")
        ping = node.get("ping", 999)
        speed = node.get("speed", 0)
        # google_check depends on the binary output for the specific URL
        gemini_ok = node.get("google_check", False)

        node_id = str(hash(link))

        if ping >= MAX_PING or ping == 0:
            dead_ids.append(node_id)
            continue

        # Tier 1: Elite (Fast + Gemini)
        if ping < ELITE_PING and gemini_ok:
            elite_gemini.append(link)
        # Tier 2: Speed Master (Fast, but no Gemini)
        elif ping < 200 and speed > SPEED_MIN:
            speed_master.append(link)
        # Tier 3: Stable Reserve (Slow but alive)
        elif ping < MAX_PING:
            stable_reserve.append(link)

    # Overwrite output files
    with open("Elite_Gemini.txt", "w") as f:
        f.write("\n".join(elite_gemini))
    with open("Speed_Master.txt", "w") as f:
        f.write("\n".join(speed_master))
    with open("Stable_Reserve.txt", "w") as f:
        f.write("\n".join(stable_reserve))

    # Update dead cache (Append mode)
    if dead_ids:
        with open(CACHE_FILE, "a") as f:
            f.write("\n".join(dead_ids) + "\n")

if __name__ == "__main__":
    manage_cache_lifecycle()
    triple_tier_classifier()
    print("[System] Sieve process finished successfully.")
