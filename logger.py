from datetime import datetime
import sys

class Stats:
    def __init__(self):
        self.total = 0
        self.processed = 0
        self.elite = 0
        self.stable = 0
        self.fast = 0
        self.dead = 0
        self.errors = 0

# Global stats instance
stats = Stats()

def log_event(msg, level="INFO"):
    """
    Advanced logging with levels and progress indicators.
    Uses global stats for progress calculation.
    """
    timestamp = datetime.now().strftime('%H:%M:%S')
    progress = ""
    if stats.total > 0:
        percent = (stats.processed / stats.total) * 100
        progress = f"[{percent:.1f}%]"
    
    print(f"[{timestamp}] {progress} [{level}] {msg}", flush=True)

