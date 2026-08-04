#!/usr/bin/env python3
"""
Sync Daemon — Runs sync_fleet_data.sync_data() on a recurring schedule.

Usage:
    python sync_daemon.py

Environment Variables:
    SYNC_INTERVAL_MINUTES  — Sync interval in minutes (default: 5)
    FLEET_URL              — Fleet server URL
    FLEET_API_TOKEN        — Fleet API token
"""

import os
import sys
import signal
import time
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env'))

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))
import sync_fleet_data

INTERVAL_MINUTES = int(os.environ.get("SYNC_INTERVAL_MINUTES", "5"))

shutdown_requested = False


def handle_signal(signum, frame):
    global shutdown_requested
    sig_name = signal.Signals(signum).name
    print(f"\n⏹️  Received {sig_name} — shutting down sync daemon...")
    shutdown_requested = True


def main():
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    print(f"{'='*60}")
    print(f"🔄 Sync Daemon started")
    print(f"   Interval: every {INTERVAL_MINUTES} minute(s)")
    print(f"   Fleet URL: {sync_fleet_data.FLEET_URL}")
    print(f"   Token set: {'Yes' if sync_fleet_data.FLEET_TOKEN else 'No'}")
    print(f"{'='*60}")

    # Run one immediate sync on startup
    print(f"\n🚀 Running initial sync...")
    try:
        sync_fleet_data.sync_data()
    except Exception as e:
        print(f"❌ Initial sync failed: {e}")

    # Recurring loop
    while not shutdown_requested:
        next_run = datetime.now().timestamp() + (INTERVAL_MINUTES * 60)
        next_run_str = datetime.fromtimestamp(next_run).strftime('%H:%M:%S')
        print(f"\n⏳ Next sync at {next_run_str} (in {INTERVAL_MINUTES}m)")

        # Sleep in small increments to respond to shutdown signals quickly
        while not shutdown_requested and time.time() < next_run:
            time.sleep(1)

        if shutdown_requested:
            break

        print(f"\n🔄 Scheduled sync triggered at {datetime.now().strftime('%H:%M:%S')}")
        try:
            sync_fleet_data.sync_data()
        except Exception as e:
            print(f"❌ Sync failed: {e}")
            # Continue running — next attempt at the next interval

    print("👋 Sync daemon stopped.")


if __name__ == "__main__":
    main()
