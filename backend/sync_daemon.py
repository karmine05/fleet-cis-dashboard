#!/usr/bin/env python3
"""
Sync Daemon — Runs sync_fleet_data.sync_data() on a recurring schedule.

Usage:
    python sync_daemon.py

Environment Variables:
    SYNC_INTERVAL_MINUTES  — Sync interval in minutes (default: 5)
    SYNC_HEARTBEAT_FILE    — Liveness file touched by the daemon (default: /tmp/sync_heartbeat)
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

# Liveness file for the container healthcheck. The mtime is the signal, so it is
# refreshed both inside the sleep loop and right after every sync attempt: a
# Fleet outage must not look like a dead container, and refreshing only once per
# interval would make the healthcheck flap. Default lives under /tmp because the
# container runs as non-root appuser and /app may not be writable.
HEARTBEAT_FILE = os.environ.get("SYNC_HEARTBEAT_FILE", "/tmp/sync_heartbeat")

shutdown_requested = False

# Only warn once about an unwritable heartbeat path — this runs once per second.
heartbeat_error_logged = False


def write_heartbeat():
    """Refresh the heartbeat file's mtime. Never raises — a broken heartbeat
    path must not stall or kill the sync loop."""
    global heartbeat_error_logged
    try:
        with open(HEARTBEAT_FILE, "w") as f:
            f.write(f"{time.time():.0f}\n")
    except Exception as e:
        if not heartbeat_error_logged:
            heartbeat_error_logged = True
            print(f"⚠️  Cannot write heartbeat file {HEARTBEAT_FILE}: {e}")


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
    print(f"   Heartbeat: {HEARTBEAT_FILE}")
    print(f"{'='*60}")

    # Touch the heartbeat before the first sync so a slow initial sync does not
    # read as unhealthy while the container is still coming up.
    write_heartbeat()

    # Run one immediate sync on startup
    print(f"\n🚀 Running initial sync...")
    try:
        sync_fleet_data.sync_data()
    except Exception as e:
        print(f"❌ Initial sync failed: {e}")
    finally:
        write_heartbeat()

    # Recurring loop
    while not shutdown_requested:
        next_run = datetime.now().timestamp() + (INTERVAL_MINUTES * 60)
        next_run_str = datetime.fromtimestamp(next_run).strftime('%H:%M:%S')
        print(f"\n⏳ Next sync at {next_run_str} (in {INTERVAL_MINUTES}m)")

        # Sleep in small increments to respond to shutdown signals quickly
        while not shutdown_requested and time.time() < next_run:
            write_heartbeat()
            time.sleep(1)

        if shutdown_requested:
            break

        print(f"\n🔄 Scheduled sync triggered at {datetime.now().strftime('%H:%M:%S')}")
        try:
            sync_fleet_data.sync_data()
        except Exception as e:
            print(f"❌ Sync failed: {e}")
            # Continue running — next attempt at the next interval
        finally:
            # Refresh regardless of outcome: a failing Fleet API is not a dead daemon.
            write_heartbeat()

    print("👋 Sync daemon stopped.")


if __name__ == "__main__":
    main()
