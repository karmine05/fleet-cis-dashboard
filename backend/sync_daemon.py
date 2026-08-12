#!/usr/bin/env python3
"""
Sync Daemon — Runs sync_fleet_data.sync_data() on a recurring schedule.

Usage:
    python sync_daemon.py

Environment Variables:
    SYNC_INTERVAL_MINUTES  — Sync interval in minutes (default: 5)
    SYNC_HEARTBEAT_FILE    — Liveness file touched by the daemon (default: /tmp/sync_heartbeat)
    SYNC_WATCHDOG_TIMEOUT_SECONDS
                           — Hard bound on a single sync cycle before the daemon
                             considers itself wedged and exits non-zero so the
                             container restart policy can recover it.
                             Default: 3x SYNC_INTERVAL_MINUTES, floor 300s.
                             0 disables the watchdog.
    FLEET_URL              — Fleet server URL
    FLEET_API_TOKEN        — Fleet API token
"""

import os
import sys
import signal
import threading
import time
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv(os.path.join(os.path.dirname(os.path.dirname(__file__)), '.env'))

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(__file__))
import sync_fleet_data

# Reuses sync_fleet_data's lenient parser so a tunable typo can't crash-loop the container.
_env_int = sync_fleet_data._env_int

# minimum=1: zero or negative would collapse the sleep loop into a tight API hammer.
INTERVAL_MINUTES = _env_int("SYNC_INTERVAL_MINUTES", 5, minimum=1)

# Container healthcheck: refreshed every second so a Fleet outage doesn't look like a dead daemon.
# Default under /tmp because the container runs as non-root.
HEARTBEAT_FILE = os.environ.get("SYNC_HEARTBEAT_FILE", "/tmp/sync_heartbeat")

# Watchdog: Docker never restarts an unhealthy container, so a sync that wedges
# stays stuck forever. The watchdog converts that wedge into process exit code 75,
# which the restart policy does act on. Bounds one cycle only (resets at each
# boundary); idle time between cycles never trips it.

WATCHDOG_INTERVAL_MULTIPLE = 3
# 900s floor protects slow-but-healthy cycles on a large fleet from crash-looping.
WATCHDOG_FLOOR_SECONDS = 900
DEFAULT_WATCHDOG_TIMEOUT_SECONDS = max(
    WATCHDOG_FLOOR_SECONDS,
    INTERVAL_MINUTES * 60 * WATCHDOG_INTERVAL_MULTIPLE,
)
# Values below 30s crash-loop healthy cycles; 0 disables the watchdog entirely.
MIN_WATCHDOG_TIMEOUT_SECONDS = 30

WATCHDOG_TIMEOUT_SECONDS = _env_int(
    "SYNC_WATCHDOG_TIMEOUT_SECONDS", DEFAULT_WATCHDOG_TIMEOUT_SECONDS, minimum=0
)
if 0 < WATCHDOG_TIMEOUT_SECONDS < MIN_WATCHDOG_TIMEOUT_SECONDS:
    print(f"SYNC_WATCHDOG_TIMEOUT_SECONDS={WATCHDOG_TIMEOUT_SECONDS} is below the "
          f"minimum of {MIN_WATCHDOG_TIMEOUT_SECONDS}s — using {MIN_WATCHDOG_TIMEOUT_SECONDS}s")
    WATCHDOG_TIMEOUT_SECONDS = MIN_WATCHDOG_TIMEOUT_SECONDS

# Matches heartbeat cadence — only compares two numbers, so the poll is free.
WATCHDOG_TICK_SECONDS = 1

# EX_TEMPFAIL (75): distinctive enough to recognise in `docker inspect`.
WATCHDOG_EXIT_CODE = 75

# Allows the watchdog to write its explanation before exiting, guarding a wedged stdout.
LOG_GRACE_SECONDS = 5

shutdown_requested = False

heartbeat_error_logged = False

# Monotonic cycle start time, or None while idle. Atomic under the GIL.
cycle_started_at = None


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
            print(f"Cannot write heartbeat file {HEARTBEAT_FILE}: {e}")


def watchdog_should_abort(started_at, now, timeout_seconds):
    """Pure predicate: has the in-flight cycle that began at `started_at`
    (monotonic seconds) outlived `timeout_seconds` as of `now`?

    False when the watchdog is disabled (timeout <= 0) and False while the
    daemon is idle (started_at is None), so neither state can ever abort.
    """
    if timeout_seconds <= 0:
        return False
    if started_at is None:
        return False
    return (now - started_at) >= timeout_seconds


def _abort_wedged(elapsed_seconds):
    """Kill the process so the restart policy recovers it.

    Uses os._exit (not sys.exit) so atexit handlers and thread joins can't block.
    Flush first because os._exit skips buffers — this message is the only
    record of why the container died. A deadline thread guarantees exit even if
    stdout itself is wedged.
    """
    deadline = threading.Timer(
        LOG_GRACE_SECONDS, lambda: os._exit(WATCHDOG_EXIT_CODE)
    )
    deadline.daemon = True
    deadline.start()

    print(f"{'='*60}")
    print(f"WATCHDOG: sync cycle has been running for {elapsed_seconds:.0f}s, "
          f"over the {WATCHDOG_TIMEOUT_SECONDS}s limit — the daemon is wedged.")
    print(f"   A wedged thread cannot be interrupted cooperatively, so the")
    print(f"   process is exiting with code {WATCHDOG_EXIT_CODE} to let the container")
    print(f"   restart policy recover it. Raise SYNC_WATCHDOG_TIMEOUT_SECONDS if")
    print(f"   this fleet genuinely needs longer syncs, or set it to 0 to disable.")
    print(f"{'='*60}")
    sys.stdout.flush()
    sys.stderr.flush()
    os._exit(WATCHDOG_EXIT_CODE)


def _watchdog_loop():
    """Poll in-flight cycle age as a daemon thread."""
    while True:
        time.sleep(WATCHDOG_TICK_SECONDS)
        started_at = cycle_started_at
        if watchdog_should_abort(started_at, time.monotonic(), WATCHDOG_TIMEOUT_SECONDS):
            _abort_wedged(time.monotonic() - started_at)


def run_sync_cycle(label):
    """Run one sync cycle inside the watched window.

    Opens the watchdog window, runs the sync, and closes the window again on the
    way out — including when the sync raised, since a failing Fleet API is a
    completed cycle, not a wedge.
    """
    global cycle_started_at
    # Monotonic, not wall clock: an NTP step must not fabricate (or mask) a
    # wedge.
    cycle_started_at = time.monotonic()
    try:
        sync_fleet_data.sync_data()
    except Exception as e:
        print(f"{label} failed: {e}")
        # Continue running — next attempt at the next interval
    finally:
        # Refresh regardless of outcome: a failing Fleet API is not a dead daemon.
        # Deliberately still inside the watched window — a heartbeat write that
        # blocks on a hung filesystem is as wedged as a hung sync, and the
        # healthcheck alone cannot recover from either.
        write_heartbeat()
        cycle_started_at = None


def handle_signal(signum, frame):
    global shutdown_requested
    sig_name = signal.Signals(signum).name
    print(f"\nReceived {sig_name} — shutting down sync daemon...")
    shutdown_requested = True


def main():
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    watchdog_desc = (f"{WATCHDOG_TIMEOUT_SECONDS}s per cycle"
                     if WATCHDOG_TIMEOUT_SECONDS > 0 else "disabled")

    print(f"{'='*60}")
    print(f"🔄 Sync Daemon started")
    print(f"   Interval: every {INTERVAL_MINUTES} minute(s)")
    print(f"   Fleet URL: {sync_fleet_data.FLEET_URL}")
    print(f"   Token set: {'Yes' if sync_fleet_data.FLEET_TOKEN else 'No'}")
    print(f"   Heartbeat: {HEARTBEAT_FILE}")
    print(f"   Watchdog: {watchdog_desc}")
    print(f"{'='*60}")

    # Started here rather than at import time so that importing this module
    # spawns nothing.
    if WATCHDOG_TIMEOUT_SECONDS > 0:
        threading.Thread(target=_watchdog_loop, name="sync-watchdog",
                         daemon=True).start()

    # Touch the heartbeat before the first sync so a slow initial sync does not
    # read as unhealthy while the container is still coming up.
    write_heartbeat()

    # Run one immediate sync on startup
    print(f"\nRunning initial sync...")
    run_sync_cycle("Initial sync")

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
        run_sync_cycle("Sync")

    print("👋 Sync daemon stopped.")


if __name__ == "__main__":
    main()
