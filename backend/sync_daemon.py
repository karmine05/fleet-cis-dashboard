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

# Reuse sync_fleet_data's lenient integer parser rather than copying it: this
# module is the sync container's entrypoint, so a typo in any tunable must fall
# back to the documented default and say so on stdout. Raising at import time
# would crash-loop the container before the first heartbeat is ever written, and
# the only visible symptom would be a stale heartbeat with no explanation.
_env_int = sync_fleet_data._env_int

# minimum=1: a zero or negative interval would collapse the sleep loop into a
# tight loop that hammers the Fleet API. (Cosmetic divergence worth knowing:
# /api/sync-status reports this tunable with _env_int("SYNC_INTERVAL_MINUTES", 5)
# and no minimum, so a value < 1 is reported verbatim there while the daemon
# actually runs at the default.)
INTERVAL_MINUTES = _env_int("SYNC_INTERVAL_MINUTES", 5, minimum=1)

# Liveness file for the container healthcheck. The mtime is the signal, so it is
# refreshed both inside the sleep loop and right after every sync attempt: a
# Fleet outage must not look like a dead container, and refreshing only once per
# interval would make the healthcheck flap. Default lives under /tmp because the
# container runs as non-root appuser and /app may not be writable.
HEARTBEAT_FILE = os.environ.get("SYNC_HEARTBEAT_FILE", "/tmp/sync_heartbeat")

# ---------------------------------------------------------------------------
# Watchdog
#
# Why this exists: the heartbeat healthcheck DETECTS a wedged sync (a socket
# with no timeout, a lock wait) but nothing ACTS on it. Docker Engine — unlike
# Swarm — never restarts a container because its healthcheck failed;
# `restart: unless-stopped` reacts only to process exit. So a daemon stuck
# inside sync_data() is correctly marked unhealthy and then stays stuck forever.
# The watchdog converts that wedge into a process exit, which the restart policy
# does act on (measured: RestartCount 0 -> 1 when the process exits).
#
# What "progress" means here: the daemon cannot see inside sync_data(), so the
# only progress signal available is a cycle boundary. The timer therefore bounds
# ONE cycle and is reset at every boundary — a long run of slow-but-completing
# cycles never accumulates toward the bound, because each cycle starts from
# zero. The bound is then set far above a healthy cycle (measured: ~1.6s for 32
# hosts / 789 policies; the default bound is 900s at the 5-minute interval and
# 2700s at the deployed 15-minute one, i.e. 500-1700x headroom), so "slow but
# progressing" — Fleet under load, a first run relocating history rows, a wide
# full-refresh sweep — stays well inside it while a true wedge crosses it
# decisively. Idle time is outside the window entirely: cycle_started_at is None
# between cycles, so the sleep loop can never trip the watchdog.
# ---------------------------------------------------------------------------

# Default is derived from the sync cadence — an operator who widens the interval
# is implicitly widening what "too long" means — with a floor so that a very
# short interval does not produce a trigger-happy bound.
WATCHDOG_INTERVAL_MULTIPLE = 3
# The floor is what protects a legitimately slow cycle on a large fleet from an
# operator who lowered the interval for freshness. At SYNC_INTERVAL_MINUTES=2 the
# derived bound would be 360s, which a real 6-minute sync would cross every time —
# and the container would then restart forever. 900s is comfortably above any
# plausible healthy cycle here (the reference deployment syncs 32 hosts and 789
# policies in about 1.6s, and a fleet 100x larger would still be far inside it)
# while a true wedge — a hung socket or a lock wait — crosses it decisively.
WATCHDOG_FLOOR_SECONDS = 900
DEFAULT_WATCHDOG_TIMEOUT_SECONDS = max(
    WATCHDOG_FLOOR_SECONDS,
    INTERVAL_MINUTES * 60 * WATCHDOG_INTERVAL_MULTIPLE,
)
# An explicit non-zero value below this would kill healthy cycles and crash-loop
# the container, so it is raised to the floor with a warning instead. 0 is not
# clamped: it is the documented way to disable the watchdog.
MIN_WATCHDOG_TIMEOUT_SECONDS = 30

WATCHDOG_TIMEOUT_SECONDS = _env_int(
    "SYNC_WATCHDOG_TIMEOUT_SECONDS", DEFAULT_WATCHDOG_TIMEOUT_SECONDS, minimum=0
)
if 0 < WATCHDOG_TIMEOUT_SECONDS < MIN_WATCHDOG_TIMEOUT_SECONDS:
    print(f"⚠ SYNC_WATCHDOG_TIMEOUT_SECONDS={WATCHDOG_TIMEOUT_SECONDS} is below the "
          f"minimum of {MIN_WATCHDOG_TIMEOUT_SECONDS}s — using {MIN_WATCHDOG_TIMEOUT_SECONDS}s")
    WATCHDOG_TIMEOUT_SECONDS = MIN_WATCHDOG_TIMEOUT_SECONDS

# How often the watchdog re-checks. Matches the heartbeat cadence; it only ever
# compares two numbers, so the poll is free.
WATCHDOG_TICK_SECONDS = 1

# EX_TEMPFAIL from sysexits.h — "temporary failure, retry later", which is
# exactly a wedged cycle. Distinctive enough to recognise in
# `docker inspect --format '{{.State.ExitCode}}'`.
WATCHDOG_EXIT_CODE = 75

# Grace period the watchdog allows itself to write its explanation before exiting
# unconditionally. Guards the case where stdout is the thing that is wedged.
LOG_GRACE_SECONDS = 5

shutdown_requested = False

# Only warn once about an unwritable heartbeat path — this runs once per second.
heartbeat_error_logged = False

# Monotonic start time of the in-flight sync cycle, or None while idle. Written
# by the main thread, read by the watchdog thread; a single-name assignment is
# atomic under the GIL, so no lock is needed (and a lock would be the wrong tool
# here — the watchdog must never be able to block on the thread it is watching).
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
            print(f"⚠️  Cannot write heartbeat file {HEARTBEAT_FILE}: {e}")


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
    """Log loudly and kill the process so the restart policy can recover it.

    os._exit rather than sys.exit: sys.exit raises SystemExit, which from a
    non-main thread only unwinds that thread, and even from the main thread it
    runs atexit handlers and joins non-daemon threads — any of which the wedged
    work could itself block. Flush first, because os._exit skips buffer
    flushing and this message is the only record of why the container died.

    The logging below is best-effort on purpose: writing to stdout is itself
    something that can block (docker's json-file driver writes synchronously, so a
    full disk wedges the writer — and a full disk is one of the things that wedges
    a sync in the first place). A deadline thread therefore guarantees the exit
    even if this function never gets to its own last line.
    """
    deadline = threading.Timer(
        LOG_GRACE_SECONDS, lambda: os._exit(WATCHDOG_EXIT_CODE)
    )
    deadline.daemon = True
    deadline.start()

    print(f"{'='*60}")
    print(f"🚨 WATCHDOG: sync cycle has been running for {elapsed_seconds:.0f}s, "
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
    """Poll the in-flight cycle's age. Runs as a daemon thread so it never keeps
    a graceful shutdown alive."""
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
        print(f"❌ {label} failed: {e}")
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
    print(f"\n⏹️  Received {sig_name} — shutting down sync daemon...")
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
    print(f"\n🚀 Running initial sync...")
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
