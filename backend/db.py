import os
import time
import psycopg2
from psycopg2 import pool, extras
from contextlib import contextmanager
import logging

logger = logging.getLogger(__name__)

DB_POOL = None

# Pool sizing. Every gunicorn worker process builds its own pool, and the sync
# daemon builds one more in its own process, so the ceiling the server has to
# absorb is (gunicorn workers x DB_POOL_MAX) + DB_POOL_MAX for the daemon.
# With the defaults below and 4 workers: 4 x 8 + 8 = 40 connections worst case,
# which fits comfortably under the max_connections=200 the compose config now
# sets (postgres ships with 100, and the old maxconn=20 gave 4 x 20 + 20 = 100,
# i.e. exactly the stock ceiling with zero headroom).
# The default of 8 is deliberately small, not an oversight: gunicorn runs 2
# threads per worker, so a single worker can only ever use 2 connections
# concurrently. Anything past that is idle sockets held open against postgres.
DEFAULT_DB_POOL_MIN = 1
DEFAULT_DB_POOL_MAX = 8

# Retry budget for creating the pool: 5 attempts, 2s apart.
POOL_CONNECT_RETRIES = 5
POOL_CONNECT_RETRY_SLEEP_SECONDS = 2

# Cooldown after the retry budget is exhausted.
#
# Pool creation at import time in app.py is now wrapped in try/except (so the
# module is importable without a database). The side effect: with Postgres down,
# every request re-enters the retry loop below and blocks a gunicorn thread for
# the full budget above. gunicorn runs 4 workers x 2 threads, so 8 concurrent
# requests wedge the entire backend for ~8 seconds each, repeatedly.
#
# Remembering the failure makes the failed path cheap: the first request in a
# window pays the retry loop, every request after it raises immediately until the
# deadline passes and one more attempt is allowed through. Tuned via
# DB_POOL_RETRY_COOLDOWN_SECONDS with the same lenient parsing as the bounds.
DEFAULT_POOL_RETRY_COOLDOWN_SECONDS = 10
# time.monotonic() deadline, so an NTP step cannot park it hours in the future.
_POOL_FAILED_UNTIL = 0.0

def _env_pool_bound(name, default):
    """
    Parse a positive-int pool bound from the environment.

    Garbage input (empty, non-numeric, zero, negative) falls back to the
    default instead of raising, because this runs at pool-creation time inside
    gunicorn workers where an exception would look like a database outage.
    """
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw.strip())
    except ValueError:
        logger.warning(f"{name}={raw!r} is not an integer, using default {default}.")
        return default
    if value < 1:
        logger.warning(f"{name}={value} must be >= 1, using default {default}.")
        return default
    return value

def _pool_bounds():
    minconn = _env_pool_bound("DB_POOL_MIN", DEFAULT_DB_POOL_MIN)
    maxconn = _env_pool_bound("DB_POOL_MAX", DEFAULT_DB_POOL_MAX)
    # ThreadedConnectionPool raises if minconn > maxconn, so reconcile an
    # inverted pair here rather than failing to start.
    if minconn > maxconn:
        logger.warning(
            f"DB_POOL_MIN={minconn} exceeds DB_POOL_MAX={maxconn}, "
            f"clamping minconn to {maxconn}."
        )
        minconn = maxconn
    return minconn, maxconn

def _pool_retry_cooldown():
    return _env_pool_bound(
        "DB_POOL_RETRY_COOLDOWN_SECONDS", DEFAULT_POOL_RETRY_COOLDOWN_SECONDS
    )


def get_db_pool():
    global DB_POOL, _POOL_FAILED_UNTIL
    # Successful path: unchanged and allocation-free once the pool exists.
    if DB_POOL is not None:
        return DB_POOL

    # Fast-fail while a recent attempt is still cooling down, so a dead database
    # costs one retry loop per window rather than one per request. The raised
    # exception is the same type and shape callers already handle.
    remaining = _POOL_FAILED_UNTIL - time.monotonic()
    if remaining > 0:
        raise Exception(
            "Failed to connect to database. "
            f"Retry suppressed for another {remaining:.1f}s."
        )

    minconn, maxconn = _pool_bounds()
    # Retry connection logic
    retries = POOL_CONNECT_RETRIES
    while retries > 0:
        try:
            DB_POOL = psycopg2.pool.ThreadedConnectionPool(
                minconn=minconn,
                maxconn=maxconn,
                dsn=os.environ.get("DATABASE_URL")
            )
            logger.info(
                f"Database connection pool created. "
                f"(minconn={minconn}, maxconn={maxconn})"
            )
            break
        except psycopg2.OperationalError as e:
            retries -= 1
            if retries <= 0:
                # No point sleeping after the last attempt: that was 2s of a
                # blocked gunicorn thread buying nothing.
                logger.warning(f"Database connection failed, giving up: {e}")
                break
            logger.warning(
                f"Database connection failed, retrying in "
                f"{POOL_CONNECT_RETRY_SLEEP_SECONDS}s... ({retries})"
            )
            time.sleep(POOL_CONNECT_RETRY_SLEEP_SECONDS)

    if DB_POOL is None:
        cooldown = _pool_retry_cooldown()
        _POOL_FAILED_UNTIL = time.monotonic() + cooldown
        # Threads that entered the loop before this deadline was recorded each pay
        # one retry budget; with 2 threads per gunicorn worker that is the bound,
        # and every later request in the window is cheap.
        raise Exception(
            f"Failed to connect to database. "
            f"Suppressing retries for {cooldown}s."
        )

    _POOL_FAILED_UNTIL = 0.0
    return DB_POOL

@contextmanager
def get_db_connection():
    pool = get_db_pool()
    conn = pool.getconn()
    try:
        yield conn
    finally:
        pool.putconn(conn)

@contextmanager
def get_db_cursor(commit=False):
    """
    Yields a RealDictCursor by default for dict-like access (replaces sqlite3.Row).
    """
    with get_db_connection() as conn:
        cursor = conn.cursor(cursor_factory=extras.RealDictCursor)
        try:
            yield cursor
            if commit:
                conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            cursor.close()
