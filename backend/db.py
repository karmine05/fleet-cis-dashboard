import os
import time
import psycopg2
from psycopg2 import pool, extras
from contextlib import contextmanager
import logging

logger = logging.getLogger(__name__)

DB_POOL = None

# Connection pool per process: 4 workers × 8 max + 1 daemon = 40, well under Postgres max_connections=200.
DEFAULT_DB_POOL_MIN = 1
DEFAULT_DB_POOL_MAX = 8

# Retry budget for creating the pool: 5 attempts, 2s apart.
POOL_CONNECT_RETRIES = 5
POOL_CONNECT_RETRY_SLEEP_SECONDS = 2

# Cooldown after the retry budget is exhausted: the first request in a window
# pays the retry loop; every request after it raises immediately until the
# deadline passes. Tuned via DB_POOL_RETRY_COOLDOWN_SECONDS.
DEFAULT_POOL_RETRY_COOLDOWN_SECONDS = 10
# Monotonic deadline so an NTP step cannot move it.
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
