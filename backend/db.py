import os
import time
import psycopg2
from psycopg2 import pool, extras
from contextlib import contextmanager
import logging

logger = logging.getLogger(__name__)

DB_POOL = None

def get_db_pool():
    global DB_POOL
    if DB_POOL is None:
        # Retry connection logic
        retries = 5
        while retries > 0:
            try:
                DB_POOL = psycopg2.pool.ThreadedConnectionPool(
                    minconn=1,
                    maxconn=20,
                    dsn=os.environ.get("DATABASE_URL")
                )
                logger.info("Database connection pool created.")
                break
            except psycopg2.OperationalError as e:
                logger.warning(f"Database connection failed, retrying in 2s... ({retries})")
                time.sleep(2)
                retries -= 1
        if DB_POOL is None:
            raise Exception("❌ Failed to connect to database.")
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
