#!/usr/bin/env python3
"""
CIS Compliance Dashboard Backend API (PostgreSQL Version)
Serves real-time data from Fleet via PostgreSQL.
"""

from flask import Flask, jsonify, request, g
from flask_cors import CORS
from werkzeug.exceptions import HTTPException
from functools import wraps
import hmac
import math
import os
import json
import logging
import time
from logging.handlers import RotatingFileHandler
from urllib.parse import urlencode
from datetime import datetime
from dotenv import load_dotenv


def _env_int(name, default):
    """Read an integer env var, falling back to default on missing/junk input.

    Lenient on purpose: a typo in a deployment env var must not stop the app from
    booting. Called before logging is configured for the log tunables themselves,
    which is fine — logging's last-resort handler still surfaces the warning.
    """
    raw = os.environ.get(name)
    if raw is None or str(raw).strip() == '':
        return default
    try:
        return int(str(raw).strip())
    except ValueError:
        logging.getLogger(__name__).warning(
            f"Invalid {name}={raw!r}, using default {default}"
        )
        return default


# Configure logging. Default is stdout only, which is what a container wants:
# docker collects and rotates it. A file log is opt-in via LOG_FILE and always
# rotates, because the previous unconditional FileHandler("backend.log") had all
# 4 gunicorn workers appending to one never-rotated file inside the container.
LOG_FORMAT = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
LOG_FILE = os.environ.get('LOG_FILE', '').strip()
LOG_MAX_BYTES = _env_int('LOG_MAX_BYTES', 10 * 1024 * 1024)
LOG_BACKUP_COUNT = _env_int('LOG_BACKUP_COUNT', 3)

logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

if LOG_FILE:
    # Rotation state is per-process and workers share the path, so the file log is
    # a convenience for single-process runs, not the primary sink.
    try:
        _file_handler = RotatingFileHandler(
            LOG_FILE, maxBytes=LOG_MAX_BYTES, backupCount=LOG_BACKUP_COUNT
        )
        _file_handler.setFormatter(logging.Formatter(LOG_FORMAT))
        logging.getLogger().addHandler(_file_handler)
        logger.info(f"File logging enabled: {LOG_FILE}")
    except OSError as e:
        # An unwritable LOG_FILE must never keep the app from starting.
        logger.warning(
            f"Could not open LOG_FILE {LOG_FILE}: {e} - logging to stdout only"
        )

def error_response(message, status_code=500, error_details=None):
    """Standardized error response and logging.

    error_details is for the LOG only unless FLASK_DEBUG=1. Every caller passes
    str(exception) there, and psycopg2's messages embed the DSN host, port and user,
    so that gate is the one thing keeping a connection failure from being narrated
    to an unauthenticated client. Both call sites are on /api/config.

    FLASK_DEBUG is the standard Flask env var. The gate keeps DSN host/port/user
    out of the response body for unauthenticated clients.
    """
    log_msg = f"{message}"
    if error_details:
        log_msg += f" - Details: {error_details}"
    logger.error(log_msg)
    
    response = {"error": message}
    # Only include details in debug mode for security
    if error_details and os.environ.get('FLASK_DEBUG', '0') == '1':
        response["details"] = error_details
    return jsonify(response), status_code

# Valid configuration keys for validation
VALID_CONFIG_KEYS = {
    'risk_exposure_multiplier',
    'security_debt_hours_per_issue',
    'impact_high_threshold',
    'impact_medium_threshold',
    'effort_low_keywords',
    'effort_high_keywords',
    'framework_cis_multiplier',
    'framework_nist_multiplier',
    'framework_iso_multiplier',
    'maturity_level_5',
    'maturity_level_4',
    'maturity_level_3',
    'maturity_level_2',
    'maturity_level_1',
}

# How much of a rejected PUT /api/config body is quoted back in the 400. The keys
# come straight from the request, and echoing an unbounded number of unbounded
# strings into both the response and the log line is free amplification for the
# caller; the first few, truncated, identify the mistake just as well.
MAX_ECHOED_KEYS = 10
MAX_ECHOED_KEY_CHARS = 64

# Import new DB module
import db
import policy_catalog

# --- Optional .env, for host runs only ---
# basedir is the repo root, so this resolves to <repo>/.env outside a container and
# to /app/.env inside the image, where it NEVER exists: .dockerignore keeps .env out
# of the build context and configuration arrives through the Compose environment.
#
# Kept (conditional + logged) rather than removed, because it is not dead in every
# context: the README documents running the backend straight on the host
# (`python backend/app.py`, which is what PORT is for), and there Compose is not
# involved to inject anything, so the repo-root .env that Compose itself interpolates
# is the operator's only source of config. What was wrong was the unconditional call:
# a silent no-op that read as ".env is read at runtime" to anyone auditing the file.
# load_dotenv() does not overwrite variables that are already set, so a stray .env
# can never win over the Compose environment.
#
# Note the position: LOG_FILE, LOG_MAX_BYTES and LOG_BACKUP_COUNT are read above this
# line, so those three come from the real environment only, never from .env. Left
# that way on purpose - moving the load to the top of the module would change which
# tunables .env can reach.
basedir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
_dotenv_path = os.path.join(basedir, '.env')
if os.path.isfile(_dotenv_path):
    load_dotenv(_dotenv_path)
    logger.info(
        f"Applied {_dotenv_path} for variables not already set "
        f"(host run; this file is absent in the container image)"
    )


app = Flask(__name__)

# --- CORS allow-list for /api/* ---
# The default chain is unchanged and stays localhost-only: ALLOWED_ORIGINS, then the
# legacy single-origin FRONTEND_URL, then http://localhost:8081. Compose always sets
# ALLOWED_ORIGINS=http://localhost:8081,http://localhost:8082, so the documented
# port-8082 flow does not depend on this built-in default at all - and served through
# nginx the UI is same-origin, where CORS never applies.
#
# The default is deliberately NOT '*'. Reads here are unauthenticated, so a wildcard
# would let any page a browser visits read this API with the visitor's network
# position. An operator who really wants that has to write it down.
#
# What changed: entries are stripped and empties dropped. Without that,
# ALLOWED_ORIGINS="http://a, http://b" yielded the entry " http://b", which matches no
# Origin header at all - CORS then failed silently for that origin with nothing in the
# log to explain it. A list that parses to nothing (ALLOWED_ORIGINS=" " or ",") falls
# back to the built-in default and says so, instead of becoming a deny-everything list
# that looks like a broken deployment. The effective list is logged at boot, because a
# CORS allow-list nobody can see is a CORS allow-list nobody can debug.
CORS_DEFAULT_ORIGIN = 'http://localhost:8081'


def parse_allowed_origins(raw):
    """Split a comma-separated CORS allow-list, tolerating whitespace and empties."""
    return [o.strip() for o in (raw or '').split(',') if o.strip()]


allowed_origins = parse_allowed_origins(
    os.environ.get('ALLOWED_ORIGINS', os.environ.get('FRONTEND_URL', CORS_DEFAULT_ORIGIN))
)
if not allowed_origins:
    allowed_origins = parse_allowed_origins(CORS_DEFAULT_ORIGIN)
    logger.warning(
        f"ALLOWED_ORIGINS parsed to no usable origin; falling back to {allowed_origins}"
    )
if '*' in allowed_origins:
    logger.warning(
        "CORS allow-list is '*': any origin can read /api/* through a visitor's "
        "browser, and nothing in this stack authenticates reads."
    )
logger.info(f"CORS allow-list for /api/*: {allowed_origins}")
CORS(app, resources={r"/api/*": {"origins": allowed_origins}})

# Cap the request body. The only endpoint that reads one is PUT /api/config, whose
# payload is a handful of numbers and two short keyword lists. With no cap, whatever a
# client sends is materialized in the worker's memory as soon as anything reads the
# stream (request.get_json here), and the size of that allocation was entirely the
# caller's choice. With the cap Werkzeug refuses instead of reading. 1 MiB is orders of
# magnitude above any legitimate config save and equals nginx's own default
# client_max_body_size, so the proxy and the app agree on the ceiling; over it Werkzeug
# raises 413, which the JSON error handler below renders as JSON. A hard constant, not
# a tunable: no deployment needs a different value, and every new env var is another
# line the operator has to be told about.
MAX_REQUEST_BODY_BYTES = 1024 * 1024
app.config['MAX_CONTENT_LENGTH'] = MAX_REQUEST_BODY_BYTES


@app.errorhandler(HTTPException)
def handle_http_exception(e):
    """Render Werkzeug's HTTP errors as JSON, keeping their own status code.

    Werkzeug's defaults are HTML pages, and every consumer of this app parses JSON -
    a 404 from a typo'd path or a 413 from an oversized body used to arrive as markup.
    e.description is Werkzeug's own static text for the status; nothing here comes
    from the database or is echoed back from the request.
    """
    return jsonify({
        "error": e.name,
        "status": e.code,
        "detail": e.description,
    }), (e.code or 500)


@app.errorhandler(Exception)
def handle_unexpected_exception(e):
    """Last resort: log the traceback, answer with an opaque JSON 500.

    None of the read endpoints has a try/except, so before this an unhandled
    psycopg2 error reached Werkzeug's generic 500 page: an HTML body where every
    client expects JSON, and one FLASK_DEBUG=1 deployment away from serving the
    interactive debugger - whose traceback carries the DSN host, port and user - to an
    unauthenticated client. The message returned here is a constant; the exception and
    its traceback go to the log.
    """
    if app.debug or app.testing or app.config.get('PROPAGATE_EXCEPTIONS'):
        # Keep `python backend/app.py` with FLASK_DEBUG=1 debuggable, and let the
        # test client see the real exception instead of a masked 500.
        raise e
    logger.exception(
        f"Unhandled exception on {request.method} {request.path}: {type(e).__name__}"
    )
    return jsonify({"error": "Internal server error"}), 500

# Initialize the DB pool eagerly so a misconfigured database shows up in the boot log.
# Guarded on DATABASE_URL and on the failure itself: importing app.py doesn't require live Postgres.
if os.environ.get('DATABASE_URL'):
    try:
        db.get_db_pool()
    except Exception as e:
        logger.warning(f"Deferred DB pool creation: {e}")

    # Seed default config rows that may be absent on existing databases.
    # INSERT ... ON CONFLICT DO NOTHING is idempotent: safe on every restart.
    try:
        with db.get_db_cursor(commit=True) as cur:
            cur.execute("""
                INSERT INTO config_settings (key, value, description)
                VALUES
                    ('maturity_level_5', '90', 'Posture score threshold for maturity level 5'),
                    ('maturity_level_4', '80', 'Posture score threshold for maturity level 4'),
                    ('maturity_level_3', '70', 'Posture score threshold for maturity level 3'),
                    ('maturity_level_2', '50', 'Posture score threshold for maturity level 2'),
                    ('maturity_level_1', '0',  'Posture score threshold for maturity level 1')
                ON CONFLICT (key) DO NOTHING
            """)
    except Exception as e:
        logger.warning(f"Could not seed maturity config defaults: {e}")

# Load MITRE Data from JSON (technique id → name + tactic for architecture matrix)
MITRE_DATA = {}
def load_mitre_data():
    global MITRE_DATA
    mitre_file = os.path.join(os.path.dirname(__file__), 'mitre_data.json')
    if os.path.exists(mitre_file):
        try:
            with open(mitre_file, 'r') as f:
                MITRE_DATA = json.load(f)
        except Exception as e:
            logger.warning(f"Could not load MITRE Data: {e}")

load_mitre_data()

# ATT&CK techniques with more than this many CIS cells are flagged as coarse
COARSE_ATTACK_THRESHOLD = 40

# --- History trend window ---
# /api/architecture gains/losses and /api/strategy remediation velocity read
# policy_results_history. That table is NOT a daily snapshot: a sync only writes
# rows for the policies it refetched, so a quiet day can contain zero rows. Every
# number below is therefore computed from the earliest and the latest observation
# of each (policy_id, host_id) pair *inside* the window, which keeps both ends of
# the comparison on the same denominator and never reads "no rows today" as 0%.
# 30 days is the default: long enough for a fleet syncing every 15 minutes to
# accumulate several distinct days, short enough that the scan touches only one or
# two monthly partitions and stays on idx_history_checked_policy.
# It bounds the compliance_snapshots lookback for the team leaderboard trend too. That
# is a reuse, not an oversight: "how far back does a trend look" has one answer in this
# app, and a second env var for the same question is surface an operator has to be told
# about for no behavioural gain.
HISTORY_TREND_DAYS = max(1, _env_int('HISTORY_TREND_DAYS', 30))
# A technique whose trend rests on a handful of observed pairs swings by tens of
# points when one host flips, which reads as a dramatic gain that is really
# sampling noise. Techniques below this many observed pairs are left out of
# gains/losses; they still appear in the current-state matrix.
HISTORY_TREND_MIN_SAMPLE = max(1, _env_int('HISTORY_TREND_MIN_SAMPLE', 5))
# How many techniques to report on each side of the trend.
HISTORY_TREND_TOP_N = 5

# Legacy cis_to_d3fend_*.csv loaders were removed: runtime mapping uses
# policy_catalog (safeguard_d3fend.json + tight policy-name rules).
# See docs/mapping-policy.md — bulk CSV ATT&CK import is forbidden.

# Write API token — required for mutating endpoints (fail closed if unset)
DASHBOARD_API_TOKEN = os.environ.get("DASHBOARD_API_TOKEN", "").strip()


def _extract_bearer_token() -> str:
    auth = request.headers.get("Authorization", "") or ""
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return (request.headers.get("X-API-Token") or "").strip()


def require_write_auth(fn):
    """Require DASHBOARD_API_TOKEN for write endpoints. Fail closed if unset."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        expected = DASHBOARD_API_TOKEN
        if not expected:
            return error_response(
                "Write API disabled: set DASHBOARD_API_TOKEN on the server",
                503,
            )
        provided = _extract_bearer_token()
        if not provided or not hmac.compare_digest(provided, expected):
            return error_response("Unauthorized", 401)
        return fn(*args, **kwargs)
    return wrapper


# --- Request input limits ---
# /api/devices used to honour any ?limit= (a full table dump once the fleet grows)
# and passed a negative ?page= straight through as a negative OFFSET, which
# Postgres rejects — a 500 from pure user input. Both are clamped now.
DEFAULT_PAGE_SIZE = 100
MAX_PAGE_SIZE = max(1, _env_int('MAX_PAGE_SIZE', 500))
# Ceiling on the computed OFFSET so an absurd ?page= returns an empty page rather
# than a bigint out-of-range error from Postgres.
MAX_PAGE_OFFSET = 10000000


def request_int(name, default):
    """Parse a numeric query arg, falling back to default on junk input.

    Lenient on purpose: ?limit=abc has always fallen back to the default instead
    of erroring and the frontend relies on that. Range clamping is the caller's
    job so each endpoint can pick its own bounds.
    """
    raw = request.args.get(name)
    if raw is None or raw.strip() == '':
        return default
    try:
        return int(raw.strip())
    except ValueError:
        return default


# --- Host scope filters (single source of truth) ---
# The query args that actually change a response body. Two places read this:
# get_filtered_hosts_subquery() builds its WHERE clauses from HOST_SCOPE_FILTERS,
# and the response cache builds its key from CACHE_SCOPE_ARGS, which is derived
# from it. Deriving one from the other is the whole point: the cache key used to
# hash the COMPLETE request arg set, so any unauthenticated client could mint an
# unbounded number of ~800 KB cache entries with ?junk1=1&junk2=2&… against a
# Redis whose maxmemory is 0 (unlimited) — an eviction/OOM lever with no auth.
#
# Any arg that changes a cached response must appear in this list. If it does
# not, two materially different responses share one cache entry and the wrong
# body is served. In the normal case (a host column compare) adding it to
# HOST_SCOPE_FILTERS is enough and the cache key follows automatically. An arg an
# endpoint reads straight off request.args goes in HOST_SCOPE_EXTRA_ARGS.
HOST_SCOPE_FILTERS = {
    'team': 'team_name',
    'platform': 'platform',
    'osVersion': 'platform_version',
}
# Scope args that are not plain column compares: 'label' drives a JOIN through
# host_labels/fleet_labels instead of a WHERE on fleet_hosts.
HOST_SCOPE_EXTRA_ARGS = ('label',)
CACHE_SCOPE_ARGS = tuple(sorted(set(HOST_SCOPE_FILTERS) | set(HOST_SCOPE_EXTRA_ARGS)))


# --- Response cache (optional Redis) ---
# /api/heatmap-data (~731 KB), /api/safeguard-compliance (~816 KB),
# /api/architecture and /api/strategy are recomputed from Postgres on every page
# load. Their serialized bodies are cached under a key that embeds the sync
# generation (and, for config-dependent endpoints, the config generation), so a
# completed sync or a saved setting moves the whole key space and retires stale
# entries with no explicit invalidation step.
# Redis is strictly optional: a missing package, an unset REDIS_URL or an
# unreachable server degrades to serving the live result and warns once per state.
CACHE_KEY_PREFIX = 'fleetcis:v1'
CACHE_TTL_SECONDS = max(1, _env_int('CACHE_TTL_SECONDS', 900))
REDIS_URL = os.environ.get('REDIS_URL', '').strip()
# Deliberately sub-second: a wedged Redis must never add more latency than the
# query it stands in for. Milliseconds so the tunable stays an int.
REDIS_TIMEOUT_MS = max(1, _env_int('REDIS_TIMEOUT_MS', 500))
# How long to serve uncached after a TRANSIENT Redis failure before re-probing.
# Default 30s. A single blip used to disable the cache for the whole life of the
# gunicorn worker, silently reverting the app to fully uncached until the
# container was restarted.
CACHE_RETRY_COOLDOWN_SECONDS = max(1, _env_int('CACHE_RETRY_COOLDOWN_SECONDS', 30))
# Scope-arg value length cap: a request with an 8 KB query string (nginx's limit)
# used to mint an 8 KB Redis key whose body was a few hundred bytes.
# Team names, platforms, OS versions and label names are host attributes; nothing real
# comes close to 200 characters. A request carrying a longer value is served LIVE and
# uncached - the SQL filter itself is untouched, so the response body is byte-identical
# to before and no key is ever created for it. This bounds key SIZE; key COUNT is
# bounded by allkeys-lru plus the fact that every new key costs the caller a full round
# of Postgres queries.
MAX_CACHE_SCOPE_VALUE_LEN = 200

_cache_client = None
# 'new'      -> not probed yet.
# 'ready'    -> _cache_client is usable.
# 'off'      -> PERMANENTLY unavailable in this process (no redis package, no
#               REDIS_URL). Nothing a re-probe could observe would change, so we
#               never look again.
# 'cooldown' -> TRANSIENT failure (unreachable server, failed read/write). Re-probe
#               once _cache_retry_at passes.
_cache_state = 'new'
# Last state we emitted a log line for, so each transition is logged exactly once
# instead of once per request.
_cache_logged_state = None
_cache_retry_at = 0.0


def _log_cache_state(state, message):
    """Log a cache state transition exactly once per state.

    Keyed on the state rather than the message because a hard outage re-probes
    every CACHE_RETRY_COOLDOWN_SECONDS and must not log on every attempt — the
    re-probe reinstates 'cooldown', which is already the logged state, so a
    multi-hour outage still costs exactly one warning.
    """
    global _cache_logged_state
    if _cache_logged_state == state:
        return
    _cache_logged_state = state
    if state == 'ready':
        logger.info(message)
    else:
        logger.warning(message)


def _disable_cache(reason):
    """Turn caching off permanently for this worker and say why once.

    Only for conditions a running process cannot recover from. Anything that
    could come back on its own belongs in _cooldown_cache().
    """
    global _cache_state, _cache_client
    _cache_client = None
    _cache_state = 'off'
    _log_cache_state('off', f"Response cache disabled: {reason}")


def _cooldown_cache(reason):
    """Park the cache after a transient Redis failure and re-probe later.

    The failure now costs CACHE_RETRY_COOLDOWN_SECONDS of uncached responses
    instead of the rest of the worker's life. time.monotonic() so an NTP step or
    a DST change cannot push the deadline hours into the future.
    """
    global _cache_state, _cache_client, _cache_retry_at
    _cache_client = None
    _cache_state = 'cooldown'
    _cache_retry_at = time.monotonic() + CACHE_RETRY_COOLDOWN_SECONDS
    _log_cache_state(
        'cooldown',
        f"Response cache paused for {CACHE_RETRY_COOLDOWN_SECONDS}s "
        f"(will re-probe): {reason}",
    )


def get_cache_client():
    """Return a usable Redis client, or None when caching is unavailable."""
    global _cache_client, _cache_state
    if _cache_state == 'ready':
        return _cache_client
    if _cache_state == 'off':
        return None
    if _cache_state == 'cooldown' and time.monotonic() < _cache_retry_at:
        return None
    if not REDIS_URL:
        _disable_cache("REDIS_URL is not set")
        return None
    try:
        # Imported lazily so a build without the redis package still boots.
        import redis
    except ImportError as e:
        _disable_cache(f"redis package not installed ({e})")
        return None
    timeout = REDIS_TIMEOUT_MS / 1000.0
    try:
        client = redis.Redis.from_url(
            REDIS_URL,
            socket_timeout=timeout,
            socket_connect_timeout=timeout,
        )
        client.ping()
    except Exception as e:
        # Transient, not permanent: a Redis container that is still starting up,
        # or restarting, reaches this path and must be picked up when it returns.
        _cooldown_cache(f"cannot reach REDIS_URL: {e}")
        return None
    _cache_client = client
    _cache_state = 'ready'
    _log_cache_state(
        'ready', f"Response cache enabled via Redis (ttl={CACHE_TTL_SECONDS}s)"
    )
    return client


def get_sync_generation():
    """Cache generation token: "<newest-success>|<newest-sync-id>:<its-status>".

    Both halves are load-bearing. The first is the completed_at of the newest
    SUCCESSFUL sync, which is what retires a completed generation's entries. The
    second is the newest sync row whatever its outcome, which is what keeps an
    IN-PROGRESS sync out of a completed generation's key space: sync_data() sets
    status='success' only in its final statement, so for the entire duration of a
    sync every read sees half-written state. With the timestamp alone those
    partial bodies were cached under the PREVIOUS generation's key, and if the
    sync then failed the generation never advanced — so a partial-state body was
    served for the full TTL. They now land under "…|N:running", a key space that
    stops resolving the instant that row flips to success or failed.

    Mid-sync bodies are still cached, just under their own generation — a sync can
    take minutes and that is exactly when Postgres is busiest, so read-through is
    worth keeping. The cost is one extra orphaned generation per sync, aging out
    over CACHE_TTL_SECONDS. What bounds total memory is the allow-list in
    _cache_key(): entries per generation is the number of real filter scopes, not
    the number of distinct URLs a client can invent.

    Returns None when the lookup itself failed (caller then bypasses the cache
    rather than sharing the pre-first-sync key space). One indexed lookup per
    request, which is why only the four heavy endpoints are cached — on the small
    endpoints this query would cost more than the work it saves.
    """
    try:
        with db.get_db_cursor() as cur:
            # A bare SELECT returns exactly one row even against an empty table,
            # and all three subqueries share one snapshot, so newest_id and
            # newest_status can never come from different rows.
            cur.execute("""
                SELECT
                    (SELECT completed_at
                     FROM sync_metadata
                     WHERE status = 'success' AND completed_at IS NOT NULL
                     ORDER BY completed_at DESC
                     LIMIT 1) AS last_success,
                    (SELECT sync_id
                     FROM sync_metadata
                     ORDER BY sync_id DESC
                     LIMIT 1) AS newest_id,
                    (SELECT status
                     FROM sync_metadata
                     ORDER BY sync_id DESC
                     LIMIT 1) AS newest_status
            """)
            row = cur.fetchone() or {}
            last_success = row.get('last_success')
            success_token = last_success.isoformat() if last_success else "none"
            newest_id = row.get('newest_id')
            newest_id = "none" if newest_id is None else newest_id
            newest_status = row.get('newest_status') or "none"
            return f"{success_token}|{newest_id}:{newest_status}"
    except Exception as e:
        logger.warning(f"Cache generation lookup failed, serving uncached: {e}")
        return None


def get_config_generation():
    """Config generation token for config_settings: "<row-count>@<newest-updated-at>".

    /api/strategy's numbers come from get_config() — risk_exposure_multiplier,
    security_debt_hours_per_issue, impact_high_threshold and the effort keyword
    lists — so a PUT /api/config changes its body with no sync involved. Tracking
    only the sync generation meant Settings reported success while the dashboard
    kept serving pre-save numbers for up to a full TTL.

    Reading the token from Postgres, rather than flipping a flag in memory, is
    what makes the invalidation correct across all 4 gunicorn workers: every
    worker derives the same token from the same row, so whichever worker answers
    the next request computes the new key. A per-process flag would only fix the
    one worker that happened to handle the PUT.

    The row count is included because MAX(updated_at) alone does not move when a
    non-newest row is deleted. Returns None on lookup failure; the caller then
    bypasses the cache.
    """
    try:
        with db.get_db_cursor() as cur:
            cur.execute(
                "SELECT COUNT(*) AS n, MAX(updated_at) AS newest FROM config_settings"
            )
            row = cur.fetchone() or {}
            newest = row.get('newest')
            return "%s@%s" % (
                row.get('n') or 0,
                newest.isoformat() if newest else "none",
            )
    except Exception as e:
        logger.warning(f"Config generation lookup failed, serving uncached: {e}")
        return None


def _cache_key(endpoint_name, generation, config_generation):
    """fleetcis:v1:<endpoint-name>:<sync_generation>:<config_generation>:<scope-querystring>

    scope-querystring is urlencode() over CACHE_SCOPE_ARGS ONLY, never the whole
    request arg set: an arg nobody reads cannot change the body, so it must not be
    able to mint a new entry either. ?junk=1 therefore hits the same key as no arg
    at all. Repeated values of an allow-listed arg are all kept, and sorting makes
    the key insensitive to arg order.

    config_generation is '-' for endpoints whose body does not depend on
    config_settings, so every key keeps the same number of segments.
    """
    scope = []
    for name in CACHE_SCOPE_ARGS:
        # request.args.get() — same accessor every reader uses. getlist() made the
        # key disagree with the body (?team=&team=X). Empty values are skipped.
        val = request.args.get(name)
        if val:
            scope.append((name, val))
    query_string = urlencode(sorted(scope))
    return f"{CACHE_KEY_PREFIX}:{endpoint_name}:{generation}:{config_generation}:{query_string}"


def cache_scope_within_limits():
    """False when an allow-listed scope value is too long to be worth keying on."""
    for name in CACHE_SCOPE_ARGS:
        val = request.args.get(name)
        if val and len(val) > MAX_CACHE_SCOPE_VALUE_LEN:
            return False
    return True


def cached_response(endpoint_name, config_dependent=False):
    """Cache an expensive read-only endpoint's serialized JSON body in Redis.

    Set config_dependent=True for an endpoint that reads get_config(): its key
    then also carries the config generation, so saving Settings is visible on the
    next request instead of after the TTL.

    Every failure path falls through to the live result: a cache problem must
    never become a 5xx on a read endpoint.
    """
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            # Checked before the Redis probe and the two generation lookups: a
            # request nobody will cache should not pay for them either.
            if not cache_scope_within_limits():
                return fn(*args, **kwargs)
            client = get_cache_client()
            if client is None:
                return fn(*args, **kwargs)
            generation = get_sync_generation()
            if generation is None:
                return fn(*args, **kwargs)
            # Only paid for by the endpoints that need it — one aggregate over a
            # table with a handful of rows.
            config_generation = get_config_generation() if config_dependent else '-'
            if config_generation is None:
                return fn(*args, **kwargs)
            key = _cache_key(endpoint_name, generation, config_generation)
            try:
                cached = client.get(key)
            except Exception as e:
                _cooldown_cache(f"read failed: {e}")
                return fn(*args, **kwargs)
            if cached is not None:
                resp = app.response_class(cached, mimetype='application/json')
                resp.headers['X-Cache'] = 'HIT'
                return resp
            resp = app.make_response(fn(*args, **kwargs))
            resp.headers['X-Cache'] = 'MISS'
            # Only successful JSON bodies are worth keeping — error_response()
            # returns a non-200 tuple and must not be cached.
            if resp.status_code == 200 and resp.mimetype == 'application/json':
                try:
                    client.setex(key, CACHE_TTL_SECONDS, resp.get_data())
                except Exception as e:
                    _cooldown_cache(f"write failed: {e}")
            return resp
        return wrapper
    return decorator


# --- Configuration Management ---
def get_config(key, default):
    """Fetch configuration value from database with fallback to default."""
    try:
        with db.get_db_cursor() as cur:
            cur.execute("SELECT value FROM config_settings WHERE key = %s", (key,))
            row = cur.fetchone()
            if row:
                val = row['value']
                # Stored values are free-form text; fall back through JSON, then
                # number, then raw string. Narrow excepts so a SystemExit or
                # KeyboardInterrupt is not swallowed by the parse attempt.
                try:
                    return json.loads(val)
                except (TypeError, ValueError):
                    try:
                        return float(val) if '.' in val else int(val)
                    except (TypeError, ValueError):
                        return val
            return default
    except Exception as e:
        logger.error(f"Config error for {key}: {e}")
        return default


def config_number(key, default):
    """get_config() with a numeric guarantee, for values that reach arithmetic.

    config_settings.value is free-form TEXT and get_config() hands back whatever it
    parses to, so a stored "True" comes back as the string 'True'. /api/strategy then
    evaluated `min(100, fail_count * 'True')`, which is a string repetition followed by
    comparing str to int: TypeError, i.e. a 500 on a read endpoint on EVERY request
    until someone edits the database. PUT /api/config validates with float() and so
    accepts a JSON boolean, and the operator has psql, so the value does not have to
    arrive well-formed.

    A well-formed value is returned untouched, ints included, so the response bodies
    are byte-identical to before for every value the Settings UI can produce. Junk
    falls back to the documented default with a warning - the same lenient contract the
    env tunables use, for the same reason: a read path must not die on configuration.
    """
    val = get_config(key, default)
    # bool is an int subclass, and arithmetic on "somebody typed a boolean into a
    # numeric setting" is meaningless rather than merely odd.
    if not isinstance(val, bool) and isinstance(val, (int, float)) and math.isfinite(val):
        return val
    try:
        num = float(str(val).strip())
    except (TypeError, ValueError):
        num = None
    if num is None or not math.isfinite(num):
        logger.warning(
            f"Config {key}={val!r} is not a finite number, using default {default}"
        )
        return default
    return num


def config_keyword_list(key, default):
    """get_config() as a list of lowercase keywords, whatever is stored.

    Same failure class as config_number: the effort keyword settings are not in
    update_config's numeric list, so any JSON value can be stored under them. A stored
    number came back as an int and `[k.lower() for k in 5]` is a TypeError; a stored
    [1, 2] reached str.lower() on an int. Both 500'd /api/strategy permanently.

    Accepts the two shapes that actually occur - a JSON array (what the Settings UI
    sends) and a comma-separated string - and degrades anything else into a keyword
    that simply matches no policy name, which is the harmless outcome.
    """
    val = get_config(key, default)
    if isinstance(val, str):
        items = val.split(',')
    elif isinstance(val, (list, tuple, set)):
        items = list(val)
    elif val is None:
        items = []
    else:
        items = [val]
    keywords = []
    for item in items:
        text = str(item).strip().lower()
        if text:
            keywords.append(text)
    return keywords

# --- Helper Query Builder ---
def build_filter_query(base_query, params, filters_map):
    """
    Appends WHERE clauses based on filters.
    filters_map: dict of {url_param: sql_column}

    Currently unused. If you wire this into a @cached_response endpoint, the
    filters_map you pass MUST be HOST_SCOPE_FILTERS (or its args added to
    HOST_SCOPE_EXTRA_ARGS), otherwise the args it reads are absent from the cache
    key and two different responses will share one entry.
    """
    conditions = []
    
    for param, col in filters_map.items():
        val = request.args.get(param)
        if val:
            if col == 'platform_version':
                conditions.append(f"{col} LIKE %s")
                params.append(f"%{val}%")
            else:
                conditions.append(f"{col} = %s")
                params.append(val)
            
    if conditions:
        if "WHERE" in base_query.upper() and ("FROM" in base_query.upper().split("WHERE")[-1] or "SELECT" not in base_query.upper().split("WHERE")[-1]):
             base_query += " AND " + " AND ".join(conditions)
        else:
             base_query += " WHERE " + " AND ".join(conditions)
            
    return base_query, params

def get_filtered_hosts_subquery():
    """
    Build a subquery to get host_ids with label + standard filters applied.
    Returns (subquery_string, params_list)

    The filter map is HOST_SCOPE_FILTERS, shared with the response cache key so
    the two can never disagree about which args change a body. Iteration order is
    the dict's insertion order, so the emitted SQL is unchanged.
    """
    label_filter = request.args.get('label')
    filters = HOST_SCOPE_FILTERS

    params = []
    conditions = []
    
    if label_filter:
        base = """
            SELECT h.host_id FROM fleet_hosts h
            JOIN host_labels hl ON h.host_id = hl.host_id
            JOIN fleet_labels fl ON hl.label_id = fl.label_id
            WHERE fl.label_name = %s
        """
        params.append(label_filter)
    else:
        base = "SELECT host_id FROM fleet_hosts h WHERE 1=1"
    
    for param, col in filters.items():
        val = request.args.get(param)
        if val:
            conditions.append(f"h.{col} = %s")
            params.append(val)
    
    if conditions:
        base += " AND " + " AND ".join(conditions)

    return base, params


# --- Historical trend helpers (policy_results_history) ---
# Trends come from policy_results_history (raw per-host statuses) — compliance_snapshots
# has no per-policy grain. critical_failures and passing_hosts can't be compared across time
# because old revisions stored wrong values. compliance_score is comparable: every revision
# wrote the same quantity and it is the only column team_score_trends() reads.
def history_window_bounds(cur, h_query, params):
    """Earliest/latest history observation in the trend window, for this scope.

    Returns (window_meta, first_seen, last_seen). window_meta['multi_day'] is the
    "is there enough history to compare" test: comparing MIN and MAX dates is
    exactly equivalent to "at least 2 distinct days present" but costs one bounded
    range scan instead of sorting the window to count distinct days.

    checked_at is constrained by a stable expression so PG can prune partitions at
    execution start and serve the range from idx_history_checked_policy, instead of
    scanning every partition that will ever exist.
    """
    cur.execute(f"""
        SELECT MIN(checked_at) AS first_seen,
               MAX(checked_at) AS last_seen,
               MIN(checked_at)::date <> MAX(checked_at)::date AS multi_day
        FROM policy_results_history
        WHERE checked_at >= NOW() - make_interval(days => %s)
          AND host_id IN ({h_query})
    """, [HISTORY_TREND_DAYS] + list(params))
    row = cur.fetchone() or {}
    first_seen = row.get('first_seen')
    last_seen = row.get('last_seen')
    window_meta = {
        "days": HISTORY_TREND_DAYS,
        "first_observed": first_seen.isoformat() if first_seen else None,
        "last_observed": last_seen.isoformat() if last_seen else None,
        # False whenever the window holds fewer than 2 distinct days, including
        # the empty case (NULL <> NULL is NULL, not true).
        "multi_day": bool(row.get('multi_day')),
        "source": "policy_results_history",
    }
    return window_meta, first_seen, last_seen


def history_pair_deltas(cur, h_query, params):
    """Per-policy first-vs-last observed status inside the trend window.

    One row per policy_id: how many (policy_id, host_id) pairs were observed at
    all, how many of them were failing at their FIRST observation in the window,
    and how many at their LAST. A pair that produced no rows in the window is
    absent from both counts rather than being assumed failing, which is what makes
    this safe on a sparse history.

    scoped is MATERIALIZED on purpose: it is referenced twice, so without it PG
    would inline the window scan into both DISTINCT ON branches and read the
    partitions twice. DISTINCT ON yields exactly one row per pair on each side, so
    the join is 1:1 and duplicate rows for the same (pair, checked_at) - possible
    if Fleet ever reported a host as both passing and failing in one sync - cannot
    inflate the counts.
    """
    cur.execute(f"""
        WITH scoped AS MATERIALIZED (
            SELECT history_id, policy_id, host_id, status, checked_at
            FROM policy_results_history
            WHERE checked_at >= NOW() - make_interval(days => %s)
              AND host_id IN ({h_query})
        ),
        first_obs AS (
            SELECT DISTINCT ON (policy_id, host_id)
                   policy_id, host_id, status, checked_at, history_id
            FROM scoped
            ORDER BY policy_id, host_id, checked_at ASC, history_id ASC
        ),
        last_obs AS (
            SELECT DISTINCT ON (policy_id, host_id)
                   policy_id, host_id, status, checked_at, history_id
            FROM scoped
            ORDER BY policy_id, host_id, checked_at DESC, history_id DESC
        )
        SELECT f.policy_id,
               COUNT(*) AS observed_pairs,
               COUNT(*) FILTER (WHERE f.status = 'fail') AS first_fail,
               COUNT(*) FILTER (WHERE l.status = 'fail') AS last_fail
        FROM first_obs f
        JOIN last_obs l
          ON l.policy_id = f.policy_id AND l.host_id = f.host_id
        GROUP BY f.policy_id
    """, [HISTORY_TREND_DAYS] + list(params))
    return cur.fetchall()


def technique_trends(trend_rows, policy_techniques):
    """Roll per-policy history deltas up to ATT&CK techniques.

    policy_techniques comes from the caller's own pass over
    policy_catalog.mapping_for_policy() + MITRE_DATA, so there is exactly one
    mapping path in the file and gains/losses can never disagree with the matrix
    they sit next to.

    "passing" here means "not failing", matching the current-state aggregate in
    /api/architecture where a host with fail_count = 0 counts as passing - an
    'error' result therefore lands on the passing side in both places.
    """
    stats = {}
    for row in trend_rows:
        techniques = policy_techniques.get(row['policy_id'])
        if not techniques:
            continue
        pairs = int(row['observed_pairs'] or 0)
        if pairs <= 0:
            continue
        first_pass = pairs - int(row['first_fail'] or 0)
        last_pass = pairs - int(row['last_fail'] or 0)
        for aid in techniques:
            acc = stats.setdefault(aid, {'pairs': 0, 'first_pass': 0, 'last_pass': 0})
            # A policy mapped to several techniques contributes its full volume to
            # each of them, exactly as the current-state mitre_stats rollup does.
            acc['pairs'] += pairs
            acc['first_pass'] += first_pass
            acc['last_pass'] += last_pass

    moved = []
    for aid, acc in stats.items():
        pairs = acc['pairs']
        if pairs < HISTORY_TREND_MIN_SAMPLE:
            continue
        baseline = 100.0 * acc['first_pass'] / pairs
        current = 100.0 * acc['last_pass'] / pairs
        change = round(current - baseline, 1)
        # Techniques that did not move are not news, and reporting a 0.0% "gain"
        # would fill the list with float noise.
        if change == 0:
            continue
        meta = MITRE_DATA.get(aid) or {}
        moved.append({
            "id": aid,
            "name": meta.get('name') or aid,
            "tactic": meta.get('tactic') or '',
            # Display string the frontend prints verbatim; the sign is included.
            "change": f"{change:+.1f}%",
            # Percentage points, not a ratio of a ratio.
            "change_pp": change,
            "baseline_rate": round(baseline, 1),
            "current_rate": round(current, 1),
            "sample_size": pairs,
        })

    gains = sorted(
        [m for m in moved if m['change_pp'] > 0],
        key=lambda m: m['change_pp'], reverse=True
    )[:HISTORY_TREND_TOP_N]
    losses = sorted(
        [m for m in moved if m['change_pp'] < 0],
        key=lambda m: m['change_pp']
    )[:HISTORY_TREND_TOP_N]
    return gains, losses


# --- Team score trend (compliance_snapshots) ---
# compliance_snapshots is the only per-day record of a team's score — one row per
# (snapshot_date, team_id) replaced in place. /api/strategy's leaderboard now reads it
# instead of hardcoding "trend": "unknown".
#
# A change smaller than this many percentage points is reported as 'stable', not as a
# direction. Half a point because the score shown next to the trend is rounded to a
# whole percent: under 0.5 pp the displayed number cannot have moved at all, so calling
# it a rise or a fall would be presenting float noise as progress. It is a statement
# about the resolution of what is being compared, not a guess at measurement error.
TEAM_TREND_FLAT_THRESHOLD_PP = 0.5
# ?platform= / ?osVersion= / ?label= make the live score and stored history describe
# different host sets, so the trend goes back to "unknown". ?team= is compatible.
TEAM_TREND_UNSUPPORTED_SCOPE_ARGS = tuple(a for a in CACHE_SCOPE_ARGS if a != 'team')
# Fewer than this many distinct snapshot dates in the window is not a trend.
TEAM_TREND_MIN_DATES = 2


def team_trend_scope_is_comparable():
    """True when the request scope is one compliance_snapshots can answer."""
    return not any(request.args.get(a) for a in TEAM_TREND_UNSUPPORTED_SCOPE_ARGS)


def classify_team_trend(delta_pp):
    """'up' / 'down' / 'stable' from a percentage-point delta.

    Called with the ROUNDED delta, the same number that is reported, so the direction
    and the figure next to it can never disagree at the threshold.
    """
    if delta_pp >= TEAM_TREND_FLAT_THRESHOLD_PP:
        return 'up'
    if delta_pp <= -TEAM_TREND_FLAT_THRESHOLD_PP:
        return 'down'
    return 'stable'


def team_score_trends(cur):
    """team_name -> {trend, delta, trend_basis} from compliance_snapshots.

    A team appears in the result ONLY when the window holds at least
    TEAM_TREND_MIN_DATES distinct snapshot dates for it carrying a non-NULL
    compliance_score. One row is not a trend - there is no second end to compare
    against - so such a team is left at "unknown" by the caller instead of being
    reported as 0, which would read as "measured, and it did not move".

    The delta is snapshot minus snapshot (newest in the window minus oldest), never the
    live leaderboard score minus the oldest snapshot: those two numbers are measured at
    different instants and, because the rotating full-refresh sweep re-enumerates a
    slice of policies each sync, over slightly different row sets. Subtracting one from
    the other would bake that difference into the delta and call it progress.

    Excluded on purpose:
      - team_id IS NULL, the global row. It covers every host, so it is emphatically not
        the leaderboard's 'Unassigned' entry (hosts with no team), and using it there
        would attach fleet-wide movement to one bucket.
      - compliance_score IS NULL. An unscored row is not evidence of a date.
      - team names that are not unique in fleet_teams. The leaderboard groups by
        team_name, so a duplicated name cannot be resolved to one team's snapshots
        without guessing; guessing here would silently attribute one team's movement to
        another.

    DISTINCT ON gives exactly one row per team on each end. The snapshot_id tiebreak
    matters only on a database provisioned before the (snapshot_date, team_id) unique
    constraint existed: it keeps the highest snapshot_id for a date, which is the same
    "most recently written aggregate wins" rule schema.sql uses when it de-duplicates.
    It is carried in the select list rather than only in ORDER BY, matching
    history_pair_deltas() above, so the CTE does not depend on how a given PostgreSQL
    version treats an ORDER BY column that a DISTINCT query does not select.
    """
    cur.execute("""
        WITH scoped AS (
            SELECT snapshot_id, team_id, snapshot_date, compliance_score
            FROM compliance_snapshots
            WHERE team_id IS NOT NULL
              AND compliance_score IS NOT NULL
              AND snapshot_date >= CURRENT_DATE - make_interval(days => %s)
        ),
        first_obs AS (
            SELECT DISTINCT ON (team_id)
                   team_id, snapshot_date, compliance_score, snapshot_id
            FROM scoped
            ORDER BY team_id, snapshot_date ASC, snapshot_id DESC
        ),
        last_obs AS (
            SELECT DISTINCT ON (team_id)
                   team_id, snapshot_date, compliance_score, snapshot_id
            FROM scoped
            ORDER BY team_id, snapshot_date DESC, snapshot_id DESC
        ),
        spans AS (
            SELECT team_id, COUNT(DISTINCT snapshot_date) AS observed_dates
            FROM scoped
            GROUP BY team_id
        )
        SELECT t.team_name,
               s.observed_dates,
               f.snapshot_date AS first_date,
               f.compliance_score AS first_score,
               l.snapshot_date AS last_date,
               l.compliance_score AS last_score
        FROM spans s
        JOIN first_obs f ON f.team_id = s.team_id
        JOIN last_obs l ON l.team_id = s.team_id
        JOIN fleet_teams t ON t.team_id = s.team_id
    """, [HISTORY_TREND_DAYS])
    rows = cur.fetchall()

    name_counts = {}
    for row in rows:
        name = row['team_name']
        name_counts[name] = name_counts.get(name, 0) + 1

    trends = {}
    for row in rows:
        name = row['team_name']
        if not name or name_counts.get(name, 0) > 1:
            continue
        if int(row['observed_dates'] or 0) < TEAM_TREND_MIN_DATES:
            continue
        first_score = row['first_score']
        last_score = row['last_score']
        if first_score is None or last_score is None:
            continue
        first_score = float(first_score)
        last_score = float(last_score)
        # Percentage points, not a ratio of a ratio.
        delta = round(last_score - first_score, 1)
        first_date = row['first_date']
        last_date = row['last_date']
        trends[name] = {
            "trend": classify_team_trend(delta),
            "delta": delta,
            # The evidence the direction rests on, so a consumer never has to take
            # the label on trust.
            "trend_basis": {
                "first_date": first_date.isoformat() if first_date else None,
                "first_score": round(first_score, 1),
                "last_date": last_date.isoformat() if last_date else None,
                "last_score": round(last_score, 1),
                "observed_dates": int(row['observed_dates'] or 0),
                "source": "compliance_snapshots",
            },
        }
    return trends


@app.route('/', methods=['GET'])
def index():
    return jsonify({
        "status": "ok",
        "message": "Fleet CIS Compliance Dashboard Backend API (PostgreSQL)",
        "endpoints": [
            "/api/teams",
            "/api/platforms",
            "/api/devices",
            "/api/compliance-summary",
            "/api/safeguard-compliance",
            "/api/heatmap-data",
            "/api/sync-status",
            "/api/config"
        ]
    })


@app.route('/healthz', methods=['GET'])
def healthz():
    """Readiness probe that actually exercises the data path.

    GET / cannot do this job and is deliberately left alone (the frontend and the
    existing probes read it): it returns a static payload, so since pool creation
    at import became non-fatal a backend with an unreachable Postgres answers it
    200 — "healthy" — while every /api/* request 500s. This runs SELECT 1 through
    db.get_db_cursor(), i.e. through the real pool and a real checked-out
    connection, so a dead database is a 503 that an orchestrator can act on.

    The body carries the exception CLASS only. psycopg2's OperationalError text
    embeds the DSN host, port and user, and this endpoint is unauthenticated; the
    full message goes to the log instead.
    """
    try:
        with db.get_db_cursor() as cur:
            cur.execute("SELECT 1 AS ok")
            row = cur.fetchone()
        if not row:
            logger.warning("Health check: SELECT 1 returned no row")
            return jsonify({"status": "unhealthy", "database": "no_result"}), 503
        return jsonify({"status": "ok", "database": "ok"}), 200
    except Exception as e:
        logger.warning(f"Health check failed: {type(e).__name__}: {e}")
        return jsonify({
            "status": "unhealthy",
            "database": "unreachable",
            "error": type(e).__name__,
        }), 503


@app.route('/api/sync-status', methods=['GET'])
def get_sync_status():
    """Return the latest sync metadata for the frontend indicator."""
    try:
        with db.get_db_cursor() as cur:
            cur.execute("""
                SELECT sync_id, started_at, completed_at, status,
                       hosts_changed, policies_changed, results_changed,
                       duration_ms, error_message
                FROM sync_metadata
                ORDER BY sync_id DESC
                LIMIT 1
            """)
            row = cur.fetchone()
            if not row:
                return jsonify({
                    "last_sync": None,
                    "status": "never",
                    "degraded": False,
                    "message": "No sync has been performed yet"
                })

            # Handle TZ-aware datetimes from Postgres
            completed = row['completed_at']
            started = row['started_at']
            status = row['status']
            error_message = row['error_message']

            return jsonify({
                "last_sync": completed.isoformat() if completed else started.isoformat(),
                "status": status,
                # Truthful partial-failure signal. sync_fleet_data records
                # status='success' with error_message="N fetch error(s); first — …"
                # when some fetches failed but the run still wrote data, so
                # "status" alone says everything is fine and a consumer had to
                # string-inspect "error" to notice. Additive on purpose: no
                # existing key is renamed or removed, the frontend reads them.
                "degraded": status == 'success' and bool(error_message),
                "duration_ms": row['duration_ms'],
                # _env_int so a non-numeric SYNC_INTERVAL_MINUTES cannot turn this
                # read endpoint into a 500.
                "sync_interval_minutes": _env_int("SYNC_INTERVAL_MINUTES", 5),
                "changes": {
                    "hosts": row['hosts_changed'],
                    "policies": row['policies_changed'],
                    "results": row['results_changed']
                },
                "error": error_message
            })
    except Exception as e:
        logger.error(f"Sync status fetch failed: {str(e)}")
        return jsonify({
            "last_sync": None,
            "status": "error",
            # Present on every branch so a consumer can read it unconditionally.
            "degraded": False,
            "message": "Internal server error"
        }), 500

@app.route('/api/config', methods=['GET'])
def get_all_config():
    try:
        with db.get_db_cursor() as cur:
            cur.execute("SELECT key, value, description FROM config_settings ORDER BY key")
            config = {}
            for row in cur.fetchall():
                key = row['key']
                val = row['value']
                try:
                    parsed = json.loads(val)
                except (TypeError, ValueError):
                    try:
                        parsed = float(val) if '.' in val else int(val)
                    except (TypeError, ValueError):
                        parsed = val
                config[key] = {
                    "value": parsed,
                    "description": row['description']
                }
            return jsonify(config)
    except Exception as e:
        return error_response("Failed to fetch configuration", 500, str(e))

@app.route('/api/config', methods=['PUT'])
@require_write_auth
def update_config():
    try:
        # silent=True so a malformed body or a missing JSON content-type reports
        # 400 here instead of raising and being reported as a 500 by the handler
        # below. A JSON array or scalar would also break the .items() loop.
        updates = request.get_json(silent=True)
        if not updates:
            return error_response("No configuration provided", 400)
        if not isinstance(updates, dict):
            return error_response("Configuration must be a JSON object", 400)

        # Validation for keys
        invalid_keys = [k for k in updates if k not in VALID_CONFIG_KEYS]
        if invalid_keys:
            # Bounded echo: see MAX_ECHOED_KEYS. The body is already capped by
            # MAX_CONTENT_LENGTH, but a 1 MiB body of long junk keys would still be
            # quoted back in full into both the response and the log line.
            shown = [str(k)[:MAX_ECHOED_KEY_CHARS] for k in invalid_keys[:MAX_ECHOED_KEYS]]
            if len(invalid_keys) > MAX_ECHOED_KEYS:
                shown.append(f"(+{len(invalid_keys) - MAX_ECHOED_KEYS} more)")
            return error_response(f"Invalid configuration keys: {', '.join(shown)}", 400)

        # Basic type validation for numeric fields
        numeric_keys = [
            'risk_exposure_multiplier', 
            'security_debt_hours_per_issue', 
            'impact_high_threshold', 
            'impact_medium_threshold',
            'framework_cis_multiplier',
            'framework_nist_multiplier',
            'framework_iso_multiplier',
            'maturity_level_5',
            'maturity_level_4',
            'maturity_level_3',
            'maturity_level_2',
            'maturity_level_1',
        ]
        for key, value in updates.items():
            if key in numeric_keys:
                try:
                    numeric_value = float(value)
                except (ValueError, TypeError):
                    return error_response(f"Value for {key} must be numeric", 400)
                # "nan"/"inf" pass float() and would be stored verbatim, then
                # serialized into /api/strategy as a non-standard JSON token that
                # strict clients reject.
                if not math.isfinite(numeric_value):
                    return error_response(
                        f"Value for {key} must be a finite number", 400
                    )
        
        with db.get_db_cursor(commit=True) as cur:
            updated_count = 0
            for key, value in updates.items():
                val_str = json.dumps(value) if isinstance(value, (list, dict)) else str(value)
                cur.execute("""
                    INSERT INTO config_settings (key, value, updated_at)
                    VALUES (%s, %s, NOW())
                    ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()
                """, (key, val_str))
                updated_count += 1 
            
            logger.info(f"Updated {updated_count} config settings: {list(updates.keys())}")
            return jsonify({"success": True, "updated": updated_count})
    except HTTPException:
        # silent=True suppresses parse failures, not the length check — re-raise
        # so an oversized body returns 413, not a misleading 500.
        raise
    except Exception as e:
        return error_response("Failed to update configuration", 500, str(e))

@app.route('/api/teams', methods=['GET'])
def get_teams():
    h_query, params = get_filtered_hosts_subquery()

    query = f"""
        SELECT DISTINCT h.team_name
        FROM fleet_hosts h
        WHERE h.host_id IN ({h_query}) AND h.team_name IS NOT NULL
        ORDER BY h.team_name
    """

    with db.get_db_cursor() as cur:
        cur.execute(query, params)
        teams = [row['team_name'] for row in cur.fetchall()]
        return jsonify({"teams": teams})

@app.route('/api/platforms', methods=['GET'])
def get_platforms():
    h_query, params = get_filtered_hosts_subquery()

    query = f"""
        SELECT DISTINCT h.platform
        FROM fleet_hosts h
        WHERE h.host_id IN ({h_query}) AND h.platform IS NOT NULL
        ORDER BY h.platform
    """

    with db.get_db_cursor() as cur:
        cur.execute(query, params)
        platforms = [row['platform'] for row in cur.fetchall()]
        return jsonify({"platforms": platforms})

@app.route('/api/labels', methods=['GET'])
def get_labels():
    with db.get_db_cursor() as cur:
        cur.execute("SELECT DISTINCT label_name FROM fleet_labels ORDER BY label_name")
        labels = [row['label_name'] for row in cur.fetchall()]
        return jsonify({"labels": labels})

@app.route('/api/os-versions', methods=['GET'])
def get_os_versions():
    h_query, params = get_filtered_hosts_subquery()

    query = f"""
        SELECT DISTINCT h.platform, h.platform_version
        FROM fleet_hosts h
        WHERE h.host_id IN ({h_query}) AND h.platform IS NOT NULL
    """

    with db.get_db_cursor() as cur:
        cur.execute(query, params)
        os_versions = {}
        for row in cur.fetchall():
            plat = row['platform']
            ver = row['platform_version']
            if plat not in os_versions: os_versions[plat] = []
            if ver not in os_versions[plat]: os_versions[plat].append(ver)
        return jsonify({"os_versions": os_versions})

@app.route('/api/devices', methods=['GET'])
def get_devices():
    # Pagination — clamp before these values ever reach SQL. Junk input still
    # falls back to the defaults rather than erroring; out-of-range numbers are
    # clamped so ?limit=999999 cannot dump the table and ?page=-1 cannot send a
    # negative OFFSET to Postgres.
    page = max(0, request_int('page', 0))
    limit = min(MAX_PAGE_SIZE, max(1, request_int('limit', DEFAULT_PAGE_SIZE)))
    page = min(page, MAX_PAGE_OFFSET // limit)
    offset = page * limit

    label_filter = request.args.get('label')
    params = []
    
    # Base query
    if label_filter:
        query = """
            SELECT h.*, 
            (SELECT COUNT(*) FROM policy_results pr WHERE pr.host_id = h.host_id AND pr.status = 'fail') as fail_count
            FROM fleet_hosts h
            JOIN host_labels hl ON h.host_id = hl.host_id
            JOIN fleet_labels fl ON hl.label_id = fl.label_id
            WHERE fl.label_name = %s
        """
        count_query = """
            SELECT COUNT(*) as total FROM fleet_hosts h
            JOIN host_labels hl ON h.host_id = hl.host_id
            JOIN fleet_labels fl ON hl.label_id = fl.label_id
            WHERE fl.label_name = %s
        """
        params.append(label_filter)
    else:
        query = """
            SELECT h.*, 
            (SELECT COUNT(*) FROM policy_results pr WHERE pr.host_id = h.host_id AND pr.status = 'fail') as fail_count
            FROM fleet_hosts h
            WHERE 1=1
        """
        count_query = "SELECT COUNT(*) as total FROM fleet_hosts h WHERE 1=1"
    
    # Additional filters — same map as get_filtered_hosts_subquery(), so a new
    # scope filter lands here too instead of silently applying to one endpoint.
    for param, col in HOST_SCOPE_FILTERS.items():
        val = request.args.get(param)
        if val:
            clause = f" AND h.{col} = %s"
            query += clause
            count_query += clause
            params.append(val)
    
    # Add Pagination
    query += " ORDER BY h.last_seen DESC LIMIT %s OFFSET %s"
    
    with db.get_db_cursor() as cur:
        # Get Total Count
        cur.execute(count_query, params) # Uses params without limit/offset
        total = cur.fetchone()['total']
        
        # Get Rows
        cur.execute(query, params + [limit, offset])
        rows = cur.fetchall()
        
        devices = []
        for row in rows:
            status = "non-compliant" if (row.get('fail_count') or 0) > 0 else "compliant"
            last_seen = row['last_seen'].isoformat() if row['last_seen'] else None
            
            devices.append({
                "device_id": str(row['host_id']),
                "hostname": row['hostname'],
                "team": row['team_name'],
                "platform": row['platform'],
                "os_version": row['platform_version'],
                "last_seen": last_seen,
                "compliance_status": status,
                "policies": []
            })
            
        return jsonify({
            "total": total,
            "count": len(devices),
            "page": page,
            # Effective values after clamping, so a caller can tell it asked for
            # more than the server is willing to return.
            "limit": limit,
            "max_limit": MAX_PAGE_SIZE,
            "offset": offset,
            "devices": devices
        })

@app.route('/api/compliance-summary', methods=['GET'])
def get_compliance_summary():
    h_query, params = get_filtered_hosts_subquery()
    
    # 1. Device Counts
    device_query = f"""
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN (SELECT COUNT(*) FROM policy_results pr WHERE pr.host_id = h.host_id AND pr.status = 'fail') = 0 THEN 1 ELSE 0 END) as compliant
        FROM ({h_query}) sq
        JOIN fleet_hosts h ON sq.host_id = h.host_id
    """
    
    # 2. Policy Stats
    policy_query = f"""
        SELECT pr.status, COUNT(*) as count 
        FROM policy_results pr
        WHERE pr.host_id IN ({h_query})
        GROUP BY pr.status
    """
    
    with db.get_db_cursor() as cur:
        cur.execute(device_query, params)
        dev_row = cur.fetchone()
        total_dev = dev_row['total']
        compliant_dev = dev_row['compliant'] if dev_row['compliant'] is not None else 0
        non_compliant_dev = total_dev - compliant_dev

        cur.execute(policy_query, params)
        policy_stats = {row['status']: row['count'] for row in cur.fetchall()}
        
        passed = policy_stats.get('pass', 0)
        failed = policy_stats.get('fail', 0)
        total_pol = passed + failed
        pass_rate = (passed / total_pol * 100) if total_pol > 0 else 0

        # Distinct policies with ≥1 fail (not row-inflated "critical" count)
        cur.execute(f"""
            SELECT COUNT(DISTINCT policy_id) as n
            FROM policy_results
            WHERE status = 'fail' AND host_id IN ({h_query})
        """, params)
        failing_policies = cur.fetchone()['n'] or 0
        
        return jsonify({
            "total_devices": total_dev,
            # Fully compliant = zero failing checks on the device
            "compliant_devices": compliant_dev,
            "fully_compliant_devices": compliant_dev,
            "non_compliant_devices": non_compliant_dev,
            # policy_pass_rate = pass result rows / all result rows (NOT device compliance)
            "compliance_percentage": pass_rate,
            "policy_pass_rate": pass_rate,
            "total_policies": total_pol,
            "policies_passed": passed,
            "policies_failed": failed,
            "open_failures": failed,
            "failing_policies_count": failing_policies,
            "total_policy_results": total_pol
        })

@app.route('/api/safeguard-compliance', methods=['GET'])
@cached_response('safeguard-compliance')
def get_safeguard_compliance():
    h_query, params = get_filtered_hosts_subquery()
    
    query = f"""
        SELECT p.policy_id, p.policy_name, p.cis_control, p.description, p.resolution, p.query, p.cis_safeguard_ids, pr.status, COUNT(*) as count
        FROM policy_results pr
        JOIN cis_policies p ON pr.policy_id = p.policy_id
        WHERE pr.host_id IN ({h_query})
        GROUP BY p.policy_id, p.policy_name, p.cis_control, p.description, p.resolution, p.query, p.cis_safeguard_ids, pr.status
    """
    
    with db.get_db_cursor() as cur:
        cur.execute(query, params)
        rows = cur.fetchall()
        
        policy_stats = {}
        for row in rows:
            pid = row['policy_id']
            if pid not in policy_stats:
                policy_stats[pid] = {
                    "policy_name": row['policy_name'],
                    "control": row['cis_control'],
                    "description": row['description'],
                    "resolution": row['resolution'],
                    "query": row['query'],
                    "cis_safeguard_ids": row.get('cis_safeguard_ids') or [],
                    "pass": 0,
                    "fail": 0
                }
            if row['status'] == 'pass':
                policy_stats[pid]['pass'] += row['count']
            elif row['status'] == 'fail':
                policy_stats[pid]['fail'] += row['count']
                
        # Expand each policy into its safeguard IDs, deduplicating on (safeguard_id, policy_name)
        result_list = []
        seen = set()
        for p in policy_stats.values():
            sids = list(p['cis_safeguard_ids']) if p['cis_safeguard_ids'] else []
            if not sids:
                sids = ['policy_' + str(p['policy_name'].lower().replace(' ', '_'))]
            total = p['pass'] + p['fail']
            pass_rate = (p['pass'] / total * 100) if total > 0 else 0
            for sid in sids:
                key = (sid, p['policy_name'])
                if key not in seen:
                    seen.add(key)
                    result_list.append({
                        "safeguard_id": sid,
                        "name": p['policy_name'],
                        "control": p['control'],
                        "description": p['description'],
                        "resolution": p['resolution'],
                        "query": p['query'],
                        "pass": p['pass'],
                        "fail": p['fail'],
                        "pass_rate": pass_rate
                    })
            
        return jsonify({"safeguards": result_list})

def build_policy_host_agg(h_query, params):
    """Build the policy_results subquery aggregated by (policy_id, host_id).

    Returns (sql_fragment, params) where *sql_fragment* can be used
    directly as ``FROM ({fragment}) sq`` in a larger query.
    """
    fragment = (
        "SELECT pr.policy_id, pr.host_id, "
        "SUM(CASE WHEN pr.status = 'fail' THEN 1 ELSE 0 END) as fail_count "
        "FROM policy_results pr "
        f"WHERE pr.host_id IN ({h_query}) "
        "GROUP BY pr.policy_id, pr.host_id"
    )
    return fragment, params


@app.route('/api/heatmap-data', methods=['GET'])
@cached_response('heatmap-data')
def get_heatmap_data():
    """
    Heat map grain: policy (or cis_safeguard_id aggregation).

    Primary identity comes from fleet_policies tags:
      - cis_safeguard_ids (e.g. CIS8.4)
      - cis_category / benchmark / control slug
    D3FEND is derived from safeguard_d3fend.json (category + CIS Controls function),
    NOT the legacy benchmark-section CIS→ATT&CK dump CSVs.

    risk_score = fail_hosts / fleet_size * 100
    """
    h_query, params = get_filtered_hosts_subquery()
    filter_platform = request.args.get('platform', '')
    # group_mode query param reserved; frontend groups client-side

    sq, sq_params = build_policy_host_agg(h_query, params)

    query = f"""
        SELECT
            p.policy_id,
            p.policy_name,
            p.cis_control,
            p.platform AS policy_platform,
            p.cis_safeguard_ids,
            p.benchmark,
            p.control_slug,
            p.cis_category,
            p.cis_subcategory,
            p.framework,
            p.level,
            p.catalog_matched,
            h.platform AS host_platform,
            COUNT(*) as total_count,
            SUM(CASE WHEN fail_count = 0 THEN 1 ELSE 0 END) as pass_count
        FROM ({sq}) sq
        JOIN cis_policies p ON sq.policy_id = p.policy_id
        JOIN fleet_hosts h ON sq.host_id = h.host_id
        GROUP BY
            p.policy_id, p.policy_name, p.cis_control, p.platform,
            p.cis_safeguard_ids, p.benchmark, p.control_slug,
            p.cis_category, p.cis_subcategory, p.framework, p.level,
            p.catalog_matched, h.platform
    """

    with db.get_db_cursor() as cur:
        cur.execute(f"SELECT COUNT(*) as n FROM ({h_query}) hosts", params)
        fleet_size = cur.fetchone()['n'] or 0

        cur.execute(query, sq_params)
        rows = cur.fetchall()

        heatmap_data = []
        attack_counts = {}
        status_counts = {}
        catalog_hits = 0
        safeguard_hits = 0

        for row in rows:
            host_plat = row['host_platform'] or row['policy_platform'] or 'unknown'
            total = int(row['total_count'] or 0)
            passed = int(row['pass_count'] or 0)
            fail_hosts = max(0, total - passed)
            pass_rate = (passed / total * 100) if total else 0.0
            risk_score = (fail_hosts / fleet_size * 100) if fleet_size else 0.0

            name = row.get('policy_name') or ''
            resolved = policy_catalog.resolve_policy_safeguards(
                name,
                db_sids=row.get('cis_safeguard_ids') or [],
                platform=host_plat or row.get('policy_platform') or '',
            )
            sids = list(resolved.get('cis_safeguard_ids') or [])
            primary_sg = resolved.get('primary') or ''
            cis_category = resolved.get('cis_category') or row.get('cis_category') or ''
            cis_subcategory = resolved.get('cis_subcategory') or row.get('cis_subcategory') or ''

            # Policy-level D3FEND (category/name) with safeguard fallback
            if primary_sg:
                safeguard_hits += 1
            mapping = policy_catalog.mapping_for_policy(
                policy_name=name,
                cis_category=cis_category,
                cis_subcategory=cis_subcategory,
                safeguard_id=primary_sg,
            )

            if resolved.get('catalog_matched') or row.get('catalog_matched'):
                catalog_hits += 1

            attack_ids = list(mapping.get('attack_ids') or [])
            if not attack_ids:
                primary = (mapping.get('attack_id') or '').strip()
                if primary and primary not in ('Unmapped', 'N/A'):
                    attack_ids = [primary]
            attack_id = attack_ids[0] if attack_ids else ''
            for aid in attack_ids:
                if aid and aid not in ('Unmapped', 'N/A'):
                    attack_counts[aid] = attack_counts.get(aid, 0) + 1

            mapping_status = mapping.get('mapping_status') or (
                'mapped' if attack_id else 'unmapped'
            )
            status_counts[mapping_status] = status_counts.get(mapping_status, 0) + 1

            section = row['cis_control'] or resolved.get('benchmark_section') or ''
            heatmap_data.append({
                "policy_id": row['policy_id'],
                "policy_name": name,
                "cis_id": section,  # legacy benchmark section for filters
                "cis_section": section,
                "cis_safeguard_id": primary_sg or 'CISNone',
                "cis_safeguard_ids": list(sids),
                "platform": host_plat,
                "benchmark": row.get('benchmark') or '',
                "control_slug": row.get('control_slug') or '',
                "cis_category": cis_category,
                "cis_subcategory": cis_subcategory,
                "framework": row.get('framework') or '',
                "level": row.get('level') or '',
                "key": f"{host_plat}:{row['policy_id']}",
                "pass": passed,
                "total": total,
                "fail": fail_hosts,
                "pass_rate": round(pass_rate, 1),
                "risk_score": round(risk_score, 1),
                "fleet_size": fleet_size,
                "d3fend_id": mapping.get('d3fend_id') or 'N/A',
                "d3fend_technique": mapping.get('d3fend_technique') or 'Unmapped',
                "d3fend_tactic": mapping.get('d3fend_tactic') or 'Unmapped',
                "attack_id": attack_id or '',
                "attack_ids": attack_ids,
                "mapping_confidence": mapping.get('mapping_confidence') or 'unmapped',
                "mapping_status": mapping_status,
                "mapping_source": mapping.get('mapping_source') or 'none',
                "mapping_rationale": mapping.get('mapping_rationale') or '',
                # Prefer fleet_policies category label over official CIS Controls title
                # (benchmark tags reuse CIS* ids that are not always Controls v8.1 semantics)
                "safeguard_title": (
                    cis_category
                    or mapping.get('title')
                    or mapping.get('safeguard_title')
                    or primary_sg
                ),
                "catalog_matched": bool(resolved.get('catalog_matched') or row.get('catalog_matched')),
            })

        heatmap_data.sort(key=lambda x: (x['platform'], x['cis_safeguard_id'], x['policy_name']))

        coarse_techniques = sorted(
            aid for aid, n in attack_counts.items() if n >= COARSE_ATTACK_THRESHOLD
        )
        for item in heatmap_data:
            item['mapping_coarse'] = bool(item['attack_id'] and item['attack_id'] in coarse_techniques)

        platforms_present = sorted({i['platform'] for i in heatmap_data if i['platform']})
        stats = policy_catalog.catalog_stats()
        total_rows = max(len(heatmap_data), 1)
        attack_coverage = {
            "by_status": status_counts,
            "pct_mapped": round(100.0 * status_counts.get("mapped", 0) / total_rows, 1),
            "pct_not_applicable": round(100.0 * status_counts.get("not_applicable", 0) / total_rows, 1),
            "pct_needs_review": round(100.0 * status_counts.get("needs_review", 0) / total_rows, 1),
            "pct_unmapped": round(100.0 * status_counts.get("unmapped", 0) / total_rows, 1),
            "unique_techniques": len(attack_counts),
        }

        return jsonify({
            "heatmap": heatmap_data,
            "total_controls": len(heatmap_data),
            "fleet_size": fleet_size,
            "platforms": platforms_present,
            "multi_platform": len(platforms_present) > 1,
            "coarse_techniques": coarse_techniques,
            "filter_platform": filter_platform or None,
            "attack_coverage": attack_coverage,
            "catalog": {
                **stats,
                "matched_rows": catalog_hits,
                "safeguard_mapped_rows": safeguard_hits,
                "total_rows": len(heatmap_data),
            },
            "identity": "fleet_policies_tags",
        })

@app.route('/api/strategy', methods=['GET'])
# config_dependent because this body is computed from config_settings (the risk
# and effort tunables read via get_config() below), not from sync output alone. The
# key therefore carries the config generation and a saved setting is visible on the
# very next request in every worker, instead of after up to a full CACHE_TTL.
@cached_response('strategy', config_dependent=True)
def get_strategy():
    h_query, params = get_filtered_hosts_subquery()
    
    with db.get_db_cursor() as cur:
        # 1. Score
        cur.execute(f"SELECT 100.0 * SUM(CASE WHEN status='pass' THEN 1 ELSE 0 END) / NULLIF(COUNT(*), 0) as rate FROM policy_results WHERE host_id IN ({h_query})", params)
        posture_score = float(round(cur.fetchone()['rate'] or 0, 1))

        # 2. Coverage
        cur.execute(f"SELECT 100.0 * COUNT(DISTINCT CASE WHEN status='pass' THEN policy_id END) / NULLIF(COUNT(DISTINCT policy_id), 0) as coverage FROM policy_results WHERE host_id IN ({h_query})", params)
        coverage = round(cur.fetchone()['coverage'] or 0, 1)

        # 3. Risk Exposure
        cur.execute(f"SELECT COUNT(*) as fail_count FROM policy_results WHERE status='fail' AND host_id IN ({h_query})", params)
        fail_count = cur.fetchone()['fail_count'] or 0
        # config_number, not get_config: these three values land in arithmetic and a
        # non-numeric stored value used to be a permanent 500 here.
        risk_multiplier = config_number('risk_exposure_multiplier', 2)
        risk_exposure = min(100, fail_count * risk_multiplier)

        # 4. Security Debt
        debt_per_issue = config_number('security_debt_hours_per_issue', 0.5)
        security_debt_hours = fail_count * debt_per_issue
        if security_debt_hours < 1: security_debt = "< 1h"
        elif security_debt_hours < 8: security_debt = f"{int(security_debt_hours)}h"
        elif security_debt_hours < 40: security_debt = f"{int(security_debt_hours / 8)}d"
        else: security_debt = f"{int(security_debt_hours / 40)}w"

        # 5. Velocity — net failing checks remediated per day over the trend
        #    window, from policy_results_history. Stays None (never 0, never a
        #    fabricated rate) when the window holds fewer than 2 distinct days,
        #    because "nothing was recorded" is not "nothing changed".
        velocity = None
        velocity_window, vel_first, vel_last = history_window_bounds(cur, h_query, params)
        if velocity_window['multi_day']:
            net_fixed = 0
            for row in history_pair_deltas(cur, h_query, params):
                # Net over the same pair set at both ends of the window: pairs the
                # window never observed contribute nothing instead of counting as
                # newly fixed or newly broken.
                net_fixed += int(row['first_fail'] or 0) - int(row['last_fail'] or 0)
            span_days = (vel_last - vel_first).total_seconds() / 86400.0
            # multi_day only guarantees two different calendar dates, so the span
            # can be minutes across midnight. Flooring at one day stops that from
            # inflating a per-day rate by three orders of magnitude.
            velocity = round(net_fixed / max(1.0, span_days), 1)

        # Maturity — configurable thresholds from config_settings, evaluated
        # highest level first so the first match wins.
        maturity = 1
        if posture_score >= config_number('maturity_level_5', 90): maturity = 5
        elif posture_score >= config_number('maturity_level_4', 80): maturity = 4
        elif posture_score >= config_number('maturity_level_3', 70): maturity = 3
        elif posture_score >= config_number('maturity_level_2', 50): maturity = 2

        # 6. Roadmap — projected targets only; actual only for current month (no fabricated history)
        roadmap = []
        months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]
        current_month_idx = datetime.now().month - 1
        for i, m in enumerate(months):
            # Linear target path from current posture toward 95% by year end
            remaining = max(1, 11 - current_month_idx)
            if i < current_month_idx:
                projected = None  # no fake past
                actual = None
            elif i == current_month_idx:
                projected = round(posture_score)
                actual = round(posture_score)
            else:
                steps = i - current_month_idx
                projected = min(95, round(posture_score + steps * (95 - posture_score) / remaining))
                actual = None
            roadmap.append({"month": m, "projected": projected, "actual": actual})

        # 7. Team Leaderboard
        cur.execute(f"""
            SELECT h.team_name, 
                   COUNT(CASE WHEN pr.status = 'pass' THEN 1 END) as pass_count,
                   COUNT(*) as total_count
            FROM policy_results pr
            JOIN fleet_hosts h ON pr.host_id = h.host_id
            WHERE pr.host_id IN ({h_query})
            GROUP BY h.team_name
        """, params)
        
        team_stats = []
        for row in cur.fetchall():
            team_name = row['team_name'] or 'Unassigned'
            total = row['total_count']
            passed = row['pass_count']
            score = round(passed / total * 100) if total > 0 else 0
            team_stats.append({
                "name": team_name,
                "score": score,
                # Filled from compliance_snapshots by step 9. "unknown" stays for any team
                # snapshots can't speak for (fewer than 2 dates, 'Unassigned', scope mismatch, or failed lookup).
                "trend": "unknown",
                "delta": None,
                "trend_basis": None,
            })

        # Sort by score descending and assign rank
        team_stats.sort(key=lambda x: x['score'], reverse=True)
        for i, team in enumerate(team_stats):
            team['rank'] = i + 1

        # 8. Priority Actions (Top failing policies)
        cur.execute(f"""
            SELECT p.policy_name, p.cis_control, COUNT(*) as fail_count
            FROM policy_results pr
            JOIN cis_policies p ON pr.policy_id = p.policy_id
            WHERE pr.status = 'fail' AND pr.host_id IN ({h_query})
            GROUP BY p.policy_id, p.policy_name, p.cis_control
            ORDER BY fail_count DESC
            LIMIT 5
        """, params)
        
        priorities = []
        impact_threshold = config_number('impact_high_threshold', 5)

        # Effort Configuration. config_keyword_list keeps the two shapes this already
        # handled (JSON array, comma-separated string) and stops a stored number or a
        # list of numbers from raising inside the comparison below.
        low_keywords = config_keyword_list('effort_low_keywords', ['Ensure', 'Set'])
        high_keywords = config_keyword_list('effort_high_keywords', ['Manual', 'Review'])

        for row in cur.fetchall():
            fail_count = row['fail_count']
            policy_name = row['policy_name'].lower()
            
            # Calculate Impact
            impact = "High" if fail_count > impact_threshold else "Medium"
            
            # Calculate Effort
            effort = "Medium"
            if any(k in policy_name for k in low_keywords):
                effort = "Low"
            elif any(k in policy_name for k in high_keywords):
                effort = "High"

            priorities.append({
                "policy": row['policy_name'],
                "control": row['cis_control'] or "N/A",
                "affected": fail_count,
                "impact": impact,
                "effort": effort
            })

        # 9. Team trend, from compliance_snapshots.
        # Deliberately last: wrapped so a snapshot problem can't turn /api/strategy into a 500.
        # Cached with the rest under fleetcis:v1:strategy:...; a sync-written snapshot always
        # moves the sync generation, so the key space refreshes. Stale for up to CACHE_TTL_SECONDS
        # only on a manual backfill or the midnight window edge — older trend, not wrong.
        team_trend = {
            "source": "compliance_snapshots",
            "days": HISTORY_TREND_DAYS,
            "flat_threshold_pp": TEAM_TREND_FLAT_THRESHOLD_PP,
            "min_snapshot_dates": TEAM_TREND_MIN_DATES,
            "scope_comparable": team_trend_scope_is_comparable(),
            "teams_with_trend": 0,
            "reason": None,
        }
        if not team_trend['scope_comparable']:
            team_trend['reason'] = 'scope_not_comparable'
        else:
            trends = {}
            try:
                trends = team_score_trends(cur)
            except Exception as e:
                logger.warning(
                    f"Team snapshot trend lookup failed, reporting unknown: {e}"
                )
                team_trend['reason'] = 'lookup_failed'
            # The board can carry a duplicated name too, not just fleet_teams: hosts
            # with no team are bucketed as 'Unassigned', so a real Fleet team named
            # "Unassigned" produces two rows with one name. Matching a snapshot to
            # either of them would be a guess, so both stay unknown - the same rule
            # team_score_trends() applies on its side.
            board_name_counts = {}
            for team in team_stats:
                board_name_counts[team['name']] = board_name_counts.get(team['name'], 0) + 1
            for team in team_stats:
                if board_name_counts.get(team['name'], 0) > 1:
                    continue
                fields = trends.get(team['name'])
                if not fields:
                    continue
                team.update(fields)
                team_trend['teams_with_trend'] += 1
            if team_trend['reason'] is None and team_trend['teams_with_trend'] == 0:
                # Distinguish "no team has two snapshot dates yet" - the state of this
                # deployment today, with exactly one snapshot date on record - from
                # "there is history, but none of it belongs to a listed team".
                team_trend['reason'] = (
                    'no_matching_team' if trends else 'insufficient_snapshot_history'
                )

        return jsonify({
            "posture_score": posture_score,
            "maturity_level": maturity,
            "compliance_coverage": coverage,
            "risk_exposure": risk_exposure,
            "security_debt": security_debt,
            "remediation_velocity": velocity,
            "velocity_available": velocity is not None,
            # Signed net checks remediated per day. Negative means the fleet lost
            # ground over the window.
            "velocity_unit": "checks/day",
            "velocity_window": velocity_window,
            "roadmap": roadmap,
            "team_leaderboard": team_stats,
            # Additive, and additive only: every key the frontend reads inside
            # team_leaderboard keeps its name and meaning. This says where the trend
            # came from and, when it is "unknown" for everyone, why.
            "team_trend": team_trend,
            "priorities": priorities
        })

@app.route('/api/architecture', methods=['GET'])
@cached_response('architecture')
def get_architecture():
    h_query, params = get_filtered_hosts_subquery()
    sq, sq_params = build_policy_host_agg(h_query, params)

    with db.get_db_cursor() as cur:
        # Aggregate by policy × host platform; map via cis_safeguard_ids
        cur.execute(f"""
            SELECT
                h.platform AS host_platform,
                p.policy_id,
                p.policy_name,
                p.cis_safeguard_ids,
                p.cis_category,
                SUM(CASE WHEN fail_count = 0 THEN 1 ELSE 0 END) as pass_count,
                COUNT(*) as total_count
            FROM ({sq}) sq
            JOIN cis_policies p ON sq.policy_id = p.policy_id
            JOIN fleet_hosts h ON sq.host_id = h.host_id
            GROUP BY h.platform, p.policy_id, p.policy_name, p.cis_safeguard_ids, p.cis_category
        """, sq_params)
        rows = cur.fetchall()

        mitre_stats = {}
        d3fend_tech_stats = {}
        tactic_stats = {}
        # policy_id -> set of ATT&CK technique ids, harvested from the same
        # mapping pass as the matrix below so the history trend rolls up through
        # one mapping path rather than resolving policies a second time.
        policy_techniques = {}

        total_checks = 0
        total_passed = 0

        for row in rows:
            count = row['total_count']
            pass_count = row['pass_count']
            total_checks += count
            total_passed += pass_count

            resolved = policy_catalog.resolve_policy_safeguards(
                row.get('policy_name') or '',
                db_sids=row.get('cis_safeguard_ids') or [],
                platform=row.get('host_platform') or '',
            )
            primary = resolved.get('primary') or ''
            mapping = policy_catalog.mapping_for_policy(
                policy_name=row.get('policy_name') or '',
                cis_category=resolved.get('cis_category') or row.get('cis_category') or '',
                cis_subcategory=resolved.get('cis_subcategory') or '',
                safeguard_id=primary,
            )

            d3_tech = mapping.get('d3fend_technique')
            if d3_tech and d3_tech != 'Unmapped':
                if d3_tech not in d3fend_tech_stats:
                    d3fend_tech_stats[d3_tech] = {'pass': 0, 'total': 0}
                d3fend_tech_stats[d3_tech]['total'] += count
                d3fend_tech_stats[d3_tech]['pass'] += pass_count

            attack_ids = list(mapping.get('attack_ids') or [])
            if not attack_ids:
                primary = (mapping.get('attack_id') or '').strip()
                if primary:
                    attack_ids = [primary]
            for aid in attack_ids:
                if aid and aid in MITRE_DATA:
                    policy_techniques.setdefault(row['policy_id'], set()).add(aid)

            # Count each technique once per policy check volume (primary weight for multi-map)
            seen_tactics = set()
            for attack_id in attack_ids:
                if not attack_id or attack_id not in MITRE_DATA:
                    continue
                meta = MITRE_DATA[attack_id]
                tactic = meta['tactic']
                if attack_id not in mitre_stats:
                    mitre_stats[attack_id] = {
                        'pass': 0, 'total': 0,
                        'name': meta['name'], 'tactic': tactic
                    }
                mitre_stats[attack_id]['total'] += count
                mitre_stats[attack_id]['pass'] += pass_count
                # Tactic rollup once per policy (avoid multi-counting same check)
                if tactic not in seen_tactics:
                    seen_tactics.add(tactic)
                    if tactic not in tactic_stats:
                        tactic_stats[tactic] = {'pass': 0, 'total': 0}
                    tactic_stats[tactic]['total'] += count
                    tactic_stats[tactic]['pass'] += pass_count

        if total_checks == 0:
            # Nothing in scope right now, so there is nothing for history to be a
            # trend of. Skip the history queries entirely.
            return jsonify({
                "overall_compliance": 0,
                "compliance_by_tactic": {},
                "top_5_weakest": [],
                "top_3_strongest": [],
                "biggest_gains": [],
                "biggest_losses": [],
                "history_available": False,
                "history_window": {
                    "days": HISTORY_TREND_DAYS,
                    "first_observed": None,
                    "last_observed": None,
                    "multi_day": False,
                    "source": "policy_results_history",
                },
                "mitre_matrix": []
            })

        overall_score = (total_passed / total_checks * 100)

        comp_by_tactic = {}
        for tactic, stats in tactic_stats.items():
            if stats['total'] > 0:
                comp_by_tactic[tactic] = round(stats['pass'] / stats['total'] * 100)

        tech_list = []
        for name, stats in d3fend_tech_stats.items():
            if stats['total'] > 0:
                rate = round(stats['pass'] / stats['total'] * 100)
                tech_list.append({'name': name, 'rate': rate})

        tech_list.sort(key=lambda x: x['rate'])
        top_weakest = tech_list[:5]
        top_strongest = sorted(tech_list, key=lambda x: x['rate'], reverse=True)[:3]

        # Real gains/losses per ATT&CK technique: pass rate at each technique's
        # last observation in the window versus its first. With fewer than 2
        # distinct days of history (the state of a freshly seeded database, where
        # every row shares one checked_at date) the comparison has no two ends, so
        # both lists stay empty and history_available stays False rather than
        # reporting a 0.0% change for everything.
        history_window, _hist_first, _hist_last = history_window_bounds(cur, h_query, params)
        history_available = history_window['multi_day']
        gains = []
        losses = []
        if history_available:
            gains, losses = technique_trends(
                history_pair_deltas(cur, h_query, params), policy_techniques
            )

        # 5. MITRE Matrix (Grouped by Tactic)
        # Expected: [{tactic: "Initial Access", rate: 50, techniques: [{id: T1078, name:..., rate:..}]}]
        mitre_matrix = []
        # Pre-define tactic order if desired, or just iterate
        # Let's group techniques by tactic first
        tactics_map = {} # Tactic -> [Techniques]
        
        for aid, stats in mitre_stats.items():
            if stats['total'] > 0:
                rate = round(stats['pass'] / stats['total'] * 100)
                tech_obj = {
                    'id': aid,
                    'name': stats['name'],
                    'rate': rate
                }
                tactic = stats['tactic']
                if tactic not in tactics_map: tactics_map[tactic] = []
                tactics_map[tactic].append(tech_obj)
        
        # Build final list
        for tactic, techs in tactics_map.items():
            # Tactic-level rate
            t_stats = tactic_stats.get(tactic, {'pass':0, 'total':1})
            t_rate = round(t_stats['pass'] / t_stats['total'] * 100)
            
            mitre_matrix.append({
                'tactic': tactic,
                'rate': t_rate,
                'techniques': sorted(techs, key=lambda x: x['name'])
            })
            
        # Sort matrix by Tactic name or standard Kill Chain order if possible (Alphabetical for now)
        mitre_matrix.sort(key=lambda x: x['tactic'])

        return jsonify({
            "overall_compliance": round(overall_score, 1),
            "compliance_by_tactic": comp_by_tactic,
            "top_5_weakest": top_weakest,
            "top_3_strongest": top_strongest,
            "biggest_gains": gains,
            "biggest_losses": losses,
            "history_available": history_available,
            "history_window": history_window,
            "mitre_matrix": mitre_matrix
        })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    debug_mode = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.run(debug=debug_mode, port=port, host='0.0.0.0')
