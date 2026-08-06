import os
import time
import requests
import json
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from dotenv import load_dotenv
import psycopg2
from psycopg2 import extras

# Import DB
import db
import policy_catalog

import urllib3

# Load environment variables
basedir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
load_dotenv(os.path.join(basedir, '.env'))

# Configuration
FLEET_URL = os.environ.get("FLEET_URL", "https://fleet.example.com")
FLEET_TOKEN = os.environ.get("FLEET_API_TOKEN", "")


def _env_int(name, default, minimum=None):
    """Read an integer tunable from the environment, leniently.

    A typo in a tunable must never raise at import time: sync_daemon imports this
    module before it writes its first heartbeat, so an exception here crash-loops
    the sync container and the symptom is a stale heartbeat with no sync_metadata
    row that explains why. A bad value falls back to the documented default and
    says so on stdout instead.

    Same contract as db._env_pool_bound(); this module prints rather than logging
    because the sync container's diagnostics are its stdout.
    """
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw.strip())
    except ValueError:
        print(f"⚠ {name}={raw!r} is not an integer — using default {default}")
        return default
    if minimum is not None and value < minimum:
        print(f"⚠ {name}={value} is below the minimum of {minimum} — using default {default}")
        return default
    return value


# Default to 10 workers for API calls
MAX_WORKERS = _env_int("SYNC_MAX_WORKERS", 10, minimum=1)
HOSTS_PER_PAGE = _env_int("SYNC_HOSTS_PER_PAGE", 100, minimum=1)

# Page size for the per-policy host lists. Larger than HOSTS_PER_PAGE because a
# policy can cover the whole fleet and every extra page is an extra round trip;
# a short page terminates the loop, so small policies still cost one request.
POLICY_HOSTS_PER_PAGE = _env_int("SYNC_POLICY_HOSTS_PER_PAGE", 500, minimum=1)
# Hard stop so a misbehaving API that always returns a full page cannot spin
# forever. Hitting it is treated as a failed (incomplete) fetch.
MAX_POLICY_HOST_PAGES = 200

# Retention / partition housekeeping (see run_retention()).
# policy_results_history keeps this many whole months; older partitions are
# DROPped, which is far cheaper than a row-wise DELETE. 0 (or any negative
# value) disables retention, so no minimum is enforced on the parse.
HISTORY_RETENTION_MONTHS = _env_int("HISTORY_RETENTION_MONTHS", 12)
# Rows that landed in the DEFAULT history partition can never be reclaimed by
# dropping a partition (see prune_history_default_partition()), so they are swept
# row-wise, at most this many per sync. Bounded on purpose: an unbounded DELETE
# over years of stranded rows would hold locks on a table the dashboard reads.
HISTORY_DEFAULT_SWEEP_LIMIT = _env_int("HISTORY_DEFAULT_SWEEP_LIMIT", 50000, minimum=1)
# sync_metadata rows older than this are deleted, except that the newest
# SYNC_METADATA_KEEP_ROWS rows are always kept so /api/sync-status still has
# something to report on a long-idle instance. 0 disables retention.
SYNC_METADATA_RETENTION_DAYS = _env_int("SYNC_METADATA_RETENTION_DAYS", 90)
SYNC_METADATA_KEEP_ROWS = 20
# Current month plus this many future months of history partitions are created
# on every sync, so a sync that runs over a month boundary never has to wait
# for DDL that nobody scheduled.
HISTORY_PARTITION_MONTHS_AHEAD = 2

# Rotating full-refresh sweep (see section 5 of sync_data()).
# Fleet's cached passing_host_count/failing_host_count are NOT a reliable change
# signal: measured live, 39 of 789 policies had aggregates that disagreed with
# Fleet's own live host lists. Counts are also structurally blind to
# count-preserving churn — host A pass->fail while host B fail->pass leaves both
# totals equal, so a policy holding wrong rows would never be re-enumerated.
# Every sync therefore force-refreshes the slice of policies satisfying
# policy_id %% divisor == sync_id %% divisor: a rotating ~1/divisor of the
# catalog per sync rather than an every-Nth-sync spike, and every policy is fully
# re-enumerated within `divisor` syncs (24 syncs = 6h at the 15-minute cadence).
# 0 disables the sweep entirely; 1 force-refreshes every policy every sync.
SYNC_FULL_REFRESH_DIVISOR = _env_int("SYNC_FULL_REFRESH_DIVISOR", 24, minimum=0)

# SQLSTATEs that mean "another session held the lock longer than we were willing
# to wait" (55P03 lock_not_available from SET LOCAL lock_timeout, 57014
# query_canceled from a statement_timeout). Partition DDL takes ACCESS EXCLUSIVE
# on policy_results_history, which /api/architecture and /api/strategy now read
# on the request path, so hitting one of these is a skip, not a failure.
PG_LOCK_TIMEOUT_SQLSTATES = ('55P03', '57014')
# Long enough to win an uncontended race, short enough that a slow reader cannot
# stall the sync behind DDL.
DDL_LOCK_TIMEOUT = '5s'

# SSL Verification Strategy — default ON (secure). Set FLEET_SSL_VERIFY=false
# only for lab/self-signed Fleet endpoints.
ssl_verify_env = os.environ.get("FLEET_SSL_VERIFY", "true").lower()
FLEET_SSL_VERIFY = ssl_verify_env not in ('false', '0', 'no', 'off')

if not FLEET_SSL_VERIFY:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    print("⚠ FLEET_SSL_VERIFY is disabled — TLS certificate checks skipped")


# CIS control regex
import re
CIS_REGEX = re.compile(r'(?:CIS|Benchmark)\s*[-:]?\s*(\d+(?:\.\d+)+)', re.IGNORECASE)
CIS_FALLBACK_REGEX = re.compile(r'^(\d+(?:\.\d+)+)\s')

# Monthly history partitions are named policy_results_history_y<YYYY>m<MM>.
# Anything that does not match this exactly (notably the DEFAULT partition
# policy_results_history_def) is never a retention-drop candidate.
HISTORY_PARTITION_RE = re.compile(r'^policy_results_history_y(\d{4})m(\d{2})$')

def get_fleet_headers():
    return {
        "Authorization": f"Bearer {FLEET_TOKEN}",
        "Content-Type": "application/json"
    }


# Fetch failures are collected here instead of being swallowed silently, so a
# sync that talks to an unreachable/unauthenticated Fleet is reported as failed
# rather than as a "successful" sync that happened to write zero rows.
FETCH_ERRORS = []
MAX_RECORDED_FETCH_ERRORS = 20


def record_fetch_error(context, exc):
    """Log a fetch failure and keep a bounded sample for the sync record."""
    message = f"{context}: {type(exc).__name__}: {exc}"
    print(f"  ⚠ {message}")
    if len(FETCH_ERRORS) < MAX_RECORDED_FETCH_ERRORS:
        FETCH_ERRORS.append(message)

def init_db():
    """Ensure schema exists."""
    schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
    with open(schema_path, 'r') as f:
        schema_sql = f.read()
    
    with db.get_db_cursor(commit=True) as cur:
        cur.execute(schema_sql)
    print("✅ Database schema ensured.")

# --- API Generators ---

def fetch_hosts_generator():
    """Yields batches of hosts from Fleet API."""
    if not FLEET_TOKEN: return
    page = 0
    while True:
        try:
            url = f"{FLEET_URL}/api/v1/fleet/hosts?per_page={HOSTS_PER_PAGE}&page={page}&populate_labels=true"
            response = requests.get(url, headers=get_fleet_headers(), timeout=30, verify=FLEET_SSL_VERIFY)
            response.raise_for_status()
            hosts = response.json().get("hosts", [])
            if not hosts:
                break
            yield hosts
            page += 1
        except Exception as e:
            record_fetch_error(f"hosts page {page}", e)
            break

def fetch_teams():
    if not FLEET_TOKEN: return []
    try:
        url = f"{FLEET_URL}/api/v1/fleet/teams"
        response = requests.get(url, headers=get_fleet_headers(), timeout=10, verify=FLEET_SSL_VERIFY)
        response.raise_for_status()
        return response.json().get("teams", [])
    except Exception as e:
        record_fetch_error("teams", e)
        return []

def fetch_labels():
    if not FLEET_TOKEN: return []
    try:
        url = f"{FLEET_URL}/api/v1/fleet/labels"
        response = requests.get(url, headers=get_fleet_headers(), timeout=10, verify=FLEET_SSL_VERIFY)
        response.raise_for_status()
        return response.json().get("labels", [])
    except Exception as e:
        record_fetch_error("labels", e)
        return []

def fetch_hosts_by_label(label_id):
    """Fetch all host IDs that belong to a specific label."""
    if not FLEET_TOKEN: return []
    host_ids = []
    page = 0
    while True:
        try:
            url = f"{FLEET_URL}/api/v1/fleet/hosts?per_page={HOSTS_PER_PAGE}&page={page}&label_id={label_id}"
            response = requests.get(url, headers=get_fleet_headers(), timeout=30, verify=FLEET_SSL_VERIFY)
            hosts = response.json().get("hosts", [])
            if not hosts:
                break
            host_ids.extend([h['id'] for h in hosts])
            page += 1
        except Exception:
            break
    return host_ids

def fetch_host_details(host_id):
    try:
        url = f"{FLEET_URL}/api/v1/fleet/hosts/{host_id}"
        response = requests.get(url, headers=get_fleet_headers(), timeout=10, verify=FLEET_SSL_VERIFY)
        return response.json().get("host", {})
    except Exception: return None

def fetch_policies(teams):
    if not FLEET_TOKEN: return []
    all_policies = {}
    
    try:
        # Global
        url = f"{FLEET_URL}/api/latest/fleet/policies"
        response = requests.get(url, headers=get_fleet_headers(), timeout=10, verify=FLEET_SSL_VERIFY)
        response.raise_for_status()
        gl_pols = response.json().get("policies", [])
        print(f"Global policies fetched: {len(gl_pols)}")
        for p in gl_pols:
            p['team_id'] = None
            all_policies[p['id']] = p
    except Exception as e:
        record_fetch_error("global policies", e)

    for team in teams:
        try:
            url = f"{FLEET_URL}/api/latest/fleet/teams/{team['id']}/policies"
            response = requests.get(url, headers=get_fleet_headers(), timeout=10, verify=FLEET_SSL_VERIFY)
            response.raise_for_status()
            data = response.json()
            team_policies = data.get("policies", []) + data.get("inherited_policies", [])
            print(f"Team {team['id']} policies fetched: {len(team_policies)} (pol: {len(data.get('policies',[]))}, inh: {len(data.get('inherited_policies',[]))})")
            for p in team_policies:
                if p['id'] not in all_policies:
                    p['team_id'] = team['id']
                    all_policies[p['id']] = p
                else:
                    pass
        except Exception as e:
            record_fetch_error(f"team {team['id']} policies", e)


    print(f"Total unique policies returned: {len(all_policies)}")
    return list(all_policies.values())

def fetch_policy_hosts(policy_id, status):
    """Fetch every host Fleet reports for (policy_id, status).

    Returns a (ok, rows) tuple. ok is True only when the complete host list was
    enumerated. The old signature returned [] both for "Fleet reports no hosts"
    and "the request blew up", and that ambiguity is exactly what makes pruning
    stale policy_results impossible: an empty list from a broken request would
    read as "delete everything for this policy".

    The list is paginated explicitly for the same reason — a truncated page is
    not a full host set, and pruning against a truncated set deletes live rows.
    """
    if not FLEET_TOKEN:
        return False, []

    response_type = "passing" if status == "pass" else "failing"
    rows = []
    page = 0
    while page < MAX_POLICY_HOST_PAGES:
        try:
            url = (
                f"{FLEET_URL}/api/v1/fleet/hosts?policy_id={policy_id}"
                f"&policy_response={response_type}"
                f"&per_page={POLICY_HOSTS_PER_PAGE}&page={page}"
            )
            response = requests.get(url, headers=get_fleet_headers(), timeout=30, verify=FLEET_SSL_VERIFY)
            response.raise_for_status()
            hosts = response.json().get("hosts", [])

            # Everything that touches the payload stays INSIDE this try. Fleet's
            # Go handler can marshal a nil slice as JSON null, and an element
            # without 'id' is equally possible; outside the try those raise
            # TypeError/KeyError in the worker thread, the exception escapes
            # through the unguarded future.result() in sync_data() and the ENTIRE
            # sync dies. A malformed page is one failed page, nothing more.
            if not isinstance(hosts, list):
                raise TypeError(
                    "Fleet returned %s for \"hosts\", expected a list"
                    % type(hosts).__name__
                )

            checked_at = datetime.now()
            rows.extend([(policy_id, h['id'], status, checked_at) for h in hosts])

            # A short page is the last page, so a policy with few hosts still
            # costs exactly one request like it did before pagination was added.
            if len(hosts) < POLICY_HOSTS_PER_PAGE:
                return True, rows
        except Exception as e:
            # ok=False with the rows gathered so far: the caller must never prune
            # a policy against a host set we know is incomplete.
            record_fetch_error(f"policy {policy_id} {status} hosts page {page}", e)
            return False, rows

        page += 1

    # Never claim success on a host set we know is truncated.
    record_fetch_error(
        f"policy {policy_id} {status} hosts",
        RuntimeError(f"host list exceeded {MAX_POLICY_HOST_PAGES} pages")
    )
    return False, rows

# --- Schema Maintenance ---

# Identifiers that are safe to interpolate into DDL without quoting surprises.
# Anything else is skipped rather than escaped: an exotic schema name is not a
# scenario worth silently guessing at inside a DROP TABLE.
SAFE_IDENT_RE = re.compile(r'^[A-Za-z_][A-Za-z0-9_$]*$')


def _is_lock_timeout(exc):
    """True when exc is Postgres refusing to keep waiting for a lock."""
    return getattr(exc, 'pgcode', None) in PG_LOCK_TIMEOUT_SQLSTATES


def _quote_ident(name):
    """Double-quote a validated SQL identifier. Raises on anything unexpected."""
    if not name or not SAFE_IDENT_RE.match(name):
        raise ValueError(f"unsafe SQL identifier: {name!r}")
    return '"%s"' % name


def _set_ddl_lock_timeout(cur):
    """Bound how long a DDL transaction waits for ACCESS EXCLUSIVE.

    SET takes no bound parameters, so the interval is a module constant checked
    for shape here rather than a query parameter. SET LOCAL means it reverts with
    the transaction and never leaks into the pooled connection.
    """
    if not re.match(r'^\d+(ms|s|min)?$', DDL_LOCK_TIMEOUT):
        raise ValueError(f"invalid DDL_LOCK_TIMEOUT: {DDL_LOCK_TIMEOUT!r}")
    cur.execute("SET LOCAL lock_timeout = '" + DDL_LOCK_TIMEOUT + "'")


def _history_partition_spec(year, month):
    """Return (partition_name, range_start, range_end) for one month.

    The name is interpolated into DDL, so it is built from integers that are
    validated here and nowhere else — no caller-supplied string ever reaches it.
    """
    year = int(year)
    month = int(month)
    # Upper bound is 9998, not 9999: month 12 of 9999 would need an exclusive
    # upper bound of 10000-01-01, which is not a valid date literal.
    if year < 2000 or year > 9998:
        raise ValueError(f"history partition year out of range: {year}")
    if month < 1 or month > 12:
        raise ValueError(f"history partition month out of range: {month}")

    name = "policy_results_history_y%04dm%02d" % (year, month)
    start = "%04d-%02d-01" % (year, month)
    end_year = year + 1 if month == 12 else year
    end_month = 1 if month == 12 else month + 1
    end = "%04d-%02d-01" % (end_year, end_month)
    return name, start, end


def _ensure_history_partition(year, month):
    """Create one monthly partition if it is missing. Returns True if created."""
    name, start, end = _history_partition_spec(year, month)

    with db.get_db_cursor(commit=True) as cur:
        # CREATE TABLE ... PARTITION OF takes ACCESS EXCLUSIVE on the parent, and
        # policy_results_history is read on the request path (/api/architecture,
        # /api/strategy). Bound the wait so a slow reader cannot stall the sync;
        # the caller treats the timeout as a skip.
        _set_ddl_lock_timeout(cur)

        cur.execute("SELECT to_regclass(%s) IS NOT NULL AS present", (name,))
        if cur.fetchone()['present']:
            return False

        # Rows for this month can already be sitting in the DEFAULT partition —
        # that is where every history row landed while no monthly partition
        # existed. Postgres refuses to create an overlapping partition while the
        # default still holds matching rows, so move them across inside this
        # same transaction: either the whole move plus the DDL commits, or
        # nothing does and the rows stay where they were.
        cur.execute("SELECT to_regclass('policy_results_history_def') IS NOT NULL AS present")
        has_default = cur.fetchone()['present']

        moved = 0
        if has_default:
            # ON COMMIT DROP plus the fact that a rollback also discards the
            # table means a leftover from an earlier attempt is impossible, so
            # no defensive pre-drop is needed here.
            cur.execute("""
                CREATE TEMP TABLE history_partition_move ON COMMIT DROP AS
                SELECT * FROM policy_results_history_def
                WHERE checked_at >= %s AND checked_at < %s
            """, (start, end))
            cur.execute("SELECT COUNT(*) AS n FROM history_partition_move")
            moved = cur.fetchone()['n'] or 0
            if moved:
                cur.execute("""
                    DELETE FROM policy_results_history_def
                    WHERE checked_at >= %s AND checked_at < %s
                """, (start, end))

        # name comes from _history_partition_spec (validated ints only); the
        # range bounds are still passed as parameters.
        cur.execute(
            "CREATE TABLE " + name + " PARTITION OF policy_results_history "
            "FOR VALUES FROM (%s) TO (%s)",
            (start, end)
        )

        if moved:
            # Re-insert through the parent so tuple routing files the rows into
            # the partition we just created. history_id is carried over so the
            # rows keep their identity and the sequence is untouched.
            cur.execute("""
                INSERT INTO policy_results_history (history_id, policy_id, host_id, status, checked_at)
                SELECT history_id, policy_id, host_id, status, checked_at
                FROM history_partition_move
            """)

    suffix = f" (relocated {moved} row(s) from the default partition)" if moved else ""
    print(f"  🧱 Created history partition {name}{suffix}")
    return True


def ensure_history_partitions(months_ahead=None):
    """Create the current month's history partition plus the next few.

    Idempotent, so it is safe (and intended) to call once per sync before any
    INSERT into policy_results_history.
    """
    if months_ahead is None:
        months_ahead = HISTORY_PARTITION_MONTHS_AHEAD

    now = datetime.now()
    created = 0
    for offset in range(int(months_ahead) + 1):
        absolute_month = (now.month - 1) + offset
        year = now.year + absolute_month // 12
        month = absolute_month % 12 + 1
        try:
            if _ensure_history_partition(year, month):
                created += 1
        except Exception as e:
            if not _is_lock_timeout(e):
                raise
            # Caught per month, not per call: a reader blocking this month's DDL
            # must not stop the following months from being created. The missing
            # partition only means rows land in the DEFAULT partition until the
            # next sync retries.
            print(
                f"  ⚠ Skipped history partition for {year:04d}-{month:02d}: "
                f"policy_results_history was locked longer than {DDL_LOCK_TIMEOUT}."
            )
    if created:
        print(f"  ✅ Ensured history partitions ({created} created).")
    return created


def prune_history_partitions():
    """Drop whole history partitions older than HISTORY_RETENTION_MONTHS."""
    if HISTORY_RETENTION_MONTHS <= 0:
        return 0

    now = datetime.now()
    # Absolute month index of the oldest month we keep.
    cutoff = (now.year * 12 + (now.month - 1)) - HISTORY_RETENTION_MONTHS
    dropped = []

    try:
        with db.get_db_cursor(commit=True) as cur:
            # DROP TABLE takes ACCESS EXCLUSIVE on the parent, which is read on
            # the request path. Bound the wait; the handler below turns a timeout
            # into a skip.
            _set_ddl_lock_timeout(cur)

            # Resolve the parent through to_regclass so the search_path picks the
            # same table the sync writes to, instead of matching on a bare name that
            # another schema could also use.
            #
            # nspname comes along and is filtered to current_schema(): pg_inherits
            # is cluster-wide, so without the filter a same-named child in another
            # schema could be enumerated here and then an unqualified DROP would
            # resolve through search_path to a different table than the one that
            # was checked.
            cur.execute("""
                SELECT n.nspname AS schema_name, c.relname AS partition_name
                FROM pg_inherits i
                JOIN pg_class c ON c.oid = i.inhrelid
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE i.inhparent = to_regclass('policy_results_history')
                  AND n.nspname = current_schema()
            """)
            partitions = [
                (row.get('schema_name'), row['partition_name'])
                for row in cur.fetchall()
            ]

            for schema_name, raw_name in partitions:
                match = HISTORY_PARTITION_RE.match(raw_name)
                if not match:
                    # Not a monthly partition — this is what keeps the DEFAULT
                    # partition (policy_results_history_def) out of the drop list.
                    continue
                year = int(match.group(1))
                month = int(match.group(2))
                if year < 2000 or year > 9999 or month < 1 or month > 12:
                    continue
                if year * 12 + (month - 1) >= cutoff:
                    continue
                # Rebuild the identifier from the validated ints rather than reusing
                # the string read out of the catalog.
                name, _, _ = _history_partition_spec(year, month)
                try:
                    qualified = _quote_ident(schema_name) + "." + _quote_ident(name)
                except ValueError as e:
                    # A schema we cannot safely name is a schema we do not touch.
                    print(f"  ⚠ Skipping history partition {name}: {e}")
                    continue
                cur.execute("DROP TABLE IF EXISTS " + qualified)
                dropped.append(name)
    except Exception as e:
        if not _is_lock_timeout(e):
            raise
        # The transaction rolled back, so nothing was actually dropped — reporting
        # 0 keeps the log honest.
        print(
            f"  ⚠ History partition drop skipped: policy_results_history was "
            f"locked longer than {DDL_LOCK_TIMEOUT}."
        )
        return 0

    if dropped:
        print(
            f"  🗑 Dropped {len(dropped)} history partition(s) older than "
            f"{HISTORY_RETENTION_MONTHS} month(s): {', '.join(dropped)}"
        )
    return len(dropped)


def prune_history_default_partition():
    """Sweep aged rows out of the DEFAULT history partition, one bounded batch.

    prune_history_partitions() refuses to drop anything that is not named
    policy_results_history_y<YYYY>m<MM>, which is exactly what protects the
    DEFAULT partition — but it also means rows in there are unreachable by
    retention. And rows do land there: ensure_history_partitions() only creates
    the current month and the months ahead of it, so any month whose partition
    was never created (every month before partitioning existed, or a month missed
    while the container was down) keeps its rows in policy_results_history_def
    forever. A row-wise DELETE is the only way to reclaim those.

    Bounded to HISTORY_DEFAULT_SWEEP_LIMIT rows per sync: a large backlog is
    worked down over consecutive syncs instead of holding locks for minutes on a
    table the dashboard reads.
    """
    if HISTORY_RETENTION_MONTHS <= 0:
        return 0

    now = datetime.now()
    # Same boundary prune_history_partitions() uses, expressed as a date: the
    # first day of the oldest month that is still kept. Rows before it are exactly
    # the rows whose monthly partition would have been dropped.
    cutoff_index = (now.year * 12 + (now.month - 1)) - HISTORY_RETENTION_MONTHS
    cutoff_year = cutoff_index // 12
    # An absurd retention window walks the cutoff back before Fleet existed. No
    # row can be older than that, so there is nothing to sweep — and building the
    # literal anyway would hand Postgres a negative year to reject once per sync.
    if cutoff_year < 2000:
        return 0
    cutoff = "%04d-%02d-01" % (cutoff_year, cutoff_index % 12 + 1)

    removed = 0
    remaining = 0
    with db.get_db_cursor(commit=True) as cur:
        # A DELETE only takes ROW EXCLUSIVE, but this table is on the read path,
        # so it still waits behind nothing for long.
        _set_ddl_lock_timeout(cur)

        cur.execute(
            "SELECT to_regclass('policy_results_history_def') IS NOT NULL AS present"
        )
        row = cur.fetchone()
        if not row or not row['present']:
            # No DEFAULT partition on this instance: nothing can be stranded.
            return 0

        # The ctid sub-select is what bounds the statement. LIMIT cannot be
        # attached to a DELETE directly.
        cur.execute("""
            DELETE FROM policy_results_history_def
            WHERE ctid IN (
                SELECT ctid FROM policy_results_history_def
                WHERE checked_at < %s
                LIMIT %s
            )
        """, (cutoff, HISTORY_DEFAULT_SWEEP_LIMIT))
        removed = cur.rowcount or 0

        cur.execute("""
            SELECT COUNT(*) AS n FROM policy_results_history_def
            WHERE checked_at < %s
        """, (cutoff,))
        row = cur.fetchone()
        remaining = (row['n'] if row else 0) or 0

    if removed:
        print(
            f"  🗑 Swept {removed} row(s) older than {cutoff} out of the default "
            f"history partition ({remaining} aged row(s) still there; "
            f"limit {HISTORY_DEFAULT_SWEEP_LIMIT}/sync)."
        )
    return removed


def prune_sync_metadata():
    """Delete old sync_metadata rows, always keeping the newest ones."""
    if SYNC_METADATA_RETENTION_DAYS <= 0:
        return 0

    with db.get_db_cursor(commit=True) as cur:
        cur.execute("""
            DELETE FROM sync_metadata
            WHERE started_at < NOW() - make_interval(days => %s)
              AND sync_id NOT IN (
                  SELECT sync_id FROM sync_metadata
                  ORDER BY started_at DESC, sync_id DESC
                  LIMIT %s
              )
        """, (SYNC_METADATA_RETENTION_DAYS, SYNC_METADATA_KEEP_ROWS))
        removed = cur.rowcount or 0

    if removed:
        print(
            f"  🗑 Pruned {removed} sync_metadata row(s) older than "
            f"{SYNC_METADATA_RETENTION_DAYS} day(s) (kept the newest {SYNC_METADATA_KEEP_ROWS})."
        )
    return removed


def run_retention():
    """Housekeeping pass, run once per sync.

    Every failure here is swallowed on purpose: losing a whole sync run over a
    retention error would be a worse bug than the unbounded growth it fixes.
    """
    try:
        prune_history_partitions()
    except Exception as e:
        print(f"  ⚠ History retention skipped: {type(e).__name__}: {e}")
    try:
        # Second pass, and not redundant: dropping partitions can never reach rows
        # sitting in the DEFAULT partition.
        prune_history_default_partition()
    except Exception as e:
        print(f"  ⚠ Default-partition sweep skipped: {type(e).__name__}: {e}")
    try:
        prune_sync_metadata()
    except Exception as e:
        print(f"  ⚠ sync_metadata retention skipped: {type(e).__name__}: {e}")

# --- Sync Logic ---

def _dedupe_result_rows(rows):
    """Collapse duplicate (policy_id, host_id) rows, keeping the newest checked_at.

    Required before every policy_results upsert. A policy with both passing and
    failing hosts is two separate requests resolved at two different instants, so
    a host that flips between them is legitimately present in both lists. Postgres
    aborts the whole statement with SQLSTATE 21000 ("ON CONFLICT DO UPDATE command
    cannot affect row a second time") if one VALUES list carries the same
    conflict key twice — which would kill the sync over a single flapping host.

    The newest checked_at wins because it is the later observation of the two.
    Insertion order is preserved for everything else so the flush stays stable.
    """
    latest = {}
    for row in rows:
        key = (row[0], row[1])
        current = latest.get(key)
        if current is None or row[3] >= current[3]:
            latest[key] = row
    return list(latest.values())


def sync_data():
    start_time = time.time()
    print(f"\n🔄 Sync started at {datetime.now()}")
    
    # Initialize DB (create tables if missing)
    try:
        init_db()
    except Exception as e:
        print(f"❌ DB Init failed: {e}")
        return

    if not FLEET_TOKEN:
        print("⚠ FLEET_API_TOKEN not set.")
        return

    FETCH_ERRORS.clear()

    # Start Sync Metadata
    with db.get_db_cursor(commit=True) as cur:
        cur.execute("INSERT INTO sync_metadata (started_at, status) VALUES (NOW(), 'running') RETURNING sync_id")
        sync_id = cur.fetchone()['sync_id']

    try:
        # 1. Sync Teams & Labels (Small datasets)
        # The error baseline is captured BEFORE fetch_teams(), not after: teams
        # feed the per-team policy fetch, so a teams blip silently shrinks the
        # policy set to "global policies only" (zero on this Fleet) without
        # producing a single policy-fetch error. Capturing after it is what let
        # that run be recorded as status='success' with 0 policies synced.
        errors_before_teams = len(FETCH_ERRORS)
        teams = fetch_teams()
        teams_fetch_failed = len(FETCH_ERRORS) > errors_before_teams
        labels = fetch_labels()
        
        with db.get_db_cursor(commit=True) as cur:
            # Upsert Teams
            if teams:
                extras.execute_values(cur, """
                    INSERT INTO fleet_teams (team_id, team_name, description, created_at)
                    VALUES %s
                    ON CONFLICT (team_id) DO UPDATE SET team_name=EXCLUDED.team_name
                """, [(t['id'], t['name'], t.get('description'), t.get('created_at')) for t in teams])
            
            # Upsert Labels
            if labels:
                extras.execute_values(cur, """
                    INSERT INTO fleet_labels (label_id, label_name, label_type, description)
                    VALUES %s
                    ON CONFLICT (label_id) DO UPDATE SET label_name=EXCLUDED.label_name
                """, [(l['id'], l['name'], l.get('label_type'), l.get('description')) for l in labels])
        
        print(f"  ✅ Synced {len(teams)} teams and {len(labels)} labels.")

        # 2. Sync Hosts (Differential)
        # Get DB state: {host_id: updated_at}
        with db.get_db_cursor() as cur:
            cur.execute("SELECT host_id, updated_at FROM fleet_hosts")
            # Convert DB timestamp to str or object for comparison
            # Fleet API timestamps are usually ISO strings.
            # We'll rely on 'seen_time' from Fleet.
            db_state = {row['host_id']: row['updated_at'] for row in cur.fetchall()}
        
        hosts_upsert_buffer = []
        host_ids_processed = set()
        hosts_changed_ids = []
        host_labels_buffer = []  # Buffer for host-label associations

        print("  🔄 Fetching hosts...")
        errors_before_hosts = len(FETCH_ERRORS)

        for batch in fetch_hosts_generator():
            for host in batch:
                hid = host['id']
                seen_time = host.get('seen_time') # ISO String
                # Compare Logic: If local doesn't exist or seen_time changed
                # Simplification: Always update 'last_seen', but only trigger deep sync if changed significantly

                hosts_upsert_buffer.append((
                    hid, host['hostname'], host['uuid'], host['platform'],
                    host['os_version'], host['osquery_version'], host.get('team_id'),
                    host.get('team_name'), host['status'], seen_time,
                    datetime.now()
                ))

                # Extract labels from host response
                host_labels_list = host.get('labels', [])
                for label in host_labels_list:
                    host_labels_buffer.append((hid, label['id']))

                hosts_changed_ids.append(hid) # For now assume all valid for label sync (optimize later)
                host_ids_processed.add(hid)
            
            # Flush Buffer
            if len(hosts_upsert_buffer) >= 1000:
                with db.get_db_cursor(commit=True) as cur:
                    extras.execute_values(cur, """
                        INSERT INTO fleet_hosts (
                            host_id, hostname, uuid, platform, platform_version,
                            osquery_version, team_id, team_name, online_status, last_seen, updated_at
                        ) VALUES %s
                        ON CONFLICT (host_id) DO UPDATE SET
                            hostname=EXCLUDED.hostname,
                            platform=EXCLUDED.platform,
                            platform_version=EXCLUDED.platform_version,
                            team_id=EXCLUDED.team_id,
                            team_name=EXCLUDED.team_name,
                            online_status=EXCLUDED.online_status,
                            last_seen=EXCLUDED.last_seen,
                            updated_at=NOW()
                    """, hosts_upsert_buffer)
                hosts_upsert_buffer = []
                print(f"    ... flushed {len(host_ids_processed)} hosts")

        # Flush remaining
        if hosts_upsert_buffer:
            with db.get_db_cursor(commit=True) as cur:
                extras.execute_values(cur, """
                    INSERT INTO fleet_hosts (
                        host_id, hostname, uuid, platform, platform_version,
                        osquery_version, team_id, team_name, online_status, last_seen, updated_at
                    ) VALUES %s
                    ON CONFLICT (host_id) DO UPDATE SET 
                        hostname=EXCLUDED.hostname,
                        platform=EXCLUDED.platform,
                        platform_version=EXCLUDED.platform_version,
                        team_id=EXCLUDED.team_id,
                        team_name=EXCLUDED.team_name,
                        online_status=EXCLUDED.online_status,
                        last_seen=EXCLUDED.last_seen,
                        updated_at=NOW()
                """, hosts_upsert_buffer)
            print(f"    ... flushed remaining. Total {len(host_ids_processed)} hosts.")
        
        hosts_fetch_failed = len(FETCH_ERRORS) > errors_before_hosts

        # An empty host list caused by a failed request is not an empty Fleet.
        # Abort before the stale-host cleanup below, which would otherwise read
        # "no hosts returned" as "every host was deleted in Fleet" and wipe
        # fleet_hosts, host_labels and policy_results.
        if hosts_fetch_failed and not host_ids_processed:
            raise RuntimeError(
                "Host enumeration failed and returned no hosts — refusing to "
                f"sync. First error — {FETCH_ERRORS[errors_before_hosts]}"
            )

        # 2.1 Clean up stale hosts (deletions in Fleet)
        stale_ids = set(db_state.keys()) - host_ids_processed
        if stale_ids and hosts_fetch_failed:
            print(
                f"  ⚠ Skipping stale-host cleanup: host enumeration was partial "
                f"({len(stale_ids)} host(s) would have been deleted)."
            )
        elif stale_ids:
            print(f"  🗑 Removing {len(stale_ids)} stale hosts that are no longer in Fleet...")
            with db.get_db_cursor(commit=True) as cur:
                # Due to FK constraints, we should delete from policy_results first 
                # unless we've successfully updated the schema with ON DELETE CASCADE.
                # To be safe, we'll do it explicitly here as well.
                cur.execute("DELETE FROM policy_results WHERE host_id = ANY(%s)", (list(stale_ids),))
                cur.execute("DELETE FROM host_labels WHERE host_id = ANY(%s)", (list(stale_ids),))
                cur.execute("DELETE FROM fleet_hosts WHERE host_id = ANY(%s)", (list(stale_ids),))
            print(f"  ✅ Removed {len(stale_ids)} stale hosts.")

        # 3. Host Labels - Save labels collected during host fetch (populate_labels=true)
        if host_labels_buffer:
            print(f"  🔄 Saving {len(host_labels_buffer)} host-label associations...")
            processed_host_ids = list(set(h for h, _ in host_labels_buffer))
            # ONE transaction for the DELETE and the re-INSERT. With two commits
            # there is a window in which host_labels is empty for every host in
            # this sync, and a dashboard read landing in it sees zero label
            # memberships — which the response cache then memoizes for a full TTL,
            # long after the data is correct again.
            with db.get_db_cursor(commit=True) as cur:
                if processed_host_ids:
                    cur.execute("DELETE FROM host_labels WHERE host_id = ANY(%s)", (processed_host_ids,))
                extras.execute_values(cur, """
                    INSERT INTO host_labels (host_id, label_id) VALUES %s
                    ON CONFLICT DO NOTHING
                """, host_labels_buffer)
            print(f"  ✅ Synced {len(host_labels_buffer)} host-label associations.")
        else:
            print(f"  ✅ No host labels to sync.")

        # 4. Policies & Results
        errors_before_policies = len(FETCH_ERRORS)
        policies = fetch_policies(teams)
        policies_fetch_failed = len(FETCH_ERRORS) > errors_before_policies

        # Same reasoning as the host guard: no policies plus failing requests is
        # a broken sync, not a Fleet without policies. Reporting it as success is
        # what makes a bad FLEET_URL / token / TLS setting invisible.
        #
        # The teams fetch counts as part of that path. When it fails, teams == []
        # and only global policies are fetched — zero of them on a Fleet where
        # every policy lives on a team — with no policy-fetch error to show for it.
        # The cleanup guards below already keep the data intact in that case; this
        # guard exists so sync_metadata does not call the run a success.
        if not policies and (policies_fetch_failed or teams_fetch_failed):
            if policies_fetch_failed:
                reason = "Policy fetch failed and returned no policies."
                first_error = FETCH_ERRORS[errors_before_policies]
            else:
                reason = (
                    "The teams fetch failed, so only global policies were "
                    "requested and the policy set came back empty."
                )
                first_error = FETCH_ERRORS[errors_before_teams]
            raise RuntimeError(f"{reason} First error — {first_error}")
        policy_buffer = []
        matched = 0
        for p in policies:
            # Benchmark section number from name (legacy display only)
            policy_name = p['name']
            match = CIS_REGEX.search(policy_name) or CIS_FALLBACK_REGEX.search(policy_name)
            cis_control = match.group(1) if match else None

            # Authoritative tags / cis_safeguard_ids from fleet_policies catalog
            # (Fleet API currently does not return policy tags)
            enrich = policy_catalog.enrich_policy_from_catalog(
                policy_name, platform=p.get('platform') or ''
            )
            if enrich.get('catalog_matched'):
                matched += 1

            sids = enrich.get('cis_safeguard_ids') or []
            tags = enrich.get('tags') or {}
            category = enrich.get('cis_category') or 'General'
            severity = 'Critical' if enrich.get('critical') else 'Medium'

            policy_buffer.append((
                p['id'],
                p['name'],
                cis_control,
                p.get('description'),
                p.get('resolution'),
                p.get('query'),
                category,
                severity,
                p.get('platform') or enrich.get('platform') or 'all',
                sids,
                enrich.get('benchmark') or None,
                enrich.get('control_slug') or None,
                enrich.get('cis_category') or None,
                enrich.get('cis_subcategory') or None,
                enrich.get('framework') or None,
                enrich.get('level') or None,
                json.dumps(tags),
                bool(enrich.get('catalog_matched')),
            ))

        print(f"  📚 Catalog match: {matched}/{len(policies)} policies "
              f"({policy_catalog.catalog_stats().get('policy_count', 0)} in catalog)")

        with db.get_db_cursor(commit=True) as cur:
            # The WHERE on DO UPDATE is what makes policies_changed an honest
            # number: without it every policy is "touched" every sync (789 here),
            # so the metric was a constant, and every unchanged row still burned a
            # heap update plus WAL. IS DISTINCT FROM on the row constructors
            # handles NULLs, which plain <> would not. RETURNING then yields
            # exactly the inserts plus the genuine updates.
            written_policies = extras.execute_values(cur, """
                INSERT INTO cis_policies (
                    policy_id, policy_name, cis_control, description, resolution, query,
                    category, severity, platform,
                    cis_safeguard_ids, benchmark, control_slug, cis_category, cis_subcategory,
                    framework, level, tags, catalog_matched
                ) VALUES %s
                ON CONFLICT (policy_id) DO UPDATE SET
                    policy_name=EXCLUDED.policy_name,
                    cis_control=EXCLUDED.cis_control,
                    description=EXCLUDED.description,
                    resolution=EXCLUDED.resolution,
                    query=EXCLUDED.query,
                    category=EXCLUDED.category,
                    severity=EXCLUDED.severity,
                    platform=EXCLUDED.platform,
                    cis_safeguard_ids=EXCLUDED.cis_safeguard_ids,
                    benchmark=EXCLUDED.benchmark,
                    control_slug=EXCLUDED.control_slug,
                    cis_category=EXCLUDED.cis_category,
                    cis_subcategory=EXCLUDED.cis_subcategory,
                    framework=EXCLUDED.framework,
                    level=EXCLUDED.level,
                    tags=EXCLUDED.tags,
                    catalog_matched=EXCLUDED.catalog_matched
                WHERE (
                    cis_policies.policy_name, cis_policies.cis_control,
                    cis_policies.description, cis_policies.resolution, cis_policies.query,
                    cis_policies.category, cis_policies.severity, cis_policies.platform,
                    cis_policies.cis_safeguard_ids, cis_policies.benchmark,
                    cis_policies.control_slug, cis_policies.cis_category,
                    cis_policies.cis_subcategory, cis_policies.framework,
                    cis_policies.level, cis_policies.tags, cis_policies.catalog_matched
                ) IS DISTINCT FROM (
                    EXCLUDED.policy_name, EXCLUDED.cis_control,
                    EXCLUDED.description, EXCLUDED.resolution, EXCLUDED.query,
                    EXCLUDED.category, EXCLUDED.severity, EXCLUDED.platform,
                    EXCLUDED.cis_safeguard_ids, EXCLUDED.benchmark,
                    EXCLUDED.control_slug, EXCLUDED.cis_category,
                    EXCLUDED.cis_subcategory, EXCLUDED.framework,
                    EXCLUDED.level, EXCLUDED.tags, EXCLUDED.catalog_matched
                )
                RETURNING policy_id
            """, policy_buffer, fetch=True)
        # fetch=True concatenates the RETURNING rows of every page execute_values
        # sends, so this is the whole batch, not just the last page.
        policies_written = len(written_policies or [])
        print(
            f"  ✍ cis_policies: {policies_written} of {len(policy_buffer)} row(s) "
            f"inserted or actually changed."
        )

        # 4.1 Clean up policies deleted in Fleet.
        # Guarded exactly like the stale-host cleanup: a partial or empty policy
        # fetch is indistinguishable from "Fleet has no policies", and acting on
        # that would wipe the whole catalog off the dashboard.
        # policies_fetch_failed was captured right after fetch_policies() above,
        # before anything else could add to FETCH_ERRORS.
        api_policy_ids = [p['id'] for p in policies]
        if policies_fetch_failed:
            print("  ⚠ Skipping stale-policy cleanup: policy fetch was partial.")
        elif not api_policy_ids:
            print("  ⚠ Skipping stale-policy cleanup: Fleet returned no policies.")
        else:
            with db.get_db_cursor(commit=True) as cur:
                cur.execute(
                    "SELECT policy_id FROM cis_policies "
                    "WHERE NOT (policy_id = ANY(%s::bigint[]))",
                    (api_policy_ids,)
                )
                stale_policy_ids = [row['policy_id'] for row in cur.fetchall()]
                if stale_policy_ids:
                    # policy_results.policy_id has a plain FK with no cascade, so
                    # the child rows have to go first. policy_results_history is
                    # deliberately left untouched — it is the audit trail and
                    # outlives the policy it describes.
                    cur.execute(
                        "DELETE FROM policy_results WHERE policy_id = ANY(%s::bigint[])",
                        (stale_policy_ids,)
                    )
                    cur.execute(
                        "DELETE FROM cis_policies WHERE policy_id = ANY(%s::bigint[])",
                        (stale_policy_ids,)
                    )
            if stale_policy_ids:
                print(f"  🗑 Removed {len(stale_policy_ids)} policies that no longer exist in Fleet.")

        # Monthly partitions must exist before the first history INSERT below,
        # otherwise every row lands in the DEFAULT partition and retention can
        # never reclaim it by dropping a partition.
        try:
            ensure_history_partitions()
        except Exception as e:
            # Non-fatal: without the partition, rows still land in the DEFAULT
            # partition, so the sync itself is unaffected.
            print(f"  ⚠ History partition maintenance failed: {type(e).__name__}: {e}")

        # 5. Policy Results (Differential by Counts)
        # We check pass/fail counts. If changed, we re-fetch the list for that policy.
        print(f"  📊 Syncing {len(policies)} policies...")
        with db.get_db_cursor() as cur:
            cur.execute("""
                SELECT policy_id, 
                       COUNT(CASE WHEN status='pass' THEN 1 END) as pass_count,
                       COUNT(CASE WHEN status='fail' THEN 1 END) as fail_count
                FROM policy_results
                GROUP BY policy_id
            """)
            db_counts = {row['policy_id']: (row['pass_count'], row['fail_count']) for row in cur.fetchall()}
            
        tasks = []
        # policy_id -> number of fetches that together make up its full host set.
        expected_tasks = {}
        # Rotating full-refresh slice — see SYNC_FULL_REFRESH_DIVISOR. sync_id is
        # monotonic, so the slice advances by one on every sync and the whole
        # catalog is covered in `divisor` syncs with a flat per-sync cost.
        refresh_slice = sync_id % SYNC_FULL_REFRESH_DIVISOR if SYNC_FULL_REFRESH_DIVISOR > 0 else None
        force_refreshed = 0
        force_refreshed_unchanged = 0
        for p in policies:
            pid = p['id']
            # Zero is only trustworthy when Fleet actually reported BOTH counts. A
            # missing field is not evidence that the policy covers no hosts, and
            # treating it as zero would prune every result row for the half Fleet
            # never told us about: with only passing_host_count present, the
            # failing count defaulted to 0 and the prune deleted every failing row
            # of that policy.
            #
            # Read each count with an is-None test rather than `or 0`, because an
            # explicit JSON null must not read as a measured zero either.
            raw_pass = p.get('passing_host_count')
            raw_fail = p.get('failing_host_count')
            counts_reported = raw_pass is not None and raw_fail is not None
            api_pass = raw_pass if raw_pass is not None else 0
            api_fail = raw_fail if raw_fail is not None else 0
            stored = db_counts.get(pid, (0, 0))

            counts_agree = (api_pass == stored[0] and api_fail == stored[1])
            force_refresh = refresh_slice is not None and pid % SYNC_FULL_REFRESH_DIVISOR == refresh_slice

            if force_refresh:
                # Enumerate BOTH halves regardless of the counts. The point of the
                # sweep is to stop trusting the aggregates at all, so the prune
                # for this policy rests on two measured host lists — which also
                # covers the case where the counts are missing entirely.
                tasks.append((pid, 'pass'))
                tasks.append((pid, 'fail'))
                expected_tasks[pid] = 2
                force_refreshed += 1
                if counts_agree:
                    force_refreshed_unchanged += 1
                continue

            if not counts_agree:
                # Queue fetch
                queued = 0
                if api_pass > 0:
                    tasks.append((pid, 'pass'))
                    queued += 1
                if api_fail > 0:
                    tasks.append((pid, 'fail'))
                    queued += 1
                if counts_reported:
                    # queued == 0 here means Fleet reports 0 passing and 0 failing
                    # hosts while the DB still holds rows — the empty fetched set
                    # is the correct answer and every row is stale.
                    expected_tasks[pid] = queued

        if force_refreshed:
            print(
                f"  🔁 Full-refresh sweep force-queued {force_refreshed} policy(ies) "
                f"(slice {refresh_slice} of {SYNC_FULL_REFRESH_DIVISOR}); "
                f"{force_refreshed_unchanged} of them looked unchanged by Fleet's counts."
            )

        # Fetch results
        results_buffer = []
        count = 0
        # policy_id -> host ids Fleet reported this sync, and how many of that
        # policy's fetches actually succeeded. Only the host ids are kept in
        # memory (not the rows), so the existing 5000-row flush batching stays.
        fetched_hosts = {}
        completed_tasks = {}
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {
                executor.submit(fetch_policy_hosts, pid, status): (pid, status)
                for pid, status in tasks
            }
            for future in as_completed(futures):
                task_pid = futures[future][0]
                ok, items = future.result()
                if ok:
                    completed_tasks[task_pid] = completed_tasks.get(task_pid, 0) + 1
                    seen = fetched_hosts.setdefault(task_pid, set())
                    for row in items:
                        seen.add(row[1])
                if items:
                    results_buffer.extend(items)
                    count += len(items)

                if len(results_buffer) > 5000:
                    # De-duplicate immediately before the upsert — see
                    # _dedupe_result_rows() for why a single flush can legitimately
                    # carry the same (policy_id, host_id) twice.
                    flush_rows = _dedupe_result_rows(results_buffer)
                    with db.get_db_cursor(commit=True) as cur:
                        # Upsert first, prune afterwards (see the prune block
                        # below the final flush). Ordering it that way means the
                        # only state a concurrent dashboard read can observe is a
                        # superset of the truth — fresh rows plus not-yet-pruned
                        # stale ones — never a half-empty policy.
                        extras.execute_values(cur, """
                            INSERT INTO policy_results (policy_id, host_id, status, checked_at)
                            VALUES %s
                            ON CONFLICT (policy_id, host_id) DO UPDATE SET
                                status=EXCLUDED.status, checked_at=EXCLUDED.checked_at
                        """, flush_rows)

                        # Also Insert into History Log (Partitioned)
                        # We only check 'status' change logic if we want to reduce log volume
                        # Same de-duplicated rows: the history log records what was
                        # observed, and the discarded duplicate is the older
                        # observation of a host that flipped mid-sync.
                        extras.execute_values(cur, """
                            INSERT INTO policy_results_history (policy_id, host_id, status, checked_at)
                            VALUES %s
                        """, flush_rows)

                    results_buffer = []
                    print(f"    ... synced {count} policy results")

        # Flush final
        if results_buffer:
             flush_rows = _dedupe_result_rows(results_buffer)
             with db.get_db_cursor(commit=True) as cur:
                extras.execute_values(cur, """
                    INSERT INTO policy_results (policy_id, host_id, status, checked_at)
                    VALUES %s
                    ON CONFLICT (policy_id, host_id) DO UPDATE SET
                        status=EXCLUDED.status, checked_at=EXCLUDED.checked_at
                """, flush_rows)
                extras.execute_values(cur, """
                    INSERT INTO policy_results_history (policy_id, host_id, status, checked_at)
                    VALUES %s
                """, flush_rows)

        # 5.1 Prune result rows Fleet no longer reports.
        # policy_results was upsert-only, so a (policy_id, host_id) pair that
        # drops out of Fleet's lists (label change, scope change, host moved
        # team) survived forever: it skewed the compliance denominator and kept
        # the differential check permanently unequal, refetching that policy
        # every single sync.
        #
        # Pruning is only safe for a policy whose *complete* picture arrived:
        # a policy with both passing and failing hosts queues two fetches, and
        # with only one of them successful we cannot account for the other half's
        # hosts, so that policy is skipped rather than half-deleted.
        prune_targets = []
        for pid, expected in expected_tasks.items():
            if completed_tasks.get(pid, 0) != expected:
                continue
            prune_targets.append((pid, sorted(fetched_hosts.get(pid, set()))))

        if prune_targets:
            removed_results = 0
            with db.get_db_cursor(commit=True) as cur:
                for pid, host_ids in prune_targets:
                    # One statement per policy, so the delete is atomic for that
                    # policy. An empty host_ids array removes every row for the
                    # policy, which is exactly right when Fleet reports 0/0.
                    cur.execute(
                        "DELETE FROM policy_results "
                        "WHERE policy_id = %s AND NOT (host_id = ANY(%s::bigint[]))",
                        (pid, host_ids)
                    )
                    removed_results += cur.rowcount or 0
            if removed_results:
                print(
                    f"  🗑 Pruned {removed_results} stale policy result row(s) "
                    f"across {len(prune_targets)} fully-fetched policies."
                )
        skipped_prunes = len(expected_tasks) - len(prune_targets)
        if skipped_prunes:
            print(f"  ⚠ Skipped prune for {skipped_prunes} policy(ies) with an incomplete host fetch.")

        # 6. Snapshots
        create_compliance_snapshot()

        # 7. Retention housekeeping (never fatal — see run_retention()).
        run_retention()

        # Update Metadata
        duration = int((time.time() - start_time) * 1000)
        # Partial failures still count as a successful sync (data landed), but
        # the errors are surfaced so /api/sync-status can show degraded runs.
        partial_error = (
            f"{len(FETCH_ERRORS)} fetch error(s); first — {FETCH_ERRORS[0]}"
            if FETCH_ERRORS else None
        )
        with db.get_db_cursor(commit=True) as cur:
            cur.execute("""
                UPDATE sync_metadata
                SET status='success', completed_at=NOW(), duration_ms=%s,
                    hosts_changed=%s, policies_changed=%s, results_changed=%s,
                    error_message=%s
                WHERE sync_id=%s
            """, (duration, len(host_ids_processed), policies_written, count,
                  partial_error, sync_id))

        if partial_error:
            print(f"⚠ Sync completed with {len(FETCH_ERRORS)} fetch error(s)")
        print(f"✅ Sync complete in {duration/1000:.1f}s")
        
    except Exception as e:
        print(f"❌ Sync Failed: {e}")
        with db.get_db_cursor(commit=True) as cur:
             cur.execute("""
                UPDATE sync_metadata 
                SET status='failed', completed_at=NOW(), error_message=%s
                WHERE sync_id=%s
            """, (str(e), sync_id))

def _snapshot_metrics(cur, team_id):
    """Compute (compliance_score, passing_hosts, critical_failures) for one scope.

    team_id None means the global scope (every host and every result row);
    otherwise the scope is the hosts belonging to that team. The same SQL serves
    both cases so the global row and the team rows can never drift apart.
    """
    # Row-level metrics. The join to fleet_hosts is what scopes results to a
    # team; the join to cis_policies is what makes severity available. Both are
    # inner joins backed by foreign keys, so they cannot drop a live row.
    cur.execute("""
        SELECT COUNT(*) AS total_rows,
               COUNT(*) FILTER (WHERE r.status = 'pass') AS passing_rows,
               COUNT(*) FILTER (WHERE r.status = 'fail' AND p.severity = 'Critical')
                   AS critical_failures
        FROM policy_results r
        JOIN fleet_hosts h ON h.host_id = r.host_id
        JOIN cis_policies p ON p.policy_id = r.policy_id
        WHERE (%s::bigint IS NULL OR h.team_id = %s::bigint)
    """, (team_id, team_id))
    row = cur.fetchone()
    total_rows = row['total_rows'] or 0
    passing_rows = row['passing_rows'] or 0
    critical_failures = row['critical_failures'] or 0
    score = (100.0 * passing_rows / total_rows) if total_rows > 0 else 0.0

    # passing_hosts counts HOSTS, not result rows: a host is passing when it has
    # no failing result at all. The old code stored the passing row count here,
    # which is why the number looked like a policy count instead of a fleet size.
    #
    # "No failing row" is not sufficient on its own: a host with NO policy results
    # whatsoever also has no failing row, and was being counted as compliant
    # (measured on the live DB: one host, never reported by any policy, inflating
    # the number). Passing now requires evidence of measurement — at least one
    # policy_result for that host — and the unmeasured hosts are counted and
    # logged so the denominator is not silently wrong.
    cur.execute("""
        SELECT COUNT(*) FILTER (WHERE has_any_result AND NOT has_failing_result)
                   AS passing_hosts,
               COUNT(*) FILTER (WHERE NOT has_any_result) AS unmeasured_hosts
        FROM (
            SELECT EXISTS (
                       SELECT 1 FROM policy_results r WHERE r.host_id = h.host_id
                   ) AS has_any_result,
                   EXISTS (
                       SELECT 1 FROM policy_results r
                       WHERE r.host_id = h.host_id AND r.status = 'fail'
                   ) AS has_failing_result
            FROM fleet_hosts h
            WHERE (%s::bigint IS NULL OR h.team_id = %s::bigint)
        ) evidence
    """, (team_id, team_id))
    hosts_row = cur.fetchone()
    passing_hosts = hosts_row['passing_hosts'] or 0
    unmeasured_hosts = hosts_row['unmeasured_hosts'] or 0
    if unmeasured_hosts:
        scope = "global" if team_id is None else f"team {team_id}"
        print(
            f"  ⚠ {scope}: {unmeasured_hosts} host(s) excluded from passing_hosts — "
            f"no policy results at all, so compliance was never measured for them."
        )

    # Distinguish "measured zero critical failures" from "no policy carries a
    # Critical severity at all". The shipped catalog marks every policy
    # non-critical, so a hard 0 would read as "nothing severe is failing" when
    # the truth is that severity is unpopulated. NULL says unknown; a real 0
    # only appears once at least one policy is actually classified Critical.
    cur.execute(
        "SELECT EXISTS (SELECT 1 FROM cis_policies WHERE severity = 'Critical') AS any_critical"
    )
    if not cur.fetchone()['any_critical']:
        critical_failures = None

    return score, passing_hosts, critical_failures


def create_compliance_snapshot():
    """Write today's compliance_snapshots rows: one global plus one per team.

    Delete-then-insert per (snapshot_date, team_id) inside a single transaction,
    so re-running a sync on the same day replaces the day's rows instead of
    duplicating them. This does not depend on a UNIQUE constraint existing.
    """
    today = datetime.now().date()
    with db.get_db_cursor(commit=True) as cur:
        cur.execute("SELECT team_id FROM fleet_teams ORDER BY team_id")
        # None first = the global scope; compliance_snapshots.team_id has an FK
        # to fleet_teams, so only teams that exist locally get a row.
        scopes = [None] + [row['team_id'] for row in cur.fetchall()]

        for team_id in scopes:
            score, passing_hosts, critical_failures = _snapshot_metrics(cur, team_id)

            # IS NOT DISTINCT FROM so the same statement matches the global row
            # (team_id IS NULL) and a team row.
            cur.execute("""
                DELETE FROM compliance_snapshots
                WHERE snapshot_date = %s AND team_id IS NOT DISTINCT FROM %s::bigint
            """, (today, team_id))
            cur.execute("""
                INSERT INTO compliance_snapshots (
                    snapshot_date, team_id, compliance_score, passing_hosts, critical_failures
                ) VALUES (%s, %s, %s, %s, %s)
            """, (today, team_id, score, passing_hosts, critical_failures))

    print(f"  📸 Wrote {len(scopes)} compliance snapshot row(s) for {today} (1 global + {len(scopes) - 1} team).")


if __name__ == "__main__":
    sync_data()
