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

import urllib3

# Load environment variables
basedir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
load_dotenv(os.path.join(basedir, '.env'))

# Configuration
FLEET_URL = os.environ.get("FLEET_URL", "https://fleet.example.com")
FLEET_TOKEN = os.environ.get("FLEET_API_TOKEN", "")
# Default to 10 workers for API calls
MAX_WORKERS = int(os.environ.get("SYNC_MAX_WORKERS", "10"))
HOSTS_PER_PAGE = int(os.environ.get("SYNC_HOSTS_PER_PAGE", "100"))

# SSL Verification Strategy
ssl_verify_env = os.environ.get("FLEET_SSL_VERIFY", "false").lower()
FLEET_SSL_VERIFY = ssl_verify_env in ('true', '1', 'yes')

if not FLEET_SSL_VERIFY:
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# CIS control regex
import re
CIS_REGEX = re.compile(r'(?:CIS|Benchmark)\s*[-:]?\s*(\d+(?:\.\d+)+)', re.IGNORECASE)
CIS_FALLBACK_REGEX = re.compile(r'^(\d+(?:\.\d+)+)\s')

def get_fleet_headers():
    return {
        "Authorization": f"Bearer {FLEET_TOKEN}",
        "Content-Type": "application/json"
    }

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
            print(f"  ⚠ Error fetching hosts page {page}: {e}")
            break

def fetch_teams():
    if not FLEET_TOKEN: return []
    try:
        url = f"{FLEET_URL}/api/v1/fleet/teams"
        response = requests.get(url, headers=get_fleet_headers(), timeout=10, verify=FLEET_SSL_VERIFY)
        return response.json().get("teams", [])
    except Exception: return []

def fetch_labels():
    if not FLEET_TOKEN: return []
    try:
        url = f"{FLEET_URL}/api/v1/fleet/labels"
        response = requests.get(url, headers=get_fleet_headers(), timeout=10, verify=FLEET_SSL_VERIFY)
        return response.json().get("labels", [])
    except Exception: return []

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
        gl_pols = response.json().get("policies", [])
        print(f"Global policies fetched: {len(gl_pols)}")
        for p in gl_pols:
            p['team_id'] = None
            all_policies[p['id']] = p
    except Exception as e: 
        print(f"Error fetching global policies: {e}")
    
    for team in teams:
        try:
            url = f"{FLEET_URL}/api/latest/fleet/teams/{team['id']}/policies"
            response = requests.get(url, headers=get_fleet_headers(), timeout=10, verify=FLEET_SSL_VERIFY)
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
            print(f"Error fetching team {team['id']} policies: {e}")
        
    print(f"Total unique policies returned: {len(all_policies)}")
    return list(all_policies.values())

def fetch_policy_hosts(policy_id, status):
    if not FLEET_TOKEN: return []
    try:
        response_type = "passing" if status == "pass" else "failing"
        url = f"{FLEET_URL}/api/v1/fleet/hosts?policy_id={policy_id}&policy_response={response_type}"
        response = requests.get(url, headers=get_fleet_headers(), timeout=30, verify=FLEET_SSL_VERIFY)
        hosts = response.json().get("hosts", [])
        return [(policy_id, h['id'], status, datetime.now()) for h in hosts]
    except Exception: return []

# --- Sync Logic ---

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

    # Start Sync Metadata
    with db.get_db_cursor(commit=True) as cur:
        cur.execute("INSERT INTO sync_metadata (started_at, status) VALUES (NOW(), 'running') RETURNING sync_id")
        sync_id = cur.fetchone()['sync_id']

    try:
        # 1. Sync Teams & Labels (Small datasets)
        teams = fetch_teams()
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
        
        # 2.1 Clean up stale hosts (deletions in Fleet)
        stale_ids = set(db_state.keys()) - host_ids_processed
        if stale_ids:
            print(f"  🗑 Removing {len(stale_ids)} stale hosts that are no longer in Fleet...")
            with db.get_db_cursor(commit=True) as cur:
                # Due to FK constraints, we should delete from policy_results first 
                # unless we've successfully updated the schema with ON DELETE CASCADE.
                # To be safe, we'll do it explicitly here as well.
                cur.execute("DELETE FROM policy_results WHERE host_id = ANY(%s)", (list(stale_ids),))
                cur.execute("DELETE FROM host_labels WHERE host_id = ANY(%s)", (list(stale_ids),))
                cur.execute("DELETE FROM fleet_hosts WHERE host_id = ANY(%s)", (list(stale_ids),))
            print(f"  ✅ Removed {len(stale_ids)} stale hosts.")

        # 3. Host Labels - Query hosts by each label
        print("  🔄 Syncing host-label associations...")
        all_labels = fetch_labels()
        host_labels_buffer = []

        for label in all_labels:
            label_id = label['id']
            host_ids_for_label = fetch_hosts_by_label(label_id)
            for hid in host_ids_for_label:
                host_labels_buffer.append((hid, label_id))

        if host_labels_buffer:
            print(f"  🔄 Saving {len(host_labels_buffer)} host-label associations...")
            # Delete existing labels for processed hosts
            processed_host_ids = list(set(h for h, _ in host_labels_buffer))
            if processed_host_ids:
                with db.get_db_cursor(commit=True) as cur:
                    cur.execute("DELETE FROM host_labels WHERE host_id = ANY(%s)", (processed_host_ids,))
            # Insert new associations
            with db.get_db_cursor(commit=True) as cur:
                extras.execute_values(cur, """
                    INSERT INTO host_labels (host_id, label_id) VALUES %s
                    ON CONFLICT DO NOTHING
                """, host_labels_buffer)
            print(f"  ✅ Synced {len(host_labels_buffer)} host-label associations.")

        # 4. Policies & Results
        policies = fetch_policies(teams)
        policy_buffer = []
        for p in policies:
            # Regex logic for CIS...
            policy_name = p['name']
            match = CIS_REGEX.search(policy_name) or CIS_FALLBACK_REGEX.search(policy_name)
            cis_control = match.group(1) if match else None
            policy_buffer.append((
                p['id'], p['name'], cis_control, p.get('description'),
                p.get('resolution'), p.get('query'), 'General', 'Medium', p.get('platform', 'all')
            ))
            
        with db.get_db_cursor(commit=True) as cur:
            extras.execute_values(cur, """
                INSERT INTO cis_policies (
                    policy_id, policy_name, cis_control, description, resolution, query,
                    category, severity, platform
                ) VALUES %s
                ON CONFLICT (policy_id) DO UPDATE SET policy_name=EXCLUDED.policy_name
            """, policy_buffer)
            
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
        for p in policies:
            pid = p['id']
            api_pass = p.get('passing_host_count', 0)
            api_fail = p.get('failing_host_count', 0)
            stored = db_counts.get(pid, (0, 0))
            
            if api_pass != stored[0] or api_fail != stored[1]:
                # Queue fetch
                if api_pass > 0: tasks.append((pid, 'pass'))
                if api_fail > 0: tasks.append((pid, 'fail'))

        # Fetch results
        results_buffer = []
        count = 0
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = [executor.submit(fetch_policy_hosts, pid, status) for pid, status in tasks]
            for future in as_completed(futures):
                items = future.result()
                if items:
                    results_buffer.extend(items)
                    count += len(items)
                
                if len(results_buffer) > 5000:
                    with db.get_db_cursor(commit=True) as cur:
                        # Clear old results for these policies? 
                        # Ideally we delete valid rows first, but bulk insert "ON CONFLICT" is safer for existing
                        # For now, just UPSERT current state
                        extras.execute_values(cur, """
                            INSERT INTO policy_results (policy_id, host_id, status, checked_at)
                            VALUES %s
                            ON CONFLICT (policy_id, host_id) DO UPDATE SET 
                                status=EXCLUDED.status, checked_at=EXCLUDED.checked_at
                        """, results_buffer)
                        
                        # Also Insert into History Log (Partitioned)
                        # We only check 'status' change logic if we want to reduce log volume
                        extras.execute_values(cur, """
                            INSERT INTO policy_results_history (policy_id, host_id, status, checked_at)
                            VALUES %s
                        """, results_buffer)
                        
                    results_buffer = []
                    print(f"    ... synced {count} policy results")
                    
        # Flush final
        if results_buffer:
             with db.get_db_cursor(commit=True) as cur:
                extras.execute_values(cur, """
                    INSERT INTO policy_results (policy_id, host_id, status, checked_at)
                    VALUES %s
                    ON CONFLICT (policy_id, host_id) DO UPDATE SET 
                        status=EXCLUDED.status, checked_at=EXCLUDED.checked_at
                """, results_buffer)
                extras.execute_values(cur, """
                    INSERT INTO policy_results_history (policy_id, host_id, status, checked_at)
                    VALUES %s
                """, results_buffer)

        # 6. Snapshots
        create_compliance_snapshot()

        # Update Metadata
        duration = int((time.time() - start_time) * 1000)
        with db.get_db_cursor(commit=True) as cur:
            cur.execute("""
                UPDATE sync_metadata 
                SET status='success', completed_at=NOW(), duration_ms=%s,
                    hosts_changed=%s, policies_changed=0, results_changed=%s
                WHERE sync_id=%s
            """, (duration, len(host_ids_processed), count, sync_id))
            
        print(f"✅ Sync complete in {duration/1000:.1f}s")
        
    except Exception as e:
        print(f"❌ Sync Failed: {e}")
        with db.get_db_cursor(commit=True) as cur:
             cur.execute("""
                UPDATE sync_metadata 
                SET status='failed', completed_at=NOW(), error_message=%s
                WHERE sync_id=%s
            """, (str(e), sync_id))

def create_compliance_snapshot():
    today = datetime.now().date()
    with db.get_db_cursor(commit=True) as cur:
        # Clear existing for today to allow re-runs
        cur.execute("DELETE FROM compliance_snapshots WHERE snapshot_date = %s AND team_id IS NULL", (today,))
        
        # Global

        cur.execute("""
            SELECT COUNT(*) as total,
                   SUM(CASE WHEN status='pass' THEN 1 ELSE 0 END) as passing
            FROM policy_results
        """)
        row = cur.fetchone()
        total = row['total'] or 0
        passing = row['passing'] or 0
        score = (passing / total * 100) if total > 0 else 0
        
        cur.execute("""
            INSERT INTO compliance_snapshots (snapshot_date, compliance_score, passing_hosts, critical_failures)
            VALUES (%s, %s, %s, 0)
        """, (today, score, passing))
        
if __name__ == "__main__":
    sync_data()
