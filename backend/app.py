#!/usr/bin/env python3
"""
CIS Compliance Dashboard Backend API (PostgreSQL Version)
Serves real-time data from Fleet via PostgreSQL.
"""

from flask import Flask, jsonify, request, g
from flask_cors import CORS
import os
import json
import logging
from datetime import datetime
from dotenv import load_dotenv

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("backend.log")
    ]
)
logger = logging.getLogger(__name__)

def error_response(message, status_code=500, error_details=None):
    """Standardized error response and logging."""
    log_msg = f"{message}"
    if error_details:
        log_msg += f" - Details: {error_details}"
    logger.error(log_msg)
    
    response = {"error": message}
    # Only include details in debug mode for security
    if error_details and os.environ.get('FLASK_1_DEBUG', '0') == '1':
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
    'framework_iso_multiplier'
}

# Import new DB module
import db

# Load environment variables
# Load environment variables
basedir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
load_dotenv(os.path.join(basedir, '.env'))


# Note: random is used inline for simulated historical data.
import random 

app = Flask(__name__)
# Enable CORS for restricted domains
allowed_origins = os.environ.get('ALLOWED_ORIGINS', os.environ.get('FRONTEND_URL', 'http://localhost:8081')).split(',')
CORS(app, resources={r"/api/*": {"origins": allowed_origins}})

# Initialize DB Pool
db.get_db_pool()

# D3FEND Mapping


# D3FEND Mapping

# Load MITRE Data from JSON
MITRE_DATA = {}
def load_mitre_data():
    global MITRE_DATA
    mitre_file = os.path.join(os.path.dirname(__file__), 'mitre_data.json')
    if os.path.exists(mitre_file):
        try:
            import json
            with open(mitre_file, 'r') as f:
                MITRE_DATA = json.load(f)
        except Exception as e:
            logger.warning(f"Could not load MITRE Data: {e}")

load_mitre_data()

def _load_csv_into_dict(filepath, techniques_set):
    """Load a D3FEND CSV file into a dict keyed by cis_id."""
    result = {}
    import csv
    with open(filepath, 'r') as f:
        reader = csv.DictReader(f, skipinitialspace=True)
        if reader.fieldnames:
            reader.fieldnames = [name.strip() for name in reader.fieldnames]
        for row in reader:
            row = {k.strip(): v.strip() for k, v in row.items()}
            cis_id = row.get('cis_id', '').strip()
            if cis_id:
                result[cis_id] = {
                    'd3fend_id':        row.get('d3fend_id', '').strip(),
                    'd3fend_technique':  row.get('d3fend_technique', '').strip(),
                    'd3fend_tactic':     row.get('d3fend_tactic', '').strip(),
                    'attack_id':         row.get('attack_id', '').strip(),
                }
                if result[cis_id]['d3fend_id']:
                    techniques_set.add(result[cis_id]['d3fend_id'])
    return result

def load_d3fend_mapping():
    """
    Load per-platform D3FEND mapping files.

    Discovers all cis_to_d3fend_<platform>.csv files in the backend directory
    and loads each into its own independent dict. Each file is the authoritative
    source for its platform — there is no shared default that bleeds across
    platforms. Maintainers edit only the relevant platform file.

    Returns:
        mapping_by_platform: {'darwin': {...}, 'linux': {...}, 'windows': {...}, ...}
        d3fend_techniques:    sorted list of all unique D3FEND IDs across all files
    """
    techniques = set()
    base_dir = os.path.dirname(__file__)
    mapping_by_platform = {}

    import glob
    platform_files = glob.glob(os.path.join(base_dir, 'cis_to_d3fend_*.csv'))
    if not platform_files:
        logger.warning("No per-platform D3FEND mapping files found (cis_to_d3fend_<platform>.csv)")

    for filepath in platform_files:
        platform_name = os.path.basename(filepath).replace('cis_to_d3fend_', '').replace('.csv', '')
        try:
            mapping_by_platform[platform_name] = _load_csv_into_dict(filepath, techniques)
            logger.info(f"Loaded D3FEND mapping: {len(mapping_by_platform[platform_name])} entries for platform='{platform_name}'")
        except Exception as e:
            logger.warning(f"Could not load D3FEND mapping for platform '{platform_name}': {e}")

    return mapping_by_platform, sorted(list(techniques))

D3FEND_MAPPING, D3FEND_TECHNIQUES = load_d3fend_mapping()

# Host/policy platform values → mapping CSV keys (cis_to_d3fend_<key>.csv)
PLATFORM_ALIASES = {
    'linux': 'ubuntu',
    'ubuntu': 'ubuntu',
    'darwin': 'darwin',
    'macos': 'darwin',
    'mac': 'darwin',
    'windows': 'windows',
    'win32': 'windows',
    'win': 'windows',
}

# Non-canonical mapping labels → D3FEND tactic vocabulary
TACTIC_NORMALIZE = {
    'access control': 'Harden',
    'recover': 'Restore',
    'restore': 'Restore',
    'model': 'Model',
    'harden': 'Harden',
    'detect': 'Detect',
    'isolate': 'Isolate',
    'deceive': 'Deceive',
    'evict': 'Evict',
}

# ATT&CK techniques with more than this many CIS cells are flagged as coarse
COARSE_ATTACK_THRESHOLD = 40


def normalize_platform(platform):
    """Map host/policy platform strings to D3FEND CSV keys."""
    if not platform:
        return ''
    key = str(platform).strip().lower()
    return PLATFORM_ALIASES.get(key, key)


def normalize_d3fend_tactic(tactic):
    """Normalize mapping CSV tactics to D3FEND vocabulary."""
    if not tactic:
        return 'Unmapped'
    raw = str(tactic).strip()
    return TACTIC_NORMALIZE.get(raw.lower(), raw)


def mapping_confidence(entry):
    """high | medium | unmapped based on D3FEND + ATT&CK fields present."""
    if not entry:
        return 'unmapped'
    d3_id = (entry.get('d3fend_id') or '').strip()
    d3_tech = (entry.get('d3fend_technique') or '').strip()
    attack = (entry.get('attack_id') or '').strip()
    has_d3 = bool(d3_id and d3_id not in ('N/A',) and d3_tech and d3_tech != 'Unmapped')
    has_atk = bool(attack and attack not in ('Unmapped', 'N/A', ''))
    if has_d3 and has_atk:
        return 'high'
    if has_d3 or has_atk:
        return 'medium'
    return 'unmapped'


def get_d3fend_entry(cis_id, platform=''):
    """
    Look up a CIS ID in the platform-specific D3FEND mapping.

    When platform is known, only that platform's file is consulted.
    When unknown, search all platform dicts (sorted) and return first match.
    """
    plat = normalize_platform(platform)
    if plat and plat in D3FEND_MAPPING:
        return D3FEND_MAPPING[plat].get(cis_id, {}) or {}

    # No platform: search all platforms deterministically
    for p in sorted(D3FEND_MAPPING.keys()):
        entry = D3FEND_MAPPING[p].get(cis_id)
        if entry:
            return entry
    return {}


def enrich_mapping(cis_id, platform=''):
    """Return mapping fields with normalized tactic + confidence."""
    entry = get_d3fend_entry(cis_id, platform)
    raw_tactic = (entry.get('d3fend_tactic') or '').strip() or 'Unmapped'
    return {
        'd3fend_id': entry.get('d3fend_id') or 'N/A',
        'd3fend_technique': entry.get('d3fend_technique') or 'Unmapped',
        'd3fend_tactic': normalize_d3fend_tactic(raw_tactic),
        'd3fend_tactic_raw': raw_tactic,
        'attack_id': entry.get('attack_id') or 'Unmapped',
        'mapping_confidence': mapping_confidence(entry),
    }

# --- Configuration Management ---
def get_config(key, default):
    """Fetch configuration value from database with fallback to default."""
    try:
        with db.get_db_cursor() as cur:
            cur.execute("SELECT value FROM config_settings WHERE key = %s", (key,))
            row = cur.fetchone()
            if row:
                val = row['value']
                try:
                    return json.loads(val)
                except:
                    try:
                        return float(val) if '.' in val else int(val)
                    except:
                        return val
            return default
    except Exception as e:
        logger.error(f"Config error for {key}: {e}")
        return default

# --- Helper Query Builder ---
def build_filter_query(base_query, params, filters_map):
    """
    Appends WHERE clauses based on filters.
    filters_map: dict of {url_param: sql_column}
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
    """
    label_filter = request.args.get('label')
    filters = {'team': 'team_name', 'platform': 'platform', 'osVersion': 'platform_version'}
    
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
                    "message": "No sync has been performed yet"
                })

            # Handle TZ-aware datetimes from Postgres
            completed = row['completed_at']
            started = row['started_at']
            
            return jsonify({
                "last_sync": completed.isoformat() if completed else started.isoformat(),
                "status": row['status'],
                "duration_ms": row['duration_ms'],
                "sync_interval_minutes": int(os.environ.get("SYNC_INTERVAL_MINUTES", "5")),
                "changes": {
                    "hosts": row['hosts_changed'],
                    "policies": row['policies_changed'],
                    "results": row['results_changed']
                },
                "error": row['error_message']
            })
    except Exception as e:
        logger.error(f"Sync status fetch failed: {str(e)}")
        return jsonify({
            "last_sync": None,
            "status": "error",
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
                except:
                    try:
                        parsed = float(val) if '.' in val else int(val)
                    except:
                        parsed = val
                config[key] = {
                    "value": parsed,
                    "description": row['description']
                }
            return jsonify(config)
    except Exception as e:
        return error_response("Failed to fetch configuration", 500, str(e))

@app.route('/api/config', methods=['PUT'])
def update_config():
    try:
        updates = request.json
        if not updates:
            return error_response("No configuration provided", 400)
        
        # Validation for keys
        invalid_keys = [k for k in updates if k not in VALID_CONFIG_KEYS]
        if invalid_keys:
            return error_response(f"Invalid configuration keys: {', '.join(invalid_keys)}", 400)

        # Basic type validation for numeric fields
        numeric_keys = [
            'risk_exposure_multiplier', 
            'security_debt_hours_per_issue', 
            'impact_high_threshold', 
            'impact_medium_threshold',
            'framework_cis_multiplier',
            'framework_nist_multiplier',
            'framework_iso_multiplier'
        ]
        for key, value in updates.items():
            if key in numeric_keys:
                try:
                    float(value)
                except (ValueError, TypeError):
                    return error_response(f"Value for {key} must be numeric", 400)
        
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
    # Pagination
    try:
        page = int(request.args.get('page', 0))
        limit = int(request.args.get('limit', 100)) # Default 100
        offset = page * limit
    except:
        page, limit, offset = 0, 100, 0

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
    
    # Additional filters
    filters = {'team': 'team_name', 'platform': 'platform', 'osVersion': 'platform_version'}
    for param, col in filters.items():
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
            "limit": limit,
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
def get_safeguard_compliance():
    h_query, params = get_filtered_hosts_subquery()
    
    query = f"""
        SELECT p.policy_id, p.policy_name, p.cis_control, p.description, p.resolution, p.query, pr.status, COUNT(*) as count
        FROM policy_results pr
        JOIN cis_policies p ON pr.policy_id = p.policy_id
        WHERE pr.host_id IN ({h_query})
        GROUP BY p.policy_id, p.policy_name, p.cis_control, p.description, p.resolution, p.query, pr.status
    """
    
    with db.get_db_cursor() as cur:
        cur.execute(query, params)
        rows = cur.fetchall()
        
        stats = {}
        for row in rows:
            pid = row['policy_id']
            if pid not in stats:
                stats[pid] = {
                    "safeguard_id": str(pid),
                    "name": row['policy_name'],
                    "control": row['cis_control'],
                    "description": row['description'],
                    "resolution": row['resolution'],
                    "query": row['query'],
                    "pass": 0,
                    "fail": 0
                }
            if row['status'] == 'pass':
                stats[pid]['pass'] += row['count']
            elif row['status'] == 'fail':
                stats[pid]['fail'] += row['count']
                
        result_list = []
        for s in stats.values():
            total = s['pass'] + s['fail']
            s['pass_rate'] = (s['pass'] / total * 100) if total > 0 else 0
            result_list.append(s)
            
        return jsonify({"safeguards": result_list})

@app.route('/api/heatmap-data', methods=['GET'])
def get_heatmap_data():
    """
    Heat map grain: (host.platform, cis_control) — never collapse CIS IDs across OS.
    risk_score = fail_hosts / fleet_size * 100 (fleet exposure, not in-control pass rate alone).
    """
    h_query, params = get_filtered_hosts_subquery()
    filter_platform = request.args.get('platform', '')

    query = f"""
        SELECT
            platform,
            cis_control,
            COUNT(*) as total_count,
            SUM(CASE WHEN fail_count = 0 THEN 1 ELSE 0 END) as pass_count
        FROM (
            SELECT
                h.platform,
                p.cis_control,
                pr.host_id,
                SUM(CASE WHEN pr.status = 'fail' THEN 1 ELSE 0 END) as fail_count
            FROM policy_results pr
            JOIN cis_policies p ON pr.policy_id = p.policy_id
            JOIN fleet_hosts h ON pr.host_id = h.host_id
            WHERE pr.host_id IN ({h_query})
              AND p.cis_control IS NOT NULL
              AND h.platform IS NOT NULL
            GROUP BY h.platform, p.cis_control, pr.host_id
        ) sq
        GROUP BY platform, cis_control
    """

    with db.get_db_cursor() as cur:
        # Fleet size in current filter (denominator for exposure)
        cur.execute(f"SELECT COUNT(*) as n FROM ({h_query}) hosts", params)
        fleet_size = cur.fetchone()['n'] or 0

        cur.execute(query, params)
        rows = cur.fetchall()

        heatmap_data = []
        attack_counts = {}

        for row in rows:
            host_plat = row['platform'] or 'unknown'
            cis_id = row['cis_control'] or 'Unknown'
            total = int(row['total_count'] or 0)
            passed = int(row['pass_count'] or 0)
            fail_hosts = max(0, total - passed)
            pass_rate = (passed / total * 100) if total else 0.0
            # Exposure: share of filtered fleet failing this control
            risk_score = (fail_hosts / fleet_size * 100) if fleet_size else 0.0

            mapping = enrich_mapping(cis_id, host_plat)
            attack_id = mapping['attack_id']
            if attack_id and attack_id not in ('Unmapped', 'N/A'):
                attack_counts[attack_id] = attack_counts.get(attack_id, 0) + 1

            heatmap_data.append({
                "cis_id": cis_id,
                "platform": host_plat,
                "key": f"{host_plat}:{cis_id}",
                "pass": passed,
                "total": total,
                "fail": fail_hosts,
                "pass_rate": round(pass_rate, 1),
                "risk_score": round(risk_score, 1),
                "fleet_size": fleet_size,
                "d3fend_id": mapping['d3fend_id'],
                "d3fend_technique": mapping['d3fend_technique'],
                "d3fend_tactic": mapping['d3fend_tactic'],
                "d3fend_tactic_raw": mapping['d3fend_tactic_raw'],
                "attack_id": attack_id,
                "mapping_confidence": mapping['mapping_confidence'],
            })

        heatmap_data.sort(key=lambda x: (x['platform'], x['cis_id']))

        coarse_techniques = sorted(
            aid for aid, n in attack_counts.items() if n >= COARSE_ATTACK_THRESHOLD
        )
        # Annotate coarse mapping on cells
        for item in heatmap_data:
            item['mapping_coarse'] = item['attack_id'] in coarse_techniques

        platforms_present = sorted({i['platform'] for i in heatmap_data})

        return jsonify({
            "heatmap": heatmap_data,
            "total_controls": len(heatmap_data),
            "fleet_size": fleet_size,
            "platforms": platforms_present,
            "multi_platform": len(platforms_present) > 1,
            "coarse_techniques": coarse_techniques,
            "filter_platform": filter_platform or None,
        })

@app.route('/api/strategy', methods=['GET'])
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
        risk_multiplier = get_config('risk_exposure_multiplier', 2)
        risk_exposure = min(100, fail_count * risk_multiplier)

        # 4. Security Debt
        debt_per_issue = get_config('security_debt_hours_per_issue', 0.5)
        security_debt_hours = fail_count * debt_per_issue
        if security_debt_hours < 1: security_debt = "< 1h"
        elif security_debt_hours < 8: security_debt = f"{int(security_debt_hours)}h"
        elif security_debt_hours < 40: security_debt = f"{int(security_debt_hours / 8)}d"
        else: security_debt = f"{int(security_debt_hours / 40)}w"

        # 5. Velocity
        velocity = round(posture_score * 0.12, 1)
        
        # Maturity
        if posture_score > 90: maturity = 5
        elif posture_score > 75: maturity = 4
        elif posture_score > 50: maturity = 3
        elif posture_score > 25: maturity = 2
        else: maturity = 1

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
                "trend": "stable", # Placeholder for trend logic
                "delta": 0
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
        impact_threshold = get_config('impact_high_threshold', 5)
        
        # Effort Configuration
        low_kw = get_config('effort_low_keywords', ['Ensure', 'Set'])
        high_kw = get_config('effort_high_keywords', ['Manual', 'Review'])
        
        # Ensure they are lists (in case of misconfiguration)
        if isinstance(low_kw, str): low_kw = [k.strip() for k in low_kw.split(',')]
        if isinstance(high_kw, str): high_kw = [k.strip() for k in high_kw.split(',')]
            
        low_keywords = [k.lower() for k in low_kw if k]
        high_keywords = [k.lower() for k in high_kw if k]

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

        return jsonify({
            "posture_score": posture_score,
            "maturity_level": maturity,
            "compliance_coverage": coverage,
            "risk_exposure": risk_exposure,
            "security_debt": security_debt,
            "remediation_velocity": velocity,
            "roadmap": roadmap,
            "team_leaderboard": team_stats,
            "priorities": priorities
        })

@app.route('/api/architecture', methods=['GET'])
def get_architecture():
    h_query, params = get_filtered_hosts_subquery()

    with db.get_db_cursor() as cur:
        # Host-level compliance per (platform, cis_control) — no cross-OS collapse
        cur.execute(f"""
            SELECT
                platform,
                cis_control,
                SUM(CASE WHEN fail_count = 0 THEN 1 ELSE 0 END) as pass_count,
                COUNT(*) as total_count
            FROM (
                SELECT
                    h.platform,
                    p.cis_control,
                    pr.host_id,
                    SUM(CASE WHEN pr.status = 'fail' THEN 1 ELSE 0 END) as fail_count
                FROM policy_results pr
                JOIN cis_policies p ON pr.policy_id = p.policy_id
                JOIN fleet_hosts h ON pr.host_id = h.host_id
                WHERE pr.host_id IN ({h_query})
                  AND p.cis_control IS NOT NULL
                  AND h.platform IS NOT NULL
                GROUP BY h.platform, p.cis_control, pr.host_id
            ) sq
            GROUP BY platform, cis_control
        """, params)
        rows = cur.fetchall()

        mitre_stats = {}
        d3fend_tech_stats = {}
        tactic_stats = {}

        total_checks = 0
        total_passed = 0

        for row in rows:
            cis_id = row['cis_control']
            host_plat = row['platform']
            if not cis_id:
                continue

            count = row['total_count']
            pass_count = row['pass_count']
            total_checks += count
            total_passed += pass_count

            mapping = enrich_mapping(cis_id, host_plat)

            d3_tech = mapping.get('d3fend_technique')
            if d3_tech and d3_tech != 'Unmapped':
                if d3_tech not in d3fend_tech_stats:
                    d3fend_tech_stats[d3_tech] = {'pass': 0, 'total': 0}
                d3fend_tech_stats[d3_tech]['total'] += count
                d3fend_tech_stats[d3_tech]['pass'] += pass_count

            attack_id = mapping.get('attack_id')
            if attack_id and attack_id in MITRE_DATA:
                meta = MITRE_DATA[attack_id]
                tactic = meta['tactic']
                if attack_id not in mitre_stats:
                    mitre_stats[attack_id] = {
                        'pass': 0, 'total': 0,
                        'name': meta['name'], 'tactic': tactic
                    }
                mitre_stats[attack_id]['total'] += count
                mitre_stats[attack_id]['pass'] += pass_count
                if tactic not in tactic_stats:
                    tactic_stats[tactic] = {'pass': 0, 'total': 0}
                tactic_stats[tactic]['total'] += count
                tactic_stats[tactic]['pass'] += pass_count

        if total_checks == 0:
            return jsonify({
                "overall_compliance": 0,
                "compliance_by_tactic": {},
                "top_5_weakest": [],
                "top_3_strongest": [],
                "biggest_gains": [],
                "biggest_losses": [],
                "history_available": False,
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

        # No historical store yet — do not invent gains/losses
        gains = []
        losses = []

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
            "history_available": False,
            "mitre_matrix": mitre_matrix
        })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    debug_mode = os.environ.get('FLASK_1_DEBUG', '0') == '1'
    app.run(debug=debug_mode, port=port, host='0.0.0.0')
