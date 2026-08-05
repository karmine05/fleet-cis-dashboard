#!/usr/bin/env python3
"""
CIS Compliance Dashboard Backend API (PostgreSQL Version)
Serves real-time data from Fleet via PostgreSQL.
"""

from flask import Flask, jsonify, request, g
from flask_cors import CORS
from functools import wraps
import hmac
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
import policy_catalog

# Load environment variables
# Load environment variables
basedir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
load_dotenv(os.path.join(basedir, '.env'))


app = Flask(__name__)
# Enable CORS for restricted domains
allowed_origins = os.environ.get('ALLOWED_ORIGINS', os.environ.get('FRONTEND_URL', 'http://localhost:8081')).split(',')
CORS(app, resources={r"/api/*": {"origins": allowed_origins}})

# Initialize DB Pool
db.get_db_pool()

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
@require_write_auth
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
        FROM (
            SELECT
                pr.policy_id,
                pr.host_id,
                SUM(CASE WHEN pr.status = 'fail' THEN 1 ELSE 0 END) as fail_count
            FROM policy_results pr
            WHERE pr.host_id IN ({h_query})
            GROUP BY pr.policy_id, pr.host_id
        ) sq
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

        cur.execute(query, params)
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

        # 5. Velocity — no historical store; do not invent a fake rate
        velocity = None

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
                "trend": "unknown",  # no snapshot history yet
                "delta": None
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
            "velocity_available": False,
            "roadmap": roadmap,
            "team_leaderboard": team_stats,
            "priorities": priorities
        })

@app.route('/api/architecture', methods=['GET'])
def get_architecture():
    h_query, params = get_filtered_hosts_subquery()

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
            FROM (
                SELECT
                    pr.policy_id,
                    pr.host_id,
                    SUM(CASE WHEN pr.status = 'fail' THEN 1 ELSE 0 END) as fail_count
                FROM policy_results pr
                WHERE pr.host_id IN ({h_query})
                GROUP BY pr.policy_id, pr.host_id
            ) sq
            JOIN cis_policies p ON sq.policy_id = p.policy_id
            JOIN fleet_hosts h ON sq.host_id = h.host_id
            GROUP BY h.platform, p.policy_id, p.policy_name, p.cis_safeguard_ids, p.cis_category
        """, params)
        rows = cur.fetchall()

        mitre_stats = {}
        d3fend_tech_stats = {}
        tactic_stats = {}

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
