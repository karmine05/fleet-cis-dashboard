"""Fleet policy identity for dashboard rows.

Fleet policy identity is policy_id. CIS Controls safeguard IDs (CIS4.8) are
shared by many policies and are family tags only. CIS benchmark sections
(81.23) are the user-facing control numbers, matching Fleet's policy list.

Every /api/safeguard-compliance row is one policy_id. UI selection, metrics,
and click-through must use policy_id — never safeguard_id alone.
"""

from __future__ import annotations


def _synthetic_sid(policy_name: object) -> str:
    return "policy_" + str(policy_name).lower().replace(" ", "_")


def _sid_list(raw) -> list:
    if not raw:
        return []
    if isinstance(raw, str):
        return [part.strip() for part in raw.split(",") if part.strip()]
    return [str(sid) for sid in raw if sid]


def build_safeguard_compliance_list(rows):
    """Collapse grouped policy_results into one audit entry per policy_id.

    ``rows`` is the result of grouping policy_results by policy + status:
    each mapping has policy_id, policy_name, cis_control, description,
    resolution, query, cis_safeguard_ids, status, count.
    """
    policy_stats = {}
    for row in rows:
        pid = row["policy_id"]
        if pid not in policy_stats:
            policy_stats[pid] = {
                "policy_id": pid,
                "policy_name": row["policy_name"],
                "control": row["cis_control"],
                "description": row["description"],
                "resolution": row["resolution"],
                "query": row["query"],
                "cis_safeguard_ids": _sid_list(row.get("cis_safeguard_ids")),
                "pass": 0,
                "fail": 0,
            }
        if row["status"] == "pass":
            policy_stats[pid]["pass"] += row["count"]
        elif row["status"] == "fail":
            policy_stats[pid]["fail"] += row["count"]

    result_list = []
    for policy in policy_stats.values():
        sids = list(policy["cis_safeguard_ids"])
        if not sids:
            sids = [_synthetic_sid(policy["policy_name"])]
        total = policy["pass"] + policy["fail"]
        pass_rate = (policy["pass"] / total * 100) if total > 0 else 0
        result_list.append(
            {
                "policy_id": policy["policy_id"],
                "name": policy["policy_name"],
                "control": policy["control"],
                "safeguard_id": sids[0],
                "cis_safeguard_ids": sids,
                "description": policy["description"],
                "resolution": policy["resolution"],
                "query": policy["query"],
                "pass": policy["pass"],
                "fail": policy["fail"],
                "pass_rate": pass_rate,
            }
        )
    return result_list


def audit_policy_key(policy):
    """Stable UI selection key. policy_id wins; name is cache-compat only."""
    if not policy:
        return ""
    pid = policy.get("policy_id")
    if pid is not None and pid != "":
        return str(pid)
    return f"{policy.get('safeguard_id') or ''}::{policy.get('name') or ''}"


def unique_by_policy_id(policies):
    """Keep the first row for each policy identity."""
    seen = set()
    out = []
    for policy in policies or []:
        key = audit_policy_key(policy)
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(policy)
    return out


def find_audit_policy(policies, key):
    """Return the policy matching an audit list key, or None."""
    want = str(key)
    for policy in unique_by_policy_id(policies):
        if audit_policy_key(policy) == want:
            return policy
    return None


def policy_search_fields(policy):
    """Lowercased identity fields a search box may match."""
    fields = [
        policy.get("safeguard_id"),
        policy.get("control"),
        policy.get("name"),
        policy.get("policy_id"),
    ]
    fields.extend(policy.get("cis_safeguard_ids") or [])
    return [str(field).lower() for field in fields if field is not None and field != ""]


def policy_matches_search(policy, query):
    q = (query or "").strip().lower()
    if not q:
        return True
    return any(q in field for field in policy_search_fields(policy))
