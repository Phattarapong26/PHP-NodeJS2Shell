"""
OPScaner - SQLite Profile Management Database & Scan History
Stores scan profiles with detailed speed, custom stealth headers, network targets,
and historical scan records for enterprise auditing.
"""

import os
import json
import sqlite3
from typing import List, Dict, Optional, Any

DB_PATH = os.environ.get("OPSCANER_PROFILE_DB", "profiles.db")


def get_db_connection() -> sqlite3.Connection:
    """Creates a thread-safe connection to the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_profile_db():
    """Initializes tables and automatically performs safe migrations for new columns."""
    with get_db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT DEFAULT '',
                network_target TEXT DEFAULT '',
                concurrency INTEGER DEFAULT 100,
                timeout REAL DEFAULT 1.5,
                user_agent TEXT DEFAULT '',
                custom_headers TEXT DEFAULT '',
                port_mode TEXT DEFAULT 'standard',
                custom_ports TEXT DEFAULT '80, 443, 8080, 8000, 18080',
                scope_preset TEXT DEFAULT 'all',
                is_active INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # Migration helper: ensure new columns exist in older DB files
        cursor = conn.execute("PRAGMA table_info(scan_profiles);")
        existing_cols = {row["name"] for row in cursor.fetchall()}
        
        column_defs = {
            "concurrency": "INTEGER DEFAULT 100",
            "timeout": "REAL DEFAULT 1.5",
            "user_agent": "TEXT DEFAULT ''",
            "custom_headers": "TEXT DEFAULT ''",
            "port_mode": "TEXT DEFAULT 'standard'",
            "custom_ports": "TEXT DEFAULT '80, 443, 8080, 8000, 18080'",
            "scope_preset": "TEXT DEFAULT 'all'",
        }
        for col_name, col_type in column_defs.items():
            if col_name not in existing_cols:
                conn.execute(f"ALTER TABLE scan_profiles ADD COLUMN {col_name} {col_type};")

        # Scan History Table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id INTEGER,
                target_subnet TEXT NOT NULL,
                total_hosts INTEGER DEFAULT 0,
                php_hosts INTEGER DEFAULT 0,
                node_hosts INTEGER DEFAULT 0,
                vuln_hosts INTEGER DEFAULT 0,
                elapsed_seconds REAL DEFAULT 0.0,
                scan_summary TEXT DEFAULT '',
                scan_result_json TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (profile_id) REFERENCES scan_profiles(id) ON DELETE SET NULL
            );
        """)

        # IEEE MAC Vendor OUI Database Table (dynamic, non-hardcoded)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS mac_vendors (
                oui TEXT PRIMARY KEY,
                vendor TEXT NOT NULL,
                block_type TEXT DEFAULT ''
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_mac_vendors_oui ON mac_vendors(oui);")

        # Standard CVE / Dynamic Payload Rules Table (ภาษากลาง JSON)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS cve_rules (
                rule_id TEXT PRIMARY KEY,
                cve_id TEXT NOT NULL,
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                target_type TEXT DEFAULT 'web',
                severity TEXT DEFAULT 'Medium',
                cvss_score REAL DEFAULT 5.0,
                cwe TEXT DEFAULT '',
                thaicert_group INTEGER DEFAULT 1,
                is_enabled INTEGER DEFAULT 1,
                trigger_json TEXT NOT NULL,
                matchers_json TEXT NOT NULL,
                remediation TEXT DEFAULT '',
                references_json TEXT DEFAULT '[]',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cve_rules_target_type ON cve_rules(target_type);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cve_rules_enabled ON cve_rules(is_enabled);")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_cve_rules_thaicert ON cve_rules(thaicert_group);")
        conn.commit()

        # Seed default standard rules if table is empty
        try:
            r = conn.execute("SELECT COUNT(1) AS cnt FROM cve_rules;").fetchone()
            if r and r["cnt"] == 0:
                from core.cve_schema import DEFAULT_CVE_RULES
                for item in DEFAULT_CVE_RULES:
                    conn.execute("""
                        INSERT OR REPLACE INTO cve_rules (
                            rule_id, cve_id, name, description, target_type,
                            severity, cvss_score, cwe, thaicert_group, is_enabled,
                            trigger_json, matchers_json, remediation, references_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        item["rule_id"],
                        item["cve_id"],
                        item["name"],
                        item.get("description", ""),
                        item.get("target_type", "web"),
                        item.get("severity", "Medium"),
                        item.get("cvss_score", 5.0),
                        item.get("cwe", ""),
                        item.get("thaicert_group", 1),
                        1 if item.get("is_enabled", True) else 0,
                        json.dumps(item.get("trigger", {})),
                        json.dumps(item.get("matchers", [])),
                        item.get("remediation", ""),
                        json.dumps(item.get("references", []))
                    ))
                conn.commit()
        except Exception:
            pass


_MAC_VENDOR_CACHE: Dict[str, str] = {}


def init_mac_vendor_db(csv_path: Optional[str] = None):
    """
    Initializes and populates mac_vendors table in SQLite from IEEE mac_vendor_mapping.csv.
    Uses batch insertion for sub-second database ingestion and zero hardcoding.
    """
    with get_db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS mac_vendors (
                oui TEXT PRIMARY KEY,
                vendor TEXT NOT NULL,
                block_type TEXT DEFAULT ''
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_mac_vendors_oui ON mac_vendors(oui);")

        row = conn.execute("SELECT COUNT(1) AS cnt FROM mac_vendors;").fetchone()
        if row and row["cnt"] > 1000:
            return  # Already populated with 40,000+ vendors

        candidates = [
            csv_path,
            os.path.join(os.path.dirname(__file__), "mac_vendor_mapping.csv"),
            os.path.join(os.getcwd(), "mac_vendor_mapping.csv"),
            "mac_vendor_mapping.csv",
            "/app/mac_vendor_mapping.csv",
            "/app/core/mac_vendor_mapping.csv"
        ]
        target_csv = None
        for cand in candidates:
            if cand and os.path.exists(cand):
                target_csv = cand
                break

        if not target_csv:
            return

        import csv
        batch = []
        seen = set()
        with open(target_csv, "r", encoding="utf-8", errors="ignore") as f:
            reader = csv.reader(f)
            next(reader, None)  # Skip CSV header
            for r in reader:
                if len(r) >= 4:
                    raw_prefix = r[0].strip().lower().replace(":", "").replace("-", "")
                    vendor = r[3].strip()
                    block_type = r[4].strip() if len(r) >= 5 else ""
                    if len(raw_prefix) >= 6:
                        oui = raw_prefix[:6]
                        if oui not in seen:
                            seen.add(oui)
                            batch.append((oui, vendor, block_type))

        if batch:
            conn.executemany("""
                INSERT OR IGNORE INTO mac_vendors (oui, vendor, block_type)
                VALUES (?, ?, ?)
            """, batch)
            conn.commit()


def get_mac_vendor_from_db(oui: str) -> Optional[str]:
    """Looks up vendor name from SQLite database with in-memory fast caching."""
    global _MAC_VENDOR_CACHE
    clean_oui = (oui or "").strip().lower().replace(":", "").replace("-", "")[:6]
    if not clean_oui:
        return None

    if clean_oui in _MAC_VENDOR_CACHE:
        return _MAC_VENDOR_CACHE[clean_oui]

    try:
        with get_db_connection() as conn:
            row = conn.execute("SELECT vendor FROM mac_vendors WHERE oui = ?;", (clean_oui,)).fetchone()
            if row and row["vendor"]:
                vendor_val = str(row["vendor"]).strip()
                _MAC_VENDOR_CACHE[clean_oui] = vendor_val
                return vendor_val
    except Exception:
        pass
    return None


def get_all_profiles() -> List[Dict[str, Any]]:
    """Returns all profiles ordered by active first, then created_at DESC."""
    init_profile_db()
    with get_db_connection() as conn:
        cursor = conn.execute("""
            SELECT id, title, description, network_target, concurrency, timeout,
                   user_agent, custom_headers, port_mode, custom_ports, scope_preset,
                   is_active, created_at, updated_at
            FROM scan_profiles
            ORDER BY is_active DESC, id DESC
        """)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def get_profile_by_id(profile_id: int) -> Optional[Dict[str, Any]]:
    """Returns a single profile by ID."""
    init_profile_db()
    with get_db_connection() as conn:
        cursor = conn.execute("""
            SELECT id, title, description, network_target, concurrency, timeout,
                   user_agent, custom_headers, port_mode, custom_ports, scope_preset,
                   is_active, created_at, updated_at
            FROM scan_profiles
            WHERE id = ?
        """, (profile_id,))
        row = cursor.fetchone()
        return dict(row) if row else None


def get_active_profile() -> Optional[Dict[str, Any]]:
    """Returns the currently active profile, or None."""
    init_profile_db()
    with get_db_connection() as conn:
        cursor = conn.execute("""
            SELECT id, title, description, network_target, concurrency, timeout,
                   user_agent, custom_headers, port_mode, custom_ports, scope_preset,
                   is_active, created_at, updated_at
            FROM scan_profiles
            WHERE is_active = 1
            LIMIT 1
        """)
        row = cursor.fetchone()
        return dict(row) if row else None


def create_profile(
    title: str,
    description: str = "",
    network_target: str = "",
    concurrency: int = 100,
    timeout: float = 1.5,
    user_agent: str = "",
    custom_headers: str = "",
    port_mode: str = "standard",
    custom_ports: str = "80, 443, 8080, 8000, 18080",
    scope_preset: str = "all",
    set_active: bool = False
) -> Dict[str, Any]:
    """Creates a new scan profile with detailed enterprise configuration."""
    init_profile_db()
    with get_db_connection() as conn:
        if set_active:
            conn.execute("UPDATE scan_profiles SET is_active = 0")

        cursor = conn.execute("""
            INSERT INTO scan_profiles (
                title, description, network_target, concurrency, timeout,
                user_agent, custom_headers, port_mode, custom_ports, scope_preset,
                is_active, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """, (
            title.strip(),
            description.strip(),
            network_target.strip(),
            int(concurrency),
            float(timeout),
            user_agent.strip(),
            custom_headers.strip(),
            port_mode.strip(),
            custom_ports.strip(),
            scope_preset.strip(),
            1 if set_active else 0
        ))
        conn.commit()
        profile_id = cursor.lastrowid
        return get_profile_by_id(profile_id)


def update_profile(
    profile_id: int,
    title: str,
    description: Optional[str] = None,
    network_target: Optional[str] = None,
    concurrency: Optional[int] = None,
    timeout: Optional[float] = None,
    user_agent: Optional[str] = None,
    custom_headers: Optional[str] = None,
    port_mode: Optional[str] = None,
    custom_ports: Optional[str] = None,
    scope_preset: Optional[str] = None,
    is_active: Optional[bool] = None
) -> Optional[Dict[str, Any]]:
    """Updates an existing profile."""
    init_profile_db()
    curr = get_profile_by_id(profile_id)
    if not curr:
        return None

    new_title = title.strip() if title is not None else curr["title"]
    new_desc = description.strip() if description is not None else curr["description"]
    new_target = network_target.strip() if network_target is not None else curr["network_target"]
    new_concurrency = int(concurrency) if concurrency is not None else curr.get("concurrency", 100)
    new_timeout = float(timeout) if timeout is not None else curr.get("timeout", 1.5)
    new_ua = user_agent.strip() if user_agent is not None else curr.get("user_agent", "")
    new_headers = custom_headers.strip() if custom_headers is not None else curr.get("custom_headers", "")
    new_port_mode = port_mode.strip() if port_mode is not None else curr.get("port_mode", "standard")
    new_ports = custom_ports.strip() if custom_ports is not None else curr.get("custom_ports", "80, 443, 8080, 8000, 18080")
    new_scope = scope_preset.strip() if scope_preset is not None else curr.get("scope_preset", "all")

    with get_db_connection() as conn:
        if is_active is True:
            conn.execute("UPDATE scan_profiles SET is_active = 0")
            new_active_val = 1
        elif is_active is False:
            new_active_val = 0
        else:
            new_active_val = curr["is_active"]

        conn.execute("""
            UPDATE scan_profiles
            SET title = ?, description = ?, network_target = ?, concurrency = ?, timeout = ?,
                user_agent = ?, custom_headers = ?, port_mode = ?, custom_ports = ?, scope_preset = ?,
                is_active = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (
            new_title, new_desc, new_target, new_concurrency, new_timeout,
            new_ua, new_headers, new_port_mode, new_ports, new_scope,
            new_active_val, profile_id
        ))
        conn.commit()
        return get_profile_by_id(profile_id)


def delete_profile(profile_id: int) -> bool:
    """Deletes a profile. If active was deleted, activates the latest profile if any."""
    init_profile_db()
    with get_db_connection() as conn:
        cursor = conn.execute("DELETE FROM scan_profiles WHERE id = ?", (profile_id,))
        conn.commit()
        success = cursor.rowcount > 0

        # Check if an active profile still exists
        active = get_active_profile()
        if not active:
            all_p = get_all_profiles()
            if all_p:
                set_active_profile(all_p[0]["id"])

        return success


def set_active_profile(profile_id: int) -> Optional[Dict[str, Any]]:
    """Activates the given profile and deactivates all others."""
    init_profile_db()
    with get_db_connection() as conn:
        conn.execute("UPDATE scan_profiles SET is_active = 0")
        cursor = conn.execute("UPDATE scan_profiles SET is_active = 1, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (profile_id,))
        conn.commit()
        if cursor.rowcount == 0:
            return None
        return get_profile_by_id(profile_id)


# -------------------------------------------------------------
# Scan History Management
# -------------------------------------------------------------

def add_scan_history(
    profile_id: Optional[int],
    target_subnet: str,
    total_hosts: int = 0,
    php_hosts: int = 0,
    node_hosts: int = 0,
    vuln_hosts: int = 0,
    elapsed_seconds: float = 0.0,
    scan_summary: str = "",
    scan_result_json: str = ""
) -> Dict[str, Any]:
    """Records a completed scan event in history."""
    init_profile_db()
    with get_db_connection() as conn:
        cursor = conn.execute("""
            INSERT INTO scan_history (
                profile_id, target_subnet, total_hosts, php_hosts, node_hosts,
                vuln_hosts, elapsed_seconds, scan_summary, scan_result_json, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        """, (
            profile_id,
            target_subnet,
            int(total_hosts),
            int(php_hosts),
            int(node_hosts),
            int(vuln_hosts),
            float(elapsed_seconds),
            scan_summary,
            scan_result_json
        ))
        conn.commit()
        hid = cursor.lastrowid
        return get_scan_history_by_id(hid)


def get_scan_history(profile_id: Optional[int] = None, limit: int = 50) -> List[Dict[str, Any]]:
    """Returns recent scan history list, optionally filtered by profile_id."""
    init_profile_db()
    with get_db_connection() as conn:
        if profile_id:
            cursor = conn.execute("""
                SELECT h.id, h.profile_id, h.target_subnet, h.total_hosts, h.php_hosts,
                       h.node_hosts, h.vuln_hosts, h.elapsed_seconds, h.scan_summary, h.created_at,
                       p.title AS profile_title
                FROM scan_history h
                LEFT JOIN scan_profiles p ON h.profile_id = p.id
                WHERE h.profile_id = ?
                ORDER BY h.id DESC
                LIMIT ?
            """, (profile_id, limit))
        else:
            cursor = conn.execute("""
                SELECT h.id, h.profile_id, h.target_subnet, h.total_hosts, h.php_hosts,
                       h.node_hosts, h.vuln_hosts, h.elapsed_seconds, h.scan_summary, h.created_at,
                       p.title AS profile_title
                FROM scan_history h
                LEFT JOIN scan_profiles p ON h.profile_id = p.id
                ORDER BY h.id DESC
                LIMIT ?
            """, (limit,))
        rows = cursor.fetchall()
        return [dict(row) for row in rows]


def get_scan_history_by_id(history_id: int) -> Optional[Dict[str, Any]]:
    """Returns full scan history record including raw result JSON."""
    init_profile_db()
    with get_db_connection() as conn:
        cursor = conn.execute("""
            SELECT h.id, h.profile_id, h.target_subnet, h.total_hosts, h.php_hosts,
                   h.node_hosts, h.vuln_hosts, h.elapsed_seconds, h.scan_summary,
                   h.scan_result_json, h.created_at, p.title AS profile_title
            FROM scan_history h
            LEFT JOIN scan_profiles p ON h.profile_id = p.id
            WHERE h.id = ?
        """, (history_id,))
        row = cursor.fetchone()
        return dict(row) if row else None


def delete_scan_history(history_id: int) -> bool:
    """Deletes a single scan history record."""
    init_profile_db()
    with get_db_connection() as conn:
        cursor = conn.execute("DELETE FROM scan_history WHERE id = ?", (history_id,))
        conn.commit()
        return cursor.rowcount > 0


# ============================================================================
# Dynamic Standard CVE & Payload Rule Database API (ภาษากลาง JSON)
# ============================================================================

def _row_to_rule_dict(row: sqlite3.Row) -> Dict[str, Any]:
    """Helper to convert a SQLite row into a full rule specification dict."""
    d = dict(row)
    try:
        d["trigger"] = json.loads(d.pop("trigger_json", "{}"))
    except Exception:
        d["trigger"] = {}
    try:
        d["matchers"] = json.loads(d.pop("matchers_json", "[]"))
    except Exception:
        d["matchers"] = []
    try:
        d["references"] = json.loads(d.pop("references_json", "[]"))
    except Exception:
        d["references"] = []
    d["is_enabled"] = bool(d.get("is_enabled", 1))
    return d


def get_all_cve_rules(target_type: Optional[str] = None, enabled_only: bool = False) -> List[Dict[str, Any]]:
    """Retrieves all standard CVE rules, optionally filtered by target_type and enabled status."""
    init_profile_db()
    with get_db_connection() as conn:
        query = "SELECT * FROM cve_rules WHERE 1=1"
        params = []
        if target_type:
            query += " AND target_type = ?"
            params.append(target_type.strip().lower())
        if enabled_only:
            query += " AND is_enabled = 1"
        query += " ORDER BY cvss_score DESC, rule_id ASC"
        
        cursor = conn.execute(query, tuple(params))
        rows = cursor.fetchall()
        return [_row_to_rule_dict(r) for r in rows]


def get_cve_rule_by_id(rule_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves a single CVE rule by its ID."""
    init_profile_db()
    with get_db_connection() as conn:
        cursor = conn.execute("SELECT * FROM cve_rules WHERE rule_id = ?", (str(rule_id).strip(),))
        row = cursor.fetchone()
        return _row_to_rule_dict(row) if row else None


def save_cve_rule(rule_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validates, normalizes, and upserts a CVE rule into the database.
    Raises ValueError if the schema validation fails.
    """
    from core.cve_schema import validate_cve_rule, normalize_cve_rule
    
    is_valid, err = validate_cve_rule(rule_dict)
    if not is_valid:
        raise ValueError(f"Invalid rule specification: {err}")
    
    norm = normalize_cve_rule(rule_dict)
    init_profile_db()
    with get_db_connection() as conn:
        conn.execute("""
            INSERT INTO cve_rules (
                rule_id, cve_id, name, description, target_type,
                severity, cvss_score, cwe, thaicert_group, is_enabled,
                trigger_json, matchers_json, remediation, references_json,
                updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(rule_id) DO UPDATE SET
                cve_id = excluded.cve_id,
                name = excluded.name,
                description = excluded.description,
                target_type = excluded.target_type,
                severity = excluded.severity,
                cvss_score = excluded.cvss_score,
                cwe = excluded.cwe,
                thaicert_group = excluded.thaicert_group,
                is_enabled = excluded.is_enabled,
                trigger_json = excluded.trigger_json,
                matchers_json = excluded.matchers_json,
                remediation = excluded.remediation,
                references_json = excluded.references_json,
                updated_at = CURRENT_TIMESTAMP;
        """, (
            norm["rule_id"],
            norm["cve_id"],
            norm["name"],
            norm.get("description", ""),
            norm.get("target_type", "web"),
            norm.get("severity", "Medium"),
            norm.get("cvss_score", 5.0),
            norm.get("cwe", ""),
            norm.get("thaicert_group", 1),
            1 if norm.get("is_enabled", True) else 0,
            json.dumps(norm.get("trigger", {})),
            json.dumps(norm.get("matchers", [])),
            norm.get("remediation", ""),
            json.dumps(norm.get("references", []))
        ))
        conn.commit()
    return get_cve_rule_by_id(norm["rule_id"]) or norm


def delete_cve_rule(rule_id: str) -> bool:
    """Deletes a CVE rule by its ID."""
    init_profile_db()
    with get_db_connection() as conn:
        cursor = conn.execute("DELETE FROM cve_rules WHERE rule_id = ?", (str(rule_id).strip(),))
        conn.commit()
        return cursor.rowcount > 0


def toggle_cve_rule(rule_id: str, is_enabled: bool) -> bool:
    """Enables or disables an existing CVE rule."""
    init_profile_db()
    with get_db_connection() as conn:
        cursor = conn.execute(
            "UPDATE cve_rules SET is_enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE rule_id = ?",
            (1 if is_enabled else 0, str(rule_id).strip())
        )
        conn.commit()
        return cursor.rowcount > 0


def export_cve_rules_json(enabled_only: bool = False) -> Dict[str, Any]:
    """Exports all or enabled CVE rules in the standard ThaiCERT / OPScaner JSON interchange format."""
    rules = get_all_cve_rules(enabled_only=enabled_only)
    from datetime import datetime
    return {
        "format": "OPScaner-CVE-Rule-Schema",
        "version": "1.0.0",
        "exported_at": datetime.utcnow().isoformat() + "Z",
        "total_rules": len(rules),
        "rules": rules
    }


def import_cve_rules_json(payload: Any, overwrite: bool = True) -> Dict[str, Any]:
    """
    Imports a JSON payload of rules (either a list of rules or an export bundle with a 'rules' key).
    Returns a summary of imported, skipped, and error details.
    """
    if isinstance(payload, str):
        payload = json.loads(payload)
    
    rules_list = []
    if isinstance(payload, dict):
        rules_list = payload.get("rules", [])
        if not rules_list and "rule_id" in payload:
            rules_list = [payload]
    elif isinstance(payload, list):
        rules_list = payload
    else:
        raise ValueError("Invalid import payload: expected JSON array or object containing 'rules' list.")

    imported = 0
    updated = 0
    failed = 0
    errors = []

    for item in rules_list:
        if not isinstance(item, dict):
            failed += 1
            errors.append("Skipped non-object rule entry")
            continue
        rule_id = str(item.get("rule_id", "")).strip().upper()
        if not rule_id:
            failed += 1
            errors.append("Skipped rule without rule_id")
            continue
        
        existing = get_cve_rule_by_id(rule_id)
        if existing and not overwrite:
            continue
        
        try:
            save_cve_rule(item)
            if existing:
                updated += 1
            else:
                imported += 1
        except Exception as e:
            failed += 1
            errors.append(f"Failed rule {rule_id}: {str(e)}")

    return {
        "success": True,
        "imported": imported,
        "updated": updated,
        "failed": failed,
        "total_processed": len(rules_list),
        "errors": errors
    }

