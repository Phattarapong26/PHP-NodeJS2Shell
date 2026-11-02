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
        conn.commit()


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
