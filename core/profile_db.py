"""
OPScaner - SQLite Profile Management Database
Stores scan profiles with title, description, network target, and active status.
Thread-safe SQLite connector with automatic schema initialization.
"""

import os
import sqlite3
from typing import List, Dict, Optional, Any

DB_PATH = os.environ.get("OPSCANER_PROFILE_DB", "profiles.db")


def get_db_connection() -> sqlite3.Connection:
    """Creates a thread-safe connection to the SQLite database."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_profile_db():
    """Initializes the database table for scan profiles."""
    with get_db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_profiles (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT DEFAULT '',
                network_target TEXT DEFAULT '',
                is_active INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.commit()


def get_all_profiles() -> List[Dict[str, Any]]:
    """Returns all profiles ordered by active first, then created_at DESC."""
    init_profile_db()
    with get_db_connection() as conn:
        cursor = conn.execute("""
            SELECT id, title, description, network_target, is_active, created_at, updated_at
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
            SELECT id, title, description, network_target, is_active, created_at, updated_at
            FROM scan_profiles
            WHERE id = ?
        """, (profile_id,))
        row = cursor.fetchone()
        return dict(row) if row else None


def get_active_profile() -> Optional[Dict[str, Any]]:
    """Returns the currently active profile if one is selected."""
    init_profile_db()
    with get_db_connection() as conn:
        cursor = conn.execute("""
            SELECT id, title, description, network_target, is_active, created_at, updated_at
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
    set_active: bool = False
) -> Dict[str, Any]:
    """Creates a new scan profile and optionally sets it as active."""
    init_profile_db()
    title = (title or "").strip()
    if not title:
        raise ValueError("Profile title cannot be empty.")

    description = (description or "").strip()
    network_target = (network_target or "").strip()

    with get_db_connection() as conn:
        if set_active:
            conn.execute("UPDATE scan_profiles SET is_active = 0")

        cursor = conn.execute("""
            INSERT INTO scan_profiles (title, description, network_target, is_active)
            VALUES (?, ?, ?, ?)
        """, (title, description, network_target, 1 if set_active else 0))
        new_id = cursor.lastrowid
        conn.commit()

    return get_profile_by_id(new_id)


def update_profile(
    profile_id: int,
    title: str,
    description: str = "",
    network_target: str = ""
) -> Optional[Dict[str, Any]]:
    """Updates an existing scan profile."""
    init_profile_db()
    title = (title or "").strip()
    if not title:
        raise ValueError("Profile title cannot be empty.")

    with get_db_connection() as conn:
        conn.execute("""
            UPDATE scan_profiles
            SET title = ?, description = ?, network_target = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (title, (description or "").strip(), (network_target or "").strip(), profile_id))
        conn.commit()

    return get_profile_by_id(profile_id)


def delete_profile(profile_id: int) -> bool:
    """Deletes a profile by ID."""
    init_profile_db()
    with get_db_connection() as conn:
        cursor = conn.execute("DELETE FROM scan_profiles WHERE id = ?", (profile_id,))
        conn.commit()
        return cursor.rowcount > 0


def set_active_profile(profile_id: int) -> Optional[Dict[str, Any]]:
    """Sets the specified profile as active and deactivates others."""
    init_profile_db()
    target = get_profile_by_id(profile_id)
    if not target:
        return None

    with get_db_connection() as conn:
        conn.execute("UPDATE scan_profiles SET is_active = 0")
        conn.execute("UPDATE scan_profiles SET is_active = 1 WHERE id = ?", (profile_id,))
        conn.commit()

    return get_profile_by_id(profile_id)
