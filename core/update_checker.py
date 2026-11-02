"""
OPScaner - Daily Git Version Update Checker & Updater Engine
Runs a daily background worker checking for upstream commits on GitHub.
Provides endpoints and routines to inspect update status and apply updates.
"""

import os
import time
import threading
import subprocess
from datetime import datetime
from typing import Dict, Any

_UPDATE_CACHE: Dict[str, Any] = {
    "has_update": False,
    "current_commit": "unknown",
    "remote_commit": "unknown",
    "commits_behind": 0,
    "last_checked": "",
    "status_message": "ยังไม่ได้ตรวจสอบการอัปเดต",
    "is_docker": bool(os.path.exists("/.dockerenv") or os.environ.get("IS_DOCKER") == "true")
}
_UPDATE_LOCK = threading.Lock()
_WORKER_THREAD = None


def get_current_git_commit() -> str:
    """Returns local git commit short hash."""
    try:
        res = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=3
        )
        if res.returncode == 0:
            return res.stdout.strip()
    except Exception:
        pass
    return "production"


def get_remote_git_commit() -> str:
    """Checks remote repository HEAD commit without altering local state."""
    try:
        res = subprocess.run(
            ["git", "ls-remote", "origin", "-h", "refs/heads/main"],
            capture_output=True,
            text=True,
            timeout=5
        )
        if res.returncode == 0 and res.stdout:
            parts = res.stdout.strip().split()
            if parts:
                return parts[0][:7]
    except Exception:
        pass
    return ""


def check_for_updates(force_refresh: bool = False) -> Dict[str, Any]:
    """
    Checks if a newer version is available on upstream git.
    Returns status dict with has_update flag.
    """
    global _UPDATE_CACHE
    now = datetime.now()
    now_str = now.strftime("%Y-%m-%d %H:%M:%S")

    with _UPDATE_LOCK:
        current = get_current_git_commit()
        remote = get_remote_git_commit()

        has_update = False
        behind_count = 0
        status_msg = "ระบบเป็นเวอร์ชันล่าสุดแล้ว"

        if remote and current and current != "production":
            if current != remote:
                # Count commits behind if git repo is accessible
                try:
                    subprocess.run(["git", "fetch", "origin", "main", "--quiet"], timeout=8)
                    cnt_res = subprocess.run(
                        ["git", "rev-list", "--count", f"HEAD..origin/main"],
                        capture_output=True,
                        text=True,
                        timeout=3
                    )
                    if cnt_res.returncode == 0 and cnt_res.stdout.strip().isdigit():
                        behind_count = int(cnt_res.stdout.strip())
                except Exception:
                    behind_count = 1

                has_update = (behind_count > 0 or current != remote)
                if has_update:
                    status_msg = f"มีเวอร์ชันใหม่พร้อมอัปเดต (ตามหลัง {behind_count} คอมมิต)"
            else:
                has_update = False
                status_msg = "ระบบเป็นเวอร์ชันล่าสุดแล้ว (Up to date)"
        elif not remote:
            status_msg = "ไม่สามารถเชื่อมต่อไปยัง Git Repository ปลายทางได้ (ออฟไลน์)"

        _UPDATE_CACHE = {
            "has_update": has_update,
            "current_commit": current,
            "remote_commit": remote or current,
            "commits_behind": behind_count,
            "last_checked": now_str,
            "status_message": status_msg,
            "is_docker": bool(os.path.exists("/.dockerenv") or os.environ.get("IS_DOCKER") == "true")
        }
        return _UPDATE_CACHE.copy()


def get_cached_update_status() -> Dict[str, Any]:
    """Returns the cached update status immediately without blocking."""
    with _UPDATE_LOCK:
        if not _UPDATE_CACHE.get("last_checked"):
            # Trigger first check asynchronously if not yet checked
            threading.Thread(target=check_for_updates, daemon=True).start()
        return _UPDATE_CACHE.copy()


def apply_update() -> Dict[str, Any]:
    """
    Pulls the latest code from git origin main.
    Handles container environment notifications.
    """
    is_docker = bool(os.path.exists("/.dockerenv") or os.environ.get("IS_DOCKER") == "true")
    output_log = []

    try:
        pull_res = subprocess.run(
            ["git", "pull", "origin", "main"],
            capture_output=True,
            text=True,
            timeout=30
        )
        output_log.append(pull_res.stdout.strip())
        if pull_res.stderr:
            output_log.append(pull_res.stderr.strip())

        if pull_res.returncode == 0:
            check_for_updates(force_refresh=True)
            msg = "อัปเดตซอร์สโค้ดสำเร็จเรียบร้อยแล้ว"
            if is_docker:
                msg += " (แนะนำให้รีสตาร์ต Container เพื่อโหลดโมดูลล่าสุดอย่างสมบูรณ์)"
            else:
                msg += " (กรุณารีเฟรชหรือเริ่มระบบใหม่เพื่อใช้งานเวอร์ชันล่าสุด)"

            return {
                "status": "success",
                "message": msg,
                "log": "\n".join(output_log),
                "is_docker": is_docker
            }
        else:
            return {
                "status": "error",
                "message": f"ไม่สามารถดึงข้อมูลอัปเดตได้: {pull_res.stderr.strip()}",
                "log": "\n".join(output_log),
                "is_docker": is_docker
            }
    except Exception as e:
        return {
            "status": "error",
            "message": f"เกิดข้อผิดพลาดในการอัปเดต: {str(e)}",
            "is_docker": is_docker
        }


def _daily_worker_loop():
    """Background worker checking once every 24 hours."""
    time.sleep(5)  # Initial grace delay after boot
    while True:
        try:
            check_for_updates()
        except Exception:
            pass
        # Sleep for 24 hours (86,400 seconds)
        time.sleep(86400)


def start_daily_update_worker():
    """Starts the daily background update checker worker thread."""
    global _WORKER_THREAD
    if _WORKER_THREAD is None or not _WORKER_THREAD.is_alive():
        _WORKER_THREAD = threading.Thread(target=_daily_worker_loop, daemon=True, name="DailyUpdateWorker")
        _WORKER_THREAD.start()
