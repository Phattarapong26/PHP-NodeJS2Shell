"""
Background LAN ARP and Neighbor Table Syncer.
Periodically refreshes local ARP cache and writes active hosts (IP + MAC)
to active_hosts.json and active_hosts.txt for Docker container consumption.
"""

import json
import os
import re
import subprocess
import time


def get_current_arp_dict():
    hosts = {}
    try:
        r = subprocess.run(['arp', '-an'], capture_output=True, text=True, timeout=2)
        for line in r.stdout.splitlines():
            if "incomplete" in line:
                continue
            m = re.search(r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-fA-F:]+)', line)
            if m:
                ip, mac = m.group(1), m.group(2).lower()
                if not ip.startswith("224.") and not ip.endswith(".255") and ip != "127.0.0.1":
                    hosts[ip] = mac
    except Exception:
        pass
    return hosts


def sync_once(base_dir="."):
    hosts = get_current_arp_dict()
    if hosts:
        json_path = os.path.join(base_dir, "active_hosts.json")
        txt_path = os.path.join(base_dir, "active_hosts.txt")
        try:
            with open(json_path, "w") as f:
                json.dump(hosts, f, indent=2)
            with open(txt_path, "w") as f:
                lines = [f"{ip},{mac}" for ip, mac in hosts.items()]
                f.write("\n".join(lines))
        except Exception:
            pass
    return hosts


def run_daemon(base_dir=".", interval=10):
    while True:
        try:
            subprocess.run(["ping", "-c", "1", "-W", "300", "255.255.255.255"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            sync_once(base_dir)
        except Exception:
            pass
        time.sleep(interval)


if __name__ == "__main__":
    import sys
    target_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    if "--daemon" in sys.argv:
        run_daemon(target_dir)
    else:
        found = sync_once(target_dir)
        print(f"Synced {len(found)} active hosts.")
