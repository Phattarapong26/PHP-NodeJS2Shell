#!/usr/bin/env bash
# ตรวจว่าเป้าหมาย "ดูเหมือนเครื่อง Linux จริง" จากมุมของ scanner
# รันจากเครื่องอื่นในวงเดียวกัน (macvlan: container มองไม่เห็น docker host)
#   ./check-from-network.sh 10.20.4.38 10.20.4.40
set -uo pipefail

for ip in "$@"; do
  echo "=================================================================="
  echo " target: $ip"
  echo "=================================================================="

  banner=$(timeout 5 bash -c "exec 3<>/dev/tcp/$ip/22 && head -c 80 <&3" 2>/dev/null | head -1 | tr -d '\r')
  printf '  %-14s %s\n' "22/tcp ssh" "${banner:-<no response>}"

  hdr=$(curl -sS -m 5 -D - -o /dev/null "http://$ip/" 2>/dev/null | tr -d '\r')
  printf '  %-14s %s\n' "80/tcp http" "$(printf '%s' "$hdr" | head -1)"
  printf '  %-14s %s\n' "  Server" "$(printf '%s' "$hdr" | awk -F': ' 'tolower($1)=="server"{print $2}')"
  printf '  %-14s %s\n' "  X-Powered-By" "$(printf '%s' "$hdr" | awk -F': ' 'tolower($1)=="x-powered-by"{print $2}')"

  ttl=$(ping -c1 -W1 "$ip" 2>/dev/null | sed -n 's/.*ttl=\([0-9]*\).*/\1/p' | head -1)
  printf '  %-14s %s\n' "ttl" "${ttl:-<no icmp>}"

  # พอร์ตอื่นต้องปิด (RST) => scanner เห็นเป็นเครื่องที่ไม่ได้เปิดอะไรมาก
  for p in 3306 5432 6379 8080; do
    (timeout 1 bash -c "exec 3<>/dev/tcp/$ip/$p" 2>/dev/null && printf '  %-14s OPEN\n' "$p/tcp") || true
  done

  echo "  --- คำสั่งที่ควรลองต่อ ---"
  echo "  nmap -Pn -O -sV -p22,80 $ip        # OS + service detection"
  echo "  nmap -Pn --script ssh2-enum-algos -p22 $ip"
  echo
done
