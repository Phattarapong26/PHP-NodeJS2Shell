#!/usr/bin/env bash
# OPScaner PHP2Shell Lab - start all 9 listeners (portal + 8 targets)
set -uo pipefail
cd "$(dirname "$0")"
LAB=$(pwd)
BIND="${LAB_BIND:-0.0.0.0}"
mkdir -p logs run

command -v php >/dev/null 2>&1 || { echo "php not found - install php-cli first"; exit 1; }

echo "=============================================================="
echo " OPScaner PHP2Shell Lab - starting target services"
echo " bind: $BIND   php: $(php -r 'echo PHP_VERSION;')"
echo "=============================================================="

# ป้องกันการสับสน: ถ้าพอร์ตถูกใช้อยู่แล้ว ให้หยุดก่อน
busy=""
for port in 8080 8081 8082 8083 8084 8085 8086 8087 8088; do
  code=$(curl -s -m 1 -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/" 2>/dev/null)
  [ "$code" != "000" ] && busy="$busy $port"
done
if [ -n "$busy" ]; then
  echo "ERROR: พอร์ตต่อไปนี้ถูกใช้อยู่:$busy"
  echo "       หยุด lab ตัวเก่าก่อน: bash stop_lab.sh"
  exit 1
fi

# portal (8080)
php -c "$LAB/etc/app1.ini" -S "$BIND:8080" -t "$LAB" "$LAB/portal.php" >"$LAB/logs/portal.log" 2>&1 &
echo $! > "$LAB/run/portal.pid"

for i in 1 2 3 4 5 6 7 8; do
  port=$((8080 + i))
  php -c "$LAB/etc/app$i.ini" -S "$BIND:$port" -t "$LAB/apps/app$i" "$LAB/apps/app$i/router.php" \
      >"$LAB/logs/app$i.log" 2>&1 &
  echo $! > "$LAB/run/app$i.pid"
done

sleep 1.2

printf '%-8s %-6s %s\n' "PORT" "STATE" "SYSTEM"
printf '%-8s %-6s %s\n' "8080" "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/ )" "portal"
for i in 1 2 3 4 5 6 7 8; do
  port=$((8080 + i))
  code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port/health")
  name=$(curl -s "http://127.0.0.1:$port/health" | sed -n 's/.*"system": *"\([^"]*\)".*/\1/p')
  printf '%-8s %-6s %s\n' "$port" "$code" "$name"
done

echo
echo "portal: http://127.0.0.1:8080   (open that to see all targets)"
echo "logs:   $LAB/logs/    pids: $LAB/run/"
