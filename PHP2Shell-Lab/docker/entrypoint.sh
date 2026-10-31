#!/bin/sh
# OPScaner PHP2Shell Lab - start exactly one simulated system per container
set -e
APP="${LAB_APP:-app1}"
PORT="${LAB_PORT:-8081}"

if [ "$APP" = "portal" ]; then
  echo "[lab] portal on 0.0.0.0:${PORT}"
  exec php -c /app/etc/app1.ini -S "0.0.0.0:${PORT}" -t /app /app/portal.php
fi

echo "[lab] ${APP} on 0.0.0.0:${PORT} (php.ini: /app/etc/${APP}.ini)"
exec php -c "/app/etc/${APP}.ini" -S "0.0.0.0:${PORT}" -t "/app/apps/${APP}" "/app/apps/${APP}/router.php"
