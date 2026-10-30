#!/bin/sh
set -e

mkdir -p /var/lib/php/sessions
chmod 0700 /var/lib/php/sessions

echo "=========================================================="
echo " Starting OPScaner Defensive QA Test Target Services..."
echo " - Pre-Hardening Service (PHP 8.2.19 unpatched):  http://0.0.0.0:8080"
echo " - Post-Hardening Service (CIS Hardened):        http://0.0.0.0:8088"
echo "=========================================================="

php -c /etc/php-vuln.ini -S 0.0.0.0:8080 -t /var/www/vulnerable &
PID_VULN=$!

php -c /etc/php-hardened.ini -S 0.0.0.0:8088 -t /var/www/hardened &
PID_HARD=$!

# Trap signals for graceful shutdown
trap "kill -TERM $PID_VULN $PID_HARD; exit 0" SIGINT SIGTERM

wait
