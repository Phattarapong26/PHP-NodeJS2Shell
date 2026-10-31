#!/usr/bin/env bash
# OPScaner PHP2Shell Lab - stop every lab listener (works without ps/pgrep/pkill)
cd "$(dirname "$0")"
LAB=$(pwd)
killed=0

# 1) pid files written by start_lab.sh
for f in run/*.pid; do
  [ -e "$f" ] || continue
  pid=$(cat "$f" 2>/dev/null)
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null && echo "stopped $(basename "$f" .pid) (pid $pid)" && killed=$((killed+1))
  fi
  rm -f "$f"
done

# 2) fallback: scan /proc for lab servers (php -S ... router.php / portal.php)
for d in /proc/[0-9]*; do
  pid=${d#/proc/}
  [ "$pid" = "$$" ] && continue
  cmd=$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null) || continue
  case "$cmd" in
    *router.php*|*portal.php*)
      kill -TERM "$pid" 2>/dev/null && echo "stopped stray lab server (pid $pid)" && killed=$((killed+1))
      ;;
  esac
done

sleep 0.4
echo "lab stopped ($killed process(es))"
