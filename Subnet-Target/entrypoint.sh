#!/bin/sh
# entrypoint: ตั้งค่าเครื่องให้ตรงกับโปรไฟล์ แล้วเปิด sshd + nginx
set -eu

PROFILE="${PROFILE_PATH:-/os/profile.json}"
[ -f "$PROFILE" ] || { echo "[target] missing $PROFILE (bind mount ./os/hostNN:/os)"; exit 1; }

j() { python3 -c "import json;print(json.load(open('$PROFILE'))['$1'])"; }

KREL=$(j kernel_release)
KVER=$(j kernel_version)
HOSTN=$(j hostname)
PRETTY=$(j os_pretty)
OSID=$(j os_id)

# ---- 1) ค่าที่ทุกเครื่องมือจะอ่าน ----
cat > /etc/lab-kernel.env <<EOF
# สร้างโดย entrypoint — ใช้โดย uname/sysctl wrapper และ LD_PRELOAD shim
FAKEKERNEL_ROOT="/os"
FAKEKERNEL_RELEASE="$KREL"
FAKEKERNEL_VERSION="$KVER"
FAKEKERNEL_HOSTNAME="$HOSTN"
FAKEKERNEL_MACHINE="x86_64"
FAKE_KREL="$KREL"
FAKE_KVER="$KVER"
FAKE_HOST="$HOSTN"
FAKE_MPTCP="${FAKE_MPTCP:-1}"
FAKE_MIGRATE="${FAKE_MIGRATE:-0}"
EOF
chmod 0644 /etc/lab-kernel.env

# ---- 2) hostname / motd ให้เหมือนเครื่องจริง ----
hostname "$HOSTN" 2>/dev/null || true
printf '%s \\r (\\l)\\n\\n' "$PRETTY" > /etc/issue
printf 'Welcome to %s\\n\\nKernel %s on an %s system\\n' "$PRETTY" "$KREL" "$(uname -m)" > /etc/motd

# ---- 3) โหมด LD_PRELOAD ทั้งระบบ (ทำให้ python/agent scanner เห็น kernel เดียวกัน) ----
if [ "${ENABLE_PRELOAD:-1}" = "1" ] && [ -f /usr/local/lib/libfakekernel.so ]; then
    if env LD_PRELOAD=/usr/local/lib/libfakekernel.so uname -r >/dev/null 2>&1; then
        echo /usr/local/lib/libfakekernel.so > /etc/ld.so.preload
        echo "[target] system-wide kernel shim enabled (/etc/ld.so.preload)"
    else
        echo "[target] WARN: shim self-test failed, continuing without preload"
    fi
fi

# ---- 4) sshd (ของจริงของ base image) ----
ssh-keygen -A >/dev/null 2>&1 || true
mkdir -p /run/sshd
cat > /etc/ssh/sshd_config.d/99-lab-target.conf <<EOF
PasswordAuthentication no
PermitRootLogin no
X11Forwarding no
UseDNS no
PrintMotd yes
EOF
/usr/sbin/sshd -D -e &

# ---- 5) nginx (ของจริงของ base image -> Server header ตรงดิสโทร) ----
rm -f /etc/nginx/sites-enabled/default /etc/nginx/conf.d/default.conf 2>/dev/null || true
mkdir -p /run/nginx /var/log/nginx /var/lib/nginx 2>/dev/null || true
cat > /etc/nginx/conf.d/00-lab.conf <<EOF
server {
    listen 80 default_server;
    server_name _;
    root /usr/share/nginx/html;
    location / { try_files \$uri \$uri/ =404; }
    location = /healthz { return 200 "ok\n"; }
}
EOF
nginx -g 'daemon off;' &

echo "[target] ${HOSTN} up — ${PRETTY} / kernel ${KREL} / ports 22,80"
echo "[target] profile: ${OSID} ${KREL}  (CVE-2026-98432 range: >= 4.4)"

# รอจนกว่าจะมี process ใดตัวหนึ่งตาย
wait
