#!/bin/bash
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$DIR"

echo "=========================================================="
echo "  [ThaiCERT SCANNER] PHP LAN Discovery & Security Audit"
echo "=========================================================="

# 0. Clean up if Docker previously created host_network.json or active_hosts.txt as directories
if [ -d "$DIR/host_network.json" ]; then
  rm -rf "$DIR/host_network.json"
fi
if [ -d "$DIR/active_hosts.txt" ]; then
  rm -rf "$DIR/active_hosts.txt"
fi

touch "$DIR/host_network.json"
touch "$DIR/active_hosts.txt"

# 1. Dynamically Detect Physical Network (IP, Netmask, CIDR, Subnet, Gateway, Interface)
NET_JSON=$(python3 -c "
import subprocess, re, ipaddress, json, socket

def is_ignored_iface(iface):
    if not iface:
        return True
    low = iface.lower()
    return any(low.startswith(p) for p in ('lo', 'docker', 'br-', 'veth', 'virbr', 'tun', 'tap', 'utun', 'vmnet', 'vbox', 'cni', 'flannel'))

def get_net_info():
    gw = ''
    # macOS route & ifconfig
    try:
        r = subprocess.run(['route', '-n', 'get', 'default'], capture_output=True, text=True, timeout=2)
        iface_m = re.search(r'interface:\s+(\S+)', r.stdout)
        gw_m = re.search(r'gateway:\s+(\S+)', r.stdout)
        iface = iface_m.group(1) if iface_m else 'en0'
        gw = gw_m.group(1) if gw_m else ''

        if iface and not is_ignored_iface(iface):
            res_if = subprocess.run(['ifconfig', iface], capture_output=True, text=True, timeout=2)
            m = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)\s+netmask\s+(0x[0-9a-fA-F]+|\d+\.\d+\.\d+\.\d+)', res_if.stdout)
            if m:
                ip_str = m.group(1)
                mask_raw = m.group(2)
                mask_ip = str(ipaddress.IPv4Address(int(mask_raw, 16))) if mask_raw.startswith('0x') else mask_raw
                net = ipaddress.IPv4Network(f'{ip_str}/{mask_ip}', strict=False)
                return {
                    'interface': iface, 'ip': ip_str, 'gateway': gw,
                    'netmask': mask_ip, 'subnet': str(net), 'cidr': net.prefixlen,
                    'first_host': str(net.network_address + 1),
                    'last_host': str(net.broadcast_address - 1),
                    'total_hosts': net.num_addresses - 2
                }
    except Exception:
        pass

    # Linux route & ip
    try:
        r = subprocess.run(['ip', 'route', 'show', 'default'], capture_output=True, text=True, timeout=2)
        parts = r.stdout.split()
        gw = parts[parts.index('via') + 1] if 'via' in parts else ''
        iface = parts[parts.index('dev') + 1] if 'dev' in parts else 'eth0'
        if iface and not is_ignored_iface(iface):
            r_addr = subprocess.run(['ip', '-4', '-o', 'addr', 'show', iface], capture_output=True, text=True, timeout=2)
            m = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+/\d+)', r_addr.stdout)
            if m:
                net = ipaddress.IPv4Network(m.group(1), strict=False)
                ip_str = m.group(1).split('/')[0]
                return {
                    'interface': iface, 'ip': ip_str, 'gateway': gw,
                    'netmask': str(net.netmask), 'subnet': str(net), 'cidr': net.prefixlen,
                    'first_host': str(net.network_address + 1),
                    'last_host': str(net.broadcast_address - 1),
                    'total_hosts': net.num_addresses - 2
                }
    except Exception:
        pass

    # Dynamic POSIX socket probe (offline UDP connect to gateway or corporate DNS)
    socket_targets = [gw, '192.168.1.1', '10.0.0.1', '172.16.0.1', '1.1.1.1', '8.8.8.8']
    for target in socket_targets:
        if not target:
            continue
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((target, 80))
            ip_str = s.getsockname()[0]
            s.close()
            if ip_str and not ip_str.startswith('127.'):
                net = ipaddress.IPv4Network(f'{ip_str}/24', strict=False)
                return {
                    'interface': 'auto', 'ip': ip_str, 'gateway': gw,
                    'netmask': str(net.netmask), 'subnet': str(net), 'cidr': net.prefixlen,
                    'first_host': str(net.network_address + 1),
                    'last_host': str(net.broadcast_address - 1),
                    'total_hosts': net.num_addresses - 2
                }
        except Exception:
            continue

    return {
        'interface': '', 'ip': '', 'gateway': '',
        'netmask': '', 'subnet': '', 'cidr': 0,
        'first_host': '', 'last_host': '', 'total_hosts': 0
    }

print(json.dumps(get_net_info()))
")

echo "$NET_JSON" > "$DIR/host_network.json"

HOST_IP=$(echo "$NET_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin).get('ip', ''))")
HOST_SUBNET=$(echo "$NET_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin).get('subnet', ''))")
HOST_NETMASK=$(echo "$NET_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin).get('netmask', ''))")
HOST_CIDR=$(echo "$NET_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin).get('cidr', '0'))")
HOST_GATEWAY=$(echo "$NET_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin).get('gateway', ''))")
HOST_INTERFACE=$(echo "$NET_JSON" | python3 -c "import sys, json; print(json.load(sys.stdin).get('interface', ''))")

# Write .env for configuration
cat <<EOF > "$DIR/.env"
HOST_IP=$HOST_IP
HOST_SUBNET=$HOST_SUBNET
HOST_NETMASK=$HOST_NETMASK
HOST_CIDR=$HOST_CIDR
HOST_GATEWAY=$HOST_GATEWAY
HOST_INTERFACE=$HOST_INTERFACE
EOF

# 2. Extract active LAN hosts discovered by DHCP / ARP on physical interface
ACTIVE_IPS=$(arp -an 2>/dev/null | grep -v "incomplete" | awk '{print $2}' | tr -d '()' | grep -v "224.0.0" | grep -v "\.255$" | tr '\n' ',' | sed 's/,$//')
echo "$ACTIVE_IPS" > "$DIR/active_hosts.txt"

echo "[*] Physical Interface: $HOST_INTERFACE"
echo "[*] Physical Host IP:   $HOST_IP"
echo "[*] Physical Netmask:   $HOST_NETMASK"
echo "[*] Detected Subnet:    $HOST_SUBNET (/$HOST_CIDR)"
echo "[*] Default Gateway:    $HOST_GATEWAY"
echo "[*] Active ARP Hosts:   $(echo "$ACTIVE_IPS" | tr ',' '\n' | grep -v '^$' | wc -l | tr -d ' ') devices in local cache"

# Check execution mode: Docker or Native
if [ "$1" == "--docker" ] || [ ! -f "$DIR/venv/bin/python" ]; then
  echo "[*] Running mode: DOCKER CONTAINER..."
  echo "[*] Clearing existing port 5050 listeners and containers..."
  docker compose down 2>/dev/null || true
  docker rm -f thaicert-php-scanner 2>/dev/null || true
  lsof -ti:5050 | xargs kill -9 2>/dev/null || true
  
  if docker compose version >/dev/null 2>&1; then
    echo "[*] Building & Starting with Docker Compose..."
    docker compose up -d --build
  else
    echo "[*] Building Docker Image (thaicert-php-scanner)..."
    docker build -t thaicert-php-scanner .
    docker run -d --name thaicert-php-scanner \
      --restart unless-stopped \
      -p 5050:5050 \
      -e HOST_IP="$HOST_IP" \
      -e HOST_SUBNET="$HOST_SUBNET" \
      -e HOST_NETMASK="$HOST_NETMASK" \
      -e HOST_CIDR="$HOST_CIDR" \
      -e HOST_GATEWAY="$HOST_GATEWAY" \
      -e HOST_INTERFACE="$HOST_INTERFACE" \
      -e ACTIVE_HOSTS="$ACTIVE_IPS" \
      -e IS_DOCKER="true" \
      -e DOCKER_CONTAINER="true" \
      -v "$DIR/host_network.json:/app/host_network.json:ro" \
      -v "$DIR/active_hosts.txt:/app/active_hosts.txt:ro" \
      -v "$DIR/GUI.html:/app/GUI.html" \
      -v "$DIR/app.py:/app/app.py" \
      -v "$DIR/diagram.html:/app/diagram.html" \
      thaicert-php-scanner
  fi
else
  echo "[*] Running mode: NATIVE (Direct Physical Interface - Zero Virtualization)..."
  # Stop container if running on port 5050
  docker rm -f thaicert-php-scanner 2>/dev/null || true
  lsof -ti:5050 | xargs kill -9 2>/dev/null || true
  
  # Launch natively with venv in background
  "$DIR/venv/bin/python" "$DIR/app.py" > "$DIR/server.log" 2>&1 &
  PID=$!
  echo "[*] Native process started (PID: $PID)"
fi

echo ""
echo "=========================================================="
echo "  [READY] ThaiCERT Scanner Ready!"
echo "  [WEB] Opening Web Browser: http://localhost:5050"
echo "=========================================================="

if command -v open >/dev/null 2>&1; then
  sleep 1
  open "http://localhost:5050" 2>/dev/null || true
elif command -v xdg-open >/dev/null 2>&1; then
  sleep 1
  xdg-open "http://localhost:5050" 2>/dev/null || true
fi

