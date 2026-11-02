import { apiFetch } from './api';
import { detectedHostIp, detectedSubnetRange, inputCustomIp, mainSubnetInput, selectSubnetCidr, settingSubnetRange, statusIndicatorDot, statusPillText, targetIpTypeBadge } from './dom';
import { appState } from './state';
import { showToast, updateStepBadge } from './ui';

// --- Dynamic Target Web URL (IP + Port) ---
export function getWebTargetUrl(host, port) {
  if (!host) return '#';
  let ip = (typeof host === 'string' ? host : (host.ip || '')).trim();
  const parenMatch = ip.match(/\(([^)]+)\)/);
  if (parenMatch) {
    ip = parenMatch[1].trim();
  } else {
    ip = ip.split(/\s+/)[0];
  }

  // If IP is local loopback from scan run locally, resolve to accessible browser hostname
  if (ip === '127.0.0.1' || ip === 'localhost' || ip === '0.0.0.0') {
    ip = window.location.hostname || '127.0.0.1';
  }

  let p = port;
  if (!p && typeof host === 'object' && host.ports && Array.isArray(host.ports) && host.ports.length > 0) {
    const webPorts = [80, 443, 8080, 8443, 3000, 8000, 8888, 5000, 8088, 5050, 8081, 9000, 9090];
    const foundWebPort = host.ports.find(pt => webPorts.includes(pt));
    p = foundWebPort || host.ports[0];
  }
  if (!p) p = 80;

  const scheme = (p === 443 || p === 8443) ? 'https' : 'http';
  return `${scheme}://${ip}:${p}/`;
}

// --- IPv4 Bitwise Math & Dynamic Subnet Calculator ---
export function ipToInt(ip) {
  return ip.split('.').reduce((acc, octet) => ((acc << 8) + parseInt(octet, 10)) >>> 0, 0) >>> 0;
}

export function intToIp(int) {
  return [
    (int >>> 24) & 255,
    (int >>> 16) & 255,
    (int >>> 8) & 255,
    int & 255
  ].join('.');
}

export function parseSubnetDetails(targetStr) {
  if (!targetStr) return null;
  const trimmed = targetStr.trim();
  
  if (trimmed.includes('/')) {
    const parts = trimmed.split('/');
    const ipStr = parts[0].trim();
    const cidr = parseInt(parts[1], 10);
    if (isNaN(cidr) || cidr < 0 || cidr > 32) return null;
    
    const ipVal = ipToInt(ipStr);
    const mask = cidr === 0 ? 0 : (0xFFFFFFFF << (32 - cidr)) >>> 0;
    const netVal = (ipVal & mask) >>> 0;
    const bcastVal = (netVal | (~mask >>> 0)) >>> 0;
    
    let firstHostVal = netVal + 1;
    let lastHostVal = bcastVal - 1;
    let totalHosts = (bcastVal - netVal - 1);
    
    if (cidr === 31) {
      firstHostVal = netVal;
      lastHostVal = bcastVal;
      totalHosts = 2;
    } else if (cidr === 32) {
      firstHostVal = ipVal;
      lastHostVal = ipVal;
      totalHosts = 1;
    }
    
    return {
      type: "CIDR Subnet",
      subnet: `${intToIp(netVal)}/${cidr}`,
      cidr: cidr,
      netmask: intToIp(mask),
      firstHost: intToIp(firstHostVal),
      lastHost: intToIp(lastHostVal),
      totalHosts: Math.max(1, totalHosts),
      rangeText: `${intToIp(firstHostVal)} - ${intToIp(lastHostVal)} (/${cidr} รวม ${totalHosts.toLocaleString()} เครื่อง)`
    };
  } else if (trimmed.includes('-')) {
    const parts = trimmed.split('-');
    const sIp = parts[0].trim();
    const eIp = parts[1].trim();
    const sVal = ipToInt(sIp);
    const eVal = ipToInt(eIp);
    const totalHosts = Math.max(1, eVal - sVal + 1);
    return {
      type: "IP Range",
      subnet: trimmed,
      cidr: 32,
      firstHost: sIp,
      lastHost: eIp,
      totalHosts: totalHosts,
      rangeText: `${sIp} - ${eIp} (${totalHosts.toLocaleString()} เครื่อง)`
    };
  } else {
    const parts = trimmed.split(':');
    const hostOnly = parts[0];
    const portNum = parts[1] || "";
    const isDomain = !/^\d+\.\d+\.\d+\.\d+$/.test(hostOnly);
    const portLabel = portNum ? ` (Port ${portNum})` : "";
    return {
      type: isDomain ? `Domain Target${portLabel}` : (portNum ? `Host Port ${portNum}` : "Single Target"),
      subnet: trimmed,
      cidr: 32,
      firstHost: hostOnly,
      lastHost: hostOnly,
      totalHosts: 1,
      rangeText: isDomain ? `${trimmed} (โดเมนเป้าหมาย${portLabel})` : `${trimmed} (เป้าหมายเจาะจง 1 เครื่อง)`
    };
  }
}

export function updateCidrPreview() {
  const previewEl = document.getElementById("cidrPreviewRange");
  if (!previewEl || !selectSubnetCidr) return;
  const selectedOpt = selectSubnetCidr.options[selectSubnetCidr.selectedIndex];
  if (selectedOpt) {
    const sub = selectedOpt.getAttribute("data-subnet") || "";
    const netmask = selectedOpt.getAttribute("data-netmask") || "";
    const range = selectedOpt.getAttribute("data-range") || "";
    previewEl.innerHTML = `เป้าหมาย: <b class="text-blue-700 font-bold">${sub}</b> · Mask: <b class="text-slate-700 font-bold">${netmask}</b><br><span class="text-slate-500">${range}</span>`;
  }
}

export function populateDynamicCidrOptions(hostIp, detectedCidr, detectedNetmask, detectedSubnet, detectedHosts) {
  if (!selectSubnetCidr || !hostIp) return;
  const ip = hostIp.trim();
  const detCidr = parseInt(detectedCidr, 10) || 24;

  // Calculate candidate CIDRs around the detected IP
  const candidateList = [detCidr, 24, 23, 22, 21, 20, 28, 32];
  const uniqueCidrs = Array.from(new Set(candidateList))
    .filter(c => c >= 8 && c <= 32);

  // Place detected physical CIDR at the very top
  const sortedCidrs = [detCidr, ...uniqueCidrs.filter(c => c !== detCidr)];

  selectSubnetCidr.innerHTML = "";

  sortedCidrs.forEach((c) => {
    const isDetected = (c === detCidr);
    let details = null;
    if (isDetected && detectedSubnet) {
      details = parseSubnetDetails(detectedSubnet) || parseSubnetDetails(`${ip}/${c}`);
    } else {
      details = parseSubnetDetails(`${ip}/${c}`);
    }
    if (!details) return;

    const opt = document.createElement("option");
    opt.value = String(c);
    opt.setAttribute("data-subnet", details.subnet);
    opt.setAttribute("data-netmask", details.netmask);
    opt.setAttribute("data-range", details.rangeText);
    opt.setAttribute("data-hosts", details.totalHosts);

    if (isDetected) {
      opt.textContent = `[ตรวจพบจริง] ${details.subnet} (/${c}) · ${details.totalHosts.toLocaleString()} เครื่อง`;
      opt.selected = true;
    } else if (c === 32) {
      opt.textContent = `[เฉพาะเครื่องนี้] ${ip}/32 · 1 เครื่อง`;
    } else if (c === 24) {
      opt.textContent = `[Class C] ${details.subnet} (/24) · ${details.totalHosts.toLocaleString()} เครื่อง`;
    } else if (c === 28) {
      opt.textContent = `[ทดสอบด่วน] ${details.subnet} (/28) · ${details.totalHosts.toLocaleString()} เครื่อง`;
    } else {
      opt.textContent = `[วงกว้าง] ${details.subnet} (/${c}) · ${details.totalHosts.toLocaleString()} เครื่อง`;
    }

    selectSubnetCidr.appendChild(opt);
  });

  updateCidrPreview();
}

// Dynamic rendering of Recommended Subnet Chips inside Settings Drawer
export function renderDynamicPresets(presets, currentSubnet) {
  const container = document.getElementById('settingsPresetsList');
  if (!container) return;
  if (!presets || presets.length === 0) {
    container.innerHTML = `<span class="text-slate-400 text-xs">ไม่มีทางลัด</span>`;
    return;
  }
  container.innerHTML = presets.map((p) => {
    const isActive = p.subnet === currentSubnet;
    const activeClass = isActive 
      ? "bg-blue-600 text-white font-semibold shadow-sm" 
      : "bg-white/80 hover:bg-blue-50 text-slate-700 border border-slate-200/80";

    let iconName = p.icon || "ph-crosshair";
    if (p.label.includes("เฉพาะเครื่องนี้")) iconName = "ph-laptop";
    else if (p.label.includes("วงย่อย")) iconName = "ph-lightning";
    else if (p.label.includes("สำนักงาน")) iconName = "ph-buildings";
    else if (p.label.includes("Enterprise")) iconName = "ph-globe";

    const cleanLabel = p.label.replace(/\p{Extended_Pictographic}|[\u2600-\u27bf]/gu, '').trim();

    return `<button type="button" class="settings-preset-btn ${activeClass} px-3 py-2 rounded-xl text-left text-xs transition flex items-center justify-between cursor-pointer w-full" data-subnet="${p.subnet}">
      <div class="flex items-center gap-2">
        <i class="ph-bold ${iconName} text-sm ${isActive ? 'text-white' : 'text-blue-600'}"></i>
        <span class="font-medium">${cleanLabel}</span>
      </div>
      <i class="ph-bold ph-arrow-right text-[11px] opacity-70"></i>
    </button>`;
  }).join('');

  container.querySelectorAll('.settings-preset-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const sub = btn.getAttribute('data-subnet');
      if (sub) {
        if (mainSubnetInput) {
          mainSubnetInput.value = sub;
          recalculateSubnet(sub);
        }
        // Match in selectSubnetCidr
        const parts = sub.split('/');
        if (parts.length === 2 && selectSubnetCidr) {
          const cidr = parts[1];
          const matchedOpt = Array.from(selectSubnetCidr.options as HTMLCollectionOf<HTMLOptionElement>).find((o) => o.value === cidr || o.getAttribute('data-subnet') === sub);
          if (matchedOpt) {
            selectSubnetCidr.value = matchedOpt.value;
            updateCidrPreview();
          }
        }
        showToast(`เลือกเป้าหมาย: ${sub}`);
        container.querySelectorAll('.settings-preset-btn').forEach(b => {
          b.className = "settings-preset-btn bg-white/80 hover:bg-blue-50 text-slate-700 border border-slate-200/80 px-3 py-1.5 rounded-xl text-left text-xs transition flex items-center justify-between cursor-pointer w-full";
        });
        btn.className = "settings-preset-btn bg-blue-600 text-white font-semibold shadow-sm px-3 py-1.5 rounded-xl text-left text-xs transition flex items-center justify-between cursor-pointer w-full";
      }
    });
  });
}

// Step 2: คำนวณขอบเขตวง LAN (Subnet) อัตโนมัติจาก Input
export function recalculateSubnet(targetStr) {
  const inputStr = targetStr || (mainSubnetInput ? mainSubnetInput.value : "");
  if (!inputStr) return;
  const details = parseSubnetDetails(inputStr);
  if (details) {
    appState.subnet = details.subnet;
    appState.totalHosts = details.totalHosts;
    appState.firstHost = details.firstHost;
    appState.lastHost = details.lastHost;
    appState.cidr = details.cidr;

    if (detectedSubnetRange) {
      detectedSubnetRange.textContent = details.rangeText;
    }
    if (settingSubnetRange) {
      settingSubnetRange.textContent = details.rangeText;
    }
    if (targetIpTypeBadge) {
      targetIpTypeBadge.textContent = `${details.type} (${details.totalHosts.toLocaleString()} hosts)`;
    }
  }
}

export function setDiscoveredHostIp(data) {
  appState.hostIp = data.ip || "";
  appState.subnet = data.subnet || "";
  appState.cidr = data.cidr || 24;
  appState.netmask = data.netmask || "255.255.255.0";
  appState.gateway = data.gateway || "";
  appState.networkIface = data.interface || "auto";
  appState.firstHost = data.first_host || "";
  appState.lastHost = data.last_host || "";
  appState.totalHosts = data.total_hosts || 254;

  if (inputCustomIp) inputCustomIp.value = data.ip || "";
  if (detectedHostIp) detectedHostIp.textContent = data.ip || "-";
  
  const rangeStr = data.first_host && data.last_host
    ? `${data.first_host} - ${data.last_host} (/${data.cidr} รวม ${data.total_hosts.toLocaleString()} เครื่อง)`
    : (data.subnet || "-");

  if (detectedSubnetRange) detectedSubnetRange.textContent = rangeStr;
  if (settingSubnetRange) settingSubnetRange.textContent = rangeStr;

  // Update hint elements inside Settings Drawer
  const hintIp = document.getElementById('hintHostIp');
  if (hintIp) hintIp.textContent = data.ip || "-";

  const hintSub = document.getElementById('hintHostSubnet');
  if (hintSub) hintSub.textContent = data.subnet ? `${data.subnet} (/${data.cidr})` : "-";

  const hintCount = document.getElementById('hintActiveCount');
  if (hintCount) hintCount.textContent = `${data.active_devices_count ?? 0} เครื่อง`;

  const hintGw = document.getElementById('hintGateway');
  if (hintGw) hintGw.textContent = data.gateway || "-";

  const hintMask = document.getElementById('hintNetmask');
  if (hintMask) hintMask.textContent = data.netmask || "-";

  const hintIface = document.getElementById('hintNetworkIface');
  if (hintIface) hintIface.textContent = `${data.interface || 'Auto'} (DHCP/ARP)`;

  // Populate Dynamic CIDR Select from actual detected values!
  populateDynamicCidrOptions(data.ip, data.cidr, data.netmask, data.subnet, data.total_hosts);

  // Update Workflow diagram modal texts dynamically
  const step1Ex = document.getElementById('step1ExampleIp');
  if (step1Ex) step1Ex.textContent = `(ตรวจพบ IP เครื่อง: ${data.ip} บนการ์ด ${data.interface || 'Auto'})`;

  const step2Ex = document.getElementById('step2ExampleRange');
  if (step2Ex) step2Ex.textContent = `ได้เป็น ${data.first_host} ถึง ${data.last_host} (/${data.cidr} รวม ${data.total_hosts.toLocaleString()} เครื่อง)`;

  const step3Ex = document.getElementById('step3ExampleSpeed');
  if (step3Ex) step3Ex.textContent = `สแกน ${data.total_hosts.toLocaleString()} เครื่องพร้อมกันแบบ High-concurrency Async`;

  // Set main input to recommended subnet (safe Class C slice) or detected subnet only if empty
  const chosenSubnet = data.recommended_subnet || data.subnet;
  if (mainSubnetInput && (!mainSubnetInput.value || mainSubnetInput.value.trim() === "")) {
    mainSubnetInput.value = chosenSubnet;
    recalculateSubnet(chosenSubnet);
  }
  if (targetIpTypeBadge) {
    targetIpTypeBadge.textContent = `CIDR Subnet (${data.total_hosts.toLocaleString()} hosts)`;
  }

  // Render preset chips inside Settings Drawer
  renderDynamicPresets(data.presets, chosenSubnet);

  statusPillText.textContent = `Online · เครือข่าย: ${chosenSubnet || data.ip}`;
  statusIndicatorDot.className = "w-2 h-2 rounded-full bg-emerald-500 animate-pulse";
  updateStepBadge(`ระบบพร้อมสแกนเป้าหมาย: ${chosenSubnet || data.ip}`, "ph-check-circle");

  if (data.is_docker) {
    showToast(`สภาพแวดล้อม Docker (Host IP: ${data.ip})`);
  } else {
    showToast(`ตรวจพบเครือข่ายอัตโนมัติ: ${chosenSubnet} (${data.active_devices_count ?? 0} อุปกรณ์ออนไลน์)`);
  }
}

export let autoDetectTimer = null;

// Initialize Network Subnet Detection (Step 1 & 2 in diagram)
export async function autoDetectLocalNetwork() {
  updateStepBadge("กำลังตรวจสอบการเชื่อมต่อเครือข่าย...", "ph-network");
  try {
    let hintParam = "";
    const locHost = window.location.hostname;
    if (locHost && /^\d+\.\d+\.\d+\.\d+$/.test(locHost) && !locHost.startsWith("127.")) {
      hintParam = `?hint=${encodeURIComponent(locHost)}`;
    }
    const res = await apiFetch(`/api/my-ip${hintParam}`);
    if (res.ok) {
      const data = await res.json();
      if (data && data.ip) {
        appState.isLiveBackend = true;
        if (autoDetectTimer) {
          clearTimeout(autoDetectTimer);
          autoDetectTimer = null;
        }
        setDiscoveredHostIp(data);
        return;
      }
    }
  } catch (e) {
    console.warn("API my-ip connection error:", e);
  }

  // Fallback if backend API is unreachable or offline
  appState.isLiveBackend = false;
  const hostIpEl = document.getElementById('detectedHostIp');
  if (hostIpEl) hostIpEl.textContent = "รอ Backend...";

  const rangeEl = document.getElementById('detectedSubnetRange');
  if (rangeEl) rangeEl.textContent = "กรุณากรอก Subnet ด้านบนเพื่อคำนวณ";

  statusPillText.textContent = "ไม่พบ Backend · กำลังลองใหม่...";
  statusIndicatorDot.className = "w-2 h-2 rounded-full bg-amber-500 animate-ping";
  updateStepBadge("กรุณารัน ./run.sh เพื่อเชื่อมต่อเครื่องมือสแกนเนอร์", "ph-warning");

  // Auto-retry polling every 3 seconds until backend connects!
  if (!autoDetectTimer) {
    autoDetectTimer = setTimeout(() => {
      autoDetectTimer = null;
      autoDetectLocalNetwork();
    }, 3000);
  }
}