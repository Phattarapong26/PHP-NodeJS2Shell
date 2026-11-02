import { apiFetch } from './api';
import { btnHeroSearch, btnScanContent, btnScanSpinner, heroSearchInput, mainSubnetInput, quickPhpCount, radarSvg, scanElapsedDuration, scanPercentText, scanProgressBar, scanProgressStats, scanProgressWrapper, scanningRipple, statusIndicatorDot, statusPillText } from './dom';
import { parseSubnetDetails } from './network';
import { openResultsModal, renderResultsTable } from './results';
import { openProfileModal } from './shell';
import { appState } from './state';
import { delay, highlightWorkflowStep, showToast, updateStepBadge } from './ui';

export let currentScanAbortController = null;

export function cancelCurrentScan() {
  if (!appState.isScanning) return;
  if (currentScanAbortController) {
    currentScanAbortController.abort();
    currentScanAbortController = null;
  }
  appState.isScanning = false;
  finishScan("0");
  updateStepBadge("ยกเลิกการสแกนเรียบร้อย — ระบบพร้อมทำงาน", "ph-x-circle");
  showToast("ยกเลิกการสแกนแล้ว");
}

// Start 5-Step Scan Flow according to user's diagram
export async function startScanWorkflow() {
  if (appState.isScanning) return;

  // REQUIRE PROFILE SELECTION BEFORE SCANNING
  if (!appState.activeProfile) {
    openProfileModal(true);
    showToast("กรุณาเลือก Profile ที่ต้องการจะสแกน");
    return;
  }

  appState.isScanning = true;
  appState.scanStartTime = performance.now();
  appState.foundPhpHosts = [];
  appState.discardedDevices = [];

  const heroVal = heroSearchInput ? heroSearchInput.value.trim() : "";
  const mainVal = mainSubnetInput ? mainSubnetInput.value.trim() : "";
  const profileTarget = appState.activeProfile ? (appState.activeProfile.network_target || "").trim() : "";
  const targetSubnet = heroVal || mainVal || profileTarget || appState.subnet;
  if (!targetSubnet) {
    showToast("กรุณาระบุ Subnet หรือ IP เป้าหมายก่อนเริ่มสแกน");
    appState.isScanning = false;
    return;
  }
  if (heroVal && mainSubnetInput) {
    mainSubnetInput.value = heroVal;
  }

  const parsedTarget = parseSubnetDetails(targetSubnet);
  const totalToScan = parsedTarget ? parsedTarget.totalHosts : (appState.totalHosts || 254);

  // UI Changes: Activate Radar Spinning
  radarSvg.classList.add('animate-spin-radar-fast');
  scanningRipple.classList.add('animate-pulse-glow');
  scanningRipple.style.opacity = '1';
  btnScanContent.classList.add('hidden');
  btnScanSpinner.classList.remove('hidden');
  if (btnHeroSearch) {
    btnHeroSearch.disabled = true;
    btnHeroSearch.classList.add('opacity-50', 'cursor-not-allowed');
  }
  scanProgressWrapper.classList.remove('opacity-0');
  statusIndicatorDot.className = "w-2 h-2 rounded-full bg-blue-500 animate-ping";
  statusPillText.textContent = `Scanning LAN ${targetSubnet}...`;

  highlightWorkflowStep(0);

  // STEP 1: โปรแกรมอ่าน IP เครื่องตัวเองอัตโนมัติ
  await delay(200);
  highlightWorkflowStep(1);
  updateStepBadge(`1. ตรวจพบเป้าหมาย: ${targetSubnet}`, "ph-laptop");
  
  // STEP 2: คำนวณขอบเขตวง LAN (Subnet) อัตโนมัติ
  await delay(200);
  highlightWorkflowStep(2);
  updateStepBadge(`2. ตรวจสอบขอบเขตเป้าหมาย: ${parsedTarget ? parsedTarget.rangeText : targetSubnet}`, "ph-chart-pie-slice");

  // STEP 3: ส่งคำขอคู่ขนานแบบ Async (ความเร็วสูง)
  await delay(200);
  highlightWorkflowStep(3);
  const portCountInfo = (appState.selectedPorts && appState.selectedPorts.length) ? `(${appState.selectedPorts.length} พอร์ต)` : '';
  updateStepBadge(`3. ส่ง Async Parallel Request สแกน ${totalToScan.toLocaleString()} เครื่อง ${portCountInfo}...`, "ph-lightning");

  // Launch Async Request to Backend with AbortController
  currentScanAbortController = new AbortController();
  const scanPromise = (async () => {
    try {
      const res = await apiFetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          subnet: targetSubnet,
          concurrency: appState.concurrency,
          ports: appState.selectedPorts || null,
          allow_active_rce: Boolean(appState.allowActiveRce),
          i_own_this_target: Boolean(appState.allowActiveRce),
          consent_phrase: appState.allowActiveRce ? "I_CONFIRM_TARGET_OWNERSHIP" : "",
          user_agent: appState.customUserAgent || (appState.activeProfile ? appState.activeProfile.user_agent : null),
          custom_headers: appState.customHeaders || (appState.activeProfile ? appState.activeProfile.custom_headers : null),
          timeout: appState.scanTimeout || (appState.activeProfile ? appState.activeProfile.timeout : 2.2)
        }),
        signal: currentScanAbortController.signal
      });
      if (res.ok) {
        return await res.json();
      }
    } catch (e) {
      if (e.name === 'AbortError') {
        console.log("Scan cancelled by user");
      } else {
        console.warn("Scan fetch error:", e);
      }
    }
    return null;
  })();

  // Animate progress smoothly with live timer so UI NEVER freezes
  let p = 15;
  const progressTimer = setInterval(() => {
    if (!appState.isScanning) {
      clearInterval(progressTimer);
      return;
    }
    const elapsedSec = ((performance.now() - appState.scanStartTime) / 1000).toFixed(1);
    if (p < 92) {
      p += Math.max(1, Math.round((92 - p) * 0.15));
    }
    scanProgressBar.style.width = `${p}%`;
    scanPercentText.textContent = `${p}%`;
    scanProgressStats.textContent = `สแกน ${Math.round((p / 100) * totalToScan).toLocaleString()} / ${totalToScan.toLocaleString()} เครื่อง (${elapsedSec}s)`;
  }, 150);

  const backendData = await scanPromise;
  clearInterval(progressTimer);

  if (!appState.isScanning) {
    return; // Cancelled
  }
  currentScanAbortController = null;

  // STEP 4: จำแนกอุปกรณ์ในวง LAN และระบุเซิร์ฟเวอร์ PHP & Node.js
  highlightWorkflowStep(4);
  updateStepBadge(`4. จำแนกอุปกรณ์ในวง LAN และระบุเซิร์ฟเวอร์ PHP / Node.js...`, "ph-funnel");
  await delay(300);

  if (backendData) {
    appState.allHosts = backendData.all_hosts || [];
    appState.foundPhpHosts = backendData.results || [];
    appState.foundNodeHosts = backendData.node_results || [];
    appState.totalActiveFound = backendData.total_active_found || appState.allHosts.length;
    appState.totalPhpFound = backendData.total_php_found || appState.foundPhpHosts.length;
    appState.totalNodeFound = backendData.total_node_found || appState.foundNodeHosts.length;
    appState.totalVulnFound = backendData.total_vuln_found || 0;
    appState.discardedDevices = backendData.discarded || [];
    appState.thaicertSummary = backendData.thaicert_summary || {};
  } else {
    appState.allHosts = [];
    appState.foundPhpHosts = [];
    appState.foundNodeHosts = [];
    appState.totalActiveFound = 0;
    appState.totalPhpFound = 0;
    appState.totalNodeFound = 0;
    appState.totalVulnFound = 0;
    appState.discardedDevices = [];
    appState.thaicertSummary = {};
  }

  // Default to showing all discovered online devices
  appState.activeFilter = 'all_online';

  // Complete to 100%
  const actualScannedCount = (backendData && backendData.scanned_hosts_count) ? backendData.scanned_hosts_count : totalToScan;
  scanProgressBar.style.width = `100%`;
  scanPercentText.textContent = `100%`;
  scanProgressStats.textContent = `สแกนครบ ${actualScannedCount.toLocaleString()} เครื่องเรียบร้อย`;

  // STEP 5: แสดงรายการอุปกรณ์และผลตรวจความปลอดภัย
  highlightWorkflowStep(5);
  const phpCount = appState.totalPhpFound;
  const nodeCount = appState.totalNodeFound;
  const activeCount = appState.totalActiveFound;
  const vulnServers = appState.allHosts.filter(h => (h.is_php || h.is_node) && (h.vulnerability === 'Critical' || h.vulnerability === 'Outdated' || h.vulnerability === 'Warning')).length;

  if (vulnServers > 0) {
    updateStepBadge(`5. ตรวจพบความเสี่ยง ${vulnServers} เครื่อง! (PHP: ${phpCount}, Node.js: ${nodeCount})`, "ph-shield-warning");
  } else if (phpCount > 0 || nodeCount > 0) {
    updateStepBadge(`5. สแกนสำเร็จ! พบ PHP: ${phpCount}, Node.js: ${nodeCount} (${activeCount} เครื่องออนไลน์)`, "ph-check-circle");
  } else {
    updateStepBadge(`5. สแกนสำเร็จ! ตรวจพบ ${activeCount} เครื่องออนไลน์ (ทุกเครื่องปลอดภัย ไม่พบ PHP/Node.js)`, "ph-shield-check");
  }
  
  const scanElapsed = backendData && backendData.elapsed_seconds ? backendData.elapsed_seconds : ((performance.now() - appState.scanStartTime) / 1000).toFixed(2);
  scanElapsedDuration.textContent = `${scanElapsed} วินาที`;

  await delay(300);
  finishScan(scanElapsed);
}

export function finishScan(elapsedSec) {
  appState.isScanning = false;
  radarSvg.classList.remove('animate-spin-radar-fast');
  scanningRipple.classList.remove('animate-pulse-glow');
  scanningRipple.style.opacity = '0';
  btnScanContent.classList.remove('hidden');
  btnScanSpinner.classList.add('hidden');
  if (btnHeroSearch) {
    btnHeroSearch.disabled = false;
    btnHeroSearch.classList.remove('opacity-50', 'cursor-not-allowed');
  }
  
  statusIndicatorDot.className = "w-2 h-2 rounded-full bg-emerald-500";
  const totalOnline = appState.allHosts.length;
  const totalPhp = appState.foundPhpHosts.length;
  const totalNode = appState.foundNodeHosts.length;
  const totalVuln = appState.allHosts.filter(h => (h.is_php || h.is_node) && (h.vulnerability === 'Critical' || h.vulnerability === 'Outdated' || h.vulnerability === 'Warning')).length;
  
  statusPillText.textContent = `สแกนสำเร็จ (${elapsedSec}s) · ออนไลน์ ${totalOnline} เครื่อง · PHP: ${totalPhp} · Node.js: ${totalNode}`;

  const quickPhpCount = document.getElementById('quickPhpCount');
  if (quickPhpCount) {
    if (totalVuln > 0) {
      quickPhpCount.textContent = `พบความเสี่ยง ${totalVuln} เครื่อง (PHP/Node.js)`;
    } else if (totalPhp > 0 || totalNode > 0) {
      quickPhpCount.textContent = `พบเว็บ PHP ${totalPhp} | Node ${totalNode} (ปลอดภัย)`;
    } else {
      quickPhpCount.textContent = `ออนไลน์ ${totalOnline} เครื่อง (ปลอดภัย)`;
    }
  }

  // Sync active tab styling
  document.querySelectorAll('.filter-tab').forEach(t => {
    t.classList.toggle('active', t.getAttribute('data-filter') === appState.activeFilter);
  });

  // Render the Results Table (Step 5)
  renderResultsTable();

  // Automatically open the Results Modal
  openResultsModal();
}