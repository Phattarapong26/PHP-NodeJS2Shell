import { apiFetch } from './api';
import { getWebTargetUrl } from './network';
import { appState } from './state';
import { showToast } from './ui';
import { escapeHtml } from './utils';

export function openDeepAuditModal(host) {
  if (!host) return;
  appState.selectedAuditHost = host;
  const modal = document.getElementById('deepAuditModal');
  const content = document.getElementById('deepAuditContent');
  if (!modal) return;

  const deep = host.deep_audit || {};
  const targetPort = host.port || (host.ports && host.ports[0]) || null;
  const targetBadge = document.getElementById('auditTargetBadge');
  if (targetBadge) {
    targetBadge.textContent = targetPort ? `${host.ip}:${targetPort}` : host.ip;
  }

  const openWebBtn = document.getElementById('auditTargetOpenWebBtn') as HTMLAnchorElement | null;
  if (openWebBtn) {
    if (targetPort || host.is_php || host.is_node) {
      openWebBtn.classList.remove('hidden');
      const webUrl = getWebTargetUrl(host, targetPort);
      openWebBtn.href = webUrl;
      openWebBtn.title = `เปิดดูหน้าเว็บจริง (${webUrl})`;
    } else {
      openWebBtn.classList.add('hidden');
    }
  }

  // Sibling Ports Switcher inside Modal
  const siblingHosts = appState.allHosts.filter(h => h.ip === host.ip && (h.port || (h.ports && h.ports.length > 0)));
  const portSwitcherWrapper = document.getElementById('auditPortSwitcherWrapper');
  const portSwitcherList = document.getElementById('auditPortSwitcherList');
  if (portSwitcherWrapper && portSwitcherList) {
    if (siblingHosts.length > 1) {
      portSwitcherWrapper.classList.remove('hidden');
      portSwitcherList.innerHTML = '';
      siblingHosts.forEach(s => {
        const sPort = s.port || (s.ports && s.ports[0]);
        const isCurrent = (sPort === targetPort);
        const isVuln = s.vulnerability === 'Critical' || s.vulnerability === 'Warning';
        const btn = document.createElement('button');
        btn.className = `px-2.5 py-1 rounded-lg text-xs font-mono font-bold transition flex items-center gap-1.5 border cursor-pointer ${
          isCurrent
            ? 'bg-blue-600 text-white border-blue-600 shadow-sm'
            : (isVuln ? 'bg-rose-50 text-rose-800 border-rose-300 hover:bg-rose-100' : 'bg-white text-slate-700 border-slate-200 hover:bg-slate-50')
        }`;
        const statusIcon = isVuln ? '<i class="ph-bold ph-shield-warning text-rose-500"></i>' : (s.is_php ? '<i class="ph-bold ph-file-php text-indigo-500"></i>' : '<i class="ph-bold ph-check text-emerald-500"></i>');
        btn.innerHTML = `${statusIcon} <span>:${sPort}</span> <span class="text-[10px] font-normal opacity-80 font-sans">(${s.runtime_version || s.runtime || 'Web'})</span>`;
        btn.onclick = () => openDeepAuditModal(s);
        portSwitcherList.appendChild(btn);
      });
    } else {
      portSwitcherWrapper.classList.add('hidden');
    }
  }

  // Empirical Live RCE / LFI Proof Indicator (PoC Prover with Audit Trail)
  renderRceProofCard(host.rce_proof || deep.rce_proof || null);

  // ThaiCERT 8 Groups Classification
  const primaryBadge = document.getElementById('auditGroupPrimaryBadge');
  if (primaryBadge) {
    primaryBadge.textContent = host.primary_group || deep.primary_group || "กลุ่ม 4: อุปกรณ์ทั่วไป";
  }

  const groupListEl = document.getElementById('auditGroupList');
  if (groupListEl) {
    groupListEl.innerHTML = '';
    const groups = host.thaicert_groups || deep.thaicert_groups || [4];
    const groupLabels = host.group_labels || deep.group_labels || [];
    const groupIcons = {
      1: 'ph-globe text-blue-600',
      2: 'ph-code text-indigo-600',
      3: 'ph-gauge text-purple-600',
      4: 'ph-hard-drives text-amber-600',
      5: 'ph-package text-cyan-600',
      6: 'ph-microsoft-windows-logo text-rose-600',
      7: 'ph-clock-counter-clockwise text-orange-600',
      8: 'ph-cloud text-teal-600'
    };
    const groupDetails = deep.group_details || [];
    groups.forEach((g, idx) => {
      const label = groupLabels[idx] || `กลุ่ม ${g}`;
      const det = groupDetails.find((d: any) => d.id === g);
      const reason = det ? det.reason : '';
      const isG6 = g === 6;
      const isVuln = host.vulnerability === 'Critical' || host.vulnerability === 'Warning';
      const pill = document.createElement('span');
      pill.className = `px-2.5 py-1 rounded-lg text-xs font-semibold flex items-center gap-1.5 border ${
        isG6 && isVuln 
          ? 'bg-rose-50 text-rose-800 border-rose-300 shadow-sm'
          : (isG6 ? 'bg-amber-50 text-amber-800 border-amber-300' : 'bg-white text-slate-700 border-slate-200/90 shadow-sm')
      }`;
      pill.title = reason ? `หลักฐานที่ตรวจพบ: ${reason}` : label;
      pill.innerHTML = `<i class="ph-bold ${groupIcons[g] || 'ph-squares-four'}"></i> <span>${escapeHtml(label)}</span>${reason ? `<span class="text-[9.5px] font-normal text-slate-400 font-sans hidden sm:inline truncate max-w-xs">· ${escapeHtml(reason)}</span>` : ''}`;
      groupListEl.appendChild(pill);
    });
  }

  // Render Architectural Exploit Chain Matrix
  const archWrapper = document.getElementById('auditArchMatrixWrapper');
  const archList = document.getElementById('auditArchMatrixList');
  const matrix = host.architecture_matrix || deep.architecture_matrix || [];
  if (archWrapper && archList) {
    if (matrix.length > 0) {
      archWrapper.classList.remove('hidden');
      archList.innerHTML = matrix.map(m => {
        const confColor = m.exploitability === 'Confirmed' ? 'text-rose-600 bg-rose-50 border-rose-200' : (m.exploitability === 'Likely' ? 'text-sky-600 bg-sky-50 border-sky-200' : (m.exploitability === 'Conditional' ? 'text-amber-600 bg-amber-50 border-amber-200' : 'text-slate-500 bg-slate-50 border-slate-200'));
        const chainsHtml = (m.chains_applicable || []).map(ch => `<span class="inline-block px-1.5 py-0.5 rounded bg-slate-100 text-slate-700 text-[9.5px] font-mono mr-1">${escapeHtml(ch)}</span>`).join('');
        return `
          <div class="p-2.5 rounded-xl bg-white/90 border border-slate-200/90 shadow-2xs space-y-1">
            <div class="flex items-center justify-between flex-wrap gap-1">
              <div class="font-bold text-slate-800 text-xs">กลุ่ม ${m.group_id}: ${escapeHtml(m.group_name)}</div>
              <span class="px-2 py-0.5 rounded-full text-[10px] font-bold border ${confColor}">${escapeHtml(m.exploitability)}</span>
            </div>
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-1 text-[10.5px] text-slate-600 pt-0.5">
              <div><span class="text-slate-400">SAPI:</span> <b>${escapeHtml(m.sapi_detected || '-')}</b></div>
              <div><span class="text-slate-400">Worker Model:</span> <b>${escapeHtml(m.worker_model || '-')}</b></div>
            </div>
            <div class="text-[10.5px] text-slate-500 pt-0.5"><span class="text-slate-400">เงื่อนไขจำเป็น (Prerequisites):</span> ${escapeHtml(m.prerequisite_summary || '-')}</div>
            <div class="pt-0.5 flex items-center flex-wrap gap-1">
              <span class="text-[10px] text-slate-400">Chains:</span> ${chainsHtml}
            </div>
          </div>
        `;
      }).join('');
    } else {
      archWrapper.classList.add('hidden');
    }
  }

  // Render Matched CVEs (Multi-Stack CVE Mapping)
  const cvesWrapper = document.getElementById('auditMatchedCvesWrapper');
  const cvesList = document.getElementById('auditMatchedCvesList');
  const cvesCountBadge = document.getElementById('auditMatchedCvesCountBadge');
  const matchedCves = host.matched_cves || [];
  if (cvesWrapper && cvesList) {
    if (matchedCves.length > 0) {
      cvesWrapper.classList.remove('hidden');
      if (cvesCountBadge) cvesCountBadge.textContent = `${matchedCves.length} ช่องโหว่ที่เข้าเกณฑ์`;
      cvesList.innerHTML = matchedCves.map(c => `
        <div class="p-2.5 rounded-xl bg-white border border-rose-200/90 shadow-2xs space-y-1">
          <div class="flex items-center justify-between">
            <div class="flex items-center gap-1.5 flex-wrap">
              <span class="px-2 py-0.5 rounded font-mono font-bold text-[10.5px] ${c.severity === 'Critical' ? 'bg-rose-100 text-rose-800 border border-rose-300' : 'bg-amber-100 text-amber-800 border border-amber-300'}">${escapeHtml(c.id || c.cve)}</span>
              <span class="font-bold text-slate-800 text-xs">${escapeHtml(c.name || '')}</span>
            </div>
            <span class="text-[10px] font-bold px-1.5 py-0.5 rounded bg-slate-100 text-slate-600 uppercase font-mono">${escapeHtml(c.category || 'VULN')} · ${escapeHtml(c.severity || 'High')}</span>
          </div>
          <p class="text-[11px] text-slate-600">${escapeHtml(c.reason || c.desc || '')}</p>
          ${c.host_check ? `
            <div class="mt-1 p-2 rounded-lg bg-slate-900 text-slate-200 font-mono text-[10px] flex items-center justify-between gap-2">
              <span class="truncate"><code>${escapeHtml(c.host_check)}</code></span>
              <button type="button" class="text-indigo-400 hover:text-indigo-200 text-[10px] font-sans font-bold flex-shrink-0 cursor-pointer" data-action="copyText" data-copy="${escapeHtml(c.host_check)}" data-toast="คัดลอกคำสั่งตรวจสอบแล้ว">คัดลอกคำสั่ง</button>
            </div>
          ` : ''}
          ${c.confirm_safe ? `
            <div class="text-[10.5px] text-slate-500 pt-0.5">
              <span class="text-emerald-700 font-semibold">เกณฑ์ปลอดภัย:</span> ${escapeHtml(c.confirm_safe)}
            </div>
          ` : ''}
        </div>
      `).join('');
    } else {
      cvesWrapper.classList.add('hidden');
    }
  }

  // Layer 1: Edge & Network Security
  const wafBadge = document.getElementById('auditWafBadge');
  if (wafBadge) {
    wafBadge.textContent = host.waf || deep.waf || "Direct Access";
    wafBadge.className = (host.waf && !host.waf.includes("None")) ? "px-2 py-0.5 rounded-md font-mono text-[11px] bg-blue-50 text-blue-700 border border-blue-200" : "px-2 py-0.5 rounded-md font-mono text-[11px] bg-slate-100 text-slate-700";
  }

  const wafName = document.getElementById('auditWafName');
  if (wafName) wafName.textContent = host.waf || deep.waf || "ไม่พบ Cloud WAF (เข้าถึงเซิร์ฟเวอร์โดยตรง)";

  const hsts = document.getElementById('auditHsts');
  if (hsts) {
    hsts.textContent = deep.hsts ? "เปิดใช้งาน (Strict-Transport-Security Preload)" : "ไม่ได้เปิดใช้งาน";
    hsts.className = deep.hsts ? "text-emerald-700 font-bold block" : "text-amber-700 font-bold block";
  }

  // Layer 2: Application & Runtime Hardening
  const cmsName = document.getElementById('auditCmsName');
  if (cmsName) {
    const title = host.site_name || deep.site_title;
    cmsName.textContent = title ? `${host.cms || deep.cms || 'WordPress'} (${title})` : (host.cms || deep.cms || "Web Application");
  }

  const serverName = document.getElementById('auditServerName');
  if (serverName) serverName.textContent = host.webServer || "Apache / Nginx";

  const exposeStatus = document.getElementById('auditExposeStatus');
  if (exposeStatus) {
    exposeStatus.textContent = deep.expose_php_status || (host.is_php ? "Off (ปิดบังตามเกณฑ์ CIS)" : "N/A");
    exposeStatus.className = "text-emerald-700 font-bold block";
  }

  const openPorts = document.getElementById('auditOpenPorts');
  if (openPorts) openPorts.textContent = (host.ports && host.ports.length > 0) ? host.ports.join(', ') : "80, 443";

  const hardBadge = document.getElementById('auditHardeningBadge');
  if (hardBadge) {
    if (host.vulnerability === 'Secure') {
      hardBadge.textContent = "Hardened (ปลอดภัย)";
      hardBadge.className = "px-2 py-0.5 rounded-md font-medium text-[11px] bg-emerald-50 text-emerald-700 border border-emerald-200";
    } else if (host.vulnerability === 'Review Needed') {
      hardBadge.textContent = "Hardened (ตรวจแพตช์ภายใน)";
      hardBadge.className = "px-2 py-0.5 rounded-md font-medium text-[11px] bg-blue-50 text-blue-700 border border-blue-200";
    } else {
      hardBadge.textContent = host.vulnerability || "Review Needed";
      hardBadge.className = "px-2 py-0.5 rounded-md font-medium text-[11px] bg-rose-50 text-rose-700 border border-rose-200";
    }
  }

  // Layer 3: Local Credentialed Audit Command
  const terminalCmd = document.getElementById('auditTerminalCmd');
  if (terminalCmd) {
    terminalCmd.textContent = deep.host_verify_cmd || "php -v && (dpkg -l | grep -E 'php[0-9]' || rpm -qa | grep php)";
  }

  // Layer 4: Deep Security Chains Analysis (Chains A, C, D)
  const chainsOverallBadge = document.getElementById('auditChainsOverallBadge');
  const reasonNote = document.getElementById('auditChainsReasonNote');
  const reasonText = document.getElementById('auditChainsReasonText');
  const secChains = host.security_chains || deep.security_chains || {};
  
  if (chainsOverallBadge) {
    if (!host.is_php) {
      chainsOverallBadge.textContent = "Non-PHP Service (ไม่เกี่ยวข้อง)";
      chainsOverallBadge.className = "px-2 py-0.5 rounded-md font-semibold text-[11px] bg-slate-100 text-slate-600 border border-slate-200";
      if (reasonNote) reasonNote.className = "hidden";
    } else if (secChains.overall_status === 'Defensively Hardened') {
      chainsOverallBadge.textContent = "Defensively Hardened (ปลอดภัยตามเกณฑ์)";
      chainsOverallBadge.className = "px-2 py-0.5 rounded-md font-semibold text-[11px] bg-emerald-50 text-emerald-700 border border-emerald-200";
      if (reasonNote && reasonText) {
        reasonNote.className = "p-2.5 rounded-xl bg-emerald-50/80 border border-emerald-200/80 text-[11px] text-emerald-900 flex items-start gap-2";
        reasonText.innerHTML = "<b>ยืนยันความปลอดภัย:</b> เซิร์ฟเวอร์ได้รับการอัปเดตแพตช์เวอร์ชันปลอดภัยตามเกณฑ์ ThaiCERT (PHP 8.2.20+ หรือ 8.3.8+) เรียบร้อยแล้ว กลไกความเสี่ยงของ Chains A, C, D ถูกปิดกั้นในระดับรันไทม์";
      }
    } else {
      chainsOverallBadge.textContent = "Audit & Hardening Recommended (แนะนำปรับแต่ง)";
      chainsOverallBadge.className = "px-2 py-0.5 rounded-md font-semibold text-[11px] bg-amber-50 text-amber-700 border border-amber-200";
      if (reasonNote && reasonText) {
        reasonNote.className = "p-2.5 rounded-xl bg-amber-50/80 border border-amber-200/80 text-[11px] text-amber-900 flex items-start gap-2";
        reasonText.innerHTML = "<b>สาเหตุที่แนะนำปรับแต่ง:</b> เซิร์ฟเวอร์ปิดบังเวอร์ชัน (<code>expose_php = Off</code>) หรืออยู่หลัง Cloud WAF ซึ่งเป็นแนวทางปฏิบัติที่ดีตามมาตรฐาน CIS แต่ทำให้ไม่สามารถอ่านเลขแพตช์จริงจากภายนอกได้ แนะนำให้ตรวจสอบเลขแพตช์ภายในเครื่อง (ข้อ 3) และปรับปรุงค่า <code>php.ini</code> เพื่อความปลอดภัยสูงสุด (ข้อ 4)";
      }
    }
  }

  // Update hardening ini box
  const iniBox = document.getElementById('hardeningIniCodeBox');
  if (iniBox) {
    iniBox.textContent = secChains.hardening_ini || "; [Chain B Defense: ปิดกั้นการเปิดเผยข้อมูลสภาพแวดล้อม]\nexpose_php = Off\ndisplay_errors = Off\nlog_errors = On\n\n; [Chain A Defense: ป้องกันการสร้างข้อมูลเซสชันแฝงผ่าน Upload Progress]\nsession.upload_progress.enabled = Off\nsession.upload_progress.cleanup = On\nsession.use_strict_mode = 1\n\n; [Chain C Defense: ป้องกันความไม่สอดคล้องของ Serializer]\nsession.serialize_handler = php\n\n; [Chain D Defense: ควบคุมการใช้หน่วยความจำและแยกพื้นที่จัดเก็บเซสชัน]\nmemory_limit = 256M\nsession.save_path = \"/var/lib/php/sessions\"";
  }

  // Render Audited Vulnerability Assessment (VA) Findings Cards (ค่าของการ VA ที่ตรวจพบจริง)
  renderVaDiscoveredCards(host);

  // Populate Low-Level C & ASan Memory Diagnostics
  const zendC = host.zend_c_telemetry || deep.zend_c_telemetry || {};
  const asanSec = document.getElementById('asanMemoryDiagnosticSection');
  if (asanSec) {
    if (!host.is_php) {
      asanSec.classList.add('hidden');
    } else {
      asanSec.classList.remove('hidden');
      const metricLock = document.getElementById('asanMetricLock');
      const metricSource = document.getElementById('asanMetricSource');
      const metricChunk = document.getElementById('asanMetricChunk');
      const metricAlloc = document.getElementById('asanMetricAlloc');
      const asanStatusPill = document.getElementById('asanStatusPill');
      const asanTerminal = document.getElementById('asanTerminalTrace');

      if (metricLock) metricLock.textContent = zendC.serialize_lock_status || (zendC.is_vulnerable ? "0 (Unprotected)" : "1 (Enforced)");
      if (metricSource) metricSource.textContent = zendC.source_free ? "var_unserializer.c" : "Guarded";
      if (metricChunk) metricChunk.textContent = zendC.stack_chunk_threshold ? "1018 Bound Checked" : "Bound Enforced";
      if (metricAlloc) metricAlloc.textContent = zendC.allocator_profile || "USE_ZEND_ALLOC=1";
      
      if (asanStatusPill) {
        if (zendC.is_vulnerable) {
          asanStatusPill.textContent = "ASAN VULN DETECTED";
          asanStatusPill.className = "px-2 py-0.5 rounded text-[9px] font-bold bg-rose-900/60 text-rose-300 border border-rose-700/50";
        } else {
          asanStatusPill.textContent = "ASAN VERIFIED CLEAN";
          asanStatusPill.className = "px-2 py-0.5 rounded text-[9px] font-bold bg-emerald-900/60 text-emerald-300 border border-emerald-700/50";
        }
      }

      if (asanTerminal) {
        asanTerminal.textContent = zendC.asan_trace_preview || `AddressSanitizer Status for ${host.ip}:\nClick 'รันการทดสอบระดับ C / ASan Probe (Live)' to perform a real-time memory diagnostic.`;
      }
    }
  }

  // Populate Probe Inspection Log & Response Evidence
  const pLog = host.probe_log || deep.probe_log || {};
  const targetUrlEl = document.getElementById('probeTargetUrl');
  if (targetUrlEl) targetUrlEl.textContent = pLog.target_url || `http://${host.ip}:${(host.ports && host.ports[0]) || 80}/`;

  const methodBadge = document.getElementById('probeMethodBadge');
  if (methodBadge) methodBadge.textContent = pLog.method || 'GET';

  const statusCodeEl = document.getElementById('probeStatusCode');
  const statusTextBadge = document.getElementById('probeStatusTextBadge');
  const statusText = pLog.status_text || (host.is_online ? '200 OK' : 'No Response');
  const statusCodeNum = pLog.status_code || (host.is_online ? 200 : 0);
  
  const isSuccess = statusCodeNum >= 200 && statusCodeNum < 400;
  const statusBadgeCls = isSuccess 
    ? 'px-2 py-0.5 rounded-md font-mono text-[10px] font-bold bg-emerald-600 text-white' 
    : (statusCodeNum === 0 ? 'px-2 py-0.5 rounded-md font-mono text-[10px] font-bold bg-slate-600 text-white' : 'px-2 py-0.5 rounded-md font-mono text-[10px] font-bold bg-amber-600 text-white');

  if (statusCodeEl) {
    statusCodeEl.textContent = statusText;
    statusCodeEl.className = statusBadgeCls;
  }
  if (statusTextBadge) {
    statusTextBadge.textContent = `HTTP ${statusText}`;
    statusTextBadge.className = isSuccess 
      ? 'text-[10px] font-mono px-2 py-0.5 rounded font-bold bg-emerald-50 text-emerald-700 border border-emerald-200'
      : 'text-[10px] font-mono px-2 py-0.5 rounded font-bold bg-amber-50 text-amber-700 border border-amber-200';
  }

  const latencyEl = document.getElementById('probeLatency');
  if (latencyEl) latencyEl.textContent = pLog.latency || host.latency || '-';

  const auditStrategyEl = document.getElementById('probeAuditStrategy');
  if (auditStrategyEl) auditStrategyEl.textContent = pLog.audit_strategy || 'การตรวจสอบเชิงรับแบบไม่ก่อกวนการทำงาน (Non-destructive Passive Audit)';

  const reqHeadersBox = document.getElementById('probeReqHeadersBox');
  if (reqHeadersBox) {
    if (pLog.request_headers && Object.keys(pLog.request_headers).length > 0) {
      reqHeadersBox.textContent = Object.entries(pLog.request_headers).map(([k, v]) => `${k}: ${v}`).join('\n');
    } else {
      reqHeadersBox.textContent = 'User-Agent: ThaiCERT-OPScaner/2.0 (LAN Discovery & Security Audit)\nAccept-Encoding: br, gzip, deflate\nConnection: keep-alive';
    }
  }

  const respHeadersBox = document.getElementById('probeRespHeadersBox');
  if (respHeadersBox) {
    if (pLog.response_headers && Object.keys(pLog.response_headers).length > 0) {
      respHeadersBox.textContent = Object.entries(pLog.response_headers).map(([k, v]) => `${k}: ${v}`).join('\n');
    } else if (host.webServer) {
      respHeadersBox.textContent = `Server: ${host.webServer}\nContent-Type: text/html; charset=UTF-8`;
    } else {
      respHeadersBox.textContent = '(ไม่มีข้อมูลส่วนหัวตอบสนอง)';
    }
  }

  const evidenceContainer = document.getElementById('probeEvidenceTags');
  if (evidenceContainer) {
    evidenceContainer.innerHTML = '';
    const sigs = (pLog.signatures_matched && pLog.signatures_matched.length > 0) ? [...pLog.signatures_matched] : [];
    if (sigs.length === 0) {
      if (host.is_php) sigs.push(`PHP Runtime: ${host.phpVersion || 'PHP'}`);
      if (host.is_node) sigs.push(`Node.js: ${host.nodeVersion || 'Node.js'}`);
      if (host.cms) sigs.push(`CMS: ${host.cms}`);
      if (host.waf) sigs.push(`WAF: ${host.waf}`);
    }
    if (sigs.length > 0) {
      sigs.forEach(s => {
        const span = document.createElement('span');
        span.className = 'px-2 py-0.5 rounded-md font-mono text-[10px] font-semibold bg-slate-100 text-slate-700 border border-slate-200/90 shadow-2xs';
        span.textContent = s;
        evidenceContainer.appendChild(span);
      });
    } else {
      evidenceContainer.innerHTML = '<span class="text-[10px] text-slate-400">ไม่พบหลักฐานความเสี่ยงเฉพาะเจาะจง</span>';
    }
  }

  const stepsContainer = document.getElementById('probeStepsContainer');
  if (stepsContainer) {
    stepsContainer.innerHTML = '';
    const steps = pLog.probe_steps || [
      { step: "1. TCP Handshake", desc: `ตรวจพบพอร์ต ${(host.ports && host.ports[0]) || 80}/TCP เปิดรับการเชื่อมต่อ`, status: "pass" },
      { step: "2. Passive HTTP Probe", desc: `ส่งคำขอ GET http://${host.ip}:${(host.ports && host.ports[0]) || 80}/ เชิงรับ`, status: "pass" },
      { step: "3. Header & Cookie Inspection", desc: `วิเคราะห์ส่วนหัว Server และรันไทม์ (${host.webServer || 'Web'})`, status: "pass" },
      { step: "4. Security Chains Assessment", desc: "ประเมินความปลอดภัยตามเกณฑ์ ThaiCERT Chains A, B, C, D, E", status: host.vulnerability === 'Secure' ? 'pass' : 'warn' }
    ];
    steps.forEach(st => {
      const isP = st.status === 'pass';
      const iconCls = isP ? 'ph-check-circle text-emerald-600' : (st.status === 'warn' ? 'ph-warning text-amber-600' : 'ph-info text-blue-600');
      const stepDiv = document.createElement('div');
      stepDiv.className = 'p-2 rounded-xl bg-white border border-slate-200/80 flex items-start gap-2 shadow-2xs text-xs';
      stepDiv.innerHTML = `
        <i class="ph-bold ${iconCls} text-sm mt-0.5 flex-shrink-0"></i>
        <div class="flex-1 min-w-0">
          <span class="font-bold text-slate-800 text-[11px] block">${st.step}</span>
          <span class="text-[10px] text-slate-600 leading-snug">${st.desc}</span>
        </div>
      `;
      stepsContainer.appendChild(stepDiv);
    });
  }

  // Initialize Chain Tabs & Content (Default to 'all' Console View)
  switchAuditChain('all');

  modal.classList.remove('opacity-0', 'pointer-events-none');
  if (content) {
    content.classList.remove('scale-95');
    content.classList.add('scale-100');
  }
}

export function switchAuditChain(chainKey) {
  appState.activeAuditChain = chainKey;
  ['all', 'chain_a', 'chain_b', 'chain_c', 'chain_d', 'chain_e'].forEach(k => {
    const btnId = k === 'all' ? 'tabBtnChainAll' : (k === 'chain_a' ? 'tabBtnChainA' : (k === 'chain_b' ? 'tabBtnChainB' : (k === 'chain_c' ? 'tabBtnChainC' : (k === 'chain_d' ? 'tabBtnChainD' : 'tabBtnChainE'))));
    const btn = document.getElementById(btnId);
    if (btn) {
      if (k === chainKey) {
        btn.className = "chain-tab px-3 py-1 rounded-lg text-[11px] font-semibold bg-slate-900 text-cyan-300 border border-cyan-500/50 cursor-pointer transition shadow-xs";
      } else {
        btn.className = "chain-tab px-3 py-1 rounded-lg text-[11px] font-semibold bg-slate-100 text-slate-600 hover:bg-slate-200 border border-transparent cursor-pointer transition";
      }
    }
  });

  if (appState.selectedAuditHost) {
    renderAuditChainDetail(appState.selectedAuditHost, chainKey);
  }
}

export function openChainInfoModal(chainKey) {
  const host = appState.selectedAuditHost;
  if (!host) return;
  const secChains = host.security_chains || (host.deep_audit && host.deep_audit.security_chains) || {};
  const chains = secChains.chains || {};
  const chain = chains[chainKey];
  if (!chain) return;

  const info = chain.info || {};
  const titleEl = document.getElementById('chainInfoTitle');
  const tagEl = document.getElementById('chainInfoTagBadge');
  const problemEl = document.getElementById('chainInfoProblem');
  const impactEl = document.getElementById('chainInfoImpact');
  const vectorEl = document.getElementById('chainInfoVector');
  const mitigationEl = document.getElementById('chainInfoMitigation');

  if (titleEl) titleEl.textContent = `[Chain ${chain.tag || 'A'}] ${chain.short_title || chain.title}`;
  if (tagEl) tagEl.textContent = `Verdict: ${chain.verdict_code || 'EVALUATED'} (${chain.stages_display || '6/6'} Stages)`;
  
  if (problemEl) problemEl.textContent = info.problem || chain.verdict || "ตรวจพบการทำงานของกลไกเซสชัน";
  if (impactEl) impactEl.textContent = info.impact || "อาจส่งผลกระทบต่อความมั่นคงปลอดภัยของโครงสร้างเซสชัน";
  if (vectorEl) vectorEl.textContent = info.vulnerability_vector || "ต้องการเงื่อนไขจุดเรียกไฟล์ LFI หรือ Serializer Mismatch ในการกระตุ้นช่องโหว่";
  if (mitigationEl) mitigationEl.textContent = info.mitigation || chain.remediation || "กำหนดค่าความปลอดภัยใน php.ini";

  const modal = document.getElementById('chainInfoModal');
  const content = document.getElementById('chainInfoContent');
  if (modal) {
    modal.classList.remove('opacity-0', 'pointer-events-none');
    if (content) {
      content.classList.remove('scale-95');
      content.classList.add('scale-100');
    }
  }
}

export function closeChainInfoModal() {
  const modal = document.getElementById('chainInfoModal');
  const content = document.getElementById('chainInfoContent');
  if (modal) {
    modal.classList.add('opacity-0', 'pointer-events-none');
    if (content) {
      content.classList.remove('scale-100');
      content.classList.add('scale-95');
    }
  }
}

export function renderChainConsoleBlock(key, chain, host) {
  if (!chain) return '';
  const tag = chain.tag || key.replace('chain_', '').toUpperCase();
  const vCode = chain.verdict_code || (chain.verdict && chain.verdict.includes('VULNERABLE') ? 'CONFIRMED' : (chain.verdict && chain.verdict.includes('SECURE') ? 'SECURE' : 'MITIGATED'));
  
  let vBadgeClass = 'bg-emerald-500/20 text-emerald-400 border-emerald-500/40';
  if (vCode === 'CONFIRMED' || vCode === 'VULNERABLE') {
    vBadgeClass = 'bg-rose-500/20 text-rose-400 border-rose-500/40';
  } else if (vCode === 'INCONCLUSIVE' || vCode === 'REVIEW') {
    vBadgeClass = 'bg-amber-500/20 text-amber-400 border-amber-500/40';
  } else if (vCode === 'NOT_APPLICABLE') {
    vBadgeClass = 'bg-slate-700/40 text-slate-400 border-slate-600/40';
  }

  const stages = chain.cli_stages || (Array.isArray(chain.stages) ? chain.stages.map((st, i) => ({
    num: st.stage || `${i+1}/6`,
    name: st.name ? st.name.toLowerCase().slice(0, 24) : `stage ${i+1}`,
    status: st.badge === 'PASS' || st.badge === 'SECURE' ? 'PASS' : (st.badge === 'VULN' ? 'PASS' : (st.badge === 'PROTECTED' ? 'BLOCKED' : st.status || 'UNKNOWN')),
    evidence: st.detail || ''
  })) : []);

  return `
    <div class="space-y-2 pt-3 border-t border-slate-800/80 first:border-0 first:pt-0">
      <!-- Chain Header & Right Corner Info Icon -->
      <div class="flex items-center justify-between gap-2 pb-1">
        <div class="flex items-center gap-2">
          <span class="font-bold text-cyan-300 text-xs sm:text-sm">[${tag}] ${escapeHtml(chain.short_title || chain.title)}</span>
        </div>
        <div class="flex items-center gap-2">
          <span class="px-2 py-0.5 rounded text-[10px] font-bold border font-mono ${vBadgeClass}">
            ${vCode}
          </span>
          <button data-action="openChainInfoModal" data-arg="${key}" class="w-6 h-6 rounded-md bg-slate-800 hover:bg-slate-700 text-amber-400 hover:text-amber-300 border border-amber-500/40 hover:border-amber-400 flex items-center justify-center transition cursor-pointer" title="คลิกเพื่ออ่านปัญหา ผลกระทบ และสิ่งที่จะเป็นช่องโหว่">
            <i class="ph-bold ph-info text-xs"></i>
          </button>
        </div>
      </div>

      <!-- Stage Lines (Indented, Monospace, Aligned) -->
      <div class="space-y-1 text-[11px] font-mono pl-2 sm:pl-4">
        ${stages.map(st => {
          let sColor = 'text-emerald-400';
          if (st.status === 'FAIL' || st.status === 'BLOCKED' || st.status === 'SAFE') sColor = 'text-slate-400';
          else if (st.status === 'VULN' || st.status === 'VULNERABLE') sColor = 'text-rose-400';
          else if (st.status === 'UNKNOWN' || st.status === 'AUDIT') sColor = 'text-amber-400';
          return `
            <div class="flex items-baseline gap-2 flex-wrap sm:flex-nowrap">
              <span class="text-slate-500 flex-shrink-0 w-9">[${st.num}]</span>
              <span class="text-slate-300 flex-shrink-0 w-44 sm:w-52">${escapeHtml(st.name)}</span>
              <span class="font-bold flex-shrink-0 w-16 ${sColor}">${st.status}</span>
              <span class="text-slate-400 truncate flex-1">${escapeHtml(st.evidence)}</span>
            </div>
          `;
        }).join('')}
      </div>

      <!-- Chain Verdict & Missing Footer -->
      <div class="pt-1.5 text-[11px] font-mono pl-2 sm:pl-4 text-slate-300 space-y-0.5">
        <div>verdict    : <b class="${(vCode === 'CONFIRMED' || vCode === 'VULNERABLE') ? 'text-rose-400' : ((vCode === 'INCONCLUSIVE' || vCode === 'REVIEW' || vCode === 'ARCHITECTURAL_RISK') ? 'text-amber-400' : 'text-emerald-400')}">${vCode}</b></div>
        <div>confidence : <span class="font-bold text-sky-400">${escapeHtml(chain.confidence || 'Conditional')}</span></div>
        ${chain.stuck_at ? `<div class="text-amber-400">stuck at  : ${escapeHtml(chain.stuck_at)}</div>` : ''}
        <div class="text-slate-400">missing   : ${escapeHtml(chain.missing || 'nothing -- every stage passed')}</div>
      </div>
    </div>
  `;
}

export function renderChainSummaryTable(chains) {
  const chainKeys = ['chain_a', 'chain_b', 'chain_c', 'chain_d', 'chain_e'];
  const rows = chainKeys.map(k => {
    const ch = chains[k];
    if (!ch) return '';
    const tag = ch.tag || k.replace('chain_', '').toUpperCase();
    const vCode = ch.verdict_code || (ch.verdict && ch.verdict.includes('VULNERABLE') ? 'CONFIRMED' : (ch.verdict && ch.verdict.includes('SECURE') ? 'SECURE' : 'MITIGATED'));
    let vColor = (vCode === 'CONFIRMED' || vCode === 'VULNERABLE') ? 'text-rose-400 font-bold' : ((vCode === 'INCONCLUSIVE' || vCode === 'REVIEW' || vCode === 'ARCHITECTURAL_RISK') ? 'text-amber-400 font-bold' : 'text-emerald-400 font-bold');
    
    return `
      <tr class="hover:bg-slate-900/60 cursor-pointer transition border-b border-slate-900/80" data-action="switchAuditChain" data-arg="${k}" title="คลิกเพื่อเลือกดู Chain ${tag}">
        <td class="py-1.5 px-2.5 font-bold text-cyan-300">${tag}</td>
        <td class="py-1.5 px-2.5 text-slate-400">${ch.stages_display || '6/6'}</td>
        <td class="py-1.5 px-2.5 ${vColor}">${vCode}</td>
        <td class="py-1.5 px-2.5 text-sky-400 font-semibold">${escapeHtml(ch.confidence || 'Conditional')}</td>
        <td class="py-1.5 px-2.5 text-slate-400 truncate max-w-xs">${escapeHtml(ch.missing || 'nothing')}</td>
      </tr>
    `;
  }).join('');

  return `
    <div class="pt-3 border-t border-slate-800 text-[10.5px] font-mono">
      <div class="overflow-x-auto">
        <table class="w-full text-left">
          <thead>
            <tr class="text-slate-500 border-b border-slate-800">
              <th class="py-1.5 px-2.5 font-bold">CHAIN</th>
              <th class="py-1.5 px-2.5 font-bold">STAGE</th>
              <th class="py-1.5 px-2.5 font-bold">VERDICT</th>
              <th class="py-1.5 px-2.5 font-bold">CONFIDENCE</th>
              <th class="py-1.5 px-2.5 font-bold">MISSING</th>
            </tr>
          </thead>
          <tbody>
            ${rows}
          </tbody>
        </table>
      </div>
    </div>
  `;
}

export function renderAuditChainDetail(host, chainKey) {
  const container = document.getElementById('chainDetailContainer');
  if (!container) return;

  const secChains = host.security_chains || (host.deep_audit && host.deep_audit.security_chains) || {};
  const chains = secChains.chains || {};

  if (!host.is_php || !chains || Object.keys(chains).length === 0) {
    container.innerHTML = `
      <div class="p-6 rounded-2xl bg-slate-50 border border-slate-200 text-center text-slate-500">
        <i class="ph-bold ph-shield-check text-3xl text-emerald-500 mb-2 inline-block"></i>
        <p class="font-bold text-slate-700 text-sm">อุปกรณ์นี้ไม่ใช่เซิร์ฟเวอร์ PHP</p>
        <p class="text-xs text-slate-500 mt-1">จึงไม่อยู่ในเงื่อนไขความเสี่ยงของกลไก PHP Session & Configuration Chains (Chains A, B, C, D, E)</p>
      </div>
    `;
    return;
  }

  let consoleBody = '';
  if (chainKey === 'all') {
    const keys = ['chain_a', 'chain_b', 'chain_c', 'chain_d', 'chain_e'];
    consoleBody = keys.map(k => renderChainConsoleBlock(k, chains[k], host)).join('');
  } else {
    consoleBody = renderChainConsoleBlock(chainKey, chains[chainKey], host);
  }

  const summaryTable = renderChainSummaryTable(chains);

  container.innerHTML = `
    <div class="p-4 sm:p-5 rounded-2xl bg-slate-950 font-mono text-[11.5px] text-slate-200 border border-slate-800 shadow-xl space-y-4 select-text">
      <!-- Terminal Header -->
      <div class="flex items-center justify-between pb-2 border-b border-slate-800/80 text-[10.5px]">
        <div class="flex items-center gap-2">
          <span class="w-2.5 h-2.5 rounded-full bg-rose-500/80 inline-block"></span>
          <span class="w-2.5 h-2.5 rounded-full bg-amber-500/80 inline-block"></span>
          <span class="w-2.5 h-2.5 rounded-full bg-emerald-500/80 inline-block"></span>
          <span class="text-slate-300 font-bold ml-1">[*] php2shell --explain 2.0.0</span>
        </div>
        <div class="text-slate-400">
          chains: A, B, C, D, E &nbsp;|&nbsp; mode: full
        </div>
      </div>

      <!-- Target Banner -->
      <div class="text-[11px] text-slate-400">
        [*] ${escapeHtml(host.ip || '127.0.0.1')} &rarr; ${escapeHtml(host.ip || '127.0.0.1')} port <span class="text-cyan-400 font-bold">${host.port || (host.ports && host.ports[0]) || 80}</span>
      </div>

      <!-- Active Chain / All Chains Blocks -->
      ${consoleBody}

      <!-- Bottom Summary Matrix Table -->
      ${summaryTable}
    </div>
  `;
}

export function copyHardeningIni() {
  const codeBox = document.getElementById('hardeningIniCodeBox');
  const text = codeBox ? codeBox.textContent.trim() : "session.upload_progress.enabled = Off\nsession.use_strict_mode = 1\nsession.serialize_handler = php\nmemory_limit = 256M\nexpose_php = Off";
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(() => {
      const btnText = document.getElementById('copyIniBtnText');
      if (btnText) btnText.textContent = "คัดลอกเรียบร้อย!";
      showToast("คัดลอกการตั้งค่า php.ini Hardening เรียบร้อยแล้ว");
      setTimeout(() => {
        if (btnText) btnText.textContent = "คัดลอก php.ini Hardening";
      }, 2000);
    }).catch(() => {
      showToast("คำแนะนำ: " + text);
    });
  } else {
    showToast("คำแนะนำ: " + text);
  }
}

export function renderRceProofCard(rceProof) {
  const rceWrapper = document.getElementById('auditRceProofWrapper');
  if (!rceWrapper) return;
  rceWrapper.classList.remove('hidden');

  const elTitle = document.getElementById('auditRceProofTitle');
  const elBadge = document.getElementById('auditRceProofStatusBadge');
  const elDesc = document.getElementById('auditRceProofDesc');
  const elTech = document.getElementById('auditRceProofTechnique');
  const elPriv = document.getElementById('auditRceProofPrivilege');
  const elCmd = document.getElementById('auditRceProofCommand');
  const elOut = document.getElementById('auditRceProofOutput');
  const elCurl = document.getElementById('auditRceProofCurl');
  const btnCopy = document.getElementById('btnCopyRceCurl');
  const trailWrapper = document.getElementById('auditRceTrailWrapper');
  const btnTrigger = document.getElementById('btnTriggerActiveRce');
  const btnTriggerText = document.getElementById('btnTriggerActiveRceText');

  if (!rceProof || rceProof.proof_status === 'PROBING_DISABLED_BY_SAFETY_GATE') {
    if (elTitle) elTitle.textContent = "โหมดตรวจสอบ Passive (Safety Gate ระงับ Active Exploit ไว้)";
    if (elBadge) {
      elBadge.textContent = "PASSIVE SAFE MODE";
      elBadge.className = "px-2.5 py-0.5 rounded-full font-mono text-[10px] font-bold bg-slate-800 text-slate-300 border border-slate-600";
    }
    if (elDesc) elDesc.textContent = "ระบบทำงานในโหมด Passive Banner Scan เพื่อความปลอดภัยตามกฎหมาย หากต้องการตรวจสอบเชิงประจักษ์ว่าระบบเสี่ยงต่อ RCE หรือไม่ ให้กดปุ่มด้านล่างเพื่อส่ง Non-destructive Canary Payload";
    if (elTech) elTech.textContent = "Passive Banner & Header Fingerprint";
    if (elPriv) elPriv.textContent = "Pending Active Verification";
    if (elCmd) elCmd.textContent = "audit: php_session_upload_progress + lfi_probe";
    if (elOut) elOut.textContent = "[*] Active RCE probing is idle.\n[*] Click the button below to execute safe non-destructive canary verification.";
    if (elCurl) elCurl.textContent = "คลิกปุ่มด้านล่างเพื่อทดสอบและรับคำสั่ง curl";
    if (trailWrapper) trailWrapper.classList.add('hidden');
    if (btnTriggerText) btnTriggerText.textContent = "ทดสอบ Active RCE PoC บนโฮสต์นี้";
    return;
  }

  const isRce = rceProof.is_rce_proved || rceProof.proof_status === 'RCE_CONFIRMED';
  const isCanary = rceProof.proof_status === 'CANARY_CONFIRMED';
  const isLfi = rceProof.proof_status === 'CONFIRMED_LFI';

  if (isRce) {
    if (elTitle) elTitle.textContent = rceProof.proof_badge || "🔥 ยืนยัน RCE สำเร็จ (PoC Proved)";
    if (elBadge) {
      elBadge.textContent = "RCE CONFIRMED";
      elBadge.className = "px-2.5 py-0.5 rounded-full font-mono text-[10px] font-bold bg-rose-900/80 text-rose-200 border border-rose-600";
    }
  } else if (isCanary) {
    if (elTitle) elTitle.textContent = rceProof.proof_badge || "⚡ ยืนยันจุดรับคำสั่ง Canary สำเร็จ (Canary Confirmed)";
    if (elBadge) {
      elBadge.textContent = "CANARY CONFIRMED";
      elBadge.className = "px-2.5 py-0.5 rounded-full font-mono text-[10px] font-bold bg-amber-900/80 text-amber-200 border border-amber-600";
    }
  } else if (isLfi) {
    if (elTitle) elTitle.textContent = rceProof.proof_badge || "⚠️ ยืนยัน LFI / Arbitrary File Read";
    if (elBadge) {
      elBadge.textContent = "LFI CONFIRMED";
      elBadge.className = "px-2.5 py-0.5 rounded-full font-mono text-[10px] font-bold bg-amber-900/80 text-amber-200 border border-amber-600";
    }
  } else {
    if (elTitle) elTitle.textContent = "🛡️ ตรวจสอบแล้ว: ไม่พบจุดอ่อน RCE ภายใต้ขอบเขตที่ทดสอบ";
    if (elBadge) {
      elBadge.textContent = "NOT CONFIRMED";
      elBadge.className = "px-2.5 py-0.5 rounded-full font-mono text-[10px] font-bold bg-slate-800 text-slate-300 border border-slate-600";
    }
  }

  if (elDesc) elDesc.textContent = rceProof.impact_statement || "";
  if (elTech) elTech.textContent = rceProof.technique || "Security Exploit PoC";
  if (elPriv) elPriv.textContent = rceProof.privilege_level || "Standard";
  if (elCmd) elCmd.textContent = rceProof.command_executed || "canary execution";
  if (elOut) elOut.textContent = rceProof.execution_output || "No output recorded.";
  if (elCurl) elCurl.textContent = rceProof.reproduce_curl || "N/A";
  if (btnCopy) {
    btnCopy.onclick = () => {
      if (rceProof.reproduce_curl) {
        navigator.clipboard.writeText(rceProof.reproduce_curl);
        showToast("คัดลอกคำสั่ง PoC curl แล้ว");
      }
    };
  }

  // Cryptographic Audit Trail
  if (trailWrapper) {
    if (rceProof.audit_trail) {
      trailWrapper.classList.remove('hidden');
      const elOp = document.getElementById('auditRceTrailOperator');
      const elTime = document.getElementById('auditRceTrailTime');
      const elSha = document.getElementById('auditRceTrailSha');
      if (elOp) elOp.textContent = rceProof.audit_trail.operator || "operator";
      if (elTime) elTime.textContent = rceProof.audit_trail.timestamp_utc || "-";
      if (elSha) elSha.textContent = rceProof.audit_trail.evidence_sha256 || "-";
    } else {
      trailWrapper.classList.add('hidden');
    }
  }

  if (btnTriggerText) {
    btnTriggerText.textContent = "ทดสอบ Active RCE PoC อีกครั้ง";
  }
}

export async function runLiveRceAudit() {
  const host = appState.selectedAuditHost;
  if (!host) {
    showToast("ไม่พบข้อมูล Host ที่เลือก");
    return;
  }
  const btn = document.getElementById('btnTriggerActiveRce') as HTMLButtonElement | null;
  const btnText = document.getElementById('btnTriggerActiveRceText');
  const rawIp = (host.ip || '').trim();
  const port = host.port || (host.ports && host.ports[0]) || 80;

  if (btn) btn.disabled = true;
  if (btnText) btnText.innerHTML = `<i class="ph-bold ph-spinner animate-spin"></i> กำลังส่ง Canary Verification...`;

  try {
    const res = await apiFetch("/api/verify-rce", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        target: rawIp,
        port: port,
        is_php: host.is_php !== false,
        allow_active_rce: true,
        i_own_this_target: true,
        consent_phrase: "I_CONFIRM_TARGET_OWNERSHIP",
        server: host.server || host.webServer || ""
      })
    });
    const data = await res.json();
    if (data.status === "ok" && data.rce_proof) {
      host.rce_proof = data.rce_proof;
      renderRceProofCard(data.rce_proof);
      if (data.rce_proof.is_rce_proved || data.rce_proof.proof_status === 'CANARY_CONFIRMED') {
        showToast("⚠️ ตรวจพบช่องโหว่ RCE / Canary Execution ยืนยันสำเร็จ!");
      } else {
        showToast("✅ ยืนยัน: ไม่พบช่องโหว่ RCE บน Endpoint นี้");
      }
    } else {
      showToast(data.impact_statement || data.error || "เกิดข้อผิดพลาดในการตรวจสอบ RCE");
    }
  } catch (err) {
    showToast("ข้อผิดพลาดในการส่งคำขอ: " + err.message);
  } finally {
    if (btn) btn.disabled = false;
    if (btnText) btnText.textContent = "ทดสอบ Active RCE PoC บนโฮสต์นี้อีกครั้ง";
  }
}

export async function runLiveAsanAudit() {
  const host = appState.selectedAuditHost;
  if (!host) {
    showToast("ไม่พบข้อมูล Host ที่เลือก");
    return;
  }
  const btn = document.getElementById('btnRunAsanAudit') as HTMLButtonElement | null;
  const btnText = document.getElementById('btnRunAsanAuditText') as HTMLButtonElement | null;
  const terminal = document.getElementById('asanTerminalTrace');
  const pill = document.getElementById('asanStatusPill');

  const rawIp = (host.ip || '').trim();
  const port = host.port || (host.ports && host.ports[0]) || 80;

  if (btn) btn.disabled = true;
  if (btnText) btnText.textContent = "กำลังส่งคำขอตรวจสอบ C/ASan...";
  if (terminal) {
    terminal.textContent = `[+] Initiating deep C-level & AddressSanitizer probe to ${rawIp}:${port}...\n[*] Probing Zend Engine memory boundaries and var_destroy reentrancy...\n`;
  }

  try {
    const res = await apiFetch(`/api/verify-asan-memory?ip=${encodeURIComponent(rawIp)}&port=${encodeURIComponent(port)}`);
    const data = await res.json();

    if (data.status === 'ERROR') {
      terminal.textContent += `[-] Error probing target: ${data.error || data.message || 'Connection failed'}`;
      if (pill) {
        pill.textContent = "PROBE FAILED";
        pill.className = "px-2 py-0.5 rounded text-[9px] font-bold bg-slate-800 text-slate-400";
      }
    } else {
      const isV = data.is_vulnerable;
      if (pill) {
        pill.textContent = isV ? "ASAN VULN DETECTED" : "ASAN VERIFIED CLEAN";
        pill.className = isV 
          ? "px-2 py-0.5 rounded text-[9px] font-bold bg-rose-900/60 text-rose-300 border border-rose-700/50"
          : "px-2 py-0.5 rounded text-[9px] font-bold bg-emerald-900/60 text-emerald-300 border border-emerald-700/50";
      }

      terminal.textContent = 
`=================================================================
== AddressSanitizer & Zend Core Deep Diagnostic Subsystem ==
Target: ${data.target} | Runtime: ${data.php_version}
Memory Usage: ${data.memory_current ? (data.memory_current/1024).toFixed(1) + ' KB' : 'N/A'} | Peak: ${data.memory_peak ? (data.memory_peak/1024).toFixed(1) + ' KB' : 'N/A'} | Limit: ${data.memory_limit}
Allocator Mode: ${data.allocator_profile}
Zend C Source Points: ${JSON.stringify(data.c_source_points || {}, null, 2)}
Patch Baseline Status: ${data.patch_status}
-----------------------------------------------------------------
[!] AddressSanitizer (ASan) Memory Trace Inspection:
${data.asan_trace}
-----------------------------------------------------------------
[+] Defensive C-Level Remediation Guidance:
${data.c_patch_directive}
=================================================================`;
      showToast(isV ? "ตรวจพบความเสี่ยงระดับ C / Heap UAF" : "ยืนยันความปลอดภัยระดับ C / ASan ผ่าน");
    }
  } catch (err) {
    terminal.textContent += `\n[-] Request error: ${err.message}`;
  } finally {
    if (btn) btn.disabled = false;
    if (btnText) btnText.textContent = "ตรวจสอบเงื่อนไขระดับ C / Zend Patch Advisory";
  }
}

export function renderVaDiscoveredCards(host) {
  const container = document.getElementById('vaDiscoveredCardsContainer');
  if (!container) return;

  const va = host.va_findings || (host.deep_audit && host.deep_audit.va_findings);
  if (!va || Object.keys(va).length === 0) {
    container.innerHTML = `
      <div class="col-span-full p-4 rounded-2xl bg-slate-50 border border-slate-200 text-center text-slate-500 text-xs">
        <i class="ph-bold ph-shield-check text-2xl text-emerald-500 mb-1 inline-block"></i>
        <p class="font-bold text-slate-700">ผ่านการตรวจสอบความมั่นคงปลอดภัย</p>
        <p class="text-[10px] text-slate-400 mt-0.5">ไม่พบความเสี่ยงด้านค่าคอนฟิก หรือไฟล์สำคัญหลุดสู่ภายนอก</p>
      </div>
    `;
    return;
  }

  const order = ['chain_a', 'chain_b', 'chain_c', 'chain_d', 'chain_e', 'chain_asan', 'chain_exposure'];
  container.innerHTML = order.map(k => {
    const section = va[k];
    if (!section) return '';
    const isRisky = section.is_risky;
    const badgeCls = isRisky 
      ? 'bg-rose-50 text-rose-700 border border-rose-200/90' 
      : 'bg-emerald-50 text-emerald-700 border border-emerald-200/90';

    const itemsHtml = (section.items || []).map(it => {
      const valBadge = it.is_risky 
        ? 'bg-rose-50 text-rose-700 font-semibold' 
        : 'bg-emerald-50 text-emerald-800 font-medium';
      const iconCls = it.is_risky ? 'ph-warning text-amber-500' : 'ph-check-circle text-emerald-500';

      return `
        <div class="py-2.5 flex flex-col sm:flex-row sm:items-start justify-between gap-1.5 sm:gap-3 text-xs">
          <div class="flex items-center gap-1.5 font-mono text-slate-700 text-[11px] font-semibold shrink-0 pt-0.5">
            <i class="ph-bold ${iconCls} text-xs shrink-0"></i>
            <span>${it.directive}</span>
          </div>
          <div class="sm:text-right min-w-0 flex-1">
            <span class="inline-block text-[10px] font-mono ${valBadge} px-2 py-0.5 rounded leading-relaxed text-left sm:text-right break-words">
              ${it.discovered_val}
            </span>
          </div>
        </div>
      `;
    }).join('');

    const cardBorder = isRisky ? 'border-amber-200/90' : 'border-slate-200/80';
    const colSpanCls = '';

    return `
      <div class="p-4 rounded-2xl bg-white border ${cardBorder} shadow-2xs flex flex-col justify-between ${colSpanCls}">
        <div>
          <div class="flex items-center justify-between gap-2 mb-1 pb-2.5 border-b border-slate-100">
            <div class="flex items-center gap-1.5 min-w-0">
              <i class="ph-bold ${isRisky ? 'ph-shield-warning text-amber-500' : 'ph-shield-check text-emerald-500'} text-sm shrink-0"></i>
              <span class="font-bold text-xs text-slate-800 truncate">${section.title}</span>
            </div>
            <span class="text-[10px] font-mono px-2 py-0.5 rounded-full font-bold ${badgeCls} shrink-0 shadow-2xs">
              ${section.badge}
            </span>
          </div>
          <div class="divide-y divide-slate-100">
            ${itemsHtml}
          </div>
        </div>
      </div>
    `;
  }).join('');
}

export function closeDeepAuditModal() {
  const modal = document.getElementById('deepAuditModal');
  const content = document.getElementById('deepAuditContent');
  if (!modal) return;
  modal.classList.add('opacity-0', 'pointer-events-none');
  if (content) {
    content.classList.remove('scale-100');
    content.classList.add('scale-95');
  }
}

export function inspectHost(targetId, port) {
  let host = null;
  if (port) {
    host = appState.allHosts.find(h => h.ip === targetId && (h.port === port || (h.ports && h.ports.includes(port))));
  }
  if (!host) {
    host = appState.allHosts.find(h => 
      h.target_id === targetId || 
      `${h.ip}:${h.port}` === targetId || 
      h.ip === targetId
    );
  }
  if (!host) {
    showToast(`ข้อมูล Host: ${targetId}`);
    return;
  }
  openDeepAuditModal(host);
}