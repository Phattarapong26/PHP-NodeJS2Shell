import { apiFetch } from './api';
import { btnApplyUpdateNow, btnApplyUpdateText, btnCheckUpdateManual, btnCloseUpdateModal, btnHeaderUpdateBadge, headerUpdateTag, systemUpdateModal, updateEnvBadge, updateLocalCommit, updateLogBox, updateRemoteCommit, updateStatusText } from './dom';
import { appState } from './state';
import { showToast } from './ui';

export async function checkGitUpdateStatus(force = false) {
  try {
    const res = await apiFetch(`/api/system/check-update${force ? '?force=1' : ''}`);
    const data = await res.json();
    if (data.status === 'ok') {
      appState.systemUpdateInfo = data.update_info;
      renderUpdateBadgeUI();
    }
  } catch (err) {
    console.warn('Failed to check git updates:', err);
  }
}

export function renderUpdateBadgeUI() {
  const info = appState.systemUpdateInfo;
  if (!info) return;

  if (btnHeaderUpdateBadge) {
    if (info.has_update) {
      btnHeaderUpdateBadge.classList.remove('hidden');
      if (headerUpdateTag) {
        headerUpdateTag.textContent = info.commits_behind ? `+${info.commits_behind}` : 'NEW';
      }
    } else {
      btnHeaderUpdateBadge.classList.add('hidden');
    }
  }

  if (updateLocalCommit) updateLocalCommit.textContent = (info.current_commit || 'unknown').substring(0, 7);
  if (updateRemoteCommit) updateRemoteCommit.textContent = (info.remote_commit || 'unknown').substring(0, 7);
  if (updateStatusText) {
    if (info.has_update) {
      updateStatusText.textContent = `มีเวอร์ชันใหม่บน Git (${info.commits_behind || 1} commit(s) behind)`;
      updateStatusText.className = "font-bold text-rose-600";
    } else {
      updateStatusText.textContent = "ระบบเป็นเวอร์ชันล่าสุดแล้ว (Up to date)";
      updateStatusText.className = "font-bold text-emerald-700";
    }
  }
  if (updateEnvBadge) {
    updateEnvBadge.textContent = info.is_docker ? "Docker Container" : "Machine Binary / Local Host";
  }
}

export function openUpdateModal() {
  renderUpdateBadgeUI();
  if (updateLogBox) updateLogBox.classList.add('hidden');
  if (systemUpdateModal) systemUpdateModal.classList.remove('opacity-0', 'pointer-events-none');
}

export function closeUpdateModal() {
  if (systemUpdateModal) systemUpdateModal.classList.add('opacity-0', 'pointer-events-none');
}

export async function applySystemUpdate() {
  if (!btnApplyUpdateNow) return;
  btnApplyUpdateNow.disabled = true;
  if (btnApplyUpdateText) btnApplyUpdateText.textContent = "กำลังดำเนินการ git pull...";

  if (updateLogBox) {
    updateLogBox.classList.remove('hidden');
    updateLogBox.textContent = "[SYSTEM] กำลังดึงข้อมูลการเปลี่ยนแปลงจาก GitHub (git pull origin main)...\n";
  }

  try {
    const res = await apiFetch('/api/system/apply-update', { method: 'POST' });
    const data = await res.json();
    if (data.status === 'success') {
      if (updateLogBox) {
        updateLogBox.textContent += `[SUCCESS] ${data.message}\n` + (data.output || '');
        if (data.is_docker) {
          updateLogBox.textContent += "\n[NOTE] รันใน Docker: ระบบดึงโค้ดแล้ว สามารถรีสตาร์ทคอนเทนเนอร์ด้วย 'docker restart thaicert-php-scanner'";
        } else {
          updateLogBox.textContent += "\n[NOTE] กรุณารีสตาร์ทโปรแกรมเพื่อโหลดโค้ดเวอร์ชันล่าสุด";
        }
      }
      showToast("อัปเดตระบบสำเร็จเรียบร้อย");
      await checkGitUpdateStatus(true);
    } else {
      if (updateLogBox) {
        updateLogBox.textContent += `[ERROR] ${data.message}\n` + (data.error || data.output || '');
      }
      showToast(data.message || "เกิดข้อผิดพลาดในการอัปเดต");
    }
  } catch (err) {
    if (updateLogBox) {
      updateLogBox.textContent += `[EXCEPTION] ${err.message}`;
    }
    showToast("ไม่สามารถส่งคำขออัปเดตได้");
  } finally {
    btnApplyUpdateNow.disabled = false;
    if (btnApplyUpdateText) btnApplyUpdateText.textContent = "อัปเดตระบบเดี๋ยวนี้ (Git Pull)";
  }
}

/** Wires DOM event listeners for this domain. Called once from bootstrap after the DOM is mounted. */
export function initSystemUpdate() {
  if (btnHeaderUpdateBadge) btnHeaderUpdateBadge.addEventListener('click', openUpdateModal);

  if (btnCloseUpdateModal) btnCloseUpdateModal.addEventListener('click', closeUpdateModal);

  if (btnCheckUpdateManual) btnCheckUpdateManual.addEventListener('click', () => checkGitUpdateStatus(true));

  if (btnApplyUpdateNow) btnApplyUpdateNow.addEventListener('click', applySystemUpdate);

  if (systemUpdateModal) {
    systemUpdateModal.addEventListener('click', (e) => {
      if (e.target === systemUpdateModal) closeUpdateModal();
    });
  }
}
