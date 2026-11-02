import { btnCloseProfileDrawer, btnDoneProfileDrawer, btnMaximize, btnSaveSettings, btnToggleSettings, drawerDetectedIp, drawerDetectedSubnet, inputCustomIp, inputSearchHost, inputWorkerConcurrency, mainSubnetInput, profileDetailDrawer, profileDrawerBackdrop, profileScanWarningBanner, profileSelectDrawer, selectSubnetCidr, statusPillBtn, statusPillText, workerDisplayVal, workflowModal } from './dom';
import { populateDynamicCidrOptions, recalculateSubnet, updateCidrPreview } from './network';
import { updateCalculatedPorts } from './ports';
import { closeProfileDetailDrawer } from './profiles';
import { closeResultsModal, exportToCsv, renderResultsTable } from './results';
import { appState } from './state';
import { showToast, updateStepBadge } from './ui';

// Profile & Network Settings Drawer Controls
export function openProfileDrawer(fromScanAttempt = false) {
  if (profileScanWarningBanner) {
    if (fromScanAttempt) {
      profileScanWarningBanner.classList.remove('hidden');
    } else {
      profileScanWarningBanner.classList.add('hidden');
    }
  }
  if (drawerDetectedIp) drawerDetectedIp.textContent = appState.hostIp || '127.0.0.1';
  if (drawerDetectedSubnet) drawerDetectedSubnet.textContent = appState.subnet || '-';

  if (profileDrawerBackdrop) {
    profileDrawerBackdrop.classList.remove('pointer-events-none', 'opacity-0');
  }
  if (profileSelectDrawer) {
    profileSelectDrawer.classList.remove('invisible');
    requestAnimationFrame(() => {
      profileSelectDrawer.classList.remove('translate-x-full');
    });
  }
}

export function closeProfileDrawer() {
  if (profileSelectDrawer) {
    profileSelectDrawer.classList.add('translate-x-full');
  }
  if (!profileDetailDrawer || profileDetailDrawer.classList.contains('translate-x-full')) {
    if (profileDrawerBackdrop) {
      profileDrawerBackdrop.classList.add('opacity-0', 'pointer-events-none');
    }
  }
  setTimeout(() => {
    if (profileSelectDrawer) profileSelectDrawer.classList.add('invisible');
  }, 300);
}

export const openSettingsDrawer = openProfileDrawer;

export const closeSettingsDrawer = closeProfileDrawer;

export const openProfileModal = openProfileDrawer;

export const closeProfileModal = closeProfileDrawer;

// Fullscreen Toggle for Maximize button and Traffic Green
export function toggleFullScreen() {
  if (!document.fullscreenElement) {
    document.documentElement.requestFullscreen().catch(() => {});
  } else {
    if (document.exitFullscreen) {
      document.exitFullscreen().catch(() => {});
    }
  }
}

/** Wires DOM event listeners for this domain. Called once from bootstrap after the DOM is mounted. */
export function initShell() {
  if (statusPillBtn) statusPillBtn.addEventListener('click', () => openProfileDrawer(false));

  if (btnToggleSettings) btnToggleSettings.addEventListener('click', () => openProfileDrawer(false));

  if (btnCloseProfileDrawer) btnCloseProfileDrawer.addEventListener('click', closeProfileDrawer);

  if (btnDoneProfileDrawer) btnDoneProfileDrawer.addEventListener('click', closeProfileDrawer);

  if (profileDrawerBackdrop) {
    profileDrawerBackdrop.addEventListener('click', () => {
      closeProfileDetailDrawer();
      closeProfileDrawer();
    });
  }

  if (selectSubnetCidr) {
    selectSubnetCidr.addEventListener('change', () => {
      updateCidrPreview();
      const selectedOpt = selectSubnetCidr.options[selectSubnetCidr.selectedIndex];
      if (selectedOpt && mainSubnetInput) {
        const sub = selectedOpt.getAttribute('data-subnet');
        if (sub) {
          mainSubnetInput.value = sub;
          recalculateSubnet(sub);
        }
      }
    });
  }

  if (mainSubnetInput) {
    mainSubnetInput.addEventListener('input', () => {
      recalculateSubnet(mainSubnetInput.value);
    });
  }

  if (inputCustomIp) {
    inputCustomIp.addEventListener('input', (e) => {
      const val = e.target.value.trim();
      if (val && /^(\d{1,3}\.){3}\d{1,3}$/.test(val)) {
        populateDynamicCidrOptions(val, appState.cidr, appState.netmask, null, null);
      }
    });
  }

  // FIX(legacy bug): these two bindings were unguarded in GUI.html and threw a TypeError
  // on load (the #inputWorkerConcurrency / #btnSaveSettings elements do not exist in the
  // markup), which aborted the rest of the legacy init and prevented window.onload from
  // ever running. Guarded so initialisation completes.
  if (inputWorkerConcurrency) inputWorkerConcurrency.addEventListener('input', (e) => {
    if (workerDisplayVal) workerDisplayVal.textContent = `${(e.target as HTMLInputElement).value} parallel reqs`;
  });

  if (btnSaveSettings) btnSaveSettings.addEventListener('click', () => {
    let targetToSet = mainSubnetInput ? mainSubnetInput.value.trim() : "";
    if (!targetToSet) {
      const selectedOpt = selectSubnetCidr ? selectSubnetCidr.options[selectSubnetCidr.selectedIndex] : null;
      if (selectedOpt) {
        targetToSet = selectedOpt.getAttribute('data-subnet') || "";
      }
    }

    if (targetToSet && mainSubnetInput) {
      mainSubnetInput.value = targetToSet;
      recalculateSubnet(targetToSet);
      if (statusPillText) {
        statusPillText.textContent = `Online · เป้าหมาย: ${targetToSet}`;
      }
      updateStepBadge(`ระบบพร้อมสแกนเป้าหมาย: ${targetToSet}`, "ph-check-circle");
    }
    appState.concurrency = parseInt((inputWorkerConcurrency as HTMLInputElement).value, 10);
    if (typeof updateCalculatedPorts === 'function') {
      updateCalculatedPorts();
    }
    closeSettingsDrawer();
    const modeLabel = appState.portMode === 'standard' 
      ? 'มาตรฐาน Dev' 
      : (appState.portMode === 'custom' ? 'กำหนดเอง/ช่วง' : 'ปล่อยสแกนกว้าง');
    showToast(`บันทึกการตั้งค่า: ${targetToSet || 'Subnet'} · ${appState.selectedPorts.length} พอร์ต (${modeLabel})`);
  });

  document.getElementById('btnExportReport').addEventListener('click', exportToCsv);

  // Results Tabs Filtering
  document.querySelectorAll('.filter-tab').forEach(tab => {
    tab.addEventListener('click', (e) => {
      document.querySelectorAll('.filter-tab').forEach(t => {
        t.classList.remove('active');
      });
      (e.currentTarget as HTMLElement).classList.add('active');
      appState.activeFilter = (e.currentTarget as HTMLElement).getAttribute('data-filter');
      renderResultsTable();
    });
  });

  // Keyboard Shortcuts (ESC to close modals)
  window.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      closeResultsModal();
      workflowModal.classList.add('opacity-0', 'pointer-events-none');
      closeSettingsDrawer();
    }
  });

  if (btnMaximize) btnMaximize.addEventListener('click', toggleFullScreen);

  if (inputSearchHost) {
    inputSearchHost.addEventListener('input', () => {
      renderResultsTable();
    });
  }
}
