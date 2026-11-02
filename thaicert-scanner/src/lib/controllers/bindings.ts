import { closeChainInfoModal, closeDeepAuditModal, copyHardeningIni } from './audit';
import { btnAutoDetectTrigger, btnCancelScanEl, btnCloseDeepAudit, btnCloseDeepAuditBottom, btnCloseResults, btnCloseWorkflow, btnCopyAuditCmd, btnCopyHardeningIni, btnHeroSearch, btnOpenResultsQuick, btnRescanFromModal, btnScan, btnToggleWorkflow, btnWorkflowCloseDone, chainInfoModalEl, deepAuditModalEl, heroSearchInput, mainSubnetInput, workflowModal } from './dom';
import { autoDetectLocalNetwork, recalculateSubnet } from './network';
import { closeResultsModal, openResultsModal } from './results';
import { cancelCurrentScan, startScanWorkflow } from './scan';
import { closeProfileDetailDrawer } from './profiles';
import { closeProfileDrawer } from './shell';
import { appState } from './state';
import { showToast, triggerHeroSearch } from './ui';



/** Wires DOM event listeners for this domain. Called once from bootstrap after the DOM is mounted. */
export function initBindings() {
  if (heroSearchInput) {
    heroSearchInput.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        triggerHeroSearch();
      }
    });
  }

  if (btnHeroSearch) {
    btnHeroSearch.addEventListener('click', (e) => {
      e.preventDefault();
      triggerHeroSearch();
    });
  }

  // Event Listeners
  btnScan.addEventListener('click', () => {
    if (appState.isScanning) {
      cancelCurrentScan();
    } else {
      startScanWorkflow();
    }
  });

  if (btnCancelScanEl) {
    btnCancelScanEl.addEventListener('click', (e) => {
      e.preventDefault();
      cancelCurrentScan();
    });
  }

  btnOpenResultsQuick.addEventListener('click', openResultsModal);

  btnCloseResults.addEventListener('click', closeResultsModal);

  btnRescanFromModal.addEventListener('click', () => {
    closeResultsModal();
    closeProfileDetailDrawer();
    closeProfileDrawer();
    startScanWorkflow();
  });

  if (btnAutoDetectTrigger) {
    btnAutoDetectTrigger.addEventListener('click', () => {
      autoDetectLocalNetwork();
      showToast("รีเซ็ต Subnet ตามเครือข่ายเครื่องเรียบร้อย");
    });
  }

  if (mainSubnetInput) {
    mainSubnetInput.addEventListener('input', () => {
      document.querySelectorAll('.preset-chip').forEach(c => {
        c.className = "preset-chip neu-pill text-slate-600 hover:text-blue-600 px-2.5 py-1 rounded-full text-[11px] whitespace-nowrap transition-all shadow-sm flex items-center gap-1 cursor-pointer";
      });
      const val = mainSubnetInput.value.trim();
      recalculateSubnet(val);
    });
  }

  // Workflow Diagram Modal
  btnToggleWorkflow.addEventListener('click', () => {
    workflowModal.classList.remove('opacity-0', 'pointer-events-none');
  });

  btnCloseWorkflow.addEventListener('click', () => {
    workflowModal.classList.add('opacity-0', 'pointer-events-none');
  });

  btnWorkflowCloseDone.addEventListener('click', () => {
    workflowModal.classList.add('opacity-0', 'pointer-events-none');
  });

  if (btnCloseDeepAudit) btnCloseDeepAudit.addEventListener('click', closeDeepAuditModal);

  if (btnCloseDeepAuditBottom) btnCloseDeepAuditBottom.addEventListener('click', closeDeepAuditModal);

  if (deepAuditModalEl) {
    deepAuditModalEl.addEventListener('click', (e) => {
      if (e.target === deepAuditModalEl) closeDeepAuditModal();
    });
  }

  if (chainInfoModalEl) {
    chainInfoModalEl.addEventListener('click', (e) => {
      if (e.target === chainInfoModalEl) closeChainInfoModal();
    });
  }

  if (btnCopyAuditCmd) {
    btnCopyAuditCmd.addEventListener('click', () => {
      const cmdEl = document.getElementById('auditTerminalCmd');
      const text = cmdEl ? cmdEl.textContent : "php -v";
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(() => {
          const label = document.getElementById('copyCmdText');
          if (label) {
            label.textContent = "คัดลอกแล้ว!";
            setTimeout(() => { label.textContent = "คัดลอกคำสั่ง"; }, 2000);
          }
          showToast("คัดลอกคำสั่งสำหรับตรวจสอบบนเซิร์ฟเวอร์เรียบร้อย");
        }).catch(() => {
          showToast("คำสั่ง: " + text);
        });
      } else {
        showToast("คำสั่ง: " + text);
      }
    });
  }

  if (btnCopyHardeningIni) {
    btnCopyHardeningIni.addEventListener('click', copyHardeningIni);
  }
}
