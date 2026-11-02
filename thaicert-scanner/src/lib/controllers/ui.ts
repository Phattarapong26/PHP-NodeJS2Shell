import { heroSearchInput, mainSubnetInput, statusPillText, stepBadgeIcon, stepBadgeText } from './dom';
import { recalculateSubnet } from './network';
import { startScanWorkflow } from './scan';
import { appState } from './state';

export function updateStepBadge(text, iconClass) {
  stepBadgeText.textContent = text;
  stepBadgeIcon.className = `ph-bold ${iconClass} text-blue-600`;
}

export function highlightWorkflowStep(stepIndex) {
  for (let s = 0; s <= 5; s++) {
    const stepEl = document.getElementById(`flowStep${s}`);
    if (!stepEl) continue;
    if (s === stepIndex) {
      stepEl.classList.add('active-step');
    } else {
      stepEl.classList.remove('active-step');
    }
  }
}

export function showToast(msg) {
  const toast = document.getElementById('toastMessage');
  document.getElementById('toastText').textContent = msg;
  toast.classList.remove('opacity-0', 'pointer-events-none');
  setTimeout(() => {
    toast.classList.add('opacity-0', 'pointer-events-none');
  }, 3000);
}

export function delay(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// Hero Domain Search Handler
export function triggerHeroSearch() {
  if (appState.isScanning) return;
  const rawVal = heroSearchInput ? heroSearchInput.value.trim() : "";
  if (!rawVal) {
    showToast("กรุณากรอกชื่อโดเมนที่ต้องการตรวจสอบ เช่น thaicert.or.th");
    if (heroSearchInput) heroSearchInput.focus();
    return;
  }

  // Update mainSubnetInput & appState
  if (mainSubnetInput) {
    mainSubnetInput.value = rawVal;
  }
  appState.subnet = rawVal;
  recalculateSubnet(rawVal);

  if (statusPillText) {
    statusPillText.textContent = `Online · ตรวจสอบ: ${rawVal}`;
  }
  updateStepBadge(`ระบบพร้อมตรวจสอบ: ${rawVal}`, "ph-check-circle");

  // Start the scan workflow immediately!
  startScanWorkflow();
}