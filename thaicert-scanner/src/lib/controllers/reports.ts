import { apiFetch, apiUrl } from './api';
import { btnExportAmberPdf, btnExportAmberPdfModal, btnExportEvidenceBundle, btnExportEvidenceBundleModal, btnExportHostPdf, btnFooterExportAmberPdf, mainSubnetInput } from './dom';
import { appState } from './state';
import { showToast } from './ui';

// TLP:AMBER PDF Export Handlers (Zero Mock, Real Data Direct Download)
export async function downloadFullAmberPdfReport(btnElement = null) {
  let origHtml = '';
  if (btnElement) {
    origHtml = btnElement.innerHTML;
    btnElement.innerHTML = '<i class="ph ph-spinner animate-spin text-sm"></i> <span>กำลังสร้าง PDF...</span>';
  }
  showToast("กำลังประมวลผลและสร้างรายงาน PDF ทางการ สกมช. (TLP:AMBER)...");

  const targetVal = (mainSubnetInput ? mainSubnetInput.value : appState.subnetPrefix + '0/24') || 'Local Network';
  const hostsToSend = appState.allHosts && appState.allHosts.length > 0 ? appState.allHosts : [];

  try {
    const resp = await apiFetch('/api/report/pdf', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target: targetVal,
        hosts: hostsToSend
      })
    });

    if (resp.ok) {
      const blob = await resp.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `NCSA_Advisory_TLPAMBER_${targetVal.replace(/[^a-zA-Z0-9_-]/g, '_')}.pdf`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
      showToast("ดาวน์โหลดรายงานความมั่นคงปลอดภัย TLP:AMBER (PDF) สำเร็จ");
    } else {
      window.open(apiUrl('/api/report/preview'), '_blank');
    }
  } catch (err) {
    window.open(apiUrl('/api/report/preview'), '_blank');
  } finally {
    if (btnElement && origHtml) {
      btnElement.innerHTML = origHtml;
    }
  }
}

// Forensic Evidence Bundle (.ZIP) Export Handler
export async function downloadEvidenceBundleReport(btnElement = null) {
  let origHtml = '';
  if (btnElement) {
    origHtml = btnElement.innerHTML;
    btnElement.innerHTML = '<i class="ph ph-spinner animate-spin text-sm"></i> <span>กำลังบีบอัด...</span>';
  }
  showToast("กำลังรวบรวมหลักฐาน Forensic Evidence Bundle พร้อมดิจิทัลซิกเนเจอร์ SHA-256...");

  const targetVal = (mainSubnetInput ? mainSubnetInput.value : appState.subnetPrefix + '0/24') || 'Local Network';
  const hostsToSend = appState.allHosts && appState.allHosts.length > 0 ? appState.allHosts : [];

  try {
    const resp = await apiFetch('/api/report/bundle', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        target: targetVal,
        hosts: hostsToSend
      })
    });

    if (resp.ok) {
      const blob = await resp.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `ThaiCERT_Evidence_Bundle_${targetVal.replace(/[^a-zA-Z0-9_-]/g, '_')}.zip`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
      showToast("ดาวน์โหลด Forensic Evidence Bundle (.ZIP) สำเร็จเรียบร้อย");
    } else {
      showToast("ไม่สามารถสร้าง Evidence Bundle ได้ในขณะนี้");
    }
  } catch (err) {
    showToast("เกิดข้อผิดพลาดในการดาวน์โหลด Evidence Bundle");
  } finally {
    if (btnElement && origHtml) {
      btnElement.innerHTML = origHtml;
    }
  }
}

/** Wires DOM event listeners for this domain. Called once from bootstrap after the DOM is mounted. */
export function initReports() {
  if (btnExportAmberPdf) {
    btnExportAmberPdf.addEventListener('click', () => downloadFullAmberPdfReport(btnExportAmberPdf));
  }

  if (btnExportAmberPdfModal) {
    btnExportAmberPdfModal.addEventListener('click', () => downloadFullAmberPdfReport(btnExportAmberPdfModal));
  }

  if (btnExportEvidenceBundle) {
    btnExportEvidenceBundle.addEventListener('click', () => downloadEvidenceBundleReport(btnExportEvidenceBundle));
  }

  if (btnExportEvidenceBundleModal) {
    btnExportEvidenceBundleModal.addEventListener('click', () => downloadEvidenceBundleReport(btnExportEvidenceBundleModal));
  }

  if (btnFooterExportAmberPdf) {
    btnFooterExportAmberPdf.addEventListener('click', () => downloadFullAmberPdfReport(btnFooterExportAmberPdf));
  }

  if (btnExportHostPdf) {
    btnExportHostPdf.addEventListener('click', async () => {
      const host = appState.selectedAuditHost;
      if (!host) {
        window.open(apiUrl('/api/report/pdf'), '_blank');
        return;
      }
      const origHtml = btnExportHostPdf.innerHTML;
      btnExportHostPdf.innerHTML = '<i class="ph ph-spinner animate-spin text-sm"></i> <span>กำลังสร้าง PDF...</span>';
      try {
        const resp = await apiFetch('/api/report/pdf', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            target: host.ip || host.target_id,
            hosts: [host]
          })
        });
        if (resp.ok) {
          const blob = await resp.blob();
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = `NCSA_Advisory_TLPAMBER_${(host.ip || 'target').replace(/[^a-zA-Z0-9_-]/g, '_')}.pdf`;
          document.body.appendChild(a);
          a.click();
          a.remove();
          window.URL.revokeObjectURL(url);
        } else {
          window.open(apiUrl('/api/report/preview'), '_blank');
        }
      } catch (e) {
        window.open(apiUrl('/api/report/preview'), '_blank');
      } finally {
        btnExportHostPdf.innerHTML = origHtml;
      }
    });
  }
}
