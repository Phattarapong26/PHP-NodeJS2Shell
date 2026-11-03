/**
 * Delegated click actions for HTML rendered at runtime (results table, charts,
 * profile cards, CVE cards ...).
 *
 * The original single-file app used inline `onclick="fn(...)"` attributes inside
 * innerHTML templates, which require global functions and break under a strict
 * Content-Security-Policy (Tauri). Templates now emit
 *   data-action="fnName" data-arg="..." [data-arg2="..."]
 * and this single listener dispatches to the typed controller function.
 */
import { inspectHost, openChainInfoModal, switchAuditChain } from './audit';
import { toggleGroupFilter } from './results';
import {
  handleDeleteProfile,
  handleDeleteScanHistory,
  handleEditProfile,
  handlePreviewScanHistoryReport,
  handleRestoreScanHistory,
  handleSelectProfile,
  openProfileDetailDrawer
} from './profiles';
import { showToast } from './ui';

type ActionArgs = { arg?: string; arg2?: string; el: HTMLElement };

/** Original templates passed ids/group numbers as unquoted JS literals, so keep them numeric. */
function num(v: string | undefined): number | string | undefined {
  if (v === undefined) return v;
  return /^-?\d+(\.\d+)?$/.test(v) ? Number(v) : v;
}

const ACTIONS: Record<string, (a: ActionArgs) => unknown> = {
  inspectHost: ({ arg }) => inspectHost(arg, undefined),
  openChainInfoModal: ({ arg }) => openChainInfoModal(arg),
  switchAuditChain: ({ arg }) => switchAuditChain(arg),
  toggleGroupFilter: ({ arg }) => toggleGroupFilter(num(arg)),
  handleSelectProfile: ({ arg }) => handleSelectProfile(num(arg)),
  openProfileDetailDrawer: ({ arg }) => openProfileDetailDrawer(num(arg)),
  handleEditProfile: ({ arg }) => handleEditProfile(num(arg)),
  handleDeleteProfile: ({ arg }) => handleDeleteProfile(num(arg)),
  handleRestoreScanHistory: ({ arg }) => handleRestoreScanHistory(num(arg)),
  handlePreviewScanHistoryReport: ({ arg }) => handlePreviewScanHistoryReport(num(arg)),
  handleDeleteScanHistory: ({ arg, arg2 }) => handleDeleteScanHistory(num(arg), num(arg2)),
  copyText: ({ el }) => {
    const text = el.dataset.copy ?? '';
    navigator.clipboard?.writeText(text);
    if (el.dataset.toast) showToast(el.dataset.toast);
  }
};

function onDelegatedClick(e: MouseEvent): void {
  const target = e.target as Element | null;
  const el = target?.closest?.('[data-action]') as HTMLElement | null;
  if (!el) return;
  const fn = ACTIONS[el.dataset.action ?? ''];
  if (!fn) return;
  fn({ arg: el.dataset.arg ?? el.getAttribute('data-arg') ?? undefined, arg2: el.dataset.arg2, el });
}

/** Installs the delegated listener. Returns a disposer. */
export function installActionDelegation(root: Document | HTMLElement = document): () => void {
  root.addEventListener('click', onDelegatedClick as EventListener);
  return () => root.removeEventListener('click', onDelegatedClick as EventListener);
}
