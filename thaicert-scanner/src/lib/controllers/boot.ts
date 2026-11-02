import { initThaiCertChartsControls, initThaiCertTooltip } from './charts';
import { autoDetectLocalNetwork } from './network';
import { initPortSelectionControls } from './ports';
import { loadProfiles } from './profiles';
import { checkGitUpdateStatus } from './systemUpdate';

export function onAppLoad() {
  autoDetectLocalNetwork();
  initPortSelectionControls();
  initThaiCertTooltip();
  initThaiCertChartsControls();
  loadProfiles();
  checkGitUpdateStatus();
}