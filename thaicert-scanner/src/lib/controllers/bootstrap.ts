/**
 * Application bootstrap.
 *
 * Order matters and mirrors the original page:
 *   1. bind DOM references (after Svelte has mounted every component)
 *   2. attach all event listeners (init* functions, one per domain)
 *   3. kick off the initial data loads (the old `window.onload`)
 */
import { installActionDelegation } from './actions';
import { initBindings } from './bindings';
import { initCve } from './cve';
import { bindDom } from './dom';
import { initProfiles } from './profiles';
import { initReports } from './reports';
import { initShell } from './shell';
import { initSystemUpdate } from './systemUpdate';
import { onAppLoad } from './boot';

let started = false;

/** Returns a disposer that removes global listeners installed by the controllers. */
export function bootstrap(): () => void {
  if (started) return () => {};
  started = true;

  bindDom();
  const disposeActions = installActionDelegation();

  initBindings();
  initCve();
  initShell();
  initReports();
  initProfiles();
  initSystemUpdate();

  onAppLoad();

  return () => {
    disposeActions();
    started = false;
  };
}
