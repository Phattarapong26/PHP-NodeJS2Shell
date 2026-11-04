/**
 * Backend API client.
 *
 * ALL traffic to the existing backend goes through this file, so connecting the
 * app to your server is a one-place change.
 *
 * Base URL resolution order (first match wins):
 *   1. localStorage key  "thaicert.apiBase"   (runtime override, e.g. from a settings screen)
 *   2. VITE_API_BASE                          (set in .env / .env.production)
 *   3. Tauri desktop shell  -> http://localhost:5050   (the original file:// fallback)
 *   4. Browser served by the backend itself -> ""      (same-origin, relative /api/... paths)
 *
 * In `npm run dev` with an empty base, Vite proxies /api to VITE_API_PROXY
 * (default http://localhost:5050), see vite.config.ts.
 */

const STORAGE_KEY = 'thaicert.apiBase';
const DEFAULT_DESKTOP_BASE = 'http://localhost:5050';

export function isTauri(): boolean {
  return typeof window !== 'undefined' && ('__TAURI_INTERNALS__' in window || '__TAURI__' in window);
}

function trimSlash(s: string): string {
  return s.replace(/\/+$/, '');
}

/** Base API URL resolver (same behaviour as the original single-file app, plus Tauri + env support). */
export function getApiBase(): string {
  try {
    const override = localStorage.getItem(STORAGE_KEY);
    if (override) return trimSlash(override);
  } catch {
    /* storage unavailable */
  }
  const envBase = import.meta.env.VITE_API_BASE as string | undefined;
  if (envBase) return trimSlash(envBase);
  if (isTauri() || window.location.protocol === 'file:' || !window.location.host) {
    return DEFAULT_DESKTOP_BASE;
  }
  return '';
}

/** Persist (or clear, when empty) a runtime backend URL override. */
export function setApiBase(url: string | null): void {
  try {
    if (url) localStorage.setItem(STORAGE_KEY, trimSlash(url));
    else localStorage.removeItem(STORAGE_KEY);
  } catch {
    /* storage unavailable */
  }
}

/** Absolute URL for a backend path, e.g. apiUrl('/api/report/preview'). */
export function apiUrl(endpoint: string): string {
  return `${getApiBase()}${endpoint}`;
}

/** fetch() against the backend. Drop-in replacement for the original apiFetch. */
export async function apiFetch(endpoint: string, options: RequestInit = {}): Promise<Response> {
  return await fetch(apiUrl(endpoint), options);
}

/**
 * Open an http(s) URL in a new window. Inside Tauri the system browser is used
 * (via the opener plugin) because the webview blocks window.open to external origins.
 */
export async function openExternal(url: string): Promise<void> {
  if (isTauri()) {
    try {
      const { openUrl } = await import('@tauri-apps/plugin-opener');
      await openUrl(url);
      return;
    } catch {
      /* fall through to window.open */
    }
  }
  try {
    const win = window.open(url, '_blank');
    if (!win || win.closed || typeof win.closed === 'undefined') {
      const a = document.createElement('a');
      a.href = url;
      a.target = '_blank';
      a.rel = 'noopener noreferrer';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    }
  } catch {
    const a = document.createElement('a');
    a.href = url;
    a.target = '_blank';
    a.rel = 'noopener noreferrer';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  }
}
