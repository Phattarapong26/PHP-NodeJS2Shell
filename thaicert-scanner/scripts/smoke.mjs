// Loads the production build in jsdom and reports runtime errors from bootstrap.
import { JSDOM, VirtualConsole } from 'jsdom';
import fs from 'node:fs';
import path from 'node:path';

const dist = process.argv[2] || 'dist';
const html = fs.readFileSync(path.join(dist, 'index.html'), 'utf8');
const errors = [], logs = [];
const vc = new VirtualConsole();
vc.on('jsdomError', (e) => errors.push('jsdomError: ' + (e.stack || e.message || e)));
vc.on('error', (...a) => errors.push('console.error: ' + a.join(' ')));
vc.on('warn', (...a) => logs.push('warn: ' + a.join(' ')));
vc.on('log', (...a) => logs.push('log: ' + a.join(' ')));

const dom = new JSDOM(html, {
  url: 'http://localhost:1420/',
  runScripts: 'dangerously',
  resources: undefined,
  pretendToBeVisual: true,
  virtualConsole: vc
});
const { window } = dom;
// Mock backend: set MOCK=1 to return plausible payloads and exercise the render paths.
const MOCK = process.env.MOCK === '1';
const MOCKS = {
  '/api/my-ip': { ip: '192.168.1.42', netmask: '255.255.255.0', cidr: 24, gateway: '192.168.1.1', iface: 'eth0', subnet: '192.168.1.0/24' },
  '/api/profiles': {
    status: 'ok',
    active_profile: { id: 1, title: 'Stealth Profile', network_target: '192.168.1.0/24', port_mode: 'standard', scope_preset: 'all', active: true },
    profiles: [
      { id: 1, title: 'Stealth Profile', network_target: '192.168.1.0/24', port_mode: 'standard', scope_preset: 'all', active: true },
      { id: 2, title: 'Turbo Profile', network_target: '10.0.0.0/24', port_mode: 'custom', scope_preset: 'web', active: false }
    ]
  },
  '/api/cve-database': { updated: '2026-01-01', cves: [] },
  '/api/system/check-update': { update_available: false, current: '1.0.0', latest: '1.0.0' }
};
window.fetch = async (url) => {
  const key = String(url).replace(window.location.origin, '');
  logs.push('fetch: ' + url);
  if (!MOCK) {
    return { ok: false, status: 503, json: async () => ({}), text: async () => '', statusText: 'offline' };
  }
  const body = MOCKS[key] ?? [];
  return { ok: true, status: 200, statusText: 'OK', json: async () => body, text: async () => JSON.stringify(body) };
};
window.matchMedia ||= () => ({ matches: false, addListener() {}, removeListener() {}, addEventListener() {}, removeEventListener() {} });
window.SVGElement.prototype.getBBox ||= () => ({ x: 0, y: 0, width: 0, height: 0 });
window.Element.prototype.scrollIntoView ||= () => {};

// inject the built bundle manually (jsdom does not run type=module scripts)
const jsFile = fs.readdirSync(path.join(dist, 'assets')).find((f) => f.endsWith('.js'));
const code = fs.readFileSync(path.join(dist, 'assets', jsFile), 'utf8');
window.addEventListener('error', (ev) => {
  const e = ev.error || ev;
  errors.push('window.error: ' + ((e && e.stack) || ev.message || String(ev)));
});
const script = window.document.createElement('script');
script.textContent = code;
try {
  window.document.body.appendChild(script);
} catch (e) {
  errors.push('script threw: ' + e.message);
}

await new Promise((r) => setTimeout(r, 1500));
const app = window.document.getElementById('app');
const ids = app ? app.querySelectorAll('[id]').length : 0;
const components = app ? app.children.length : 0;
console.log('app children:', components, '| ids in DOM:', ids);
console.log('errors:', errors.length);
errors.slice(0, 15).forEach((e) => console.log('  !', e.slice(0, 220)));
console.log('net calls:', logs.filter((l) => l.startsWith('fetch:')).length);
const profileDrawer = window.document.getElementById('profileSelectList') || window.document.getElementById('profilesList');
if (profileDrawer) console.log('profile cards rendered:', profileDrawer.children.length);
const headerName = window.document.getElementById('headerProfileName');
if (headerName) console.log('header profile label:', JSON.stringify(headerName.textContent));
logs.filter((l) => l.startsWith('fetch:')).slice(0, 8).forEach((l) => console.log('  >', l.slice(0, 120)));
process.exit(errors.length ? 1 : 0);
