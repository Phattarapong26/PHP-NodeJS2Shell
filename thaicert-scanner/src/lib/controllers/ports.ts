import { appState } from './state';

// --- 3-Mode Port Selection & Network Impact Controller ---
export const STANDARD_DEV_PORTS = [
  { port: 80, label: "80 (HTTP)" },
  { port: 443, label: "443 (HTTPS)" },
  { port: 8080, label: "8080 (Lab Portal)" },
  { port: 8081, label: "8081 (G1 CMS)" },
  { port: 8082, label: "8082 (G2 API)" },
  { port: 8083, label: "8083 (G3 Panel)" },
  { port: 8084, label: "8084 (G4 IoT)" },
  { port: 8085, label: "8085 (G5 Cont)" },
  { port: 8086, label: "8086 (G6 IIS)" },
  { port: 8087, label: "8087 (G7 Staging)" },
  { port: 8088, label: "8088 (G8 Shared)" },
  { port: 8443, label: "8443 (Alt SSL)" },
  { port: 8000, label: "8000 (PHP/Dev)" },
  { port: 8888, label: "8888 (Jupyter/App)" },
  { port: 3000, label: "3000 (Node/React)" },
  { port: 5000, label: "5000 (Flask/Py)" },
  { port: 5173, label: "5173 (Vite)" },
  { port: 4000, label: "4000 (Hexo/Node)" },
  { port: 18080, label: "18080 (App Custom)" },
  { port: 9000, label: "9000 (PHP-FPM)" },
  { port: 5050, label: "5050 (OPS Scan)" },
  { port: 8880, label: "8880 (Alt HTTP)" },
  { port: 9090, label: "9090 (Cockpit/Prom)" }
];

export const WIDE_PORTS_COLLECTION = [
  80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 5173, 4000, 8081, 18080, 9000, 8088, 5050,
  8880, 9090, 8008, 8082, 8083, 8084, 8085, 8086, 8087, 8089, 8090, 8181, 8282, 8383, 8881,
  8882, 8889, 9001, 9002, 9080, 9443, 10000, 18081, 28080, 3001, 3002, 4200, 5001, 7000, 7001,
  7070, 7443, 9999, 81, 82, 83, 84, 85, 88, 8001, 8002, 8003, 8004, 8005, 8006, 8007, 8009,
  8010, 8099, 8100, 8200, 8300, 8400, 8500, 8600, 8700, 8800, 8900, 9005, 9010, 9020, 9030,
  9040, 9050, 9060, 9070, 9091, 9092, 9100, 9200, 9300, 9400, 9500, 9600, 9700, 9800, 9900,
  10080, 10443, 18000, 18082, 19000, 19080, 20000, 20080, 28081, 30000, 21, 22, 23, 25, 53,
  110, 111, 135, 139, 143, 445, 993, 995, 1433, 1521, 1723, 2049, 2082, 2083, 2086, 2087,
  2181, 2375, 2376, 3306, 3389, 5432, 5601, 5672, 5900, 5984, 6379, 6443, 7002, 7077, 8008,
  8085, 8086, 8091, 8123, 8180, 8280, 8380, 8404, 8444, 8501, 8554, 8686, 8787, 8848, 8883,
  8983, 9042, 9094, 9102, 9110, 9191, 9201, 9306, 9411, 9527, 9876, 9998, 10001, 10050, 10051,
  11211, 12345, 15672, 16010, 16020, 16030, 18001, 18088, 19090, 27017, 27018, 27019, 28017,
  3128, 3218, 33060, 3690, 4848, 50000, 50030, 50060, 50070, 50075, 50090, 60000, 60010, 60020,
  60030, 61616, 62078, 65534, 18083, 18084, 18085, 18086, 18087, 18088, 18089, 18090, 18091,
  18092, 18093, 18094, 18095, 18096, 18097, 18098, 18099, 18100, 18101, 18102, 18103, 18104,
  18105, 18106, 18107, 18108, 18109, 18110, 18111, 18112, 18113, 18114, 18115, 18116, 18117
];

export let updateCalculatedPorts = function() {};

export function initPortSelectionControls() {
  const tabPortModeCustom = document.getElementById('tabPortModeCustom');
  const tabPortModeStandard = document.getElementById('tabPortModeStandard');
  const tabPortModeWide = document.getElementById('tabPortModeWide');

  const panelPortCustom = document.getElementById('panelPortCustom');
  const panelPortStandard = document.getElementById('panelPortStandard');
  const panelPortWide = document.getElementById('panelPortWide');

  const subTypeBtnSlider = document.getElementById('subTypeBtnSlider');
  const subTypeBtnList = document.getElementById('subTypeBtnList');
  const subViewSlider = document.getElementById('subViewSlider');
  const subViewList = document.getElementById('subViewList');

  const inputStartPort = document.getElementById('inputStartPort');
  const inputPortRangeSpan = document.getElementById('inputPortRangeSpan');
  const sliderSpanValueDisplay = document.getElementById('sliderSpanValueDisplay');
  const sliderAlertSafe = document.getElementById('sliderAlertSafe');
  const sliderAlertWarning = document.getElementById('sliderAlertWarning');
  const alertSpanCount = document.getElementById('alertSpanCount');

  const inputCustomPortList = document.getElementById('inputCustomPortList');
  const customListCountBadge = document.getElementById('customListCountBadge');

  const standardPortsContainer = document.getElementById('standardPortsContainer');
  const btnSelectAllStandard = document.getElementById('btnSelectAllStandard');

  const selectWideScope = document.getElementById('selectWideScope');
  const widePortsCountDisplay = document.getElementById('widePortsCountDisplay');
  const portCountBadge = document.getElementById('portCountBadge');

  // 1. Render standard developer dictionary chips
  function renderStandardPortChips() {
    if (!standardPortsContainer) return;
    standardPortsContainer.innerHTML = '';
    STANDARD_DEV_PORTS.forEach(item => {
      const isChecked = appState.selectedStandardPorts.includes(item.port);
      const chip = document.createElement('button');
      chip.type = 'button';
      chip.className = `px-2 py-1 rounded-lg text-[10px] font-mono cursor-pointer transition-all flex items-center gap-1 ${
        isChecked 
          ? 'bg-blue-600 text-white font-bold shadow-sm' 
          : 'neu-concave-card text-slate-500 hover:text-slate-700'
      }`;
      chip.innerHTML = `
        <i class="ph-bold ${isChecked ? 'ph-check' : 'ph-plus'} text-[10px]"></i>
        <span>${item.label}</span>
      `;
      chip.addEventListener('click', () => {
        if (appState.selectedStandardPorts.includes(item.port)) {
          if (appState.selectedStandardPorts.length > 1) {
            appState.selectedStandardPorts = appState.selectedStandardPorts.filter(p => p !== item.port);
          }
        } else {
          appState.selectedStandardPorts.push(item.port);
        }
        renderStandardPortChips();
        updateCalculatedPorts();
      });
      standardPortsContainer.appendChild(chip);
    });
  }

  // 2. Tab switcher between the 3 modes
  function setPortMode(mode) {
    appState.portMode = mode;
    const tabs = [
      { mode: 'custom', btn: tabPortModeCustom, panel: panelPortCustom },
      { mode: 'standard', btn: tabPortModeStandard, panel: panelPortStandard },
      { mode: 'wide', btn: tabPortModeWide, panel: panelPortWide }
    ];
    tabs.forEach(t => {
      if (!t.btn || !t.panel) return;
      if (t.mode === mode) {
        t.btn.classList.add('active');
        t.btn.classList.remove('text-slate-600');
        t.panel.classList.remove('hidden');
      } else {
        t.btn.classList.remove('active');
        t.btn.classList.add('text-slate-600');
        t.panel.classList.add('hidden');
      }
    });
    updateCalculatedPorts();
  }

  if (tabPortModeCustom) tabPortModeCustom.addEventListener('click', () => setPortMode('custom'));
  if (tabPortModeStandard) tabPortModeStandard.addEventListener('click', () => setPortMode('standard'));
  if (tabPortModeWide) tabPortModeWide.addEventListener('click', () => setPortMode('wide'));

  // 3. Sub-type toggle in Mode 1 (Slider vs List)
  if (subTypeBtnSlider) {
    subTypeBtnSlider.addEventListener('click', () => {
      appState.customPortType = 'slider';
      subTypeBtnSlider?.classList.add('active');
      subTypeBtnList?.classList.remove('active');
      subViewSlider?.classList.remove('hidden');
      subViewList?.classList.add('hidden');
      updateCalculatedPorts();
    });
  }
  if (subTypeBtnList) {
    subTypeBtnList.addEventListener('click', () => {
      appState.customPortType = 'list';
      subTypeBtnList?.classList.add('active');
      subTypeBtnSlider?.classList.remove('active');
      subViewList?.classList.remove('hidden');
      subViewSlider?.classList.add('hidden');
      updateCalculatedPorts();
    });
  }

  // 4. Start Port Presets
  document.querySelectorAll('.preset-start-port').forEach(btn => {
    btn.addEventListener('click', (e) => {
      document.querySelectorAll('.preset-start-port').forEach(b => b.classList.remove('active', 'font-bold'));
      (e.currentTarget as HTMLElement).classList.add('active', 'font-bold');
      const p = parseInt((e.currentTarget as HTMLElement).getAttribute('data-port'), 10);
      if (inputStartPort) (inputStartPort as HTMLInputElement).value = String(p);
      updateSliderRangeCalculation();
    });
  });

  // 5. Dynamic Port Range Slider Calculation & Alert Threshold
  function updateSliderRangeCalculation() {
    let start = parseInt((inputStartPort as HTMLInputElement)?.value ?? '8000', 10);
    if (isNaN(start) || start < 1) start = 8000;
    if (start > 65535) start = 65535;

    const span = parseInt((inputPortRangeSpan as HTMLInputElement)?.value ?? '20', 10) || 20;
    const end = Math.min(65535, start + span);
    const total = (end - start + 1);

    appState.sliderStartPort = start;
    appState.sliderSpan = span;

    if (sliderSpanValueDisplay) {
      sliderSpanValueDisplay.textContent = `ช่วง ${start} - ${end} (${total} พอร์ต)`;
    }

    // Network Impact Assessment Alert logic:
    // Rule: If total ports <= 50 -> Makes sense, safe, do not show warning.
    // If total ports > 50 -> Alert user to avoid due to network overhead impact.
    if (total <= 50) {
      if (sliderAlertSafe) sliderAlertSafe.classList.remove('hidden');
      if (sliderAlertWarning) sliderAlertWarning.classList.add('hidden');
    } else {
      if (sliderAlertSafe) sliderAlertSafe.classList.add('hidden');
      if (sliderAlertWarning) sliderAlertWarning.classList.remove('hidden');
      if (alertSpanCount) alertSpanCount.textContent = String(total);
    }

    updateCalculatedPorts();
  }

  if (inputStartPort) inputStartPort.addEventListener('input', updateSliderRangeCalculation);
  if (inputPortRangeSpan) inputPortRangeSpan.addEventListener('input', updateSliderRangeCalculation);

  // 6. Custom Port List Input
  if (inputCustomPortList) {
    inputCustomPortList.addEventListener('input', () => {
      const raw = (inputCustomPortList as HTMLInputElement).value;
      const parsed = raw.split(/[\s,]+/).map(p => parseInt(p.trim(), 10)).filter(p => !isNaN(p) && p >= 1 && p <= 65535);
      const unique = Array.from(new Set(parsed));
      if (customListCountBadge) {
        customListCountBadge.textContent = `${unique.length} พอร์ตที่ระบุ`;
      }
      appState.customPortListStr = raw;
      updateCalculatedPorts();
    });
  }

  // 7. Select All Standard Ports
  if (btnSelectAllStandard) {
    btnSelectAllStandard.addEventListener('click', () => {
      appState.selectedStandardPorts = STANDARD_DEV_PORTS.map(p => p.port);
      renderStandardPortChips();
      updateCalculatedPorts();
    });
  }

  // 8. Wide Scan Scope Selector
  if (selectWideScope) {
    selectWideScope.addEventListener('change', (e) => {
      appState.wideScopeCount = parseInt((e.target as HTMLSelectElement).value, 10);
      if (widePortsCountDisplay) {
        widePortsCountDisplay.textContent = `${appState.wideScopeCount} พอร์ต`;
      }
      updateCalculatedPorts();
    });
  }

  // 9. Master Calculated Ports Provider
  updateCalculatedPorts = function() {
    let ports = [];
    if (appState.portMode === 'standard') {
      ports = [...appState.selectedStandardPorts];
    } else if (appState.portMode === 'custom') {
      if (appState.customPortType === 'slider') {
        const start = appState.sliderStartPort || 8000;
        const span = appState.sliderSpan || 20;
        const end = Math.min(65535, start + span);
        for (let p = start; p <= end; p++) {
          ports.push(p);
        }
      } else {
        const raw = inputCustomPortList ? (inputCustomPortList as HTMLInputElement).value : appState.customPortListStr;
        const parsed = raw.split(/[\s,]+/).map(p => parseInt(p.trim(), 10)).filter(p => !isNaN(p) && p >= 1 && p <= 65535);
        ports = Array.from(new Set(parsed));
        if (ports.length === 0) ports = [80, 443, 8080];
      }
    } else if (appState.portMode === 'wide') {
      const limit = appState.wideScopeCount || 100;
      ports = WIDE_PORTS_COLLECTION.slice(0, limit);
    }

    appState.selectedPorts = ports;
    if (portCountBadge) {
      portCountBadge.textContent = `${ports.length} พอร์ตที่เลือก`;
    }
  };

  // Initial execution
  renderStandardPortChips();
  updateSliderRangeCalculation();
  updateCalculatedPorts();
}