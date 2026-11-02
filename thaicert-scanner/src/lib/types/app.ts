/** Shape of the shared application state. Mirrors the original `appState` object. */
export interface AppState {
  isScanning: boolean;
  hostIp: string;
  subnet: string;
  cidr: number;
  netmask: string;
  gateway: string;
  networkIface: string;
  firstHost: string;
  lastHost: string;
  startHost: number;
  endHost: number;
  concurrency: number;
  scanProgress: number;
  totalHosts: number;
  allHosts: any[];
  foundPhpHosts: any[];
  foundNodeHosts: any[];
  totalActiveFound: number;
  totalPhpFound: number;
  totalNodeFound: number;
  totalVulnFound: number;
  discardedDevices: any[];
  scanStartTime: number | null;
  activeFilter: string;
  isLiveBackend: boolean;
  portMode: string;
  customPortType: string;
  sliderStartPort: number;
  sliderSpan: number;
  customPortListStr: string;
  selectedStandardPorts: number[];
  wideScopeCount: number;
  selectedPorts: number[];
  allowActiveRce: boolean;
  activeGroupFilter: number | null;
  scopePreset: string;
  selectedAuditHost: any | null;
  activeAuditChain: string;
  chainViewMode: string;
  thaicertSummary: Record<string, any>;
  activeProfile: any | null;
  profilesList: any[];
  systemUpdateInfo: any | null;
  /** Escape hatch: the legacy code attaches extra properties at runtime. */
  [key: string]: any;
}
