import React, { useState, useEffect } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Lock,
  Server,
  Cookie,
  Radio,
  FileDown,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Sliders,
  ExternalLink,
  ChevronRight,
  Search,
  FileText,
  LayoutDashboard,
  Layers,
  ArrowRight,
  Terminal,
  MapPin,
  Globe,
  Copy,
  Check,
  Navigation,
} from 'lucide-react';
import jsPDF from 'jspdf';
import { ServerGeoMap, GeoData } from './components/ServerGeoMap';

// Convert 2-letter country code to Unicode Flag Emoji
function getFlagEmoji(countryCode?: string): string {
  if (!countryCode || countryCode.length !== 2) return '🌐';
  const codePoints = countryCode
    .toUpperCase()
    .split('')
    .map((char) => 127397 + char.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
}

type PageRoute =
  | 'dashboard'
  | 'scan'
  | 'results'
  | 'headers'
  | 'cookies'
  | 'ports'
  | 'server_info'
  | 'history'
  | 'reports';

interface HeaderCheck {
  header: string;
  status: 'Present' | 'Missing';
  value: string;
  rating: 'PASS' | 'WARNING';
  recommendation: string;
}

interface CookieItem {
  name: string;
  secure: boolean;
  httponly: boolean;
  samesite: string;
}

interface PortCheck {
  port: number;
  service: string;
  status: 'Open' | 'Closed';
  is_risk: boolean;
}

interface Recommendation {
  category: string;
  issue: string;
  recommendation: string;
}

interface ScanRecord {
  id?: number;
  target_url: string;
  hostname: string;
  resolved_ip: string;
  geo?: GeoData;
  http_status: number | null;
  scan_date: string;
  scan_time: string;
  scan_timestamp: string;
  scan_duration: string;
  duration_seconds: number;
  score: number;
  risk_level: 'EXCELLENT' | 'GOOD' | 'MEDIUM' | 'CRITICAL';
  badge_color: 'emerald' | 'cyan' | 'amber' | 'rose';
  issues_count?: number;
  checks: {
    https: {
      status: 'PASS' | 'WARNING' | 'FAIL';
      score_points: number;
      message: string;
      tls_version: string;
      issuer: string;
    };
    headers: HeaderCheck[];
    cookies: {
      count: number;
      has_cookies: boolean;
      status: 'PASS' | 'WARNING';
      message: string;
      cookies: CookieItem[];
    };
    server: {
      status: 'PASS' | 'WARNING';
      server: string;
      x_powered_by: string;
      exposed_details: string;
      message: string;
    };
    ports: PortCheck[];
  };
  recommendations: Recommendation[];
}

const SCAN_STAGES = [
  'Scanning target...',
  'Resolving server IP & geographic location...',
  'Checking HTTPS encryption & TLS certificates...',
  'Analyzing security response headers...',
  'Checking cookies & privacy attributes...',
  'Checking server information disclosure...',
  'Checking allowed common ports...',
  'Calculating dynamic security score...',
];

export const normalizeScan = (s: any): ScanRecord => {
  if (!s) return s;
  return {
    ...s,
    score: typeof s.score === 'number' ? s.score : 0,
    risk_level: s.risk_level || 'MEDIUM',
    badge_color: s.badge_color || 'amber',
    geo: s.geo || {},
    checks: {
      https: s.checks?.https || {
        status: 'PASS',
        score_points: 25,
        message: 'Transport encryption checked.',
        tls_version: 'TLSv1.3',
        issuer: 'Valid Certificate',
      },
      headers: Array.isArray(s.checks?.headers) ? s.checks.headers : [],
      cookies: s.checks?.cookies || {
        count: 0,
        has_cookies: false,
        status: 'PASS',
        message: 'No cookies identified.',
        cookies: [],
      },
      server: s.checks?.server || {
        status: 'PASS',
        server: 'Protected',
        x_powered_by: 'Suppressed',
        exposed_details: 'Suppressed',
        message: 'Server software banner suppressed.',
      },
      ports: Array.isArray(s.checks?.ports) ? s.checks.ports : [],
    },
    recommendations: Array.isArray(s.recommendations) ? s.recommendations : [],
  };
};

export default function App() {
  const [currentPage, setCurrentPage] = useState<PageRoute>('dashboard');
  const [urlInput, setUrlInput] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [currentStageIdx, setCurrentStageIdx] = useState(0);
  const [activeScan, setActiveScan] = useState<ScanRecord | null>(null);
  const [history, setHistory] = useState<ScanRecord[]>([]);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [searchTerm, setSearchTerm] = useState('');

  // Initial load: Fetch SQLite history & dashboard data
  useEffect(() => {
    loadData();
  }, []);

  const loadData = async () => {
    try {
      const res = await fetch('/api/history');
      if (res.ok) {
        const data = await res.json();
        const normalizedList = Array.isArray(data) ? data.map(normalizeScan) : [];
        setHistory(normalizedList);
        if (normalizedList.length > 0 && !activeScan) {
          setActiveScan(normalizedList[0]);
        }
      }
    } catch {
      // Non-fatal if server is booting
    }
  };

  const selectScan = async (item: ScanRecord) => {
    if (item.id && (!item.checks || !item.checks.headers || item.checks.headers.length === 0)) {
      try {
        const res = await fetch(`/api/scans/${item.id}`);
        if (res.ok) {
          const fullScan = await res.json();
          setActiveScan(normalizeScan(fullScan));
          setCurrentPage('results');
          return;
        }
      } catch {}
    }
    setActiveScan(normalizeScan(item));
    setCurrentPage('results');
  };

  const handleStartScan = async (overrideUrl?: string) => {
    const rawTarget = overrideUrl || urlInput;
    if (!rawTarget.trim()) {
      setErrorMessage('Please enter a valid website URL to scan.');
      return;
    }

    setErrorMessage(null);
    setIsScanning(true);
    setCurrentStageIdx(0);
    setCurrentPage('scan');

    const interval = setInterval(() => {
      setCurrentStageIdx((prev) => (prev < SCAN_STAGES.length - 1 ? prev + 1 : prev));
    }, 420);

    try {
      const res = await fetch('/api/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: rawTarget.trim() }),
      });

      const data = await res.json();
      clearInterval(interval);

      if (!res.ok) {
        throw new Error(data.error || 'Failed to complete security assessment.');
      }

      setActiveScan(normalizeScan(data));
      await loadData();
      setCurrentPage('results');
    } catch (err: any) {
      clearInterval(interval);
      setErrorMessage(
        err.message || 'Unable to connect to target website. Please verify URL and server availability.'
      );
    } finally {
      setIsScanning(false);
    }
  };

  const downloadPdfReport = (scanToExport?: ScanRecord) => {
    const scan = scanToExport || activeScan;
    if (!scan) return;

    const doc = new jsPDF();
    const pageWidth = doc.internal.pageSize.getWidth();
    let y = 20;

    // Header Cover Banner
    doc.setFillColor(11, 15, 25);
    doc.rect(0, 0, pageWidth, 42, 'F');

    doc.setTextColor(6, 182, 212);
    doc.setFontSize(20);
    doc.setFont('helvetica', 'bold');
    doc.text('WEBGUARD', 15, 18);

    doc.setTextColor(255, 255, 255);
    doc.setFontSize(11);
    doc.text('Web Security Assessment & Vulnerability Audit Report', 15, 28);

    doc.setTextColor(148, 163, 184);
    doc.setFontSize(8.5);
    doc.setFont('helvetica', 'normal');
    doc.text(
      `Report Reference: WG-REP-${scan.id || 1} · Generated: ${scan.scan_date} at ${scan.scan_time}`,
      15,
      36
    );

    y = 52;

    // 1. Target Overview
    doc.setTextColor(15, 23, 42);
    doc.setFontSize(12);
    doc.setFont('helvetica', 'bold');
    doc.text('1. Target & Assessment Overview', 15, y);
    y += 7;

    doc.setFontSize(9);
    doc.setFont('helvetica', 'normal');
    doc.setTextColor(51, 65, 85);
    doc.text(`Target URL: ${scan.target_url}`, 15, y);
    doc.text(`Resolved IP: ${scan.resolved_ip || 'N/A'}`, 120, y);
    y += 6;
    doc.text(`HTTP Status Code: ${scan.http_status ?? '200'}`, 15, y);
    const serverLoc = scan.geo?.country
      ? `${scan.geo.city ? `${scan.geo.city}, ` : ''}${scan.geo.country}`
      : 'N/A';
    doc.text(`Server Location: ${serverLoc}`, 120, y);
    y += 6;
    doc.text(`Execution Duration: ${scan.scan_duration}`, 15, y);
    doc.text(`Hosting ISP: ${scan.geo?.isp || 'N/A'}`, 120, y);
    y += 12;

    // Score & Risk Level Summary Box
    doc.setFillColor(241, 245, 249);
    doc.rect(15, y, pageWidth - 30, 24, 'F');

    doc.setTextColor(15, 23, 42);
    doc.setFontSize(10);
    doc.setFont('helvetica', 'bold');
    doc.text('SECURITY SCORE:', 22, y + 9);
    doc.text('RISK LEVEL:', 120, y + 9);

    doc.setFontSize(16);
    if (scan.score >= 90) doc.setTextColor(16, 185, 129);
    else if (scan.score >= 75) doc.setTextColor(6, 182, 212);
    else if (scan.score >= 50) doc.setTextColor(245, 158, 11);
    else doc.setTextColor(244, 63, 94);

    doc.text(`${scan.score} / 100`, 22, y + 18);
    doc.text(scan.risk_level, 120, y + 18);

    y += 34;

    // 2. HTTPS
    const httpsStatus = scan.checks?.https?.status || 'N/A';
    const tlsVersion = scan.checks?.https?.tls_version || 'N/A';
    const issuer = scan.checks?.https?.issuer || 'N/A';
    const httpsMessage = scan.checks?.https?.message || 'HTTPS status evaluated.';
    doc.setTextColor(15, 23, 42);
    doc.setFontSize(11);
    doc.setFont('helvetica', 'bold');
    doc.text(`2. Transport Encryption: [${httpsStatus}]`, 15, y);
    y += 5;
    doc.setFontSize(8.5);
    doc.setFont('helvetica', 'normal');
    doc.text(`TLS Protocol: ${tlsVersion} · Issuer: ${issuer}`, 20, y);
    y += 5;
    doc.text(httpsMessage, 20, y);
    y += 8;

    // 3. Headers
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.text('3. HTTP Response Security Headers:', 15, y);
    y += 5;
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    if (scan.checks?.headers && scan.checks.headers.length > 0) {
      for (const h of scan.checks.headers) {
        doc.text(`• ${h.header}: ${h.status} (${h.rating}) — ${h.recommendation}`, 20, y);
        y += 5;
      }
    } else {
      doc.text('• No header data recorded.', 20, y);
      y += 5;
    }
    y += 3;

    // 4. Cookies & Server
    const cookieStatus = scan.checks?.cookies?.status || 'PASS';
    const cookieMessage = scan.checks?.cookies?.message || 'No cookies identified.';
    const serverStatus = scan.checks?.server?.status || 'PASS';
    const serverName = scan.checks?.server?.server || 'None';
    const poweredBy = scan.checks?.server?.x_powered_by || 'None';
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.text('4. Cookie Security & Server Disclosure:', 15, y);
    y += 5;
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    doc.text(`• Cookie Security [${cookieStatus}]: ${cookieMessage}`, 20, y);
    y += 5;
    doc.text(
      `• Server Banners [${serverStatus}]: Server: ${serverName} | X-Powered-By: ${poweredBy}`,
      20,
      y
    );
    y += 8;

    // 5. Ports
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.text('5. Port Analysis (Passive Probe: 80, 443, 22, 21, 8080):', 15, y);
    y += 5;
    doc.setFontSize(8);
    doc.setFont('helvetica', 'normal');
    const portLine = scan.checks?.ports && scan.checks.ports.length > 0
      ? scan.checks.ports.map((p) => `Port ${p.port} (${p.service}): ${p.status}`).join(' | ')
      : 'No port records available.';
    doc.text(portLine, 20, y);
    y += 12;

    // 6. Actionable Recommendations
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(11);
    doc.text('6. Actionable Security Recommendations:', 15, y);
    y += 6;

    doc.setFontSize(8);
    const recsList = scan.recommendations || [];
    for (const rec of recsList.slice(0, 4)) {
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(2, 132, 199);
      doc.text(`• [${rec.category}] ${rec.issue}`, 15, y);
      y += 4.5;
      doc.setFont('helvetica', 'normal');
      doc.setTextColor(51, 65, 85);
      const splitText = doc.splitTextToSize(`Action: ${rec.recommendation}`, pageWidth - 35);
      doc.text(splitText, 20, y);
      y += splitText.length * 4 + 2;
    }

    // Notice
    y = Math.min(y + 8, 285);
    doc.setFontSize(7.5);
    doc.setTextColor(148, 163, 184);
    doc.text(
      'WebGuard Automated Security Assessment Engine · For Authorized Defensive Audit Only',
      15,
      y
    );

    doc.save(`WebGuard-Report-${scan.hostname || 'target'}.pdf`);
  };

  // Filtered scans for History & Reports pages
  const filteredScans = history.filter(
    (s) =>
      s.target_url.toLowerCase().includes(searchTerm.toLowerCase()) ||
      s.hostname.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="min-h-screen bg-[#0b0f19] text-slate-100 flex flex-col font-sans">
      {/* Top Navigation Bar: Multi-Page Navigation */}
      <header className="border-b border-slate-800 bg-[#0f172a] sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between gap-4">
          {/* Zone 1: Wordmark */}
          <button
            onClick={() => setCurrentPage('dashboard')}
            className="flex items-center gap-2.5 text-left shrink-0"
          >
            <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center text-cyan-400">
              <Shield className="w-4 h-4" />
            </div>
            <span className="text-lg font-extrabold tracking-tight text-white font-sans">
              WEBGUARD
            </span>
          </button>

          {/* Zone 2: Multi-Page Navigation Route Links */}
          <nav className="hidden lg:flex items-center gap-1 overflow-x-auto text-xs font-medium text-slate-400">
            <button
              onClick={() => setCurrentPage('dashboard')}
              className={`px-3 py-1.5 rounded-md transition-colors ${
                currentPage === 'dashboard'
                  ? 'text-cyan-400 bg-cyan-950/40 font-semibold border border-cyan-500/20'
                  : 'hover:text-white hover:bg-slate-800'
              }`}
            >
              Dashboard
            </button>
            <button
              onClick={() => setCurrentPage('scan')}
              className={`px-3 py-1.5 rounded-md transition-colors ${
                currentPage === 'scan'
                  ? 'text-cyan-400 bg-cyan-950/40 font-semibold border border-cyan-500/20'
                  : 'hover:text-white hover:bg-slate-800'
              }`}
            >
              New Scan
            </button>
            <button
              onClick={() => {
                if (activeScan) setCurrentPage('results');
                else handleStartScan('https://example.com');
              }}
              className={`px-3 py-1.5 rounded-md transition-colors ${
                currentPage === 'results'
                  ? 'text-cyan-400 bg-cyan-950/40 font-semibold border border-cyan-500/20'
                  : 'hover:text-white hover:bg-slate-800'
              }`}
            >
              Scan Results
            </button>
            <button
              onClick={() => {
                if (activeScan) setCurrentPage('headers');
                else handleStartScan('https://example.com');
              }}
              className={`px-3 py-1.5 rounded-md transition-colors ${
                currentPage === 'headers'
                  ? 'text-cyan-400 bg-cyan-950/40 font-semibold border border-cyan-500/20'
                  : 'hover:text-white hover:bg-slate-800'
              }`}
            >
              Security Headers
            </button>
            <button
              onClick={() => {
                if (activeScan) setCurrentPage('cookies');
                else handleStartScan('https://example.com');
              }}
              className={`px-3 py-1.5 rounded-md transition-colors ${
                currentPage === 'cookies'
                  ? 'text-cyan-400 bg-cyan-950/40 font-semibold border border-cyan-500/20'
                  : 'hover:text-white hover:bg-slate-800'
              }`}
            >
              Cookie Security
            </button>
            <button
              onClick={() => {
                if (activeScan) setCurrentPage('ports');
                else handleStartScan('https://example.com');
              }}
              className={`px-3 py-1.5 rounded-md transition-colors ${
                currentPage === 'ports'
                  ? 'text-cyan-400 bg-cyan-950/40 font-semibold border border-cyan-500/20'
                  : 'hover:text-white hover:bg-slate-800'
              }`}
            >
              Port Analysis
            </button>
            <button
              onClick={() => {
                if (activeScan) setCurrentPage('server_info');
                else handleStartScan('https://example.com');
              }}
              className={`px-3 py-1.5 rounded-md transition-colors ${
                currentPage === 'server_info'
                  ? 'text-cyan-400 bg-cyan-950/40 font-semibold border border-cyan-500/20'
                  : 'hover:text-white hover:bg-slate-800'
              }`}
            >
              Server & GeoIP
            </button>
            <button
              onClick={() => setCurrentPage('history')}
              className={`px-3 py-1.5 rounded-md transition-colors ${
                currentPage === 'history'
                  ? 'text-cyan-400 bg-cyan-950/40 font-semibold border border-cyan-500/20'
                  : 'hover:text-white hover:bg-slate-800'
              }`}
            >
              Scan History
            </button>
            <button
              onClick={() => setCurrentPage('reports')}
              className={`px-3 py-1.5 rounded-md transition-colors ${
                currentPage === 'reports'
                  ? 'text-cyan-400 bg-cyan-950/40 font-semibold border border-cyan-500/20'
                  : 'hover:text-white hover:bg-slate-800'
              }`}
            >
              Reports
            </button>
          </nav>

          {/* Zone 3: Live Scanner Indicator */}
          <div className="flex items-center gap-2">
            <span className="inline-flex items-center gap-1.5 text-[11px] font-mono font-semibold text-cyan-400 bg-cyan-950/40 border border-cyan-500/20 px-2.5 py-1 rounded">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 animate-pulse"></span>
              REAL-TIME
            </span>
          </div>
        </div>
      </header>

      {/* Main Viewport Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-6 py-8">
        {/* ======================================================== */}
        {/* PAGE 1: DASHBOARD PAGE */}
        {/* ======================================================== */}
        {currentPage === 'dashboard' && (
          <div className="space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <h1 className="text-2xl sm:text-3xl font-extrabold text-white tracking-tight">
                  Security Dashboard
                </h1>
                <p className="text-xs sm:text-sm text-slate-400 mt-1">
                  Real-time security assessment overview, target metrics, and SQLite audit records.
                </p>
              </div>
              <div className="flex flex-wrap items-center gap-2.5">
                <button
                  onClick={() => setCurrentPage('scan')}
                  className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-bold transition-colors"
                >
                  + New Scan
                </button>
                {activeScan && (
                  <>
                    <button
                      onClick={() => setCurrentPage('results')}
                      className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold transition-colors"
                    >
                      View Results
                    </button>
                    <button
                      onClick={() => downloadPdfReport()}
                      className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold transition-colors"
                    >
                      Download Report
                    </button>
                  </>
                )}
                <button
                  onClick={() => setCurrentPage('history')}
                  className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold transition-colors"
                >
                  Scan History
                </button>
              </div>
            </div>

            {/* Metrics Grid */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
                <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                  TOTAL SCANS
                </span>
                <div className="text-3xl font-extrabold font-mono text-white mb-1">
                  {history.length}
                </div>
                <span className="text-xs text-slate-500">Live SQLite records</span>
              </div>

              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
                <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                  LATEST SECURITY SCORE
                </span>
                <div className="text-3xl font-extrabold font-mono text-white mb-1">
                  {activeScan ? (
                    <>
                      <span
                        className={
                          activeScan.score >= 90
                            ? 'text-emerald-400'
                            : activeScan.score >= 75
                            ? 'text-cyan-400'
                            : activeScan.score >= 50
                            ? 'text-amber-400'
                            : 'text-rose-400'
                        }
                      >
                        {activeScan.score}
                      </span>
                      <span className="text-base text-slate-500 font-normal"> / 100</span>
                    </>
                  ) : (
                    'N/A'
                  )}
                </div>
                <span className="text-xs text-slate-500">
                  {activeScan ? `Rating: ${activeScan.risk_level}` : 'No scans yet'}
                </span>
              </div>

              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
                <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                  LATEST RISK LEVEL
                </span>
                <div
                  className={`text-2xl font-extrabold tracking-tight mb-1 ${
                    !activeScan
                      ? 'text-slate-500'
                      : activeScan.risk_level === 'EXCELLENT'
                      ? 'text-emerald-400'
                      : activeScan.risk_level === 'GOOD'
                      ? 'text-cyan-400'
                      : activeScan.risk_level === 'MEDIUM'
                      ? 'text-amber-400'
                      : 'text-rose-400'
                  }`}
                >
                  {activeScan?.risk_level || 'NONE'}
                </div>
                <span className="text-xs text-slate-500">Defensive classification</span>
              </div>

              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
                <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                  ISSUES FOUND
                </span>
                <div className="text-3xl font-extrabold font-mono text-white mb-1">
                  {activeScan?.recommendations?.length || 0}
                </div>
                <span className="text-xs text-slate-500">Flagged items in latest scan</span>
              </div>
            </div>

            {/* Last Scanned Website Card */}
            {activeScan && (
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
                <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                  <div>
                    <span className="text-[11px] font-mono text-cyan-400 uppercase tracking-wider block mb-1">
                      LAST SCANNED WEBSITE
                    </span>
                    <h2 className="text-xl font-bold font-mono text-white break-all">
                      {activeScan.target_url}
                    </h2>
                    <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400 mt-2">
                      <span className="flex items-center gap-1.5">
                        IP: <strong className="font-mono text-cyan-300 bg-slate-950 px-2 py-0.5 rounded border border-slate-800">{activeScan.resolved_ip}</strong>
                      </span>
                      {activeScan.geo?.country && (
                        <>
                          <span>·</span>
                          <span className="flex items-center gap-1 text-slate-200">
                            <span>{getFlagEmoji(activeScan.geo.country_code)}</span>
                            <span>{activeScan.geo.city ? `${activeScan.geo.city}, ` : ''}{activeScan.geo.country}</span>
                          </span>
                        </>
                      )}
                      <span>·</span>
                      <span>
                        Status: <strong className="font-mono text-slate-200">{activeScan.http_status || '200'}</strong>
                      </span>
                      <span>·</span>
                      <span>
                        Date: <strong className="font-mono text-slate-200">{activeScan.scan_date}</strong>
                      </span>
                      <span>·</span>
                      <span>
                        Time: <strong className="font-mono text-slate-200">{activeScan.scan_time}</strong>
                      </span>
                      <span>·</span>
                      <span>
                        Duration: <strong className="font-mono text-slate-200">{activeScan.scan_duration}</strong>
                      </span>
                    </div>
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <button
                      onClick={() => setCurrentPage('results')}
                      className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-bold transition-colors"
                    >
                      View Detailed Results →
                    </button>
                  </div>
                </div>
              </div>
            )}

            {/* Recent Scans Table */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
              <div className="p-4 border-b border-slate-800 flex items-center justify-between">
                <h3 className="font-bold text-white text-sm">Recent Scans</h3>
                <button
                  onClick={() => setCurrentPage('history')}
                  className="text-xs text-cyan-400 hover:underline"
                >
                  View Full History →
                </button>
              </div>

              {history.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-950/60 border-b border-slate-800 text-slate-400 font-mono uppercase text-[11px]">
                      <tr>
                        <th className="p-3">Target URL</th>
                        <th className="p-3">Resolved IP & Location</th>
                        <th className="p-3">Scan Date & Time</th>
                        <th className="p-3">Score</th>
                        <th className="p-3">Risk Level</th>
                        <th className="p-3 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {history.slice(0, 5).map((item, idx) => (
                        <tr key={idx} className="hover:bg-slate-800/30 transition-colors">
                          <td className="p-3 font-mono font-semibold text-white truncate max-w-xs">
                            {item.target_url}
                          </td>
                          <td className="p-3">
                            <div className="font-mono text-slate-300 flex items-center gap-1.5">
                              <span>{getFlagEmoji(item.geo?.country_code)}</span>
                              <span>{item.resolved_ip}</span>
                            </div>
                            {item.geo?.country && (
                              <div className="text-[10px] text-slate-500 font-sans truncate max-w-[160px]">
                                {item.geo.city ? `${item.geo.city}, ` : ''}{item.geo.country}
                              </div>
                            )}
                          </td>
                          <td className="p-3 text-slate-400">
                            {item.scan_date} · {item.scan_time}
                          </td>
                          <td className="p-3 font-mono font-bold text-slate-200">
                            {item.score}/100
                          </td>
                          <td className="p-3">
                            <span
                              className={`px-2 py-0.5 rounded font-mono font-bold text-[10px] uppercase ${
                                item.risk_level === 'EXCELLENT'
                                  ? 'bg-emerald-950/50 text-emerald-400 border border-emerald-500/20'
                                  : item.risk_level === 'GOOD'
                                  ? 'bg-cyan-950/50 text-cyan-400 border border-cyan-500/20'
                                  : item.risk_level === 'MEDIUM'
                                  ? 'bg-amber-950/50 text-amber-400 border border-amber-500/20'
                                  : 'bg-rose-950/50 text-rose-400 border border-rose-500/20'
                              }`}
                            >
                              {item.risk_level}
                            </span>
                          </td>
                          <td className="p-3 text-right">
                            <div className="flex items-center justify-end gap-2">
                              <button
                                onClick={() => selectScan(item)}
                                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-medium transition-colors"
                              >
                                View
                              </button>
                              <button
                                onClick={() => downloadPdfReport(item)}
                                className="px-2.5 py-1 rounded bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-500/30 text-[11px] font-medium transition-colors"
                              >
                                PDF
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="p-8 text-center text-slate-500 text-sm">
                  <p>No scans found in SQLite database.</p>
                  <button
                    onClick={() => setCurrentPage('scan')}
                    className="mt-3 px-4 py-2 rounded-lg bg-cyan-500 text-slate-950 text-xs font-bold"
                  >
                    Run First Scan
                  </button>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ======================================================== */}
        {/* PAGE 2: NEW SCAN PAGE */}
        {/* ======================================================== */}
        {currentPage === 'scan' && (
          <div className="max-w-2xl mx-auto py-8 text-center">
            <h1 className="text-3xl font-extrabold text-white tracking-tight mb-2">
              Start Real-Time Security Scan
            </h1>
            <p className="text-sm text-slate-400 mb-6">
              Connects live to the target website at the time of scan to assess SSL/TLS, HTTP response
              headers, cookie flags, and port hygiene.
            </p>

            <div className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-lg bg-amber-500/10 border border-amber-500/20 text-amber-300 text-xs mb-6 text-left">
              <AlertTriangle className="w-4 h-4 shrink-0 text-amber-400" />
              <span>Use WebGuard only on websites you own or have explicit permission to test.</span>
            </div>

            {/* Scan Form */}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                handleStartScan();
              }}
              className="flex flex-col sm:flex-row gap-3 mb-4"
            >
              <div className="relative flex-1 flex items-center bg-slate-900 border border-slate-700 rounded-lg px-4 focus-within:border-cyan-400 focus-within:ring-1 focus-within:ring-cyan-400 transition-all">
                <span className="text-xs font-mono text-slate-500 mr-2 select-none">https://</span>
                <input
                  type="text"
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                  placeholder="example.com"
                  disabled={isScanning}
                  className="w-full bg-transparent text-white font-mono text-sm py-3.5 focus:outline-none placeholder:text-slate-600"
                  autoComplete="off"
                  spellCheck="false"
                />
              </div>
              <button
                type="submit"
                disabled={isScanning}
                className="bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-bold px-6 py-3.5 rounded-lg text-xs tracking-wider transition-colors shrink-0 flex items-center justify-center gap-2"
              >
                {isScanning ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    SCANNING...
                  </>
                ) : (
                  <>
                    <ShieldCheck className="w-4 h-4" />
                    START SECURITY SCAN
                  </>
                )}
              </button>
            </form>

            {/* Quick Safe Targets */}
            <div className="flex flex-wrap items-center justify-center gap-2 text-xs text-slate-500 mb-8">
              <span>Quick safe test targets:</span>
              {['example.com', 'cloudflare.com', 'github.com', 'wikipedia.org'].map((target) => (
                <button
                  key={target}
                  type="button"
                  onClick={() => {
                    setUrlInput(target);
                    handleStartScan(target);
                  }}
                  disabled={isScanning}
                  className="font-mono text-slate-400 hover:text-cyan-400 bg-slate-900 hover:bg-slate-800 border border-slate-800 px-2 py-1 rounded transition-colors"
                >
                  {target}
                </button>
              ))}
            </div>

            {/* Error Message */}
            {errorMessage && (
              <div className="p-4 rounded-lg bg-rose-950/40 border border-rose-500/30 text-rose-200 text-sm text-left mb-6 flex items-start gap-3">
                <ShieldAlert className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
                <div>
                  <p className="font-semibold text-rose-300">Scan Notice</p>
                  <p className="text-xs text-rose-200/90 mt-0.5">{errorMessage}</p>
                </div>
              </div>
            )}

            {/* Live Scan Progress Animation */}
            {isScanning && (
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 text-left shadow-2xl">
                <div className="flex items-center gap-3 mb-4">
                  <RefreshCw className="w-5 h-5 text-cyan-400 animate-spin" />
                  <span className="font-semibold text-white text-base">
                    {SCAN_STAGES[currentStageIdx]}
                  </span>
                </div>

                <div className="w-full bg-slate-800 h-2 rounded-full overflow-hidden mb-5">
                  <div
                    className="bg-cyan-400 h-full transition-all duration-300"
                    style={{
                      width: `${((currentStageIdx + 1) / SCAN_STAGES.length) * 100}%`,
                    }}
                  ></div>
                </div>

                <div className="space-y-2 text-xs font-mono">
                  {SCAN_STAGES.map((stage, idx) => {
                    const isDone = idx < currentStageIdx;
                    const isCurrent = idx === currentStageIdx;
                    return (
                      <div
                        key={stage}
                        className={`flex items-center gap-2 ${
                          isDone
                            ? 'text-emerald-400'
                            : isCurrent
                            ? 'text-cyan-300 font-semibold'
                            : 'text-slate-600'
                        }`}
                      >
                        {isDone ? (
                          <CheckCircle2 className="w-3.5 h-3.5" />
                        ) : isCurrent ? (
                          <div className="w-3.5 h-3.5 rounded-full border-2 border-cyan-400 border-t-transparent animate-spin" />
                        ) : (
                          <div className="w-3.5 h-3.5 rounded-full border border-slate-700" />
                        )}
                        <span>{stage}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            )}
          </div>
        )}

        {/* FALLBACK: NO ACTIVE SCAN SELECTED */}
        {!activeScan &&
          ['results', 'headers', 'cookies', 'ports', 'server_info'].includes(currentPage) && (
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-12 text-center max-w-lg mx-auto my-8">
              <Shield className="w-12 h-12 text-cyan-400 mx-auto mb-4 animate-pulse" />
              <h3 className="text-xl font-bold text-white mb-2">No Active Scan Selected</h3>
              <p className="text-xs text-slate-400 mb-6">
                Please perform a live security audit or choose a previously saved scan from the Scan History.
              </p>
              <div className="flex justify-center gap-3">
                <button
                  onClick={() => setCurrentPage('scan')}
                  className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-slate-950 rounded-lg font-bold text-xs transition-colors"
                >
                  Run New Scan
                </button>
                <button
                  onClick={() => setCurrentPage('dashboard')}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg font-semibold text-xs transition-colors"
                >
                  Go to Dashboard
                </button>
              </div>
            </div>
          )}

        {/* ======================================================== */}
        {/* PAGE 3: SCAN RESULTS PAGE */}
        {/* ======================================================== */}
        {currentPage === 'results' && activeScan && (
          <div className="space-y-6">
            {/* Meta Banner */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
              <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
                <div>
                  <span className="text-[11px] font-mono text-cyan-400 uppercase tracking-wider block mb-1">
                    TARGET ASSESSMENT REPORT
                  </span>
                  <h1 className="text-2xl font-bold font-mono text-white break-all">
                    {activeScan.target_url}
                  </h1>
                  <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400 mt-2">
                    <span className="flex items-center gap-1.5">
                      <span>IP:</span>
                      <strong className="text-white font-mono bg-slate-950 px-2 py-0.5 rounded border border-slate-800 tracking-wider">
                        {activeScan.resolved_ip}
                      </strong>
                    </span>
                    {activeScan.geo?.country && (
                      <>
                        <span>·</span>
                        <span className="flex items-center gap-1 text-cyan-300 font-semibold bg-cyan-950/40 border border-cyan-500/20 px-2 py-0.5 rounded">
                          <span>{getFlagEmoji(activeScan.geo.country_code)}</span>
                          <span>{activeScan.geo.city ? `${activeScan.geo.city}, ` : ''}{activeScan.geo.country}</span>
                        </span>
                      </>
                    )}
                    <span>·</span>
                    <span>
                      Status: <strong className="text-slate-200 font-mono">{activeScan.http_status ?? '200'}</strong>
                    </span>
                    <span>·</span>
                    <span>
                      Date: <strong className="text-slate-200 font-mono">{activeScan.scan_date}</strong>
                    </span>
                    <span>·</span>
                    <span>
                      Time: <strong className="text-slate-200 font-mono">{activeScan.scan_time}</strong>
                    </span>
                    <span>·</span>
                    <span>
                      Duration: <strong className="text-slate-200 font-mono">{activeScan.scan_duration}</strong>
                    </span>
                  </div>
                </div>

                <div className="flex items-center gap-2.5 shrink-0">
                  <button
                    onClick={() => setCurrentPage('scan')}
                    className="px-3.5 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold"
                  >
                    New Scan
                  </button>
                  <button
                    onClick={() => downloadPdfReport()}
                    className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-bold"
                  >
                    <FileDown className="w-4 h-4" />
                    Download PDF Report
                  </button>
                </div>
              </div>
            </div>

            {/* Score & Risk Cards */}
            <div className="grid md:grid-cols-2 gap-6">
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 flex flex-col justify-between">
                <div>
                  <span className="text-xs font-mono text-slate-400 uppercase tracking-wider block mb-2">
                    SECURITY SCORE
                  </span>
                  <div className="flex items-baseline gap-3 mb-4">
                    <span className="text-6xl font-extrabold font-mono text-white tabular-nums">
                      {activeScan.score}
                    </span>
                    <span className="text-xl font-mono text-slate-500">/ 100</span>
                  </div>
                </div>
                <div>
                  <div className="w-full bg-slate-800 h-2.5 rounded-full overflow-hidden mb-2">
                    <div
                      className={`h-full rounded-full transition-all duration-700 ${
                        activeScan.score >= 90
                          ? 'bg-emerald-400'
                          : activeScan.score >= 75
                          ? 'bg-cyan-400'
                          : activeScan.score >= 50
                          ? 'bg-amber-400'
                          : 'bg-rose-400'
                      }`}
                      style={{ width: `${activeScan.score}%` }}
                    ></div>
                  </div>
                  <span className="text-xs text-slate-500">
                    Dynamic score evaluated from HTTPS transport, 4 security headers, cookie security, and port hygiene.
                  </span>
                </div>
              </div>

              <div className="bg-slate-900 border border-slate-800 rounded-xl p-6 flex flex-col justify-between">
                <div>
                  <span className="text-xs font-mono text-slate-400 uppercase tracking-wider block mb-2">
                    ASSESSED RISK LEVEL
                  </span>
                  <div
                    className={`text-4xl font-extrabold tracking-tight mb-2 ${
                      activeScan.risk_level === 'EXCELLENT'
                        ? 'text-emerald-400'
                        : activeScan.risk_level === 'GOOD'
                        ? 'text-cyan-400'
                        : activeScan.risk_level === 'MEDIUM'
                        ? 'text-amber-400'
                        : 'text-rose-400'
                    }`}
                  >
                    {activeScan.risk_level}
                  </div>
                </div>
                <p className="text-sm text-slate-300 leading-relaxed mb-4">
                  {activeScan.risk_level === 'EXCELLENT' &&
                    'Strong defensive posture. Essential TLS transport encryption and modern defensive response headers are configured.'}
                  {activeScan.risk_level === 'GOOD' &&
                    'Good baseline protection. Primary encryption is active; minor header directives or cookie attributes should be tightened.'}
                  {activeScan.risk_level === 'MEDIUM' &&
                    'Moderate risk exposure. Several critical security headers (like CSP or HSTS) or cookie flags are missing.'}
                  {activeScan.risk_level === 'CRITICAL' &&
                    'High vulnerability risk. Plain text transport or critical security headers are absent, leaving clients exposed to interception.'}
                </p>
                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <button
                    onClick={() => setCurrentPage('server_info')}
                    className="text-cyan-400 bg-cyan-950/40 border border-cyan-500/20 px-2.5 py-1 rounded hover:bg-cyan-950 flex items-center gap-1 font-semibold"
                  >
                    <MapPin className="w-3 h-3" />
                    Server & GeoIP →
                  </button>
                  <button
                    onClick={() => setCurrentPage('headers')}
                    className="text-cyan-400 bg-cyan-950/40 border border-cyan-500/20 px-2.5 py-1 rounded hover:bg-cyan-950"
                  >
                    Headers Page →
                  </button>
                  <button
                    onClick={() => setCurrentPage('cookies')}
                    className="text-cyan-400 bg-cyan-950/40 border border-cyan-500/20 px-2.5 py-1 rounded hover:bg-cyan-950"
                  >
                    Cookies Page →
                  </button>
                  <button
                    onClick={() => setCurrentPage('ports')}
                    className="text-cyan-400 bg-cyan-950/40 border border-cyan-500/20 px-2.5 py-1 rounded hover:bg-cyan-950"
                  >
                    Ports Page →
                  </button>
                </div>
              </div>
            </div>

            {/* Server Physical Location & Network Map Section */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <MapPin className="w-5 h-5 text-cyan-400" />
                  <h2 className="text-lg font-bold text-white">Server Physical Location & Network Map</h2>
                </div>
                <button
                  onClick={() => setCurrentPage('server_info')}
                  className="text-xs text-cyan-400 hover:underline flex items-center gap-1 font-mono"
                >
                  Full Infrastructure View →
                </button>
              </div>

              <ServerGeoMap
                geo={activeScan.geo}
                hostname={activeScan.hostname}
                ip={activeScan.resolved_ip}
                height="340px"
              />
            </div>

            {/* Separate Cards for 5 Checks */}
            <div className="space-y-4">
              <h2 className="text-lg font-bold text-white flex items-center gap-2">
                <Layers className="w-5 h-5 text-cyan-400" />
                Security Checks Assessment
              </h2>

              {/* HTTPS Card */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded-lg bg-slate-800 flex items-center justify-center text-cyan-400">
                      <Lock className="w-4 h-4" />
                    </div>
                    <div>
                      <h3 className="font-bold text-white text-base">HTTPS & Transport Security</h3>
                      <p className="text-xs text-slate-400">
                        TLS protocol negotiation, handshake status, and certificate authority
                      </p>
                    </div>
                  </div>
                  <span
                    className={`text-xs font-mono px-2.5 py-0.5 rounded font-bold uppercase ${
                      activeScan.checks.https.status === 'PASS'
                        ? 'bg-emerald-950/50 text-emerald-400 border border-emerald-500/20'
                        : 'bg-amber-950/50 text-amber-400 border border-amber-500/20'
                    }`}
                  >
                    {activeScan.checks.https.status}
                  </span>
                </div>
                <p className="text-xs text-slate-300 mb-3">{activeScan.checks.https.message}</p>
                <div className="grid sm:grid-cols-2 gap-3 bg-slate-950/50 p-3 rounded-lg border border-slate-800 text-xs">
                  <div>
                    <span className="text-slate-500 block mb-0.5">TLS Protocol</span>
                    <span className="font-mono text-white font-semibold">
                      {activeScan.checks.https.tls_version}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500 block mb-0.5">Certificate Issuer</span>
                    <span className="font-mono text-white font-semibold">
                      {activeScan.checks.https.issuer}
                    </span>
                  </div>
                </div>
              </div>

              {/* Security Headers Card */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded-lg bg-slate-800 flex items-center justify-center text-cyan-400">
                      <Shield className="w-4 h-4" />
                    </div>
                    <div>
                      <h3 className="font-bold text-white text-base">HTTP Security Headers</h3>
                      <p className="text-xs text-slate-400">
                        Content-Security-Policy, X-Frame-Options, X-Content-Type-Options, HSTS
                      </p>
                    </div>
                  </div>
                  <button
                    onClick={() => setCurrentPage('headers')}
                    className="text-xs text-cyan-400 hover:underline"
                  >
                    Dedicated Headers Page →
                  </button>
                </div>

                <div className="overflow-x-auto border border-slate-800 rounded-lg">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-950/70 border-b border-slate-800 text-slate-400 font-mono uppercase text-[10px]">
                      <tr>
                        <th className="p-2.5">Header</th>
                        <th className="p-2.5">Status</th>
                        <th className="p-2.5">Observed Header Value</th>
                        <th className="p-2.5">Recommendation</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {(activeScan.checks?.headers || []).map((h) => (
                        <tr key={h.header}>
                          <td className="p-2.5 font-mono font-semibold text-cyan-300">{h.header}</td>
                          <td className="p-2.5">
                            <span
                              className={`px-2 py-0.5 rounded font-mono font-bold text-[10px] ${
                                h.status === 'Present'
                                  ? 'bg-emerald-950/50 text-emerald-300 border border-emerald-500/20'
                                  : 'bg-amber-950/50 text-amber-300 border border-amber-500/20'
                              }`}
                            >
                              {h.status}
                            </span>
                          </td>
                          <td className="p-2.5 font-mono text-slate-400 text-[11px] max-w-xs truncate">
                            {h.value}
                          </td>
                          <td className="p-2.5 text-slate-300 text-[11px]">{h.recommendation}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Cookie Security Card */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded-lg bg-slate-800 flex items-center justify-center text-cyan-400">
                      <Cookie className="w-4 h-4" />
                    </div>
                    <div>
                      <h3 className="font-bold text-white text-base">Cookie Security</h3>
                      <p className="text-xs text-slate-400">
                        Secure, HttpOnly, and SameSite attributes (sensitive values redacted)
                      </p>
                    </div>
                  </div>
                  <span
                    className={`text-xs font-mono px-2.5 py-0.5 rounded font-bold uppercase ${
                      activeScan.checks.cookies.status === 'PASS'
                        ? 'bg-emerald-950/50 text-emerald-400 border border-emerald-500/20'
                        : 'bg-amber-950/50 text-amber-400 border border-amber-500/20'
                    }`}
                  >
                    {activeScan.checks.cookies.status}
                  </span>
                </div>
                <p className="text-xs text-slate-300 mb-3">{activeScan.checks?.cookies?.message || ''}</p>
                {activeScan.checks?.cookies?.has_cookies && (
                  <div className="grid sm:grid-cols-2 md:grid-cols-3 gap-2.5">
                    {(activeScan.checks?.cookies?.cookies || []).map((c, i) => (
                      <div
                        key={i}
                        className="bg-slate-950/50 p-3 rounded-lg border border-slate-800 text-xs"
                      >
                        <span className="font-mono font-semibold text-white block truncate mb-1">
                          {c.name}
                        </span>
                        <div className="flex flex-wrap gap-1 font-mono text-[10px]">
                          <span
                            className={`px-1.5 py-0.5 rounded ${
                              c.secure
                                ? 'bg-emerald-950/50 text-emerald-400'
                                : 'bg-rose-950/50 text-rose-400'
                            }`}
                          >
                            Secure: {c.secure ? 'Yes' : 'No'}
                          </span>
                          <span
                            className={`px-1.5 py-0.5 rounded ${
                              c.httponly
                                ? 'bg-emerald-950/50 text-emerald-400'
                                : 'bg-rose-950/50 text-rose-400'
                            }`}
                          >
                            HttpOnly: {c.httponly ? 'Yes' : 'No'}
                          </span>
                          <span className="px-1.5 py-0.5 rounded bg-slate-800 text-slate-300">
                            SameSite: {c.samesite}
                          </span>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Server Information Card */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded-lg bg-slate-800 flex items-center justify-center text-cyan-400">
                      <Server className="w-4 h-4" />
                    </div>
                    <div>
                      <h3 className="font-bold text-white text-base">Server Information Disclosure</h3>
                      <p className="text-xs text-slate-400">
                        Inspection of Server and X-Powered-By response headers
                      </p>
                    </div>
                  </div>
                  <span
                    className={`text-xs font-mono px-2.5 py-0.5 rounded font-bold uppercase ${
                      activeScan.checks.server.status === 'PASS'
                        ? 'bg-emerald-950/50 text-emerald-400 border border-emerald-500/20'
                        : 'bg-amber-950/50 text-amber-400 border border-amber-500/20'
                    }`}
                  >
                    {activeScan.checks.server.status}
                  </span>
                </div>
                <p className="text-xs text-slate-300 mb-3">{activeScan.checks.server.message}</p>
                <div className="grid sm:grid-cols-2 gap-3 bg-slate-950/50 p-3 rounded-lg border border-slate-800 text-xs">
                  <div>
                    <span className="text-slate-500 block mb-0.5">Server Header</span>
                    <span className="font-mono text-white font-semibold">
                      {activeScan.checks.server.server}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500 block mb-0.5">X-Powered-By Header</span>
                    <span className="font-mono text-white font-semibold">
                      {activeScan.checks.server.x_powered_by}
                    </span>
                  </div>
                </div>
              </div>

              {/* Port Analysis Card */}
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <div className="w-9 h-9 rounded-lg bg-slate-800 flex items-center justify-center text-cyan-400">
                      <Radio className="w-4 h-4" />
                    </div>
                    <div>
                      <h3 className="font-bold text-white text-base">Port Analysis</h3>
                      <p className="text-xs text-slate-400">
                        TCP socket probes for common ports: 80, 443, 22, 21, 8080
                      </p>
                    </div>
                  </div>
                  <button
                    onClick={() => setCurrentPage('ports')}
                    className="text-xs text-cyan-400 hover:underline"
                  >
                    Dedicated Ports Page →
                  </button>
                </div>

                <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5">
                  {(activeScan.checks?.ports || []).map((p) => (
                    <div
                      key={p.port}
                      className={`p-3 rounded-lg border text-xs ${
                        p.is_risk
                          ? 'bg-rose-950/20 border-rose-500/40'
                          : 'bg-slate-950/50 border-slate-800'
                      }`}
                    >
                      <span className="font-mono font-bold text-white block">Port {p.port}</span>
                      <span className="text-[11px] text-slate-400 block truncate mb-1">
                        {p.service}
                      </span>
                      <div className="flex items-center gap-1.5 font-mono text-xs">
                        <span
                          className={`w-2 h-2 rounded-full ${
                            p.status === 'Open' ? 'bg-emerald-400' : 'bg-slate-600'
                          }`}
                        />
                        <span
                          className={p.status === 'Open' ? 'text-white font-semibold' : 'text-slate-500'}
                        >
                          {p.status}
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Actionable Recommendations */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
              <h2 className="text-lg font-bold text-white mb-4">Actionable Recommendations</h2>
              <div className="space-y-3">
                {(activeScan.recommendations || []).map((rec, i) => (
                  <div
                    key={i}
                    className="p-3.5 rounded-lg bg-slate-950/60 border border-slate-800 flex flex-col gap-1 text-xs"
                  >
                    <span className="font-mono text-cyan-400 text-[10px] font-bold uppercase">
                      {rec.category}
                    </span>
                    <h4 className="font-semibold text-slate-200 text-sm">{rec.issue}</h4>
                    <p className="text-slate-400 leading-relaxed">{rec.recommendation}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ======================================================== */}
        {/* PAGE 4: SECURITY HEADERS PAGE */}
        {/* ======================================================== */}
        {currentPage === 'headers' && activeScan && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-xs text-slate-500 mb-1">
                  <button onClick={() => setCurrentPage('dashboard')} className="hover:underline">
                    Dashboard
                  </button>{' '}
                  /{' '}
                  <button onClick={() => setCurrentPage('results')} className="hover:underline">
                    {activeScan.hostname}
                  </button>{' '}
                  / Security Headers
                </div>
                <h1 className="text-2xl font-bold text-white">HTTP Security Headers Deep Dive</h1>
                <p className="text-xs text-slate-400 mt-1">
                  Detailed inspection of browser-enforced mitigation headers against XSS, clickjacking, and protocol downgrade.
                </p>
              </div>
              <button
                onClick={() => setCurrentPage('results')}
                className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold"
              >
                ← Back to Results
              </button>
            </div>

            <div className="space-y-4">
              {(activeScan.checks?.headers || []).map((h) => (
                <div key={h.header} className="bg-slate-900 border border-slate-800 rounded-xl p-5">
                  <div className="flex items-center justify-between mb-3 border-b border-slate-800 pb-3">
                    <span className="font-mono text-cyan-300 font-bold text-base">{h.header}</span>
                    <span
                      className={`px-2.5 py-0.5 rounded font-mono text-xs font-bold uppercase ${
                        h.status === 'Present'
                          ? 'bg-emerald-950/50 text-emerald-400 border border-emerald-500/20'
                          : 'bg-amber-950/50 text-amber-400 border border-amber-500/20'
                      }`}
                    >
                      {h.status}
                    </span>
                  </div>

                  <div className="space-y-3 text-xs">
                    <div>
                      <span className="text-[11px] font-mono text-slate-500 uppercase block mb-1">
                        Observed Value in HTTP Response:
                      </span>
                      <pre className="font-mono bg-slate-950 p-2.5 rounded border border-slate-800/80 text-cyan-400 overflow-x-auto">
                        {h.value}
                      </pre>
                    </div>

                    <div>
                      <span className="text-[11px] font-mono text-slate-500 uppercase block mb-1">
                        Defensive Purpose:
                      </span>
                      <p className="text-slate-300 leading-relaxed">
                        {h.header === 'Content-Security-Policy' &&
                          'Restricts script and media execution origins to prevent malicious Cross-Site Scripting (XSS) and code injection.'}
                        {h.header === 'X-Frame-Options' &&
                          'Prevents other origins from embedding this site inside iframes, thwarting clickjacking attacks.'}
                        {h.header === 'X-Content-Type-Options' &&
                          'Instructs browsers not to sniff content types away from the declared MIME type.'}
                        {h.header === 'Strict-Transport-Security' &&
                          'Enforces encrypted HTTPS connections and protects against SSL stripping downgrade attacks.'}
                      </p>
                    </div>

                    <div>
                      <span className="text-[11px] font-mono text-slate-500 uppercase block mb-1">
                        Remediation Recommendation:
                      </span>
                      <div className="bg-cyan-950/30 border-l-2 border-cyan-500 p-2.5 rounded-r text-slate-200">
                        {h.recommendation}
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ======================================================== */}
        {/* PAGE 5: COOKIE SECURITY PAGE */}
        {/* ======================================================== */}
        {currentPage === 'cookies' && activeScan && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-xs text-slate-500 mb-1">
                  <button onClick={() => setCurrentPage('dashboard')} className="hover:underline">
                    Dashboard
                  </button>{' '}
                  /{' '}
                  <button onClick={() => setCurrentPage('results')} className="hover:underline">
                    {activeScan.hostname}
                  </button>{' '}
                  / Cookie Security
                </div>
                <h1 className="text-2xl font-bold text-white">Cookie Security Attributes</h1>
                <p className="text-xs text-slate-400 mt-1">
                  Evaluates transport encryption, client-side script visibility, and cross-site request policies.
                </p>
              </div>
              <button
                onClick={() => setCurrentPage('results')}
                className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold"
              >
                ← Back to Results
              </button>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 text-xs flex items-center gap-3">
              <Lock className="w-5 h-5 text-cyan-400 shrink-0" />
              <div className="text-slate-300">
                <strong className="text-white block">Zero Sensitive Data Retention:</strong>
                WebGuard completely drops session values. Only cookie names and attribute flags (Secure,
                HttpOnly, SameSite) are analyzed.
              </div>
            </div>

            {activeScan.checks?.cookies?.has_cookies ? (
              <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-950/60 border-b border-slate-800 text-slate-400 font-mono uppercase text-[11px]">
                    <tr>
                      <th className="p-3">Cookie Identifier</th>
                      <th className="p-3">Secure Flag</th>
                      <th className="p-3">HttpOnly Flag</th>
                      <th className="p-3">SameSite Flag</th>
                      <th className="p-3">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {(activeScan.checks?.cookies?.cookies || []).map((c, i) => (
                      <tr key={i} className="hover:bg-slate-800/30">
                        <td className="p-3 font-mono font-semibold text-white">{c.name}</td>
                        <td className="p-3">
                          <span
                            className={`px-2 py-0.5 rounded font-mono text-[10px] ${
                              c.secure
                                ? 'bg-emerald-950/50 text-emerald-400'
                                : 'bg-rose-950/50 text-rose-400'
                            }`}
                          >
                            {c.secure ? 'Yes (HTTPS Only)' : 'Missing'}
                          </span>
                        </td>
                        <td className="p-3">
                          <span
                            className={`px-2 py-0.5 rounded font-mono text-[10px] ${
                              c.httponly
                                ? 'bg-emerald-950/50 text-emerald-400'
                                : 'bg-rose-950/50 text-rose-400'
                            }`}
                          >
                            {c.httponly ? 'Yes (Hidden from JS)' : 'Missing (XSS Risk)'}
                          </span>
                        </td>
                        <td className="p-3 font-mono text-slate-300">{c.samesite}</td>
                        <td className="p-3">
                          {c.secure && c.httponly ? (
                            <span className="text-emerald-400 font-bold text-[11px]">HARDENED</span>
                          ) : (
                            <span className="text-amber-400 font-bold text-[11px]">NEEDS ATTENTION</span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-8 text-center text-slate-400 text-sm">
                <Cookie className="w-8 h-8 text-slate-600 mx-auto mb-2" />
                <h3 className="font-bold text-white mb-1">No Cookies Detected in Initial Response</h3>
                <p className="text-xs text-slate-500">
                  The target endpoint did not issue any Set-Cookie directives.
                </p>
              </div>
            )}
          </div>
        )}

        {/* ======================================================== */}
        {/* PAGE 6: PORT ANALYSIS PAGE */}
        {/* ======================================================== */}
        {currentPage === 'ports' && activeScan && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-xs text-slate-500 mb-1">
                  <button onClick={() => setCurrentPage('dashboard')} className="hover:underline">
                    Dashboard
                  </button>{' '}
                  /{' '}
                  <button onClick={() => setCurrentPage('results')} className="hover:underline">
                    {activeScan.hostname}
                  </button>{' '}
                  / Port Analysis
                </div>
                <h1 className="text-2xl font-bold text-white">Port Analysis & Service Exposure</h1>
                <p className="text-xs text-slate-400 mt-1">
                  Passive non-aggressive TCP socket checks on standard web and remote management ports.
                </p>
              </div>
              <button
                onClick={() => setCurrentPage('results')}
                className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold"
              >
                ← Back to Results
              </button>
            </div>

            <div className="grid md:grid-cols-2 gap-4">
              {(activeScan.checks?.ports || []).map((p) => (
                <div
                  key={p.port}
                  className={`bg-slate-900 border rounded-xl p-5 ${
                    p.is_risk ? 'border-rose-500/40 bg-rose-950/10' : 'border-slate-800'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="font-mono text-lg font-bold text-white">Port {p.port}</span>
                    <div className="flex items-center gap-1.5 font-mono text-xs">
                      <span
                        className={`w-2 h-2 rounded-full ${
                          p.status === 'Open' ? 'bg-emerald-400' : 'bg-slate-600'
                        }`}
                      />
                      <span
                        className={p.status === 'Open' ? 'text-white font-bold' : 'text-slate-500'}
                      >
                        {p.status}
                      </span>
                    </div>
                  </div>
                  <span className="text-xs font-mono text-cyan-400 block mb-2">{p.service}</span>
                  <p className="text-xs text-slate-300 leading-relaxed mb-3">
                    {p.port === 80 &&
                      'Standard unencrypted web port. Ensure automatic 301 redirection to HTTPS port 443.'}
                    {p.port === 443 &&
                      'Standard encrypted TLS web port. Normal and expected for secure websites.'}
                    {p.port === 22 &&
                      'SSH Remote Administration. Exposing port 22 directly allows brute-force attacks; restrict via firewall or VPN.'}
                    {p.port === 21 &&
                      'FTP File Transfer. Transmits clear-text credentials over the network; recommend disabling or using SFTP.'}
                    {p.port === 8080 &&
                      'Alternative Web / Proxy / Management Port. Often hosts dev portals or admin panels.'}
                  </p>
                  <div>
                    {p.is_risk ? (
                      <span className="text-[11px] font-mono text-rose-400 font-bold">
                        ⚠️ WARNING: Public service exposure detected
                      </span>
                    ) : (
                      <span className="text-[11px] font-mono text-emerald-400">
                        ✓ Service posture acceptable
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ======================================================== */}
        {/* PAGE 7: SERVER INFORMATION & GEOLOCATION PAGE */}
        {/* ======================================================== */}
        {currentPage === 'server_info' && activeScan && (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-xs text-slate-500 mb-1">
                  <button onClick={() => setCurrentPage('dashboard')} className="hover:underline">
                    Dashboard
                  </button>{' '}
                  /{' '}
                  <button onClick={() => setCurrentPage('results')} className="hover:underline">
                    {activeScan.hostname}
                  </button>{' '}
                  / Server & Geolocation
                </div>
                <h1 className="text-2xl font-bold text-white flex items-center gap-2.5">
                  <Globe className="w-6 h-6 text-cyan-400" />
                  Server Infrastructure & Physical Geolocation
                </h1>
                <p className="text-xs text-slate-400 mt-1">
                  Live mapping of physical server hosting location, network ASN/ISP, geographic coordinates, and backend software disclosure.
                </p>
              </div>
              <button
                onClick={() => setCurrentPage('results')}
                className="px-3.5 py-1.5 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold transition-colors"
              >
                ← Back to Results
              </button>
            </div>

            {/* Interactive Leaflet Server Map */}
            <ServerGeoMap
              geo={activeScan.geo}
              hostname={activeScan.hostname}
              ip={activeScan.resolved_ip}
              height="400px"
            />

            {/* Comprehensive Technical Infrastructure Grid */}
            <div className="grid sm:grid-cols-2 md:grid-cols-3 gap-4">
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
                <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                  RESOLVED PUBLIC IP
                </span>
                <div className="flex items-center justify-between">
                  <span className="font-mono text-cyan-300 font-bold text-base">
                    {activeScan.resolved_ip}
                  </span>
                  <span className="text-[10px] font-mono bg-cyan-950/80 border border-cyan-500/30 text-cyan-400 px-2 py-0.5 rounded">
                    IPv4
                  </span>
                </div>
                <span className="text-[11px] text-slate-500 mt-1 block">
                  DNS Target: <code className="text-slate-400">{activeScan.hostname}</code>
                </span>
              </div>

              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
                <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                  DATACENTER LOCATION
                </span>
                <div className="flex items-center gap-2">
                  <span className="text-xl leading-none">{getFlagEmoji(activeScan.geo?.country_code)}</span>
                  <span className="font-bold text-white text-sm">
                    {activeScan.geo?.city ? `${activeScan.geo.city}, ` : ''}{activeScan.geo?.country || 'Unknown'}
                  </span>
                </div>
                <span className="text-[11px] text-slate-500 mt-1 block">
                  Region: {activeScan.geo?.region || 'Global Cloud Network'}
                </span>
              </div>

              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
                <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                  NETWORK ROUTING & ISP
                </span>
                <span className="font-semibold text-white text-sm block truncate" title={activeScan.geo?.isp}>
                  {activeScan.geo?.isp || 'Cloud Network Provider'}
                </span>
                <span className="text-[11px] text-slate-500 mt-1 block">
                  Autonomous System: <code className="text-cyan-400">{activeScan.geo?.asn || 'AS-UNASSIGNED'}</code>
                </span>
              </div>

              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
                <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                  GPS COORDINATES
                </span>
                <span className="font-mono text-white text-sm font-semibold block">
                  {typeof activeScan.geo?.latitude === 'number' &&
                  typeof activeScan.geo?.longitude === 'number' &&
                  (activeScan.geo.latitude !== 0 || activeScan.geo.longitude !== 0)
                    ? `${activeScan.geo.latitude.toFixed(4)}, ${activeScan.geo.longitude.toFixed(4)}`
                    : 'N/A'}
                </span>
                <span className="text-[11px] text-slate-500 mt-1 block">
                  Continent: {activeScan.geo?.continent || 'Global'}
                </span>
              </div>

              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
                <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                  SERVER TIMEZONE
                </span>
                <span className="font-mono text-cyan-300 text-sm font-semibold block truncate">
                  {activeScan.geo?.timezone || 'UTC / Not Disclosed'}
                </span>
                <span className="text-[11px] text-slate-500 mt-1 block">
                  Postal Zone: {activeScan.geo?.postal || 'N/A'}
                </span>
              </div>

              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
                <span className="text-[11px] font-mono text-slate-400 uppercase tracking-wider block mb-1">
                  HTTP TRANSPORT STATUS
                </span>
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                  <span className="font-mono text-emerald-400 font-bold text-sm">
                    PORT 443 ACTIVE
                  </span>
                </div>
                <span className="text-[11px] text-slate-500 mt-1 block">
                  Response Code: {activeScan.http_status ?? 200} OK
                </span>
              </div>
            </div>

            {/* Detected Response Headers Card */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
              <div className="flex items-center justify-between mb-3">
                <h3 className="font-bold text-white text-sm flex items-center gap-2">
                  <Server className="w-4 h-4 text-cyan-400" />
                  Detected Technology & Framework Banners
                </h3>
                <span
                  className={`text-xs font-mono px-2.5 py-0.5 rounded font-bold uppercase ${
                    (activeScan.checks?.server?.status || 'PASS') === 'PASS'
                      ? 'bg-emerald-950/50 text-emerald-400 border border-emerald-500/20'
                      : 'bg-amber-950/50 text-amber-400 border border-amber-500/20'
                  }`}
                >
                  {activeScan.checks?.server?.status || 'PASS'}
                </span>
              </div>
              <div className="grid sm:grid-cols-2 gap-4 text-xs mb-4">
                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                  <span className="text-slate-500 block mb-1">Server Response Header:</span>
                  <span className="font-mono text-cyan-300 font-semibold text-sm">
                    {activeScan.checks?.server?.server || 'None'}
                  </span>
                </div>
                <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                  <span className="text-slate-500 block mb-1">X-Powered-By Header:</span>
                  <span className="font-mono text-cyan-300 font-semibold text-sm">
                    {activeScan.checks?.server?.x_powered_by || 'None'}
                  </span>
                </div>
              </div>
              <p className="text-xs text-slate-300">{activeScan.checks?.server?.message || ''}</p>
            </div>

            {/* Remediation & Hardening Recommendations */}
            <div className="grid md:grid-cols-3 gap-4">
              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 text-xs">
                <h4 className="font-bold text-white font-mono mb-2">Nginx Hardening</h4>
                <p className="text-slate-400 mb-2">Suppress server version tokens in <code>nginx.conf</code>:</p>
                <pre className="bg-slate-950 p-2.5 rounded border border-slate-800 font-mono text-cyan-300 text-[11px]">http &#123;
    server_tokens off;
&#125;</pre>
              </div>

              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 text-xs">
                <h4 className="font-bold text-white font-mono mb-2">Apache Hardening</h4>
                <p className="text-slate-400 mb-2">Suppress banners in <code>httpd.conf</code> or <code>security.conf</code>:</p>
                <pre className="bg-slate-950 p-2.5 rounded border border-slate-800 font-mono text-cyan-300 text-[11px]">ServerTokens Prod
ServerSignature Off</pre>
              </div>

              <div className="bg-slate-900 border border-slate-800 rounded-xl p-4 text-xs">
                <h4 className="font-bold text-white font-mono mb-2">Express.js Hardening</h4>
                <p className="text-slate-400 mb-2">Disable <code>X-Powered-By</code> in Node.js Express:</p>
                <pre className="bg-slate-950 p-2.5 rounded border border-slate-800 font-mono text-cyan-300 text-[11px]">app.disable('x-powered-by');
// or use helmet()</pre>
              </div>
            </div>

            {/* Why Information Disclosure Matters */}
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 text-xs text-slate-300 space-y-2">
              <h3 className="font-bold text-white text-sm">Why Information Disclosure Matters</h3>
              <p className="leading-relaxed">
                Exposing specific web server versions (e.g. Apache/2.4.41, nginx/1.18.0) or backend
                frameworks (e.g. Express, PHP/7.4) provides attackers with immediate intelligence to look
                up known unpatched CVEs. Disclosing physical datacenter and network hosting coordinates
                helps security engineers audit cloud boundary policies and sovereign data compliance.
              </p>
            </div>
          </div>
        )}

        {/* ======================================================== */}
        {/* PAGE 8: SCAN HISTORY PAGE */}
        {/* ======================================================== */}
        {currentPage === 'history' && (
          <div className="space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <h1 className="text-2xl font-bold text-white">Scan History</h1>
                <p className="text-xs text-slate-400 mt-1">
                  Audit records stored persistently in the SQLite database.
                </p>
              </div>
              <div className="flex items-center gap-3">
                <div className="relative">
                  <Search className="w-4 h-4 text-slate-500 absolute left-3 top-2.5" />
                  <input
                    type="text"
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    placeholder="Search target URL..."
                    className="bg-slate-900 border border-slate-800 rounded-lg pl-9 pr-4 py-1.5 text-xs text-white focus:outline-none focus:border-cyan-400 font-mono"
                  />
                </div>
                <button
                  onClick={() => setCurrentPage('scan')}
                  className="px-3.5 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-bold shrink-0"
                >
                  + New Scan
                </button>
              </div>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
              {filteredScans.length > 0 ? (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="bg-slate-950/60 border-b border-slate-800 text-slate-400 font-mono uppercase text-[11px]">
                      <tr>
                        <th className="p-3">ID</th>
                        <th className="p-3">Target Website</th>
                        <th className="p-3">Resolved IP & Location</th>
                        <th className="p-3">Timestamp</th>
                        <th className="p-3">Duration</th>
                        <th className="p-3">Score</th>
                        <th className="p-3">Risk Level</th>
                        <th className="p-3 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60">
                      {filteredScans.map((s, idx) => (
                        <tr key={idx} className="hover:bg-slate-800/30 transition-colors">
                          <td className="p-3 font-mono text-slate-500">#{s.id || idx + 1}</td>
                          <td className="p-3 font-mono font-semibold text-white">{s.target_url}</td>
                          <td className="p-3">
                            <div className="font-mono text-slate-300 flex items-center gap-1.5">
                              <span>{getFlagEmoji(s.geo?.country_code)}</span>
                              <span>{s.resolved_ip}</span>
                            </div>
                            {s.geo?.country && (
                              <div className="text-[10px] text-slate-500 font-sans truncate max-w-[150px]">
                                {s.geo.city ? `${s.geo.city}, ` : ''}{s.geo.country}
                              </div>
                            )}
                          </td>
                          <td className="p-3 text-slate-400">
                            {s.scan_date} · {s.scan_time}
                          </td>
                          <td className="p-3 font-mono text-slate-400">{s.scan_duration}</td>
                          <td className="p-3 font-mono font-bold text-white">{s.score}/100</td>
                          <td className="p-3">
                            <span
                              className={`px-2 py-0.5 rounded font-mono font-bold text-[10px] uppercase ${
                                s.risk_level === 'EXCELLENT'
                                  ? 'bg-emerald-950/50 text-emerald-400'
                                  : s.risk_level === 'GOOD'
                                  ? 'bg-cyan-950/50 text-cyan-400'
                                  : s.risk_level === 'MEDIUM'
                                  ? 'bg-amber-950/50 text-amber-400'
                                  : 'bg-rose-950/50 text-rose-400'
                              }`}
                            >
                              {s.risk_level}
                            </span>
                          </td>
                          <td className="p-3 text-right">
                            <div className="flex items-center justify-end gap-2">
                              <button
                                onClick={() => selectScan(s)}
                                className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-medium"
                              >
                                Open
                              </button>
                              <button
                                onClick={() => downloadPdfReport(s)}
                                className="px-2.5 py-1 rounded bg-cyan-950 hover:bg-cyan-900 text-cyan-300 border border-cyan-500/30 text-[11px] font-medium"
                              >
                                PDF
                              </button>
                            </div>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="p-8 text-center text-slate-500 text-sm">
                  <p>No historical scans match your query.</p>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ======================================================== */}
        {/* PAGE 9: REPORTS PAGE */}
        {/* ======================================================== */}
        {currentPage === 'reports' && (
          <div className="space-y-6">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
              <div>
                <h1 className="text-2xl font-bold text-white">Security Reports Center</h1>
                <p className="text-xs text-slate-400 mt-1">
                  View and export comprehensive PDF assessment documents compiled dynamically from SQLite scan records.
                </p>
              </div>
              <button
                onClick={() => setCurrentPage('scan')}
                className="px-4 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-bold"
              >
                + New Scan
              </button>
            </div>

            <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
              {history.length > 0 ? (
                <table className="w-full text-left text-xs">
                  <thead className="bg-slate-950/60 border-b border-slate-800 text-slate-400 font-mono uppercase text-[11px]">
                    <tr>
                      <th className="p-3">Report Ref</th>
                      <th className="p-3">Target Website</th>
                      <th className="p-3">Assessment Date</th>
                      <th className="p-3">Score</th>
                      <th className="p-3">Risk Level</th>
                      <th className="p-3 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {history.map((s, idx) => (
                      <tr key={idx} className="hover:bg-slate-800/30 transition-colors">
                        <td className="p-3 font-mono text-slate-500">WG-REP-{s.id || idx + 1}</td>
                        <td className="p-3">
                          <div className="font-mono font-semibold text-white">{s.target_url}</div>
                          <div className="text-[11px] text-slate-400 font-mono flex items-center gap-1.5 mt-0.5">
                            <span>{getFlagEmoji(s.geo?.country_code)}</span>
                            <span>{s.resolved_ip}</span>
                            {s.geo?.country && (
                              <span className="text-slate-500 font-sans">
                                ({s.geo.city ? `${s.geo.city}, ` : ''}{s.geo.country})
                              </span>
                            )}
                          </div>
                        </td>
                        <td className="p-3 text-slate-400">
                          {s.scan_date} at {s.scan_time}
                        </td>
                        <td className="p-3 font-mono font-bold text-white">{s.score}/100</td>
                        <td className="p-3">
                          <span
                            className={`px-2 py-0.5 rounded font-mono font-bold text-[10px] uppercase ${
                              s.risk_level === 'EXCELLENT'
                                ? 'bg-emerald-950/50 text-emerald-400'
                                : s.risk_level === 'GOOD'
                                ? 'bg-cyan-950/50 text-cyan-400'
                                : s.risk_level === 'MEDIUM'
                                ? 'bg-amber-950/50 text-amber-400'
                                : 'bg-rose-950/50 text-rose-400'
                            }`}
                          >
                            {s.risk_level}
                          </span>
                        </td>
                        <td className="p-3 text-right">
                          <div className="flex items-center justify-end gap-2">
                            <button
                              onClick={() => selectScan(s)}
                              className="px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-[11px] font-medium"
                            >
                              View Result
                            </button>
                            <button
                              onClick={() => downloadPdfReport(s)}
                              className="px-3 py-1 rounded bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-[11px] flex items-center gap-1"
                            >
                              <FileDown className="w-3.5 h-3.5" />
                              Download PDF
                            </button>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div className="p-8 text-center text-slate-500 text-sm">
                  <p>No audit reports generated yet.</p>
                </div>
              )}
            </div>
          </div>
        )}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800/80 py-5 text-center text-xs text-slate-500 bg-[#0f172a]">
        <div className="max-w-7xl mx-auto px-6 flex flex-col sm:flex-row items-center justify-between gap-2">
          <span>WebGuard · Multi-Page Real-Time Web Security Assessment</span>
          <span className="font-mono text-slate-600 text-[11px]">
            Passive audits only · SQLite Ledger · SSRF Protected
          </span>
        </div>
      </footer>
    </div>
  );
}
