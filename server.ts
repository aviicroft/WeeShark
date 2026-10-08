import express, { Request, Response } from 'express';
import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';
import dns from 'dns';

export const app = express();
const PORT = process.env.PORT || 3000;
const isProduction = process.env.NODE_ENV === 'production';
const ROOT_DIR = process.cwd();
const HISTORY_FILE = path.join(ROOT_DIR, 'webguard', 'scan_history.json');

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Helper: Determine cross-platform Python binary
export function getPythonCommand(): string {
  if (process.env.PYTHON_BIN) return process.env.PYTHON_BIN;
  return process.platform === 'win32' ? 'python' : 'python3';
}

// Helper: Check if IP is private or restricted (SSRF Protection)
export function isRestrictedIP(ip: string): boolean {
  if (ip === '127.0.0.1' || ip === '::1' || ip === '0.0.0.0') return true;

  // IPv4 Private & Link-local ranges:
  // 10.0.0.0 - 10.255.255.255 (10/8)
  // 172.16.0.0 - 172.31.255.255 (172.16/12)
  // 192.168.0.0 - 192.168.255.255 (192.168/16)
  // 169.254.0.0 - 169.254.255.255 (169.254/16)
  // 127.0.0.0 - 127.255.255.255 (127/8)
  const parts = ip.split('.').map(Number);
  if (parts.length === 4 && parts.every((n) => !isNaN(n) && n >= 0 && n <= 255)) {
    if (parts[0] === 10) return true;
    if (parts[0] === 127) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 0) return true;
  }

  // IPv6 unique local & link local
  const lower = ip.toLowerCase();
  if (lower.startsWith('fe80:') || lower.startsWith('fc00:') || lower.startsWith('fd')) {
    return true;
  }

  return false;
}

// Ensure webguard history directory exists
if (!fs.existsSync(path.dirname(HISTORY_FILE))) {
  fs.mkdirSync(path.dirname(HISTORY_FILE), { recursive: true });
}

// API: Perform Real-Time Security Scan
app.post('/api/scan', async (req: Request, res: Response) => {
  const targetUrl = req.body.url?.trim();

  if (!targetUrl) {
    return res.status(400).json({ error: 'Please enter a valid website URL.' });
  }

  // Basic format validation
  let normalizedUrl = targetUrl;
  if (!/^https?:\/\//i.test(normalizedUrl)) {
    normalizedUrl = 'https://' + normalizedUrl;
  }

  let parsed: URL;
  try {
    parsed = new URL(normalizedUrl);
  } catch (err) {
    return res.status(400).json({ error: 'Invalid URL format. Please verify the web address.' });
  }

  const hostname = parsed.hostname;
  if (!hostname) {
    return res.status(400).json({ error: 'Could not extract hostname from URL.' });
  }

  // SSRF Protection check against hostname
  const blockedHosts = ['localhost', '127.0.0.1', '0.0.0.0', '::1', 'metadata.google.internal'];
  if (
    blockedHosts.includes(hostname.toLowerCase()) ||
    hostname.endsWith('.local') ||
    hostname.endsWith('.internal')
  ) {
    return res.status(403).json({
      error: 'Access to internal hostnames and localhost is strictly blocked (SSRF Protection).',
    });
  }

  // Express-level DNS SSRF resolution validation
  try {
    const lookup = await dns.promises.lookup(hostname);
    if (isRestrictedIP(lookup.address)) {
      return res.status(403).json({
        error: `Target resolves to restricted IP address (${lookup.address}). Scanning internal networks is prohibited (SSRF Protection).`,
      });
    }
  } catch {
    return res.status(400).json({
      error: `DNS resolution failed for hostname '${hostname}'. Verify domain name and internet connectivity.`,
    });
  }

  // Execute python scanner script
  try {
    const pythonScript = path.join(ROOT_DIR, 'webguard', 'scanner.py');
    const child = spawn(getPythonCommand(), [pythonScript, normalizedUrl], {
      cwd: ROOT_DIR,
      env: {
        ...process.env,
        PYTHONPATH: path.join(ROOT_DIR, 'webguard'),
      },
      timeout: 30000,
    });

    let stdoutData = '';
    let stderrData = '';

    child.stdout.on('data', (chunk) => {
      stdoutData += chunk.toString();
    });

    child.stderr.on('data', (chunk) => {
      stderrData += chunk.toString();
    });

    child.on('close', (code) => {
      if (code !== 0) {
        let errMsg = 'Failed to execute security scan.';
        try {
          const parsedErr = JSON.parse(stdoutData || stderrData);
          if (parsedErr.error) errMsg = parsedErr.error;
        } catch {
          if (stderrData.trim()) errMsg = stderrData.trim();
        }
        return res.status(400).json({ error: errMsg });
      }

      try {
        const scanResult = JSON.parse(stdoutData);
        return res.json(scanResult);
      } catch (jsonErr) {
        return res.status(500).json({
          error: 'Invalid response from scanner engine.',
          details: stdoutData,
        });
      }
    });

    child.on('error', (err) => {
      return res.status(500).json({
        error: `Could not launch scanner process: ${err.message}`,
      });
    });
  } catch (err: any) {
    return res.status(500).json({ error: err.message || 'Internal server error' });
  }
});

// Helper: Query SQLite via python child process for database consistency
export function runPythonDb(scriptCode: string, args: string[] = []): Promise<any> {
  return new Promise((resolve, reject) => {
    const child = spawn(getPythonCommand(), ['-c', scriptCode, ...args], {
      cwd: ROOT_DIR,
      env: { ...process.env, PYTHONPATH: path.join(ROOT_DIR, 'webguard') },
      timeout: 10000,
    });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => (out += d.toString()));
    child.stderr.on('data', (d) => (err += d.toString()));
    child.on('close', (code) => {
      if (code === 0) {
        try {
          resolve(JSON.parse(out));
        } catch {
          resolve(out);
        }
      } else {
        reject(new Error(err || `Python script exited with code ${code}`));
      }
    });
    child.on('error', reject);
  });
}

// API: Get Dashboard Stats
app.get('/api/dashboard', async (_req: Request, res: Response) => {
  try {
    const stats = await runPythonDb(`
import database, json
stats = database.get_dashboard_stats()
print(json.dumps(stats))
`);
    return res.json(stats);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// API: Get Scan History (All scans from SQLite)
app.get('/api/history', async (_req: Request, res: Response) => {
  try {
    const scans = await runPythonDb(`
import database, json
scans = database.get_all_scans(limit=100)
print(json.dumps(scans))
`);
    return res.json(scans);
  } catch (err: any) {
    // Fallback to JSON history file if available
    try {
      if (fs.existsSync(HISTORY_FILE)) {
        const data = fs.readFileSync(HISTORY_FILE, 'utf-8');
        return res.json(JSON.parse(data));
      }
    } catch {}
    return res.json([]);
  }
});

// API: Get Single Scan by ID (Secured with strict integer validation and parameterization)
app.get('/api/scans/:id', async (req: Request, res: Response) => {
  const rawId = req.params.id;
  if (!/^\d+$/.test(rawId)) {
    return res.status(400).json({ error: 'Invalid scan ID. ID must be an integer.' });
  }

  const scanId = parseInt(rawId, 10);
  try {
    const scan = await runPythonDb(
      `
import sys, database, json
scan_id = int(sys.argv[1])
scan = database.get_scan_by_id(scan_id)
print(json.dumps(scan))
`,
      [String(scanId)]
    );
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    return res.json(scan);
  } catch (err: any) {
    return res.status(500).json({ error: err.message });
  }
});

// Setup Vite or Static File Serving
async function startServer() {
  if (!isProduction) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.join(ROOT_DIR, 'dist')));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(ROOT_DIR, 'dist', 'index.html'));
    });
  }

  if (process.env.NODE_ENV !== 'test') {
    app.listen(Number(PORT), '0.0.0.0', () => {
      console.log(`WebGuard server is running at http://0.0.0.0:${PORT}`);
    });
  }
}

if (process.env.NODE_ENV !== 'test') {
  startServer();
}
