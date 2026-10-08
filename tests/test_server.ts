/**
 * Automated Test Suite for WebGuard Express API Server (server.ts)
 */

process.env.NODE_ENV = 'test';

import http from 'http';

const TEST_PORT = 3199;

function assert(condition: boolean, message: string) {
  if (!condition) {
    throw new Error(`Assertion failed: ${message}`);
  }
}

async function runTests() {
  const { app } = await import('../server.js');
  const server = http.createServer(app);

  await new Promise<void>((resolve) => {
    server.listen(TEST_PORT, '127.0.0.1', () => {
      console.log(`[TEST] Test server listening on http://127.0.0.1:${TEST_PORT}`);
      resolve();
    });
  });

  const baseUrl = `http://127.0.0.1:${TEST_PORT}`;
  let passed = 0;
  let total = 0;

  async function test(name: string, fn: () => Promise<void>) {
    total++;
    try {
      await fn();
      passed++;
      console.log(`  ✓ ${name}`);
    } catch (err: any) {
      console.error(`  ✗ ${name}: ${err.message}`);
    }
  }

  console.log('\nRunning WebGuard Express API Tests:');

  await test('GET /api/dashboard returns metrics JSON', async () => {
    const res = await fetch(`${baseUrl}/api/dashboard`);
    assert(res.status === 200, `Expected 200, got ${res.status}`);
    const json = await res.json();
    assert(typeof json.total_scans === 'number', 'Expected total_scans number');
    assert(Array.isArray(json.recent_scans), 'Expected recent_scans array');
  });

  await test('GET /api/history returns scans list', async () => {
    const res = await fetch(`${baseUrl}/api/history`);
    assert(res.status === 200, `Expected 200, got ${res.status}`);
    const json = await res.json();
    assert(Array.isArray(json), 'Expected history array');
  });

  await test('POST /api/scan rejects empty URL with 400', async () => {
    const res = await fetch(`${baseUrl}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: '' }),
    });
    assert(res.status === 400, `Expected 400, got ${res.status}`);
    const json = await res.json();
    assert(!!json.error, 'Expected error property');
  });

  await test('POST /api/scan blocks localhost with 403 (SSRF)', async () => {
    const res = await fetch(`${baseUrl}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: 'http://localhost:3000' }),
    });
    assert(res.status === 403, `Expected 403, got ${res.status}`);
    const json = await res.json();
    assert(json.error.includes('SSRF Protection'), 'Expected SSRF error');
  });

  await test('POST /api/scan blocks 127.0.0.1 with 403 (SSRF)', async () => {
    const res = await fetch(`${baseUrl}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: 'http://127.0.0.1:8080' }),
    });
    assert(res.status === 403, `Expected 403, got ${res.status}`);
    const json = await res.json();
    assert(json.error.includes('SSRF Protection'), 'Expected SSRF error');
  });

  await test('POST /api/scan blocks cloud metadata hostname with 403 (SSRF)', async () => {
    const res = await fetch(`${baseUrl}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: 'http://metadata.google.internal' }),
    });
    assert(res.status === 403, `Expected 403, got ${res.status}`);
  });

  await test('GET /api/scans/:id rejects non-integer IDs with 400 (RCE protection)', async () => {
    const res = await fetch(`${baseUrl}/api/scans/evil;calc`);
    assert(res.status === 400, `Expected 400, got ${res.status}`);
    const json = await res.json();
    assert(json.error.includes('must be an integer'), 'Expected integer validation error');
  });

  await test('GET /api/scans/:id returns 404 for nonexistent scan ID', async () => {
    const res = await fetch(`${baseUrl}/api/scans/99999999`);
    assert(res.status === 404, `Expected 404, got ${res.status}`);
  });

  await test('GET /api/geoip/127.0.0.1 blocks loopback with 403 (SSRF)', async () => {
    const res = await fetch(`${baseUrl}/api/geoip/127.0.0.1`);
    assert(res.status === 403, `Expected 403, got ${res.status}`);
    const json = await res.json();
    assert(json.error.includes('SSRF Protection'), 'Expected SSRF error');
  });

  await test('GET /api/geoip/localhost blocks localhost with 403 (SSRF)', async () => {
    const res = await fetch(`${baseUrl}/api/geoip/localhost`);
    assert(res.status === 403, `Expected 403, got ${res.status}`);
    const json = await res.json();
    assert(json.error.includes('SSRF Protection'), 'Expected SSRF error');
  });

  await test('GET /api/geoip/192.168.1.1 blocks private IP with 403 (SSRF)', async () => {
    const res = await fetch(`${baseUrl}/api/geoip/192.168.1.1`);
    assert(res.status === 403, `Expected 403, got ${res.status}`);
    const json = await res.json();
    assert(json.error.includes('SSRF Protection'), 'Expected SSRF error');
  });

  await test('GET /api/geoip/8.8.8.8 returns geolocation metadata', async () => {
    const res = await fetch(`${baseUrl}/api/geoip/8.8.8.8`);
    assert(res.status === 200, `Expected 200, got ${res.status}`);
    const json = await res.json();
    assert(json.ip === '8.8.8.8', 'Expected ip 8.8.8.8');
    assert(typeof json.latitude === 'number', 'Expected numeric latitude');
    assert(typeof json.longitude === 'number', 'Expected numeric longitude');
  });

  await new Promise<void>((resolve) => {
    server.close(() => {
      console.log(`\nTests finished: ${passed}/${total} passed.\n`);
      resolve();
    });
  });

  if (passed !== total) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

runTests().catch((err) => {
  console.error('Fatal test error:', err);
  process.exit(1);
});

