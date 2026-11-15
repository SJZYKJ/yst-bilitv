'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { buildPublicStatus } = require('../status-metrics');

test('builds a privacy-safe public status summary', () => {
  const db = {
    stats: { '2026-11-14': { req: 12, ok: 10 }, '2026-11-15': { req: 8, ok: 7 } },
    devices: [{ id: 'secret', ip: '1.2.3.4', status: 'ok' }, { id: 'pending', status: 'pending' }],
    accounts: [{ name: 'private', cookie: 'SESSDATA=secret', valid: true }],
    lastOk: 12345,
  };
  const got = buildPublicStatus(db, { avgMs: 88, p95Ms: 130, dayOk: 7, dayFail: 1, uptime: 99 }, 110);
  assert.deepEqual(got, {
    ok: true,
    service: 'online',
    totalRequests: 20,
    todayRequests: 8,
    todaySuccess: 7,
    successRate: 87.5,
    authorizedDevices: 1,
    upstreamLatencyMs: 88,
    upstreamP95Ms: 130,
    processUptimeSec: 99,
    systemUptimeSec: 110,
    lastSuccessAt: 12345,
    updatedAt: got.updatedAt,
  });
  const text = JSON.stringify(got);
  for (const secret of ['secret', '1.2.3.4', 'private', 'SESSDATA']) assert.equal(text.includes(secret), false);
});
