'use strict';

function finiteNumber(value) {
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}

function buildPublicStatus(db, metrics, systemUptimeSec) {
  const state = db || {};
  const met = metrics || {};
  const stats = state.stats && typeof state.stats === 'object' ? state.stats : {};
  const days = Object.values(stats);
  const totalRequests = days.reduce((sum, row) => sum + Math.max(0, finiteNumber(row && row.req)), 0);
  const todayRequests = Math.max(0, finiteNumber(met.dayOk) + finiteNumber(met.dayFail));
  const todaySuccess = Math.max(0, finiteNumber(met.dayOk));
  return {
    ok: true,
    service: 'online',
    totalRequests,
    todayRequests,
    todaySuccess,
    successRate: todayRequests ? Math.round((todaySuccess / todayRequests) * 1000) / 10 : 100,
    authorizedDevices: Array.isArray(state.devices) ? state.devices.filter((d) => d && !d.orphan && d.status === 'ok').length : 0,
    upstreamLatencyMs: Math.max(0, finiteNumber(met.avgMs)),
    upstreamP95Ms: Math.max(0, finiteNumber(met.p95Ms)),
    processUptimeSec: Math.max(0, Math.floor(finiteNumber(met.uptime))),
    systemUptimeSec: Math.max(0, Math.floor(finiteNumber(systemUptimeSec))),
    lastSuccessAt: Math.max(0, finiteNumber(state.lastOk)),
    updatedAt: Date.now(),
  };
}

module.exports = { buildPublicStatus };
