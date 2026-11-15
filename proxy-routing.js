'use strict';

const { HttpsProxyAgent } = require('https-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');

const AREAS = ['cn', 'hk', 'tw', 'th', 'default'];
const ALLOWED = new Set(['http:', 'https:', 'socks:', 'socks4:', 'socks4a:', 'socks5:', 'socks5h:']);
const AGENTS = new Map();

function cleanProxyUrl(raw) {
  const value = String(raw == null ? '' : raw).trim();
  if (!value || /^(direct|none|off)$/i.test(value)) return '';
  if (value.length > 2048) throw new Error('代理地址过长');
  let parsed;
  try { parsed = new URL(value); } catch (_) { throw new Error('代理地址格式不正确'); }
  if (!ALLOWED.has(parsed.protocol)) throw new Error('仅支持 HTTP、HTTPS、SOCKS4 和 SOCKS5 代理');
  if (!parsed.hostname || !parsed.port) throw new Error('代理地址必须包含主机和端口');
  if (parsed.pathname && parsed.pathname !== '/') throw new Error('代理地址不能包含路径');
  if (parsed.search) throw new Error('代理地址不能包含查询参数');
  if (parsed.hash) throw new Error('代理地址不能包含片段');
  return value;
}

function normalizeProxyConfig(input) {
  const src = input && typeof input === 'object' ? input : {};
  const out = { enabled: src.enabled === true };
  AREAS.forEach((area) => { out[area] = cleanProxyUrl(src[area]); });
  return out;
}

function areaFromValue(value) {
  const v = String(value || '').trim().toLowerCase().replace(/_/g, '-');
  if (!v) return '';
  if (v === 'cn' || v === 'china' || v === 'zh-cn' || v.endsWith('-cn')) return 'cn';
  if (v === 'hk' || v === 'hktw' || v === 'zh-hk' || v.endsWith('-hk')) return 'hk';
  if (v === 'tw' || v === 'zh-tw' || v.endsWith('-tw')) return 'tw';
  if (v === 'th' || v === 'sea' || v === 'thai' || v === 'th-th' || v === 'zh-th' || v.endsWith('-th')) return 'th';
  return '';
}

function selectProxyArea(pathStr) {
  let u;
  try { u = new URL(String(pathStr || '/'), 'http://relay.local'); } catch (_) { return 'default'; }
  for (const key of ['area', 'region', 'country', 's_locale', 'locale']) {
    const area = areaFromValue(u.searchParams.get(key));
    if (area) return area;
  }
  return 'default';
}

function proxyForRequest(pathStr, config) {
  if (!config || config.enabled !== true) return '';
  const area = selectProxyArea(pathStr);
  return String(config[area] || '');
}

function redactProxyUrl(raw) {
  const value = String(raw || '');
  if (!value) return '';
  try {
    const u = new URL(value);
    if (u.username || u.password) {
      u.username = '***';
      u.password = '***';
    }
    return u.toString().replace(/\/$/, '');
  } catch (_) { return '[invalid proxy]'; }
}

function safeProxyError(error, proxyUrl) {
  if (proxyUrl) return '代理连接失败，请检查地址、凭据和网络';
  const code = error && error.code ? String(error.code).replace(/[^A-Z0-9_]/gi, '').slice(0, 32) : '';
  return '上游连接失败' + (code ? '（' + code + '）' : '');
}

function makeProxyAgent(raw) {
  const value = cleanProxyUrl(raw);
  if (!value) return undefined;
  if (AGENTS.has(value)) return AGENTS.get(value);
  const proto = new URL(value).protocol;
  const agent = proto === 'http:' || proto === 'https:'
    ? new HttpsProxyAgent(value)
    : new SocksProxyAgent(value);
  AGENTS.set(value, agent);
  return agent;
}

module.exports = {
  normalizeProxyConfig,
  selectProxyArea,
  proxyForRequest,
  redactProxyUrl,
  makeProxyAgent,
  safeProxyError,
};
