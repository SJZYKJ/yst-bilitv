'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');

const {
  normalizeProxyConfig,
  selectProxyArea,
  proxyForRequest,
  redactProxyUrl,
  makeProxyAgent,
  safeProxyError,
} = require('../proxy-routing');

test('normalizes cn/hk/tw/th/default proxy settings', () => {
  const got = normalizeProxyConfig({
    enabled: true,
    cn: ' http://user:pass@127.0.0.1:8080 ',
    hk: 'socks5://127.0.0.1:1080',
    tw: '', th: null, default: 'direct',
  });
  assert.deepEqual(got, {
    enabled: true,
    cn: 'http://user:pass@127.0.0.1:8080',
    hk: 'socks5://127.0.0.1:1080',
    tw: '', th: '', default: '',
  });
});

test('rejects unsupported schemes, malformed URLs, and non-endpoint URL parts', () => {
  assert.throws(() => normalizeProxyConfig({ cn: 'ftp://127.0.0.1:21' }), /仅支持/);
  assert.throws(() => normalizeProxyConfig({ cn: 'http://bad host' }), /代理地址/);
  assert.throws(() => normalizeProxyConfig({ cn: 'http://127.0.0.1:8080/path' }), /路径/);
  assert.throws(() => normalizeProxyConfig({ cn: 'http://127.0.0.1:8080/?token=x' }), /查询参数/);
  assert.throws(() => normalizeProxyConfig({ cn: 'http://127.0.0.1:8080/#x' }), /片段/);
});

test('selects explicit request area and aliases', () => {
  assert.equal(selectProxyArea('/play?area=hk'), 'hk');
  assert.equal(selectProxyArea('/play?area=cn'), 'cn');
  assert.equal(selectProxyArea('/play?area=tw'), 'tw');
  assert.equal(selectProxyArea('/play?area=th'), 'th');
  assert.equal(selectProxyArea('/play?area=sea'), 'th');
  assert.equal(selectProxyArea('/play?area=unknown'), 'default');
});

test('selects region from common locale parameters', () => {
  assert.equal(selectProxyArea('/search?region=hk'), 'hk');
  assert.equal(selectProxyArea('/search?country=TW'), 'tw');
  assert.equal(selectProxyArea('/search?s_locale=zh_TH'), 'th');
  assert.equal(selectProxyArea('/search?locale=zh-HK'), 'hk');
});

test('uses the selected regional proxy and does not fall back across regions', () => {
  const cfg = normalizeProxyConfig({ enabled: true, hk: 'socks5://127.0.0.1:1080', default: 'http://127.0.0.1:8080' });
  assert.equal(proxyForRequest('/x?area=hk', cfg), 'socks5://127.0.0.1:1080');
  assert.equal(proxyForRequest('/x?area=tw', cfg), '');
  assert.equal(proxyForRequest('/x', cfg), 'http://127.0.0.1:8080');
  assert.equal(proxyForRequest('/x?area=hk', { ...cfg, enabled: false }), '');
});

test('redacts proxy credentials for panel responses and logs', () => {
  assert.equal(redactProxyUrl('http://alice:secret@proxy.example:8080'), 'http://***:***@proxy.example:8080');
  assert.equal(redactProxyUrl('socks5://proxy.example:1080'), 'socks5://proxy.example:1080');
});

test('builds HTTP and SOCKS proxy agents and direct mode returns undefined', () => {
  assert.equal(makeProxyAgent(''), undefined);
  assert.match(makeProxyAgent('http://127.0.0.1:8080').constructor.name, /HttpsProxyAgent/);
  assert.match(makeProxyAgent('socks5://127.0.0.1:1080').constructor.name, /SocksProxyAgent/);
});

test('sanitizes proxy failures without exposing credentials', () => {
  const msg = safeProxyError(new Error('connect failed via http://alice:secret@proxy.example:8080'), 'http://alice:secret@proxy.example:8080');
  assert.equal(msg.includes('alice'), false);
  assert.equal(msg.includes('secret'), false);
  assert.match(msg, /代理连接失败/);
});
