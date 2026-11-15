'use strict';
/*
 * BiliRelay - 解析中转 + 会员 Cookie 池
 *  - 中转: 把 *.biliup.xaitr.com 的请求转发到 B 站 TV 接口, 自动注入会员 Cookie
 *  - 后台: 扫码登录 / 手机验证码登录 / 手动 Cookie, 管理 Cookie 池
 */
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const zlib = require('zlib');
const os = require('os');
const { buildPublicStatus } = require('./status-metrics');
const {
  normalizeProxyConfig,
  selectProxyArea,
  proxyForRequest,
  redactProxyUrl,
  makeProxyAgent,
  safeProxyError,
} = require('./proxy-routing');
const {
  findDeviceByBuvid,
  shouldPreferBuvidDevice,
  mergeSplitIdentity,
} = require('./device-identity');

const ROOT = __dirname;
const DATA_FILE = path.join(ROOT, 'data.json');
const PUBLIC = path.join(ROOT, 'public');
const PORT = parseInt(process.env.PORT || '8601', 10);
const BIND = process.env.BIND || '0.0.0.0';

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
const APPKEY = '4409e2ce8ffd12b8';
const APPSEC = '59b43e04ad6965f34319062b478f83dd';

const UPSTREAM = {
  api: 'api.snm0516.aisee.tv',
  app: 'app.snm0516.aisee.tv',
  passport: 'passport.snm0516.aisee.tv',
  account: 'account.snm0516.aisee.tv',
  bangumi: 'bangumi.snm0516.aisee.tv',
  member: 'member.snm0516.aisee.tv',
};

/*
 * 不用域名（IP 直连）时的上游分流：端口 -> 上游子域
 * 盒子 APP 里把各个域名改成对应端口即可；将来接了域名，Host 首段照样能自动认
 */
const PORT_UPSTREAM = (() => {
  const m = {};
  const spec = process.env.PORT_MAP
    || '80:api,8601:api,8602:app,8603:passport,8604:account,8605:bangumi,8606:member';
  String(spec).split(',').forEach((seg) => {
    const i = seg.indexOf(':');
    if (i < 0) return;
    const p = parseInt(seg.slice(0, i).trim(), 10);
    const n = seg.slice(i + 1).trim();
    if (p > 0 && UPSTREAM[n]) m[p] = n;
  });
  return m;
})();

/*
 * 80 端口（客户端 URL 不带端口时的默认口）没有域名叫它怎么分流，
 * 就按路径认：app 域只承担「配置类」这几条，其余全走 api 解析主通道
 */
const APP_PATH_RE = /^\/(x\/v2\/param|x\/v2\/version\/|x\/resource\/|x\/playurl\/ott)/i;
const DEFAULT_PORT = parseInt(process.env.DEFAULT_PORT || '80', 10);
const UPSTREAM_PORT = parseInt(process.env.UPSTREAM_PORT || '443', 10);

/* ---------------- 文件日志 + 轮转 ----------------
 * 服务日志不再只靠 journald：自己写 logs/relay.log，单文件到 10MB 就轮转，
 * 最多留 5 个历史文件 + 7 天，超期自动删，跑一年也撑不满盘。
 */
const LOGDIR = process.env.LOG_DIR || path.join(ROOT, 'logs');
const LOG_KEEP_DAYS = parseInt(process.env.LOG_KEEP_DAYS || '7', 10);
const LOG_MAX_BYTES = parseInt(process.env.LOG_MAX_BYTES || String(10 * 1024 * 1024), 10);
const LOG_SLOTS = 5;
const logCur = path.join(LOGDIR, 'relay.log');
let logBytes = 0;
function ensureLogDir() { try { fs.mkdirSync(LOGDIR, { recursive: true }); } catch (e) { /* ignore */ } }
function rotateLogNow() {
  try {
    for (let i = LOG_SLOTS - 1; i >= 1; i--) {
      const a = path.join(LOGDIR, 'relay.log.' + i);
      const b = path.join(LOGDIR, 'relay.log.' + (i + 1));
      if (fs.existsSync(a)) { try { fs.rmSync(b, { force: true }); fs.renameSync(a, b); } catch (e) { /* ignore */ } }
    }
    fs.rmSync(path.join(LOGDIR, 'relay.log.1'), { force: true });
    if (fs.existsSync(logCur)) fs.renameSync(logCur, path.join(LOGDIR, 'relay.log.1'));
    logBytes = 0;
  } catch (e) { /* ignore */ }
}
function writeLog(tag, text) {
  try {
    const line = new Date().toISOString() + ' [' + tag + '] ' + text + '\n';
    const buf = Buffer.from(line);
    if (logBytes + buf.length > LOG_MAX_BYTES) rotateLogNow();
    fs.appendFileSync(logCur, buf);
    logBytes += buf.length;
  } catch (e) { /* ignore */ }
}
function cleanLogs() {
  const now = Date.now();
  try {
    fs.readdirSync(LOGDIR).forEach((f) => {
      if (!/^relay\.log(\.\d+)?$/.test(f)) return;
      const p = path.join(LOGDIR, f);
      try {
        const st = fs.statSync(p);
        if (now - st.mtimeMs > LOG_KEEP_DAYS * 864e5) fs.rmSync(p, { force: true });
      } catch (e) { /* ignore */ }
    });
    logBytes = fs.existsSync(logCur) ? fs.statSync(logCur).size : 0;
  } catch (e) { /* ignore */ }
}
function fmtArg(a) {
  if (a instanceof Error) return a.stack || a.message;
  if (typeof a === 'object' && a !== null) { try { return JSON.stringify(a); } catch (e) { return String(a); } }
  return String(a);
}
function setupFileLog() {
  ensureLogDir();
  cleanLogs();
  const orig = { log: console.log.bind(console), warn: console.warn.bind(console), error: console.error.bind(console) };
  console.log = (...a) => { orig.log(...a); writeLog('I', a.map(fmtArg).join(' ')); };
  console.warn = (...a) => { orig.warn(...a); writeLog('W', a.map(fmtArg).join(' ')); };
  console.error = (...a) => { orig.error(...a); writeLog('E', a.map(fmtArg).join(' ')); };
  const t = setInterval(cleanLogs, 3600e3);
  if (t.unref) t.unref();
}

/* ---------------- 存储 ---------------- */
let db = {
  salt: '', passHash: '',
  accounts: [],
  stats: {},
  logs: [],
  rr: 0,
  lastOk: 0,
  gateOn: true,          // 设备授权总开关
  gateLevel: 'content',  // content=只拦内容接口(播放/搜索/详情), all=全部拦
  shareMode: 'off',      // off=不注入任何账号(纯游客解析) | full=直接注入(盒子会显示会员号) | stealth=注入但隐藏账号身份
  qualityMode: '4k',     // 4k=播放请求一律按 4K(120) 取流 | 1080=最高 1080P(80) | auto=跟随盒子客户端
  devices: [],           // 设备表
  authCodeSeq: 1000,
  authMode: 'self',      // manual=只能后台手动放行 | self=电视上输自助码自己过 | auto=新设备直接放行
  selfCode: '',          // 自助授权码（6 位数字）
  cacheOn: true,         // 接口缓存（首页/详情/搜索这类可缓存接口）
  cacheTtl: 300,         // 缓存时长（秒），5 分钟
  accountMode: 'device', // device=按设备固定分配账号 | rr=每次轮询
  accMap: {},            // 设备ID -> 账号ID，固定分配的记忆
  /* —— 防刷与安全（11-14 新增）—— */
  rlOn: true,            // 限流总开关
  rlDevPerMin: 300,      // 单台设备每分钟请求上限
  rlIpPerMin: 900,       // 单个 IP 每分钟请求上限（同一条宽带上多台盒子共用一个出口）
  rlAnonPerMin: 360,     // 无设备标识（老包/裸脚本）单 IP 每分钟上限
  rlAccPerHour: 1500,    // 单个 Cookie 号每小时取流上限
  driftOn: true,         // 指纹漂移检测
  driftSegMax: 4,        // 24 小时内出现多少个不同网段算可疑
  driftAuto: false,      // 超阈值自动转回待授权
  /* —— 未授权超额自动封禁（11-15 新增）—— */
  autoBlkOn: true,       // 未授权设备的成功请求累计满额 → 自动拉黑设备（+IP）
  autoBlkNum: 1000,      // 触发阈值：成功请求次数
  autoBlkIp: true,       // 同时拉黑它当时的网络 IP
  /* —— 分地区代理出口 —— */
  egressProxy: { enabled: false, cn: '', hk: '', tw: '', th: '', default: '' },
};
const sessions = new Map();

/* ---- 面板登录防爆破：连续错 5 次锁 10 分钟（另有全站兜底，防伪造 IP 头绕过）---- */
const LOGIN_FAIL = new Map();      // ip -> { n, at, until }
const LOGIN_FAIL_MAX = 5;
const LOGIN_LOCK_MS = 10 * 60e3;
const LOGIN_WINDOW_MS = 10 * 60e3;
let LOGIN_GLOBAL = { n: 0, at: 0, until: 0 };
const LOGIN_LASTLOG = new Map();   // ip -> 上次记日志时间（锁定期间节流）
function loginLockLeft(ip) {
  const now = Date.now();
  if (LOGIN_GLOBAL.until > now) return LOGIN_GLOBAL.until - now;
  const g = LOGIN_FAIL.get(ip);
  if (g && g.until > now) return g.until - now;
  return 0;
}
function loginFail(ip) {
  const now = Date.now();
  const g = LOGIN_FAIL.get(ip) || { n: 0, at: now, until: 0 };
  if (now - g.at > LOGIN_WINDOW_MS) { g.n = 0; g.at = now; }
  g.n++;
  if (g.n >= LOGIN_FAIL_MAX) { g.until = now + LOGIN_LOCK_MS; g.n = 0; g.at = now; }
  LOGIN_FAIL.set(ip, g);
  if (LOGIN_FAIL.size > 500) {
    for (const [k, v] of LOGIN_FAIL) { if (v.until < now && now - v.at > LOGIN_WINDOW_MS) LOGIN_FAIL.delete(k); }
  }
  if (now - LOGIN_GLOBAL.at > LOGIN_WINDOW_MS) { LOGIN_GLOBAL.n = 0; LOGIN_GLOBAL.at = now; }
  LOGIN_GLOBAL.n++;
  if (LOGIN_GLOBAL.n >= 60) { LOGIN_GLOBAL.until = now + 5 * 60e3; LOGIN_GLOBAL.n = 0; }
  return g.until > now;
}
function loginOk(ip) { LOGIN_FAIL.delete(ip); LOGIN_LASTLOG.delete(ip); }

function loadDb() {
  try {
    db = Object.assign(db, JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')));
  } catch (e) { /* 首次启动 */ }
  if (!db.salt) {
    db.salt = crypto.randomBytes(16).toString('hex');
    const pass = crypto.randomBytes(6).toString('base64').replace(/[+/=]/g, '').slice(0, 10);
    db.passHash = hashPass(pass);
    saveDb();
    fs.writeFileSync(path.join(ROOT, 'admin-password.txt'), pass + '\n', { mode: 0o600 });
    console.log('[init] 后台密码: ' + pass);
  }
  if (!db.authMode || ['manual', 'self', 'auto'].indexOf(db.authMode) < 0) db.authMode = 'self';
  if (typeof db.cacheOn !== 'boolean') db.cacheOn = true;
  if (!db.cacheTtl || db.cacheTtl < 30) db.cacheTtl = 300;
  if (['device', 'rr'].indexOf(db.accountMode) < 0) db.accountMode = 'device';
  if (!db.accMap || typeof db.accMap !== 'object') db.accMap = {};
  if (!db.selfCode) {
    db.selfCode = String(Math.floor(100000 + Math.random() * 900000));
    saveDb();
  }
  try {
    db.egressProxy = normalizeProxyConfig(db.egressProxy || {});
  } catch (e) {
    console.warn('[proxy] 代理配置无效，已临时关闭：' + e.message);
    db.egressProxy = normalizeProxyConfig({});
  }
  normalizeSecurity();
  migrateDevices();
}
/* 老 data.json 没有这些键时补默认值，并挡住离谱的数值（填 0 / 负数 / 特别大都不行） */
function normalizeSecurity() {
  const num = (k, def, lo, hi) => {
    const v = Number(db[k]);
    db[k] = (!isFinite(v) || v <= 0) ? def : Math.min(hi, Math.max(lo, Math.round(v)));
  };
  if (typeof db.rlOn !== 'boolean') db.rlOn = true;
  if (typeof db.driftOn !== 'boolean') db.driftOn = true;
  if (typeof db.driftAuto !== 'boolean') db.driftAuto = false;
  /* 设备令牌机制已下线：清掉历史遗留的开关与密钥字段 */
  ['tokenOn', 'tokenTtlH', 'tokenAnon', 'tokenSecret'].forEach((k) => { if (k in db) delete db[k]; });
  num('rlDevPerMin', 300, 10, 100000);
  num('rlIpPerMin', 900, 10, 100000);
  num('rlAnonPerMin', 360, 10, 100000);
  num('rlAccPerHour', 1500, 10, 200000);
  num('driftSegMax', 4, 2, 50);
  if (typeof db.autoBlkOn !== 'boolean') db.autoBlkOn = true;
  if (typeof db.autoBlkIp !== 'boolean') db.autoBlkIp = true;
  num('autoBlkNum', 1000, 10, 1000000);
}
/* 旧版按 IP 认设备留下的记录（没有 MAC / android_id）统一归档，面板默认不显示，不影响真实设备 */
function migrateDevices() {
  if (!Array.isArray(db.devices)) db.devices = [];
  let orphan = 0;
  db.devices.forEach((d) => {
    d.mac = normMac(d.mac || '');
    d.did = normDid(d.did || '');
    d.macs = (d.macs || []).map(normMac).filter(Boolean);
    d.dids = (d.dids || []).map(normDid).filter(Boolean);
    if (d.mac && d.macs.indexOf(d.mac) < 0) d.macs.unshift(d.mac);
    if (d.did && d.dids.indexOf(d.did) < 0) d.dids.unshift(d.did);
    if (!d.mac && !d.did && !d.macs.length && !d.dids.length) {
      if (!d.orphan) orphan++;
      d.orphan = true;
    }
  });
  if (orphan) {
    log('device', '归档无标识的历史设备记录 ' + orphan + ' 条（旧版按 IP 识别留下的）');
    saveDb();
  }
}
function saveDb() {
  try { fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2), { mode: 0o600 }); } catch (e) { console.error('save fail', e.message); }
}
let lastSave = 0;
function saveDbLazy() {
  const now = Date.now();
  if (now - lastSave < 1500) return;
  lastSave = now;
  saveDb();
}
function hashPass(p) {
  return crypto.scryptSync(String(p), db.salt, 32).toString('hex');
}
function log(type, msg) {
  db.logs.unshift({ t: Date.now(), type, msg });
  if (db.logs.length > 300) db.logs.length = 300;
}

/* ---------------- 工具 ---------------- */
function today() {
  return new Date(Date.now() + 8 * 3600 * 1000).toISOString().slice(0, 10);
}
function statToday() {
  const k = today();
  if (!db.stats[k]) db.stats[k] = { req: 0, ok: 0 };
  return db.stats[k];
}

/* ---------------- 设备授权 ---------------- */
function clientIp(req) {
  const h = req.headers || {};
  let ip = h['cf-connecting-ip'] || h['x-real-ip'] || String(h['x-forwarded-for'] || '').split(',')[0].trim() || req.socket.remoteAddress || '';
  ip = String(ip).replace(/^::ffff:/, '');
  return ip || '0.0.0.0';
}
/* 日志用 URL 脱敏：调试日志里不落 access_key / cookie 之类凭据 */
function redactUrl(u) {
  return String(u == null ? '' : u)
    .replace(/(access_key|access_token|sessdata|bili_jct|csrf|dedeuserid[^=]*)=[^&\s]*/gi, '$1=***');
}
function uaName(ua) {
  const s = String(ua || '');
  let m = /;\s*([^;)]*(?:TV|BOX|Box|box|Pro|pro|Pad|pad)[^;)]*)\s*Build/i.exec(s);
  if (m) return cleanLabel(m[1].trim().slice(0, 28));
  m = /Android[^;]*;\s*([^;)]+)\s*\)/.exec(s);
  if (m) return cleanLabel(m[1].replace(/Build.*/i, '').trim().slice(0, 28));
  return s ? '未知机型' : '未知设备';
}
/* 展示用标签净化：去掉 HTML 危险字符与控制符（设备名来自客户端 UA，不可信） */
function cleanLabel(v) {
  return String(v == null ? '' : v)
    .replace(/[<>&"'\u0000-\u001f\u007f]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, 40);
}
/* MAC 归一化：aa:bb:cc:dd:ee:ff / aabbccddeeff / aa-bb-... 统一成纯十六进制 */
function normMac(v) {
  let s = String(v || '').trim();
  try { s = decodeURIComponent(s); } catch (e) { /* ignore */ }
  s = s.toLowerCase().replace(/[^0-9a-f]/g, '');
  if (s.length < 12 || s.length > 40) return '';
  if (/^0+$/.test(s)) return '';
  const head = s.slice(0, 12);
  if (head === '020000000000' || head === 'ffffffffffff') return '';   // Android 6+ 伪 MAC / 广播地址
  return s;
}
/* 设备稳定标识
 *  order: MAC > android_id(APP 上报的 did) > IP 记忆(仅兜底，绝不新建记录)
 *  以前只用 MAC，盒子拿不到网卡 MAC（Android 9+/盒子厂商隐藏）时就退化成按 IP 认设备，
 *  于是换个网络就多出一台「未知机型」的新设备。现在 android_id 也参与识别，且
 *  纯 IP 访问（浏览器/扫描器/随手打开授权页）一律不建档。
 */
function normDid(v) {
  let s = String(v || '').trim();
  try { s = decodeURIComponent(s); } catch (e) { /* ignore */ }
  s = s.toLowerCase().replace(/[^0-9a-z_-]/g, '');
  if (!s || s === 'unknown' || s === 'null' || s === 'none') return '';
  if (s.length < 6 || s.length > 64) return '';
  return s;
}
/* 浏览器标识（授权页用）：前端首次随机生成 32 位 hex，存 localStorage + cookie，
 * 之后每次带上，同一台浏览器换网络/换宽带都算同一台，不会重复建档。
 * 扫描器/爬虫不跑 JS，拿不到这个标识，因此照旧不建档。 */
function normWid(v) {
  const s = String(v || '').trim().toLowerCase().replace(/[^0-9a-f]/g, '');
  if (s.length < 12 || s.length > 40) return '';
  return s.slice(0, 32);
}
function reqWid(req, qs) {
  if (req.__wid !== undefined) return req.__wid;
  let wid = normWid(qs && qs.get ? qs.get('wid') : '');
  if (!wid) wid = normWid(parseCookie(req.headers.cookie || '').bili_relay_wid);
  if (!wid) {
    const m = /[?&]wid=([0-9a-fA-F]{12,40})/.exec(String(req.url || ''));
    if (m) wid = normWid(m[1]);
  }
  req.__wid = wid;
  return wid;
}
/* 浏览器设备的显示名：尽量让人一眼看出这是从什么设备上的浏览器打开的 */
function webDeviceName(ua) {
  const s = String(ua || '');
  if (/iPhone|iPad|iPod/i.test(s)) return '浏览器 · iPhone/iPad';
  if (/Android/i.test(s)) {
    const m = /Android[^;]*;\s*([^;)]+?)(?:\s+Build|\))/i.exec(s);
    const model = m ? m[1].replace(/Build.*/i, '').trim().slice(0, 16) : '';
    return model && !/^wv$/i.test(model) ? '浏览器 · ' + model : '浏览器 · Android';
  }
  if (/Windows NT/i.test(s)) return '浏览器 · Windows';
  if (/Macintosh|Mac OS X/i.test(s)) return '浏览器 · Mac';
  if (/Linux/i.test(s)) return '浏览器 · Linux';
  return '浏览器';
}
/* 是否是一台“真实设备”（APP 上报过 MAC/android_id），用来和浏览器登记区分 */
function isRealDev(d) {
  if (!d) return false;
  if (d.mac) return true;
  const dids = [d.did].concat(d.dids || []).filter(Boolean);
  return dids.some((x) => !/^web[0-9a-f]{12,40}$/i.test(String(x)));
}
function reqDid(req) {
  if (req.__did !== undefined) return req.__did;  const h = req.headers || {};
  let did = normDid(h['x-dev-id']) || normDid(h['x-device-id']) || normDid(h['x-did']);
  if (!did) {
    const m = /[?&](?:did|devid|device_id)=([^&\s]+)/i.exec(String(req.url || ''));
    if (m) did = normDid(m[1]);
  }
  req.__did = did;
  return did;
}
/* 请求所属 MAC：只认请求头/参数；IP 反查放到 touchDevice 里做弱兜底 */
function reqMac(req) {
  if (req.__mac !== undefined) return req.__mac;
  const h = req.headers || {};
  let mac = normMac(h['x-dev-mac']) || normMac(h['x-mac']);
  if (!mac) {
    const m = /[?&]mac=([^&\s]+)/i.exec(String(req.url || ''));
    if (m) mac = normMac(m[1]);
  }
  req.__mac = mac;
  return mac;
}
/* IP → 最近一次上报的稳定标识（盒子普通请求不带标识头时用来认回同一台） */
function bindIpMac(ip, mac, did) {
  if (!ip || (!mac && !did)) return;
  if (!db.ipmac) db.ipmac = {};
  const old = db.ipmac[ip] || {};
  db.ipmac[ip] = { mac: mac || old.mac || '', did: did || old.did || '', at: Date.now() };
  const keys = Object.keys(db.ipmac);
  if (keys.length > 400) {
    keys.sort((a, b) => (db.ipmac[b].at || 0) - (db.ipmac[a].at || 0));
    keys.slice(300).forEach((k) => { delete db.ipmac[k]; });
  }
}
function ipHint(ip) {
  const b = db.ipmac && db.ipmac[ip];
  if (!b) return null;
  if (Date.now() - (b.at || 0) > 30 * 864e5) return null;
  return { mac: b.mac || '', did: b.did || '' };
}
/* 按 MAC / android_id 找同一台设备：任一对得上就是同一台（换了网络、换了一种取码方式都能认回） */
function findDev(mac, did) {
  if (mac) {
    const d = db.devices.find((x) => x.mac === mac || (x.macs || []).indexOf(mac) >= 0);
    if (d) return d;
  }
  if (did) {
    const d = db.devices.find((x) => x.did === did || (x.dids || []).indexOf(did) >= 0);
    if (d) return d;
  }
  return null;
}
/* 同一出口 IP（同一个网络）下的电视：浏览器打开授权页/面板时只能靠这个认回电视，
 * 浏览器本身不再有自己的身份，也不再单独建档。 */
function webLike(d) {
  if (!d) return false;
  if (d.kind === 'web') return true;
  if (/^web[0-9a-f]{12,40}$/i.test(String(d.did || ''))) return true;
  return (d.dids || []).some((v) => /^web[0-9a-f]{12,40}$/i.test(String(v)));
}
function lanTv(ip) {
  if (!ip) return null;
  const cand = db.devices.filter((d) => !d.orphan && !webLike(d)
    && (d.mac || (d.did && !/^web/i.test(String(d.did))))
    && (d.ip === ip || (d.ips || []).indexOf(ip) >= 0));
  if (!cand.length) return null;
  const h = ipHint(ip);
  if (h && h.mac) {
    const hit = cand.find((d) => d.mac === h.mac || (d.macs || []).indexOf(h.mac) >= 0);
    if (hit) return hit;
  }
  cand.sort((a, b) => (b.lastAt || 0) - (a.lastAt || 0));
  return cand[0];
}
/* 该 IP 上有没有唯一一台设备（老包没带标识时的最后兜底，不新建记录） */
function devByIpOnly(ip) {
  const hit = db.devices.filter((d) => d.ip === ip || (d.ips || []).indexOf(ip) >= 0);
  return hit.length === 1 ? hit[0] : null;
}
/* ---------------- 黑名单（IP / 设备标识） ----------------
 * db.blockIp  : { "<ip>": { at, hits, lastAt, note } }
 * db.blockDev : { "mac|<mac>" | "did|<did>": { type, value, at, hits, lastAt, note } }
 * 判定放在建档之前：拉黑的设备不再登记新记录，也不消耗限流额度；
 * 设备黑名单按标识挡，换 IP、换宽带、换网络都还是挡。
 */
function blkKey(type, value) { return type + '|' + String(value || ''); }
function blkHit(e) { if (!e) return; e.hits = (e.hits || 0) + 1; e.lastAt = Date.now(); saveDbLazy(); }
function blkFindDev(mac, did) {
  const m = db.blockDev || {};
  if (mac && m[blkKey('mac', mac)]) return m[blkKey('mac', mac)];
  if (did && m[blkKey('did', did)]) return m[blkKey('did', did)];
  return null;
}
/* 这台设备（含历史上报过的所有标识）是不是被拉黑了 */
function blkDevOf(dev) {
  if (!dev) return null;
  const m = db.blockDev || {};
  const macs = [dev.mac].concat(dev.macs || []).filter(Boolean);
  const dids = [dev.did].concat(dev.dids || []).filter(Boolean);
  for (const v of macs) { const k = blkKey('mac', normMac(v)); if (k && m[k]) return m[k]; }
  for (const v of dids) { const k = blkKey('did', normDid(v)); if (k && m[k]) return m[k]; }
  return null;
}
/* 请求命中黑名单：先看 IP，再看设备标识（请求自己带的 + 认得出的那台设备的历史标识） */
function blkCheck(req, ip) {
  const ipE = db.blockIp && ip && db.blockIp[ip];
  if (ipE) { blkHit(ipE); return { kind: 'ip', value: ip }; }
  const mac = reqMac(req), did = reqDid(req);
  let e = blkFindDev(mac, did);
  if (!e && (mac || did)) e = blkDevOf(findDev(mac, did));
  if (e) { blkHit(e); return { kind: 'dev', value: e.value, type: e.type }; }
  return null;
}
function blockedHardReply(res) {
  const body = Buffer.from(JSON.stringify({
    code: -403,
    message: '此设备已被管理员停用，如需恢复请联系管理员',
    ttl: 1,
  }));
  res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': body.length, 'Cache-Control': 'no-store' });
  res.end(body);
}
/* ---------------- 未授权超额自动封禁 ----------------
 * 未授权设备每成功拿到一次响应（2xx/3xx）就记一笔；累计到阈值（默认 1000）就自动拉黑。
 * 被门禁挡掉的、被限流挡掉的都不算成功，已授权设备完全不参与计数。
 * 阈值、开关、是否连 IP 都能在面板「黑名单」里改。
 */
function autoBlkTh() {
  const v = Number(db.autoBlkNum);
  return (isFinite(v) && v >= 10) ? Math.round(v) : 1000;
}
function autoBlkPutIp(raw, note) {
  const ip = String(raw || '').trim().replace(/^::ffff:/, '');
  if (!/^[0-9a-fA-F:.]{3,45}$/.test(ip) || !/\d/.test(ip)) return '';
  db.blockIp = db.blockIp || {};
  const old = db.blockIp[ip];
  db.blockIp[ip] = {
    at: (old && old.at) || Date.now(), hits: (old && old.hits) || 0,
    lastAt: (old && old.lastAt) || 0, note, auto: true,
  };
  return ip;
}
function autoBlkPutDev(type, raw, note) {
  const val = type === 'mac' ? normMac(raw) : normDid(raw);
  if (!val) return 0;
  db.blockDev = db.blockDev || {};
  const k = blkKey(type, val);
  if (db.blockDev[k]) { if (note) db.blockDev[k].note = note; return 0; }
  db.blockDev[k] = { type, value: val, at: Date.now(), hits: 0, lastAt: 0, note, auto: true };
  return 1;
}
/* 触发封禁：设备标识全进黑名单，IP 按设置一起封 */
function autoBlkFire(dev, ip) {
  if (!dev || dev.status === 'ok') return;
  const now = Date.now();
  const n = dev.okReq || 0;
  const note = '未授权请求成功 ' + n + ' 次，自动封禁';
  let nb = 0;
  [dev.mac].concat(dev.macs || []).filter(Boolean).forEach((v) => { nb += autoBlkPutDev('mac', v, note); });
  [dev.did].concat(dev.dids || []).filter(Boolean).forEach((v) => { nb += autoBlkPutDev('did', v, note); });
  let ipDone = '';
  if (db.autoBlkIp !== false) {
    const cur = String(ip || '').replace(/^::ffff:/, '');
    // 同一个网络里还有别的已授权设备：那多半是自己家/同一条宽带，只封设备不封 IP，免得连累自己的盒子
    const shared = cur && db.devices.some((d) => d !== dev && d.status === 'ok'
      && (d.ip === cur || (d.ips || []).indexOf(cur) >= 0));
    if (shared) log('device', '自动封禁跳过 IP ' + cur + '：该网络下还有已授权设备，只封设备');
    else if (cur) ipDone = autoBlkPutIp(cur, note);
  }
  dev.status = 'deny';
  if (!dev.actAt) dev.actAt = now;
  dev.autoBlk = { at: now, n, ip: ipDone || '', dev: nb };
  log('device', '自动封禁 ' + (dev.name || '设备') + '（设备码 ' + (dev.code || '-') + '）：未授权请求成功 ' + n
    + ' 次，已拉黑设备标识 ' + nb + ' 条' + (ipDone ? ' + IP ' + ipDone : ''));
  saveDb();
}
/* 每笔响应结束后统计一次 */
function autoBlkWatch(res, dev, ip) {
  if (!dev || db.autoBlkOn === false) return;
  let done = false;
  const fin = () => {
    if (done) return;
    done = true;
    if (!dev || dev.status === 'ok') return;
    const sc = Number(res.statusCode) || 0;
    if (sc < 200 || sc >= 400) return;      // 只算真正成功的请求
    dev.okReq = (dev.okReq || 0) + 1;
    dev.okAt = Date.now();
    if (dev.okReq >= autoBlkTh()) autoBlkFire(dev, ip);
    else saveDbLazy();
  };
  res.on('finish', fin);
  res.on('close', fin);
}
function devKey(req) {
  const mac = reqMac(req);
  if (mac) return crypto.createHash('sha1').update('mac|' + mac).digest('hex').slice(0, 12);
  const did = reqDid(req);
  if (did) return crypto.createHash('sha1').update('did|' + did).digest('hex').slice(0, 12);
  return '';
}
/*
 * 认设备 / 建档
 *  - 有稳定标识（MAC 或 android_id）→ 认回同一台，必要时建档
 *  - 没有任何标识 → 只做弱兜底（IP 记忆 / 该 IP 唯一设备），都没有就返回 null，不建档
 */
function touchDevice(req) {
  const ip = clientIp(req);
  let mac = reqMac(req);
  let did = reqDid(req);
  const ua = String(req.headers['user-agent'] || '');
  // 请求本身没有任何稳定标识（老包/浏览器）：只能靠 IP 记忆或该 IP 唯一设备弱兜底，
  // 这种认法不可靠（换宽带/共用出口都会错），打上 weak 标记，门禁不拿它当拦截依据。
  const weak = !mac && !did;
  if (weak) req.__weak = true;
  if (!mac && !did) {
    const h = ipHint(ip);
    if (h) { mac = h.mac; did = h.did; }
  }
  let dev = (mac || did) ? findDev(mac, did) : null;
  // 部分 TV 请求不带 MAC，只带另一套 device_id；其 buvid 中仍嵌有授权时上报的 12 位 MAC。
  // 用这个强关联认回已授权设备，并合并由同一电视误建的纯 DID 待授权记录。
  const buvidDev = findDeviceByBuvid(db.devices, req.url);
  if (shouldPreferBuvidDevice(dev, buvidDev)) {
    const split = dev;
    dev = buvidDev;
    if (split && mergeSplitIdentity(dev, split)) {
      db.devices = db.devices.filter((x) => x !== split);
      if (db.accMap && db.accMap[split.id] && !db.accMap[dev.id]) db.accMap[dev.id] = db.accMap[split.id];
      if (db.accMap) delete db.accMap[split.id];
      log('device', '自动合并同一电视的重复记录：' + (split.code || split.id) + ' → ' + (dev.code || dev.id));
    }
  }
  if (!dev && !mac && !did) dev = devByIpOnly(ip);
  if (!dev && !mac && !did) {
    req.__devUnknown = true;
    return null;                    // 无标识访问：不建档，避免每个新网络/每个扫描器多一台
  }
  const now = Date.now();
  if (!dev) {
    const id = devKey(req) || crypto.createHash('sha1').update('dev|' + ip + '|' + now).digest('hex').slice(0, 12);
    db.authCodeSeq = (db.authCodeSeq || 1000) + 7;
    dev = {
      id, ip, ua, mac: mac || '', did: did || '', macs: mac ? [mac] : [], dids: did ? [did] : [],
      name: uaName(ua),
      kind: 'app',
      status: 'pending',
      code: String(db.authCodeSeq).slice(-6),
      firstAt: now, lastAt: now, req: 0, blocked: 0, ips: [ip],
    };
    // 新设备一律从「待授权」起步：走自助码、手动放行，或全自动模式。
    log('device', '发现新设备 ' + dev.name + ' (' + (mac ? 'MAC ' + mac : 'did ' + did) + ')');
    if (db.authMode === 'auto') {
      dev.status = 'ok';
      dev.actAt = now;
      dev.autoAuth = true;
      log('device', '自助授权（全自动）：' + dev.name + ' 已放行');
    }
    db.devices.unshift(dev);
    noteDevNetwork(dev, ip);
  } else {
    dev.lastAt = now;
    if (dev.ip !== ip) dev.ip = ip;
    if (!dev.mac && mac) dev.mac = mac;
    if (!dev.did && did) dev.did = did;
    dev.macs = dev.macs || [];
    dev.dids = dev.dids || [];
    if (mac && dev.mac !== mac && dev.macs.indexOf(mac) < 0) { dev.macs.push(mac); if (dev.macs.length > 5) dev.macs.shift(); }
    if (did && dev.did !== did && dev.dids.indexOf(did) < 0) { dev.dids.push(did); if (dev.dids.length > 5) dev.dids.shift(); }
    dev.ips = dev.ips || [];
    if (dev.ips.indexOf(ip) < 0) { dev.ips.push(ip); if (dev.ips.length > 10) dev.ips.shift(); }
    noteDevNetwork(dev, ip);
    if (ua && ua !== 'ZakaGate/1.0' && (!dev.ua || dev.ua === 'ZakaGate/1.0')) dev.ua = ua;
    if (dev.orphan) delete dev.orphan;   // 有真实标识了，说明就是这台，从历史垃圾里捞回
  }
  dev.req++;
  return dev;
}

const GATE_CONTENT_RE = /playurl|player|\/pgc\/|season|search|web-interface\/view|web-interface\/wbi|space|rank|feed|video|bangumi|fav|history|pgc\//i;
// 浏览类接口（推荐流/首页/分区/搜索/封面）不要求设备授权：未授权设备也能正常看首页和推荐，
// 只有取流（playurl/player/pgc）和会员身份类才需要授权。db.gateBrowse=false 可恢复严格模式。
const GATE_BROWSE_RE = /\/x\/tv\/(card|feed|index|modpage|topbar|home|region|rank|search|video|material|theme|global_config|business|notify|session_id|start_callback|exit_callback|splash_ad)|web-interface\/(view|wbi\/view|popular|ranking|region)|\/x\/v2\/(homepage|banner|index|param)|feed\/index|\/(favicon\.ico|robots\.txt)$/i;
const STATIC_RE = /\.(ico|png|jpe?g|gif|svg|css|js|woff2?|ttf|map)$/i;
// 解析/取流类接口：未授权一律硬拦，不受 gateBrowse、浏览白名单、同 IP 兜底影响。
// 命中这些路径的设备必须 status=ok，否则连播放器配置和在线片单都不给。
const HARD_GATE_RE = /(playurl|player\/|\/pgc\/player|\/pgc\/view|\/x\/pd-proxy|\/x\/vas\/|xlive|\/live\/play|\/x\/player\/)/i;
// 会员身份 / 账号类接口：未授权一律拦（这类必须靠池号自己的身份，不能交给未授权设备）
const IDENT_GATE_RE = /\/x\/v2\/(vip|member)|\/x\/tv\/(vip|user|account|member|login|myinfo)|\/x\/pgc\/user|\/pgc\/account|\/x\/wallet|\/x\/tv\/(coin|bcoin)/i;
function shouldGate(req, dev) {
  if (!db.gateOn) return false;
  if (dev && dev.status === 'ok') return false;
  const __u = String(req.url || '');
  const __bare = __u.split('?')[0];
  if (STATIC_RE.test(__bare)) return false;
  // 解析先判：认不出设备也不放行
  if (HARD_GATE_RE.test(__bare)) return true;
  // 身份类接口同样硬拦
  if (IDENT_GATE_RE.test(__bare)) return true;
  // 可浏览模式：除解析/取流和身份类，其余（推荐流/首页/分区/搜索/详情/标签/播放记录上报）一律放行。
  // 原来用有限白名单，上游新加的浏览接口（/x/tv/v2/pgc/labels 等）会被误拦，导致推荐页整页加载失败。
  if (db.gateBrowse !== false) return false;
  const isContent = db.gateLevel === 'all' ? true : GATE_CONTENT_RE.test(String(req.url || ''));
  // 认得出设备：待授权、被禁用一律拦内容接口（播放/搜索/详情）
  if (dev) return isContent;
  // 认不出设备（老包不带设备标识、浏览器直连）：按网络兜底。
  // 这个 IP 上只要还有一台已授权设备就放行（同一网络共用），否则内容接口一律先授权。
  const ip = clientIp(req);
  const ipDevs = db.devices.filter((d) => d.ip === ip);
  if (ipDevs.some((d) => d.status === 'ok')) return false;
  return isContent;
}
function blockedReply(res, dev) {
  try { require('fs').appendFileSync('/tmp/gate.log', Date.now() + ' blocked p=' + String(res.__p || '?') + ' dev=' + String((dev && dev.id) || '-') + ' st=' + String((dev && dev.status) || '-') + ' ip=' + String((dev && dev.ip) || '-') + '\n'); } catch (e) {}
  const body = Buffer.from(JSON.stringify({
    code: -403,
    message: '此设备未授权，请在电视上打开授权页完成授权（设备码 ' + (dev ? dev.code : '----') + '）',
    ttl: 1,
  }));
  res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': body.length, 'Cache-Control': 'no-store' });
  res.end(body);
}

function parseCookie(str) {
  const o = {};
  String(str || '').split(';').forEach((kv) => {
    const i = kv.indexOf('=');
    if (i < 0) return;
    o[kv.slice(0, i).trim()] = kv.slice(i + 1).trim();
  });
  return o;
}
function buildCookie(o) {
  return Object.keys(o).filter((k) => o[k]).map((k) => k + '=' + o[k]).join('; ');
}
/*
 * 账号分配
 *  - device（默认）：一台设备固定用一个号（按设备ID哈希+记忆），避免多台盒子抢同一个号把 CDN 限速打满
 *  - rr：老的轮询方式，每次请求换一个号
 * 号失效（valid=false）时自动从池子里重新挑一个，并把记忆改成新的
 */
function pickAccount(dev) {
  const list = db.accounts.filter((a) => a.valid !== false && a.cookie);
  if (!list.length) return null;
  if ((db.accountMode || 'device') === 'rr') {
    db.rr = (db.rr + 1) % list.length;
    return list[db.rr];
  }
  const key = (dev && dev.id) || 'anon';
  if (!db.accMap) db.accMap = {};
  const want = db.accMap[key];
  if (want) {
    const hit = list.find((a) => a.id === want);
    if (hit) return hit;
  }
  let h = 0;
  for (let i = 0; i < key.length; i++) h = (h * 31 + key.charCodeAt(i)) >>> 0;
  const acc = list[h % list.length];
  db.accMap[key] = acc.id;
  if (Object.keys(db.accMap).length > 2000) db.accMap = { [key]: acc.id };
  saveDbLazy();
  return acc;
}

/* ---------------- 上游指标（面板用） ---------------- */
const MET = {
  startAt: Date.now(),
  lat: [], ok: 0, fail: 0, total: 0,
  day: '', dayOk: 0, dayFail: 0,
  k4Now: 0, k4Peak: 0, k4PeakAt: 0,
  cacheHit: 0, cacheMiss: 0,
  rl: 0, rlIp: 0, rlDev: 0, rlAnon: 0, rlAcc: 0,
};
function metReset() {
  const d = today();
  if (MET.day !== d) { MET.day = d; MET.dayOk = 0; MET.dayFail = 0; MET.k4Peak = 0; MET.k4PeakAt = 0; }
}
function metLat(ms) { MET.lat.push(ms); if (MET.lat.length > 400) MET.lat.shift(); }
function metResult(ok) {
  metReset();
  MET.total++;
  if (ok) { MET.ok++; MET.dayOk++; } else { MET.fail++; MET.dayFail++; }
}
function metEnter4k() {
  metReset();
  MET.k4Now++;
  if (MET.k4Now > MET.k4Peak) { MET.k4Peak = MET.k4Now; MET.k4PeakAt = Date.now(); }
}
function metLeave4k() { MET.k4Now = Math.max(0, MET.k4Now - 1); }
function metStats() {
  metReset();
  const a = MET.lat.slice().sort((x, y) => x - y);
  const avg = a.length ? Math.round(a.reduce((s, v) => s + v, 0) / a.length) : 0;
  const p95 = a.length ? a[Math.min(a.length - 1, Math.floor(a.length * 0.95))] : 0;
  const tot = MET.total || 1;
  const ch = MET.cacheHit + MET.cacheMiss;
  return {
    avgMs: avg, p95Ms: p95, samples: a.length,
    ok: MET.ok, fail: MET.fail, total: MET.total,
    failRate: Math.round((MET.fail / tot) * 1000) / 10,
    dayOk: MET.dayOk, dayFail: MET.dayFail,
    k4Now: MET.k4Now, k4Peak: MET.k4Peak, k4PeakAt: MET.k4PeakAt,
    cacheHit: MET.cacheHit, cacheMiss: MET.cacheMiss,
    cacheRate: ch ? Math.round((MET.cacheHit / ch) * 1000) / 10 : 0,
    uptime: Math.floor((Date.now() - MET.startAt) / 1000),
    rl: MET.rl, rlIp: MET.rlIp, rlDev: MET.rlDev, rlAnon: MET.rlAnon, rlAcc: MET.rlAcc,
  };
}

/* ---------------- 防刷与安全 ----------------
 * 三件事：限流（设备 / IP / 无标识裸请求 / 单个 Cookie 号取流）、指纹漂移检测、设备令牌。
 * 全部能在面板上开关和调阈值，默认档位是「正常盒子碰不到、脚本一刷就撞上」。
 */
const RL = new Map();   // key -> { t: 窗口起点, n: 窗口内次数 }
function rlTick(key, max, winMs) {
  const cap = Number(max) || 0;
  if (cap <= 0) return true;
  const now = Date.now();
  let e = RL.get(key);
  if (!e || now - e.t >= winMs) { e = { t: now, n: 0 }; RL.set(key, e); }
  e.n++;
  return e.n <= cap;
}
setInterval(() => {
  const now = Date.now();
  const dead = [];
  RL.forEach((v, k) => { if (now - v.t > 3600e3) dead.push(k); });
  dead.forEach((k) => RL.delete(k));
  if (RL.size > 50000) RL.clear();
}, 300e3).unref();

function tooFast(res) {
  const body = Buffer.from(JSON.stringify({ code: -429, message: '请求过于频繁，请稍后再试', ttl: 1 }));
  res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': body.length, 'Cache-Control': 'no-store' });
  res.end(body);
}

/* 网段：IPv4 取 /16，IPv6 取前 4 组。宽带重拨换的是末段、网段通常不变，所以拿网段数当漂移指标 */
function ipSeg(ip) {
  const s = String(ip || '').trim();
  if (!s) return '';
  if (s.indexOf(':') >= 0) return 'v6:' + s.split(':').slice(0, 4).join(':');
  const p = s.split('.');
  return p.length === 4 ? 'v4:' + p[0] + '.' + p[1] : s;
}

/* 设备网络足迹：只留 24 小时、最多 30 条；同一 IP 5 分钟内不重复写，少落盘 */
const IPLOG = new Map();   // 设备ID -> { IP: 最近一次时间 }，只在内存里，不落盘（data.json 已经不小了）
function ipLogOf(dev) {
  if (!dev || !dev.id) return {};
  let m = IPLOG.get(dev.id);
  if (!m) { m = {}; IPLOG.set(dev.id, m); }
  return m;
}
function devSegs(dev) {
  if (!dev || !dev.id) return new Set();
  const m = IPLOG.get(dev.id);
  if (!m) return new Set();
  const now = Date.now();
  return new Set(Object.keys(m).filter((k) => now - m[k] <= 24 * 3600e3).map(ipSeg).filter(Boolean));
}
function noteDevNetwork(dev, ip) {
  if (!dev || !ip || db.driftOn === false) return;
  const now = Date.now();
  const seen = ipLogOf(dev);
  if (!seen[ip] || now - seen[ip] > 300e3) seen[ip] = now;
  Object.keys(seen).forEach((k) => { if (now - seen[k] > 24 * 3600e3) delete seen[k]; });
  const keys = Object.keys(seen);
  if (keys.length > 30) {
    keys.sort((a, b) => seen[b] - seen[a]);
    keys.slice(30).forEach((k) => { delete seen[k]; });
  }
  const segs = new Set(keys.map(ipSeg).filter(Boolean));
  if (segs.size >= (db.driftSegMax || 4)) {
    const first = !dev.suspect;
    dev.suspect = {
      at: (dev.suspect && dev.suspect.at) || now, segs: segs.size, hitAt: now,
      ips: keys.slice(0, 8),
    };
    if (first) {
      log('security', '疑似设备标识被共用或复刻：' + (dev.name || '未知机型') + ' 24 小时内出现在 '
        + segs.size + ' 个不同网段（' + (dev.mac ? 'MAC ' + dev.mac : 'did ' + (dev.did || '?')) + '）');
      saveDbLazy();
      if (db.driftAuto && dev.status === 'ok') {
        dev.status = 'pending';
        log('security', '按设置已自动转待授权：' + (dev.name || '未知机型'));
        saveDb();
      }
    }
  }
}

/* ---------------- 接口缓存 ----------------
 * 只缓存「同一个请求不管谁问，答案都一样」的内容类接口：首页、番剧详情、视频详情、
 * 分区列表、搜索第 1 页这类。取流(playurl)、账号/登录、上报/心跳、互动一律不缓存。
 * 缓存的是「已经净化过身份」的最终响应体，命中直接吐，不再打上游。
 */
const CACHE = new Map();
let cacheBytes = 0;
const CACHE_MAX_ITEMS = 500;
const CACHE_MAX_BYTES = 64 * 1024 * 1024;
const CACHEABLE_RE = /(\/x\/(web-interface\/(view|wbi\/view|popular|ranking|region)|space\/(wbi\/)?arc\/search|polymer\/web-dynamic\/v1\/feed|tv\/(home|feed|card|rank|hot|season|search|zone|list)|v2\/search|v3\/search)|feed\/index|\/pgc\/(season|view)|\/x\/web-interface\/card|\/x\/v2\/(homepage|banner|index))/i;
const NO_CACHE_RE = /(playurl|player|\/x\/pd-proxy|heartbeat|report|\/log\/|click|like|coin|fav|share|follow|history|login|passport|nav|\/account|mine|svip|qr|sms|upload|reply|danmaku|subtitle|checkin|excitation|thumbup|archive\/relation)/i;

/*
 * 缓存键：把每次都会变的参数剔掉（ts/sign/access_key/请求追踪号），
 * 否则同一条视频详情每次 key 都不一样，缓存等于没有
 */
const CACHE_VARY_DROP = ['ts', '_ts', 'sign', 'access_key', 'accessKey', 'access-key', '_', 'request_id', 'trace_id', 'spmid', 'from_spmid', 'session_id'];
function cacheKeyOf(sub, url) {
  const s = String(url || '');
  const i = s.indexOf('?');
  if (i < 0) return sub + '|' + s;
  const bare = s.slice(0, i);
  try {
    const p = new URLSearchParams(s.slice(i + 1));
    CACHE_VARY_DROP.forEach((k) => p.delete(k));
    const ents = [...p.entries()].sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
    return sub + '|' + bare + '?' + ents.map(([k, v]) => k + '=' + v).join('&');
  } catch (e) {
    return sub + '|' + s;
  }
}
function cacheGet(k) {  const e = CACHE.get(k);
  if (!e) return null;
  if (Date.now() - e.t > (db.cacheTtl || 300) * 1000) {
    CACHE.delete(k); cacheBytes -= e.size;
    return null;
  }
  return e;
}
function cacheSet(k, status, headers, body) {
  const size = body.length;
  if (size > 3 * 1024 * 1024) return; // 大响应不缓存，别把内存吃掉
  const old = CACHE.get(k);
  if (old) { cacheBytes -= old.size; CACHE.delete(k); }
  CACHE.set(k, { t: Date.now(), status, headers, body, size });
  cacheBytes += size;
  while (CACHE.size > CACHE_MAX_ITEMS || cacheBytes > CACHE_MAX_BYTES) {
    const oldest = CACHE.keys().next();
    if (oldest.done) break;
    const v = CACHE.get(oldest.value);
    CACHE.delete(oldest.value);
    if (v) cacheBytes -= v.size;
  }
}
function cacheClear() { CACHE.clear(); cacheBytes = 0; }
function cacheStats() {
  return { items: CACHE.size, bytes: cacheBytes, on: db.cacheOn !== false, ttl: db.cacheTtl || 300 };
}
function json(res, code, obj) {
  const body = Buffer.from(JSON.stringify(obj));
  res.writeHead(code, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': body.length, 'Cache-Control': 'no-store' });
  res.end(body);
}

/* 授权页对外地址：默认使用面板 HTTPS 域名，data.json 里可用 authUrl/authHost 覆盖 */
function authUrlOf() {
  if (db.authUrl) return String(db.authUrl);
  const host = db.authHost ? String(db.authHost) : 'panel.b.xaitr.com';
  const proto = /:\d+$/.test(host) ? 'http://' : 'https://';
  return proto + host + '/auth';
}

/* ---------------- B 站接口 ---------------- */
function egressOf(pathStr) {
  const area = selectProxyArea(pathStr);
  const proxyUrl = proxyForRequest(pathStr, db.egressProxy);
  return { area, proxyUrl, agent: makeProxyAgent(proxyUrl) };
}

function outboundBuffered(opt, bodyBuf, maxBytes) {
  return new Promise((resolve, reject) => {
    const t0 = Date.now();
    const limit = maxBytes || 6 * 1024 * 1024;
    const preq = https.request(opt, (pres) => {
      const chunks = [];
      let size = 0;
      pres.on('data', (c) => {
        size += c.length;
        if (size <= limit) chunks.push(c);
        else preq.destroy(new Error('upstream response too large'));
      });
      pres.on('end', () => resolve({ status: pres.statusCode, headers: pres.headers, body: Buffer.concat(chunks), ms: Date.now() - t0 }));
      pres.on('error', reject);
    });
    preq.on('timeout', () => preq.destroy(new Error('upstream timeout')));
    preq.on('error', reject);
    if (bodyBuf && bodyBuf.length) preq.end(bodyBuf); else preq.end();
  });
}

async function requestUrlBuffered(rawUrl, options) {
  const u = new URL(rawUrl);
  const o = options || {};
  const eg = egressOf(o.areaPath || '/');
  try {
    return await outboundBuffered({
      host: u.hostname,
      port: Number(u.port) || 443,
      path: u.pathname + u.search,
      method: o.method || 'GET',
      headers: o.headers || {},
      servername: u.hostname,
      agent: eg.agent,
      timeout: o.timeout || 12000,
    }, o.body || null, o.maxBytes || 2 * 1024 * 1024);
  } catch (e) {
    throw new Error(safeProxyError(e, eg.proxyUrl));
  }
}

async function biliGet(url, cookie, referer) {
  const r = await requestUrlBuffered(url, {
    areaPath: '/?area=default',
    headers: Object.assign({ 'User-Agent': UA, Referer: referer || 'https://www.bilibili.com/' }, cookie ? { Cookie: cookie } : {}),
  });
  const text = r.body.toString('utf8');
  let data = null;
  try { data = JSON.parse(text); } catch (e) { data = { code: -1, message: text.slice(0, 200) }; }
  const setCookie = r.headers['set-cookie'] || [];
  return { data, setCookie: Array.isArray(setCookie) ? setCookie : [setCookie] };
}

function appSign(params) {
  const s = Object.keys(params).sort().map((k) => k + '=' + encodeURIComponent(params[k])).join('&');
  return crypto.createHash('md5').update(s + APPSEC).digest('hex');
}
async function biliPostApp(url, params) {
  const p = Object.assign({}, params);
  p.appkey = APPKEY;
  p.ts = String(Math.floor(Date.now() / 1000));
  p.sign = appSign(p);
  const body = new URLSearchParams(p).toString();
  const r = await requestUrlBuffered(url, {
    areaPath: '/?area=default',
    method: 'POST',
    headers: {
      'User-Agent': 'Mozilla/5.0 BiliDroid/7.0.0 (bbcallen@gmail.com)',
      'Content-Type': 'application/x-www-form-urlencoded',
      'Content-Length': Buffer.byteLength(body),
    },
    body: Buffer.from(body),
  });
  const text = r.body.toString('utf8');
  try { return JSON.parse(text); } catch (e) { return { code: -1, message: text.slice(0, 200) }; }
}

async function checkAccount(acc) {
  try {
    const { data } = await biliGet('https://api.bilibili.com/x/web-interface/nav', acc.cookie);
    acc.lastCheck = Date.now();
    if (data.code === 0 && data.data && data.data.isLogin) {
      acc.valid = true;
      acc.name = data.data.uname;
      acc.mid = data.data.mid;
      acc.face = data.data.face;
      acc.level = data.data.level_info && data.data.level_info.current_level;
      const vip = data.data.vipStatus === 1;
      acc.vip = vip;
      acc.vipDue = data.data.vipDueDate || 0;
      acc.vipLabel = vip ? '大会员' : '普通';
      return acc;
    }
    acc.valid = false;
    acc.vip = false;
    acc.err = data.code === -101 ? 'Cookie 已失效' : (data.message || '校验失败');
    return acc;
  } catch (e) {
    acc.valid = false;
    acc.err = '校验异常: ' + e.message;
    return acc;
  }
}

function addAccountFromCookieMap(map, source) {
  const cookie = buildCookie(map);
  if (!map.SESSDATA) throw new Error('没有拿到 SESSDATA');
  const exist = db.accounts.find((a) => map.DedeUserID && a.mid === Number(map.DedeUserID));
  const acc = exist || { id: crypto.randomBytes(6).toString('hex'), addedAt: Date.now() };
  acc.cookie = cookie;
  acc.sessdata = map.SESSDATA;
  acc.biliJct = map.bili_jct || '';
  acc.dedeUserId = map.DedeUserID || '';
  acc.source = source || 'qr';
  acc.valid = true;
  acc.err = '';
  acc.lastCheck = 0;
  if (!exist) db.accounts.push(acc);
  saveDb();
  log('account', '新增会员账号 ' + (acc.name || acc.dedeUserId || ''));
  return acc;
}

/* ---------------- 扫码登录 ---------------- */
async function qrNew() {
  const { data } = await biliGet('https://passport.bilibili.com/x/passport-login/web/qrcode/generate?source=main-fe-header');
  if (data.code !== 0) throw new Error(data.message || '生成二维码失败');
  return { key: data.data.qrcode_key, url: data.data.url };
}
async function qrPoll(key) {
  const { data, setCookie } = await biliGet(
    'https://passport.bilibili.com/x/passport-login/web/qrcode/poll?qrcode_key=' + encodeURIComponent(key) + '&source=main-fe-header'
  );
  const d = data.data || {};
  const st = typeof d.code === 'number' ? d.code : data.code;
  const ST_MSG = {
    86101: '等待扫码…',
    86090: '已扫码，请在手机上点确认',
    86038: '二维码已过期，重新生成一个',
  };
  const out = { code: st, msg: ST_MSG[st] || d.message || data.message || '' };
  if (st === 0 && data.data) {
    const c = {};
    setCookie.forEach((line) => { Object.assign(c, parseCookie(line.split(';')[0])); });
    if (data.data.url) {
      try {
        const u = new URL(data.data.url);
        u.searchParams.forEach((v, k) => { c[k] = decodeURIComponent(v); });
      } catch (e) {}
    }
    if (c.SESSDATA) {
      const acc = addAccountFromCookieMap(c, 'qr');
      await checkAccount(acc);
      saveDb();
      out.ok = true;
      out.account = acc;
      return out;
    }
    out.msg = '登录成功但没拿到 Cookie';
    return out;
  }
  return out;
}

/* ---------------- 手机验证码登录 ---------------- */
async function smsSend(tel) {
  const j = await biliPostApp('https://passport.bilibili.com/x/passport-login/sms/send', { tel, cid: '86' });
  if (j.code !== 0) return { ok: false, msg: j.message || '发送失败', code: j.code };
  const d = j.data || {};
  return { ok: true, captchaKey: d.captcha_key || '', recaptcha: d.recaptcha_url || '', isNew: !!d.is_new };
}
async function smsVerify(tel, code, extra) {
  const p = { tel, code, cid: '86' };
  if (extra && typeof extra === 'object') {
    ['captcha_key', 'gee_challenge', 'gee_validate', 'gee_seccode', 'recaptcha_token', 'login_session_id'].forEach((k) => {
      if (extra[k]) p[k] = extra[k];
    });
  }
  const j = await biliPostApp('https://passport.bilibili.com/x/passport-login/login/sms', p);
  if (j.code !== 0) {
    const hint = j.code === -400 ? 'B站对该通道强制滑块校验，短信登录需要在浏览器里手动过滑块。请改用扫码登录（等效于手机登录，3 秒完成）' : (j.message || '登录失败');
    return { ok: false, code: j.code, msg: hint };
  }
  const d = j.data || {};
  const c = {};
  if (d.cookie_info && Array.isArray(d.cookie_info.cookies)) {
    d.cookie_info.cookies.forEach((x) => { c[x.name] = x.value; });
  }
  if (!c.SESSDATA) return { ok: false, msg: '登录成功但未返回 Cookie' };
  const acc = addAccountFromCookieMap(c, 'sms');
  await checkAccount(acc);
  saveDb();
  return { ok: true, account: acc };
}

/* ---------------- 中转 ---------------- */
function probeLeak(pathStr) {
  db.leaks = db.leaks || [];
  const p = String(pathStr).split('?')[0].slice(0, 90);
  if (db.leaks.some((x) => x.p === p && Date.now() - x.t < 3600e3)) return;
  db.leaks.unshift({ t: Date.now(), p });
  if (db.leaks.length > 30) db.leaks.length = 30;
  log('share', '检测到可能暴露账号的接口：' + p);
  saveDbLazy();
}
/* ---------------- 身份净化工具 ----------------
 * 目标：盒子那头永远看不到任何会员身份（昵称/头像/mid/登录态/大会员有效期）
 * 三道关：① 盒子自带的账号 Cookie 一律剥掉 ② HTML/会员中心页不注入任何账号 ③ 响应体兜底清洗
 */
const AUTH_COOKIE_RE = /^(SESSDATA|bili_jct|DedeUserID|DedeUserID__ckMd5|sid|bili_ticket|bili_ticket_expires|ac_time_value|access_key|refresh_token|ltoken|ltuid|ltuid_v2|sessdata|buvid3_temp|b_nut)$/i;
function stripAuthCookies(c) {
  if (!c) return '';
  return String(c).split(';').map((x) => x.trim()).filter(Boolean)
    .filter((kv) => !AUTH_COOKIE_RE.test(kv.split('=')[0].trim()))
    .join('; ');
}
function filterSetCookie(arr) {
  if (!arr) return arr;
  return arr.filter((sc) => !AUTH_COOKIE_RE.test(String(sc).split('=')[0].trim()));
}
/* ---------------- access_key 压制 ----------------
 * 上游认身份的优先级：access_key > Cookie。
 * 盒子那头一旦有人登录了自己的账号，客户端每一条请求都会带上他自己的 access_key，
 * 把我们注入的会员 Cookie 直接顶掉 —— 结果就是「用他的普通号解析」，画质掉到 480P。
 * 所以只要是注入账号的模式，请求里的 access_key 一律剥掉，让它只能按池号 Cookie 认证。
 * 剥掉参数后原来的 sign 就失效了（sign 里含 access_key），必须用 appkey 重算。
 */
function stripAccessKey(pathStr) {
  const s = String(pathStr || '');
  if (!/access_?key/i.test(s)) return s;
  const qi = s.indexOf('?');
  if (qi < 0) return s;
  const bare = s.slice(0, qi);
  const qs = s.slice(qi + 1);
  let p;
  try { p = new URLSearchParams(qs); } catch (e) { return s; }
  if (!p.has('access_key') && !p.has('accessKey') && !p.has('access-key')) return s;
  const hadSign = p.has('sign');
  ['access_key', 'accessKey', 'access-key'].forEach((k) => p.delete(k));
  if (!hadSign) {
    // 未签名请求：字符串级删除，别的参数一个字不动
    return bare + '?' + qs.split('&').filter((kv) => !/^access_?key=/i.test(kv)).join('&');
  }
  p.set('appkey', APPKEY);
  return bare + '?' + serializeQuery(p, true);
}
function stripAccessKeyParams(p) {
  ['access_key', 'accessKey', 'access-key'].forEach((k) => p.delete(k));
  p.set('appkey', APPKEY);
  const o = {};
  p.forEach((v, k) => { if (k !== 'sign') o[k] = v; });
  p.set('sign', appSign(o));
  return p;
}
function scrubIdentity(s, acc, isContent) {
  s = s.replace(/"isLogin"\s*:\s*true/gi, '"isLogin":false')
       .replace(/"is_login"\s*:\s*true/gi, '"is_login":false')
       .replace(/"isLogin"\s*:\s*1\b/gi, '"isLogin":0')
       .replace(/"is_login"\s*:\s*1\b/gi, '"is_login":0');
  if (!acc) return s;
  if (acc.name) {
    const nm = String(acc.name).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
    s = s.replace(new RegExp('"uname"\\s*:\\s*"' + nm + '"', 'g'), '"uname":""');
    s = s.replace(new RegExp('"name"\\s*:\\s*"' + nm + '"', 'g'), '"name":""');
    // 昵称原样出现在任何内容里（JSON / HTML / JS）一律抹掉；内容页只动 uname 字段，避免误伤
    if (!isContent && s.indexOf(String(acc.name)) !== -1) s = s.split(String(acc.name)).join('');
  }
  if (acc.face) s = s.split(String(acc.face)).join('');
  return s;
}

/* ---------------- 画质策略 ----------------
 * 盒子取流时带的 qn 决定上游返回的「默认档位」(dash.video 里 quality 那一条)。
 *   4k   → 一律按 120(4K) 请求，上游按片源和账号能力给到最高档（片源没 4K 就自动降到它的最高档）
 *   1080 → 按 80(1080P) 请求
 *   auto → 原样透传，跟随盒子自己的设置
 * 改了 qn 必须用 appkey 重算 sign，否则上游直接 -400 参数错误。
 */
const PLAYURL_RE = /\/x\/tv\/playurl|\/x\/player\/(wbi\/)?playurl|\/x\/player\/playurl\/v2|\/pgc\/player\/(web\/)?playurl/i;
function serializeQuery(p, withSign) {
  const ents = [...p.entries()].filter(([k]) => k !== 'sign');
  ents.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  let str = ents.map(([k, v]) => k + '=' + encodeURIComponent(v)).join('&');
  if (withSign) {
    const sign = crypto.createHash('md5').update(str + APPSEC).digest('hex');
    str += '&sign=' + sign;
  }
  return str;
}
function applyQuality(pathStr) {
  const qm = db.qualityMode || '4k';
  if (qm === 'auto') return pathStr;
  const s = String(pathStr || '');
  const bare = s.split('?')[0];
  if (!PLAYURL_RE.test(bare)) return pathStr;
  if (s.indexOf('?') < 0) return pathStr;
  try {
    const u = new URL('http://relay' + s);
    const p = u.searchParams;
    if (!p.has('qn') && !p.has('quality')) return pathStr;
    const target = qm === '1080' ? '80' : '120';
    if (p.get('qn') === target) return pathStr;
    p.set('qn', target);
    if (!p.has('fnval')) p.set('fnval', '4048');
    p.delete('quality');
    const hasSign = p.has('sign');
    return u.pathname + '?' + serializeQuery(p, hasSign);
  } catch (e) {
    return pathStr; // 任何异常都退回原样转发，绝不把播放搞挂
  }
}

/* ---------------- 取流：失败自动降档 ----------------
 * 盒子要 4K(120)，上游可能因为片源没 4K、账号权限掉了、或风控临时拒绝而返回错误。
 * 原来这种情况盒子直接白屏/加载失败；现在服务端按 120 → 80(1080P) → 64(720P) 逐级重试，
 * 哪一档成功就把哪一档给盒子，盒子完全无感，不会再出现「加载失败」。
 */
function withQn(s, qn) {
  try {
    const u = new URL('http://relay' + s);
    const p = u.searchParams;
    if (!p.has('qn') && !p.has('quality')) return s;
    if (p.get('qn') === String(qn)) return s;
    p.set('qn', String(qn));
    if (!p.has('fnval')) p.set('fnval', '4048');
    p.delete('quality');
    return u.pathname + '?' + serializeQuery(p, p.has('sign'));
  } catch (e) { return s; }
}
function withQnBody(buf, qn) {
  if (!buf || !buf.length) return buf;
  const b = buf.toString('utf8');
  if (!/(^|&)qn=/.test(b)) return buf;
  try {
    const p = new URLSearchParams(b);
    if (p.get('qn') === String(qn)) return buf;
    p.set('qn', String(qn));
    if (!p.has('fnval')) p.set('fnval', '4048');
    p.delete('quality');
    return Buffer.from(serializeQuery(p, p.has('sign')), 'utf8');
  } catch (e) { return buf; }
}
function playurlLooksOk(r) {
  if (!r || r.status < 200 || r.status >= 300) return false;
  const ct = String(r.headers['content-type'] || '');
  if (!/json/i.test(ct)) return r.body.length > 0;
  let j = null;
  try { j = JSON.parse(r.body.toString('utf8')); } catch (e) { return false; }
  if (!j || j.code !== 0 || !j.data) return false;
  const d = j.data;
  if (d.durl && d.durl.length) return true;
  if (d.dash && d.dash.video && d.dash.video.length) return true;
  return false;
}
function upstreamBuffered(opt, bodyBuf) {
  return outboundBuffered(opt, bodyBuf, 6 * 1024 * 1024);
}

function stripAccessKeyBody(buf) {
  if (!buf || !buf.length) return buf;
  const b = buf.toString('utf8');
  if (!/access_?key=/i.test(b)) return buf;
  try {
    const p = new URLSearchParams(b);
    const hadSign = p.has('sign');
    if (hadSign) stripAccessKeyParams(p);
    else ['access_key', 'accessKey', 'access-key'].forEach((k) => p.delete(k));
    return Buffer.from(p.toString(), 'utf8');
  } catch (e) { return buf; }
}

async function handlePlayurl(req, res, ctx) {
  const { target, headers, fwdUrl, mode, pathStr, st, agent, proxyUrl } = ctx;
  const upH = Object.assign({}, headers);
  upH['accept-encoding'] = 'identity'; // 明文回传，便于判断成功/失败，响应本来就只有几 KB
  delete upH['content-length'];

  let bodyBuf = null;
  if (!/^(GET|HEAD)$/i.test(req.method)) {
    bodyBuf = await new Promise((resolve) => {
      const ch = []; let n = 0;
      req.on('data', (c) => { n += c.length; if (n <= 1024 * 1024) ch.push(c); });
      req.on('end', () => resolve(Buffer.concat(ch)));
      req.on('error', () => resolve(Buffer.concat(ch)));
    });
    // 登录态的盒子会把 access_key 塞在表单里，不剥掉上游就按他那条号认证，画质直接掉回 480P
    if (mode !== 'off') bodyBuf = stripAccessKeyBody(bodyBuf);
  }

  const qm = db.qualityMode || '4k';
  let targetQn = null;
  if (qm !== 'auto') targetQn = qm === '1080' ? 80 : 120;
  const tries = targetQn ? [targetQn, 80, 64].filter((v, i, a) => a.indexOf(v) === i) : [null];

  const is4k = targetQn === 120;
  if (is4k) metEnter4k();
  let last = null;
  let usedQn = targetQn;
  let lastErr = '';
  try {
    for (const qn of tries) {
      const u = qn ? withQn(fwdUrl, qn) : fwdUrl;
      const b = qn ? withQnBody(bodyBuf, qn) : bodyBuf;
      const opt = { host: target, port: UPSTREAM_PORT, path: u, method: req.method, headers: upH, servername: target, rejectUnauthorized: false, agent, timeout: 20000 };
      let r = null;
      try { r = await upstreamBuffered(opt, b); } catch (e) { lastErr = safeProxyError(e, proxyUrl); continue; }
      last = r; usedQn = qn;
      metLat(r.ms);
      metResult(r.status >= 200 && r.status < 300);
      if (playurlLooksOk(r)) break;
      try { const j = JSON.parse(r.body.toString('utf8')); lastErr = 'code=' + j.code + ' ' + (j.message || ''); } catch (e) { lastErr = 'HTTP ' + r.status; }
    }

    if (!last) {
      if (!res.headersSent) {
        res.writeHead(502, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({ code: -502, message: 'relay error: ' + (lastErr || 'upstream failed') }));
      }
      return;
    }

    if (last.status >= 200 && last.status < 400) { st.ok++; db.lastOk = Date.now(); }

    let out = last.body;
    if (mode === 'stealth') {
      try {
        const s = out.toString('utf8');
        if (Buffer.compare(Buffer.from(s, 'utf8'), out) === 0) {
          out = Buffer.from(scrubIdentity(s, ctx.acc || (db.accounts || [])[0] || null, true), 'utf8');
        }
      } catch (e) { out = last.body; }
    }

    const hh = Object.assign({}, last.headers);
    delete hh['content-encoding'];
    delete hh['transfer-encoding'];
    delete hh['content-length'];
    if (mode === 'stealth') delete hh['set-cookie'];
    hh['content-length'] = out.length;
    if (is4k) hh['x-relay-quality'] = targetQn === usedQn ? '4k' : String(usedQn === 80 ? '1080' : usedQn === 64 ? '720' : usedQn);
    if (targetQn && usedQn !== targetQn) {
      MET.degrade = (MET.degrade || 0) + 1;
      MET.degradeAt = Date.now();
      if (!MET.lastDegradeLog || Date.now() - MET.lastDegradeLog > 60000) {
        MET.lastDegradeLog = Date.now();
        log('quality', '取流降档：' + targetQn + ' → ' + usedQn + ' (' + (lastErr || '上游无该清晰度') + ')');
      }
    }
    res.writeHead(last.status, hh);
    res.end(out);
  } finally {
    if (is4k) metLeave4k();
  }
}

/* ---- 临时诊断（排「推荐页加载失败」用）：只写 /tmp/diag.log，不改任何转发行为 ---- */
const DIAG_RE = /\/x\/tv\/(card\/feed|\/index|index\/|modpage)/i;
function diagWrite(line) {
  try {
    const f = '/tmp/diag.log';
    try { if (fs.statSync(f).size > 2 * 1024 * 1024) fs.writeFileSync(f, ''); } catch (e0) {}
    fs.appendFileSync(f, new Date().toISOString() + ' ' + line + '\n');
  } catch (e) {}
}
function proxy(req, res) {
  const ip0 = clientIp(req);
  /* 黑名单先判：命中直接挡，不建档、不占限流额度、不走上游 */
  const __blk = blkCheck(req, ip0);
  if (__blk) {
    try { res.__p = String(req.url || '').split('?')[0]; } catch (e) {}
    return blockedHardReply(res);
  }
  let dev = touchDevice(req);
  const __gate = shouldGate(req, dev);
  if (__gate) {
    if (dev) dev.blocked = (dev.blocked || 0) + 1;
    saveDbLazy();
    try { res.__p = String(req.url || '').split('?')[0]; } catch (e) {} return blockedReply(res, dev);
  }

  /* ---- 限流：IP → 设备 → 无标识裸请求，逐层挡。正常盒子碰不到，脚本一刷就断 ---- */
  if (db.rlOn !== false) {
    if (!rlTick('ip|' + ip0, db.rlIpPerMin, 60e3)) {
      MET.rl++; MET.rlIp++; saveDbLazy(); return tooFast(res);
    }
    // 设备额度只对「请求自己带了设备标识」的生效：老包靠 IP 反查认出来的设备不可靠，
    // 同一个出口后面的几台盒子会被认成同一台，叠加起来容易误伤，所以它们只吃下面那档裸请求额度
    if (dev && !req.__weak && !rlTick('dev|' + dev.id, db.rlDevPerMin, 60e3)) {
      dev.blocked = (dev.blocked || 0) + 1;
      dev.rl = (dev.rl || 0) + 1;
      MET.rl++; MET.rlDev++; saveDbLazy(); return tooFast(res);
    }
    // 没有任何设备标识的（老包、curl、脚本）单独一档更严的额度
    if (req.__weak && !rlTick('anon|' + ip0, db.rlAnonPerMin, 60e3)) {
      MET.rl++; MET.rlAnon++; saveDbLazy(); return tooFast(res);
    }
  }

  /* 未授权设备：这笔请求要是真成功返回了，就记一次；累计满额自动拉黑（设备 + IP） */
  if (dev && dev.status !== 'ok') autoBlkWatch(res, dev, ip0);

  const hostHeader = String(req.headers.host || '').split(':')[0].toLowerCase();
  const hostSub = hostHeader.split('.')[0];
  const localPort = req.socket.localPort;
  // 优先按端口认上游（IP 直连），其次按 Host 首段（有域名时），最后默认 api
  let sub = PORT_UPSTREAM[localPort]
    || (UPSTREAM[hostSub] ? hostSub : '')
    || 'api';
  // 80 端口没有域名信息，按路径把 app 那几条配置类接口挑出来
  if (localPort === DEFAULT_PORT && APP_PATH_RE.test(String(req.url || ''))) sub = 'app';
  // 登录接口只认 passport 子域：api / app 上游对 /x/passport-tv-login/* 一律返回 HTML 404 页，
  // 盒子拿到非 JSON 就当成拿不到 token，直接弹「登录错误:-101」。这里强制改道。
  if (/^\/x\/passport(-tv)?-login(\/|\?|$)/i.test(String(req.url || ''))) sub = 'passport';
  const target = UPSTREAM[sub] || UPSTREAM.api;

  const headers = Object.assign({}, req.headers);
  delete headers.host;
  delete headers['content-length'];
  headers.host = target;
  delete headers.cookie;
  delete headers.referer;
  /* 设备令牌已下线：老客户端可能还带着令牌头，别往上游透传 */
  delete headers['x-relay-token'];
  delete headers['x-dev-token'];

  const mode = db.shareMode || 'off';
  const pathStr = String(req.url || '');
  const egress = egressOf(pathStr);
  // 最近请求留痕：面板/日志里能看清盒子到底问了哪些接口（排「还显示会员」这类问题用）
  db.recent = db.recent || [];
  const PROBE = /\/x\/tv\/(card\/feed|index\/|modpage)/i.test(String(req.url || ''));
  if (PROBE) { try { const f = '/tmp/rec.log'; try { if (require('fs').statSync(f).size > 1024 * 1024) require('fs').writeFileSync(f, ''); } catch (e0) {} require('fs').appendFileSync(f, 'Q ' + Date.now() + ' ' + req.method + ' ' + redactUrl(req.url).slice(0,2500) + '\n'); } catch (e) {} }
  db.recent.unshift({ t: Date.now(), h: sub, p: pathStr.split('?')[0].slice(0, 80) });
  if (db.recent.length > 4000) db.recent.length = 4000;
  saveDbLazy();

  // stealth：身份类接口一律用「游客」身份转发，上游自然返回未登录体，盒子界面看不到会员号
  // 注意 TV 端（云视听）身份接口是 /x/tv/account/*、/x/tv/mine/*、/x/tv/svip/* 这一整套，和网页端完全不同，必须一起盖住
  const IDENT_RE = /(\/x\/tv\/(account|mine|svip|guest|fission|follow|favorites|fav|history|dynamic|booking|exit|background\/half_login|cheese\/my|medal|vip|coin|relation|personal_center)|\/x\/(v2|v3|v1)\/(account|member|medal|history|fav|follow|coin|relation|dynamic)|\/x\/member\/web|\/x\/vip|\/x\/space\/(myinfo|history|fav|coin|dynamic|bangumi)|web-interface\/nav|account\/mine|member\/info|passport\/login\/info|\/account(\/|\?|$)|user_info|myinfo|medal|svip|space\/myinfo|\/x\/dm\/filter|\/x\/dm\/up\/banned)/i;
  const stealthIdent = mode === 'stealth' && IDENT_RE.test(pathStr);
  // 云视听「我的/会员中心」是 H5 网页页面，不是 JSON 接口：页面里直接渲染昵称+大会员有效期，
  // 所以凡是 HTML 请求、或命中会员/账号子域，一律不注入任何账号，让它按游客渲染
  const accept = String(req.headers.accept || '');
  const isHtmlReq = /text\/html/i.test(accept) || /\.(x?html?|htm)$/i.test(pathStr.split('?')[0]);
  const isIdentHost = sub === 'member' || sub === 'account' || sub === 'passport';
  // 解析只靠 api 域名：账号只在这一个域名上传，app/passport/account/bangumi/member 一律游客转发
  // 这样 app 那些「我的/会员中心/配置」页面天然拿不到会员身份，盒子不可能显示会员号
  const accountHost = sub === 'api';
  const FEED_PATH = /\/x\/tv\/(card\/feed(_v2|_ogv|_kid)?|index\/(ugc|v2)|feed)/i.test(pathStr.split('?')[0]);
  const noAccount = FEED_PATH || (mode === 'stealth' && !accountHost) || stealthIdent || isHtmlReq || isIdentHost;

  // 盒子自己带的账号 Cookie（历史遗留的 SESSDATA 等）在 stealth 下一律剥掉，绝不透传给上游
  let clientCookie = String(req.headers.cookie || '');
  if (mode === 'stealth') clientCookie = stripAuthCookies(clientCookie);
  if (noAccount) clientCookie = '';

  const acc = (mode === 'off' || noAccount) ? null : pickAccount(dev);
  if (acc && acc.cookie) {
    headers.cookie = clientCookie ? clientCookie + '; ' + acc.cookie : acc.cookie;
  } else if (clientCookie) {
    headers.cookie = clientCookie;
  }
  if (noAccount) delete headers.cookie;
  // 探测：stealth 下还有哪些接口把用户名吐出来（写进后台日志，便于补漏）
  headers['x-bili-relay-mode'] = mode;
  if (process.env.RELAY_DEBUG) console.log('[proxy]', pathStr.split('?')[0], 'mode=' + mode, 'ident=' + (stealthIdent ? 'y' : 'n'), 'cookie=' + (headers.cookie ? 'y' : 'n'));

  const st = statToday();
  st.req++;

  // 注入账号时必须压掉客户端自带的 access_key，否则上游按盒子登录的那个号认证，池号 Cookie 形同虚设
  let fwdUrl = req.url;
  // access_key 只在「取流」链路上压制：画质只由 playurl 决定，剥掉它就能保证走池号 4K。
  // 其它接口（推荐流 / 登录 / VIP 二维码 / 账号）一旦把 access_key 剥掉，上游认不出身份，
  // 直接回 -400 或 -101 —— 盒子那边就是「加载失败」「登录错误 101」。
  const QUALITY_PATH = PLAYURL_RE.test(String(req.url || '').split('?')[0]);
  if (mode !== 'off' && QUALITY_PATH) {
    fwdUrl = stripAccessKey(fwdUrl);
    // 请求头里的鉴权字段一并清掉（部分客户端把 access_key 塞在头里）
    Object.keys(headers).forEach((k) => {
      if (/^(x-access-?key|access-?key|authorization)$/i.test(k)) delete headers[k];
    });
  }
  fwdUrl = applyQuality(fwdUrl);

  /* ---- 接口缓存（6）---- */
  const barePath = pathStr.split('?')[0];
  const isGet = req.method === 'GET' || req.method === 'HEAD';
  const clientHasAuth = /(^|[?&])(access_key|accessKey)=/i.test(pathStr || '')
    || /(^|;)\s*(SESSDATA|DedeUserID)=/i.test(String(req.headers.cookie || ''));
  const cacheable = db.cacheOn !== false && isGet && CACHEABLE_RE.test(barePath)
    && !NO_CACHE_RE.test(barePath) && !clientHasAuth && !isHtmlReq;
  const ck = cacheable ? cacheKeyOf(sub + '|' + egress.area, req.url) : '';
  if (cacheable) {
    const hit = cacheGet(ck);
    if (hit) {
      MET.cacheHit++;
      st.ok++;
      try { if (DIAG_RE.test(barePath)) diagWrite('CACHE p=' + barePath + ' dev=' + String((dev&&dev.id)||'-') + ' st=' + String((dev&&dev.status)||'-') + ' ip=' + ip0); } catch (e0) {}
      const hh = Object.assign({}, hit.headers, { 'X-Relay-Cache': 'hit' });
      try { res.writeHead(hit.status, hh); return res.end(hit.body); } catch (e) { /* ignore */ }
    }
    MET.cacheMiss++;
  }

  /* ---- 单个 Cookie 号取流限流：一个号被刷爆，最先倒霉的是池子里的号 ---- */
  if (db.rlOn !== false && PLAYURL_RE.test(barePath) && acc && acc.id) {
    if (!rlTick('acc|' + acc.id, db.rlAccPerHour, 3600e3)) {
      MET.rl++; MET.rlAcc++;
      saveDbLazy();
      return tooFast(res);
    }
  }

  /* ---- 取流：4K 拉不到自动退 1080（10）---- */
  if (PLAYURL_RE.test(barePath)) {
    return handlePlayurl(req, res, { target, headers, fwdUrl, mode, pathStr, st, acc, agent: egress.agent, proxyUrl: egress.proxyUrl }).catch((e) => {
      try {
        if (!res.headersSent) {
          res.writeHead(502, { 'Content-Type': 'application/json; charset=utf-8' });
          res.end(JSON.stringify({ code: -502, message: 'relay error: ' + safeProxyError(e, egress.proxyUrl) }));
        } else res.end();
      } catch (_) { /* ignore */ }
    });
  }

  const t0 = Date.now();

  const preq = https.request(
    { host: target, port: UPSTREAM_PORT, path: fwdUrl, method: req.method, headers, servername: target, rejectUnauthorized: false, agent: egress.agent, timeout: 25000 },
    (pres) => {
      metLat(Date.now() - t0);
      metResult(pres.statusCode >= 200 && pres.statusCode < 400);
      if (pres.statusCode >= 200 && pres.statusCode < 400) {
        st.ok++;
        db.lastOk = Date.now();
      }
      const ct = String(pres.headers['content-type'] || '');
      const len = parseInt(pres.headers['content-length'] || '0', 10);
      const isBin = /^(video|audio|image|font|application\/octet-stream|application\/zip)/i.test(ct);
      const doClean = mode === 'stealth' && !isBin && (!len || len < 3 * 1024 * 1024);
      // 要缓存的响应必须整块读下来再回，才能存住净化后的那一版
      const doBuffer = doClean || cacheable;
      if (!doBuffer) {
        try { if (DIAG_RE.test(barePath)) diagWrite('RESP p=' + barePath + ' up=' + pres.statusCode + ' len=' + String(pres.headers['content-length']||'?') + ' ms=' + (Date.now()-t0) + ' dev=' + String((dev&&dev.id)||'-') + ' st=' + String((dev&&dev.status)||'-') + ' ip=' + ip0); } catch (e0) {}
        const ph = Object.assign({}, pres.headers);
        if (mode === 'stealth') { const sc = filterSetCookie(ph['set-cookie']); if (sc && sc.length) ph['set-cookie'] = sc; else delete ph['set-cookie']; }
        res.writeHead(pres.statusCode, ph);
        return pres.pipe(res);
      }
      // stealth 兜底：任何接口都不许告诉盒子"已登录"；顺手探测漏网的用户名字段
      const chunks = [];
      let ptx = null;
      pres.on('data', (c) => chunks.push(c));
      pres.on('end', () => {
        const orig = Buffer.concat(chunks);
        let out = orig;
        const ce = String(pres.headers['content-encoding'] || '').toLowerCase();
        if (doClean) {
          try {
            let raw = orig;
            if (ce.indexOf('gzip') !== -1) raw = zlib.gunzipSync(orig);
            else if (ce.indexOf('deflate') !== -1) raw = zlib.inflateSync(orig);
            else if (ce.indexOf('br') !== -1) raw = zlib.brotliDecompressSync(orig);
            let s = raw.toString('utf8');
            // 往返编码不一致 = 不是干净 UTF-8 文本，直接原样透传，绝不改写
            if (Buffer.compare(Buffer.from(s, 'utf8'), raw) !== 0) throw new Error('non-utf8');
            const before = s;
            const isContent = /(view|playurl|player|feed|card|space|search|season|pgc|bangumi|dynamic|reply|danmaku)/i.test(pathStr);
            const idn = acc || (db.accounts || [])[0] || null;
            if (idn && idn.name && before.indexOf(String(idn.name)) !== -1) probeLeak(pathStr);
            s = scrubIdentity(s, idn, isContent);
            ptx = s;
            if (PROBE && s.charCodeAt(0) === 123) { try { const _j = JSON.parse(s); if (_j && _j.code !== undefined && _j.code !== 0) require('fs').appendFileSync('/tmp/rec.log', 'E ' + Date.now() + ' code=' + _j.code + ' msg=' + String(_j.message || '').slice(0,60) + ' len=' + s.length + ' p=' + redactUrl(pathStr).slice(0,260) + '\n'); } catch (e2) {} }
            const plain = Buffer.from(s, 'utf8');
            if (ce.indexOf('gzip') !== -1) out = zlib.gzipSync(plain);
            else if (ce.indexOf('deflate') !== -1) out = zlib.deflateSync(plain);
            else if (ce.indexOf('br') !== -1) out = zlib.brotliCompressSync(plain);
            else out = plain;
          } catch (e) {
            out = orig; // 解压或改写失败一律原样透传，绝不把响应写坏
          }
        }
        if (PROBE && ptx === null) { try { require('fs').appendFileSync('/tmp/rec.log', 'N ' + Date.now() + ' up=' + pres.statusCode + ' ct=' + String(pres.headers['content-type']||'').slice(0,30) + ' len=' + out.length + ' p=' + redactUrl(pathStr).slice(0,200) + '\n'); } catch (e3) {} }
        const hh = Object.assign({}, pres.headers);
        delete hh['content-length'];
        delete hh['transfer-encoding'];
        if (mode === 'stealth') {
          const sc2 = filterSetCookie(hh['set-cookie']);
          if (sc2 && sc2.length) hh['set-cookie'] = sc2; else delete hh['set-cookie'];
        }
        hh['content-length'] = out.length;
        try { if (out && out.length && out[0] === 0x7b) { const _j = JSON.parse(out.toString('utf8')); if (_j && _j.code !== undefined && _j.code !== 0) require('fs').appendFileSync('/tmp/bad.log', Date.now() + ' p=' + barePath + ' up=' + pres.statusCode + ' code=' + _j.code + ' msg=' + String(_j.message || '').slice(0, 50) + ' dev=' + String((dev && dev.id) || '-') + ' ip=' + ip0 + ' auth=' + (pathStr.indexOf('access_key') >= 0 ? 'y' : 'n') + '\n'); } } catch (e) {}
        try { if (pres.statusCode >= 400) require('fs').appendFileSync('/tmp/bad.log', Date.now() + ' p=' + barePath + ' upstatus=' + pres.statusCode + ' dev=' + String((dev && dev.id) || '-') + ' ip=' + ip0 + '\n'); } catch (e) {}
        if (cacheable && pres.statusCode >= 200 && pres.statusCode < 400) {
          const saveH = Object.assign({}, hh);
          delete saveH['set-cookie'];
          cacheSet(ck, pres.statusCode, saveH, out);
        }
        try { if (DIAG_RE.test(barePath)) { let _c=''; try { const _j=JSON.parse(out.toString('utf8')); _c=' code=' + _j.code; } catch(e9) {} diagWrite('RESP p=' + barePath + ' up=' + pres.statusCode + ' len=' + out.length + ' ms=' + (Date.now()-t0) + ' dev=' + String((dev&&dev.id)||'-') + ' st=' + String((dev&&dev.status)||'-') + ' ip=' + ip0 + _c); } } catch (e0) {}
        res.writeHead(pres.statusCode, hh);
        res.end(out);
      });
      pres.on('error', () => { try { res.end(); } catch (e) { /* ignore */ } });
    }
  );
  preq.on('timeout', () => preq.destroy(new Error('upstream timeout')));
  preq.on('error', (e) => {
    metResult(false);
    const safeErr = safeProxyError(e, egress.proxyUrl);
    try { diagWrite('UPERR sub=' + sub + ' p=' + String(req.url||'').split('?')[0] + ' dev=' + String((dev&&dev.id)||'-') + ' ip=' + ip0 + ' err=' + safeErr); } catch (e0) {}
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'application/json; charset=utf-8' });
      res.end(JSON.stringify({ code: -502, message: 'relay error: ' + safeErr }));
    } else res.end();
  });
  // 表单体里也可能夹带 access_key（登录类客户端会把鉴权放表单），一并剥掉
  const reqCt = String(req.headers['content-type'] || '');
  if (mode !== 'off' && QUALITY_PATH && /application\/x-www-form-urlencoded/i.test(reqCt)) {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => { size += c.length; if (size <= 1024 * 1024) chunks.push(c); });
    req.on('end', () => {
      let b = Buffer.concat(chunks).toString('utf8');
      if (/access_?key=/i.test(b)) {
        try {
          const p = new URLSearchParams(b);
          const hadSign = p.has('sign');
          if (hadSign) stripAccessKeyParams(p);
          else ['access_key', 'accessKey', 'access-key'].forEach((k) => p.delete(k));
          b = p.toString();
        } catch (e) { /* 改不动就原样发 */ }
      }
      preq.end(b);
    });
    req.on('error', () => { try { preq.destroy(); } catch (e) {} });
    return;
  }
  req.pipe(preq);
}

/* ---------------- 后台 API ---------------- */
function readBody(req) {
  return new Promise((resolve) => {
    let n = 0;
    const chunks = [];
    req.on('data', (c) => {
      n += c.length;
      if (n > 2 * 1024 * 1024) { req.destroy(); resolve({}); return; }
      chunks.push(c);
    });
    req.on('end', () => {
      try { resolve(JSON.parse(Buffer.concat(chunks).toString() || '{}')); } catch (e) { resolve({}); }
    });
    req.on('error', () => resolve({}));
  });
}
function authed(req) {
  const c = parseCookie(req.headers.cookie || '');
  const tok = c.bili_relay_sid;
  const exp = tok && sessions.get(tok);
  return !!(exp && exp > Date.now());
}

const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'application/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.png': 'image/png', '.svg': 'image/svg+xml' };

function handleStatus(req, res, url) {
  if (req.method !== 'GET' && req.method !== 'HEAD') return json(res, 405, { ok: false, msg: 'method not allowed' });
  if (url.pathname === '/status-api') {
    const body = Buffer.from(JSON.stringify(buildPublicStatus(db, metStats(), os.uptime())));
    res.writeHead(200, {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Length': body.length,
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
    });
    return req.method === 'HEAD' ? res.end() : res.end(body);
  }
  const body = fs.readFileSync(path.join(PUBLIC, 'status.html'));
  res.writeHead(200, {
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Length': body.length,
    'Cache-Control': 'no-cache',
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
  });
  return req.method === 'HEAD' ? res.end() : res.end(body);
}

async function handlePanel(req, res, url) {
  const p = url.pathname;

  /* 设备令牌机制已下线，接口一并撤掉 */
  if (p === '/relay-api/token') return json(res, 404, { ok: false, msg: 'not found' });

  if (p === '/auth' || p === '/auth/') {
    const f = path.join(PUBLIC, 'auth.html');
    const body = fs.readFileSync(f);
    res.writeHead(200, { 'Content-Type': MIME['.html'], 'Content-Length': body.length });
    return res.end(body);
  }
  if (p === '/auth-api/app') {
    const ip = clientIp(req);
    const did = normDid(url.searchParams.get('did') || '');
    const model = String(url.searchParams.get('m') || '').trim();
    const mac = normMac(url.searchParams.get('mac') || '');
    if (mac || did) bindIpMac(ip, mac, did);
    const me = touchDevice({
      headers: { 'cf-connecting-ip': ip, 'user-agent': model || req.headers['user-agent'] || '', 'x-dev-id': did, 'x-dev-mac': mac },
      socket: { remoteAddress: ip }, url: '/auth-api/app',
    });
    if (!me) {
      return json(res, 200, { ok: true, auth: false, status: 'unknown', unknown: true, gate: db.gateOn !== false, authMode: db.authMode || 'self', msg: '这台设备没有上报设备信息' });
    }
    if (did) {
      me.dids = me.dids || [];
      if (me.dids.indexOf(did) < 0) me.dids.push(did);
      me.did = me.did || did;
    }
    if (model && model.toLowerCase() !== 'unknown') { me.model = model.slice(0, 28); me.name = me.model; }
    saveDbLazy();
    const body = Buffer.from(JSON.stringify({
      ok: true,
      auth: me.status === 'ok',
      status: me.status,
      code: me.code,
      mac: me.mac || mac || '',
      gate: db.gateOn !== false,
      authMode: db.authMode || 'self',
    }));
    res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Content-Length': body.length, 'Cache-Control': 'no-store' });
    return res.end(body);
  }
  if (p === '/auth-api/status') {
    const __blk = blkCheck(req, clientIp(req));
    if (__blk) return json(res, 200, { ok: false, blocked: true, msg: '此设备已被管理员停用，如需恢复请联系管理员' });
    const ip = clientIp(req);
    const ua = String(req.headers['user-agent'] || '');
    const macQ = normMac(url.searchParams.get('mac') || '') || normMac(req.headers['x-dev-mac'] || '');
    let did = normDid(url.searchParams.get('did') || '') || normDid(req.headers['x-dev-id'] || '');
    let mac = macQ;
    /* 浏览器打开授权页：浏览器没有自己的身份，也不单独建档。
     * 只按「同一个网络（出口 IP）」找回这台电视上报过的 MAC / android_id，认回那台电视。 */
    if (!mac && !did) {
      const tv = lanTv(ip);
      if (tv) {
        mac = normMac(tv.mac || '') || normMac((tv.macs || [])[0] || '');
        did = normDid(tv.did || '') || normDid((tv.dids || [])[0] || '');
        if (did && /^web/i.test(did)) did = '';
      }
      if (!mac && !did) {
        return json(res, 200, {
          ok: true, known: false, ip, me: null, same: [],
          gateOn: db.gateOn, authMode: db.authMode || 'self', authUrl: authUrlOf(),
          msg: '这个网络下没有登记过的电视，请在电视上用 APP 打开授权页',
        });
      }
    }
    const me = touchDevice({
      headers: { 'cf-connecting-ip': ip, 'user-agent': ua, 'x-dev-id': did, 'x-dev-mac': mac },
      socket: { remoteAddress: ip }, url: '/auth-api/status',
    });
    saveDbLazy();
    if (!me) {
      // 老包/拿不到 MAC 时的兜底：这个 IP 上只登记过一台真实设备，就认为就是它（不新建记录）
      const only = lanTv(ip);
      if (only && (only.mac || only.did || (only.macs || []).length || (only.dids || []).length)) {
        return json(res, 200, {
          ok: true, known: true, approx: true, ip,
          me: publicDev(only), same: [],
          gateOn: db.gateOn, authMode: db.authMode || 'self', authUrl: authUrlOf(),
        });
      }
      // 同网络下没有电视：不凭空造记录，只做提示
      return json(res, 200, {
        ok: true, known: false, ip, me: null, same: [],
        gateOn: db.gateOn, authMode: db.authMode || 'self', authUrl: authUrlOf(),
        msg: '这个网络下没有登记过的电视，请在电视上用 APP 打开授权页',
      });
    }
    const same = db.devices.filter((d) => !d.orphan && d.id !== me.id && d.ip === ip).map(publicDev);
    return json(res, 200, { ok: true, known: true, ip, me: publicDev(me), same, gateOn: db.gateOn, authMode: db.authMode || 'self', authUrl: authUrlOf() });
  }
  if (p === '/auth-api/self') {
    const __blk = blkCheck(req, clientIp(req));
    if (__blk) return json(res, 200, { ok: false, blocked: true, msg: '此设备已被管理员停用，如需恢复请联系管理员' });
    const b = await readBody(req);
    const ip = clientIp(req);
    let mac = normMac(b.mac || '') || normMac(req.headers['x-dev-mac'] || '');
    let did = normDid(b.did || '') || normDid(req.headers['x-dev-id'] || '');
    /* 同上：浏览器不自建身份，按同一个网络下的电视认 */
    if (!mac && !did) {
      const tv = lanTv(ip);
      if (tv) {
        mac = normMac(tv.mac || '') || normMac((tv.macs || [])[0] || '');
        did = normDid(tv.did || '') || normDid((tv.dids || [])[0] || '');
        if (did && /^web/i.test(did)) did = '';
      }
    }
    const me = touchDevice({
      headers: {
        'cf-connecting-ip': ip, 'user-agent': String(req.headers['user-agent'] || ''),
        'x-dev-id': did, 'x-dev-mac': mac,
      },
      socket: { remoteAddress: ip }, url: '/auth-api/self',
    });
    if (!me) {
      return json(res, 200, { ok: false, msg: '认不出这台电视，请在电视上用 APP 重新打开授权页' });
    }
    if (db.authMode === 'manual') {
      return json(res, 200, { ok: false, msg: '自助授权没有开启，请让管理员在后台放行' });
    }
    if (me.status === 'deny') {
      return json(res, 200, { ok: false, msg: '这台设备被管理员拒绝了，联系管理员处理' });
    }
    const now = Date.now();
    // 同一 IP 连续输错 5 次锁 10 分钟，防瞎猜
    if (!db.selfFails) db.selfFails = {};
    const f = db.selfFails[ip] || { n: 0, until: 0 };
    if (f.until > now) {
      return json(res, 200, { ok: false, msg: '试太多次了，' + Math.ceil((f.until - now) / 60000) + ' 分钟后再试' });
    }
    const code = String(b.code || '').trim();
    if (!code || code !== String(db.selfCode || '')) {
      f.n = (f.n || 0) + 1;
      if (f.n >= 5) { f.until = now + 10 * 60000; f.n = 0; }
      db.selfFails[ip] = f;
      saveDb();
      return json(res, 200, { ok: false, msg: '授权码不对，再看看电视上的 6 位数字' });
    }
    delete db.selfFails[ip];
    // 只放行这台设备本身（按 MAC / android_id 认），不再把同 IP 的设备一起放开
    let granted = 0;
    if (me.status !== 'ok') { me.status = 'ok'; me.actAt = now; me.selfAt = now; me.okReq = 0; delete me.autoBlk; granted++; }
    else { me.actAt = now; }
    log('device', '自助授权通过：' + me.name + ' (' + (me.mac ? 'MAC ' + me.mac : 'did ' + (me.did || '?')) + ')');
    saveDb();
    return json(res, 200, { ok: true, status: 'ok', code: me.code, granted });
  }

  if (p === '/panel' || p === '/panel/' || p === '/') {
    const f = path.join(PUBLIC, 'index.html');
    const body = fs.readFileSync(f);
    res.writeHead(200, { 'Content-Type': MIME['.html'], 'Content-Length': body.length });
    return res.end(body);
  }
  if (p.startsWith('/panel/assets/')) {
    const name = path.basename(p);
    const f = path.join(PUBLIC, name);
    if (!fs.existsSync(f)) { res.writeHead(404); return res.end('not found'); }
    const body = fs.readFileSync(f);
    res.writeHead(200, { 'Content-Type': MIME[path.extname(f)] || 'application/octet-stream', 'Content-Length': body.length });
    return res.end(body);
  }

  if (p === '/panel-api/login') {
    const b = await readBody(req);
    const rip = clientIp(req);
    const waitMs = loginLockLeft(rip);
    if (waitMs > 0) {
      const min = Math.max(1, Math.ceil(waitMs / 60000));
      const last = LOGIN_LASTLOG.get(rip) || 0;
      if (Date.now() - last > 60000) {
        LOGIN_LASTLOG.set(rip, Date.now());
        log('panel', '登录仍在锁定中，有人还在试密码：' + rip);
      }
      return json(res, 200, { ok: false, msg: '尝试次数过多，请 ' + min + ' 分钟后再试' });
    }
    if (hashPass(b.password || '') === db.passHash) {
      loginOk(rip);
      const tok = crypto.randomBytes(16).toString('hex');
      sessions.set(tok, Date.now() + 7 * 864e5);
      res.writeHead(200, { 'Content-Type': 'application/json', 'Set-Cookie': 'bili_relay_sid=' + tok + '; Path=/; HttpOnly; Max-Age=604800; SameSite=Lax' });
      return res.end(JSON.stringify({ ok: true }));
    }
    const justLocked = loginFail(rip);
    log('panel', justLocked ? ('面板密码连续错 5 次，已锁定 10 分钟：' + rip) : ('面板密码错误：' + rip));
    return json(res, 200, { ok: false, msg: justLocked ? '密码错误次数过多，已锁定 10 分钟' : '密码不对' });
  }

  if (p === '/panel-api/logout') {
    const c0 = parseCookie(req.headers.cookie || '');
    if (c0.bili_relay_sid) sessions.delete(c0.bili_relay_sid);
    res.writeHead(200, { 'Content-Type': 'application/json', 'Set-Cookie': 'bili_relay_sid=; Path=/; HttpOnly; Max-Age=0; SameSite=Lax' });
    return res.end(JSON.stringify({ ok: true }));
  }

  if (!authed(req)) return json(res, 200, { ok: false, needLogin: true });

  if (p === '/panel-api/password') {
    const b = await readBody(req);
    const oldP = String(b.old == null ? '' : b.old);
    const next = String(b.next == null ? '' : b.next);
    if (!oldP) return json(res, 200, { ok: false, msg: '请输入当前密码' });
    if (!next) return json(res, 200, { ok: false, msg: '请输入新密码' });
    if (hashPass(oldP) !== db.passHash) return json(res, 200, { ok: false, msg: '当前密码不对' });
    if (next.length < 6) return json(res, 200, { ok: false, msg: '新密码至少 6 位' });
    if (next.length > 64) return json(res, 200, { ok: false, msg: '新密码最多 64 位' });
    if (hashPass(next) === db.passHash) return json(res, 200, { ok: false, msg: '新密码不能和当前密码一样' });
    db.salt = crypto.randomBytes(16).toString('hex');
    db.passHash = hashPass(next);
    saveDb();
    const curSid = parseCookie(req.headers.cookie || '').bili_relay_sid;
    Array.from(sessions.keys()).forEach((k) => { if (k !== curSid) sessions.delete(k); });
    try {
      fs.writeFileSync(path.join(ROOT, 'admin-password.txt'),
        '后台密码已于 ' + new Date().toLocaleString('zh-CN', { hour12: false }) + ' 在后台被修改，本文件不再保存明文密码。\n' +
        '忘记密码：停服后删除 data.json 里的 salt 和 passHash 两个字段，再启动服务，会重新生成一个随机密码并写回本文件。\n',
        { mode: 0o600 });
    } catch (e) { /* 忽略：写不进去不影响改密 */ }
    log('panel', '管理员密码已修改（其他设备的登录已失效）');
    return json(res, 200, { ok: true, msg: '密码已更新' });
  }

  if (p === '/panel-api/proxy') {
    if (req.method === 'POST') {
      const b = await readBody(req);
      try {
        const current = normalizeProxyConfig(db.egressProxy || {});
        const merged = Object.assign({}, current);
        if (typeof b.enabled === 'boolean') merged.enabled = b.enabled;
        ['cn', 'hk', 'tw', 'th', 'default'].forEach((k) => {
          if (!Object.prototype.hasOwnProperty.call(b, k)) return;
          merged[k] = b[k] == null ? '' : String(b[k]);
        });
        const next = normalizeProxyConfig(merged);
        db.egressProxy = next;
        cacheClear();
        const configured = ['cn', 'hk', 'tw', 'th', 'default'].filter((k) => !!next[k]);
        log('proxy', '代理出口设置已更新：' + (next.enabled ? '开启' : '关闭') + ' · 已配置 ' + (configured.join('/') || '无'));
        saveDb();
      } catch (e) {
        return json(res, 200, { ok: false, msg: e.message });
      }
    }
    const cfg = normalizeProxyConfig(db.egressProxy || {});
    const entries = {};
    ['cn', 'hk', 'tw', 'th', 'default'].forEach((k) => {
      entries[k] = { configured: !!cfg[k], display: redactProxyUrl(cfg[k]) };
    });
    return json(res, 200, { ok: true, enabled: cfg.enabled, entries });
  }
  if (p === '/panel-api/proxy/test') {
    const b = await readBody(req);
    const area = ['cn', 'hk', 'tw', 'th', 'default'].includes(String(b.area)) ? String(b.area) : 'default';
    const cfg = normalizeProxyConfig(db.egressProxy || {});
    const proxyUrl = proxyForRequest('/?area=' + area, cfg);
    try {
      const probes = [
        'https://ifconfig.me/ip',
        'https://ipinfo.io/ip',
        'https://myip.ipip.net',
      ];
      let ip = '', lastError = null;
      for (const probe of probes) {
        try {
          const r = await requestUrlBuffered(probe, { areaPath: '/?area=' + area, timeout: 12000, maxBytes: 65536 });
          const text = r.body.toString('utf8');
          const hit = text.match(/(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9a-f]{0,4}:){2,}[0-9a-f:]+/i);
          if (r.status >= 200 && r.status < 300 && hit) { ip = hit[0]; break; }
        } catch (e) { lastError = e; }
      }
      if (!ip) throw lastError || new Error('出口 IP 检测失败');
      return json(res, 200, {
        ok: true,
        area,
        ip,
        mode: proxyUrl ? 'proxy' : 'direct',
        proxy: redactProxyUrl(proxyUrl),
      });
    } catch (e) {
      return json(res, 200, { ok: false, area, mode: proxyUrl ? 'proxy' : 'direct', proxy: redactProxyUrl(proxyUrl), msg: e.message });
    }
  }
  if (p === '/panel-api/overview') {
    const st = statToday();
    return json(res, 200, {
      ok: true,
      today: st.req,
      todayOk: st.ok,
      accounts: db.accounts.length,
      valid: db.accounts.filter((a) => a.valid !== false).length,
      lastOk: db.lastOk,
      devices: db.devices.length,
      pending: db.devices.filter((d) => d.status === 'pending').length,
      gateOn: db.gateOn !== false,
      qualityMode: db.qualityMode || '4k',
      shareMode: db.shareMode || 'off',
      stats: db.stats,
    });
  }
  if (p === '/panel-api/metrics') {
    const counts = {};
    Object.values(db.accMap || {}).forEach((id) => { counts[id] = (counts[id] || 0) + 1; });
    return json(res, 200, {
      ok: true,
      metrics: metStats(),
      cache: cacheStats(),
      accountMode: db.accountMode || 'device',
      qualityMode: db.qualityMode || '4k',
      accounts: db.accounts.map((a) => ({
        id: a.id, name: cleanLabel(a.name), valid: a.valid !== false, vip: !!a.vip,
        vipDue: a.vipDue || 0,
        daysLeft: a.vipDue ? Math.ceil((a.vipDue - Date.now()) / 864e5) : null,
        devices: counts[a.id] || 0,
      })),
    });
  }
  if (p === '/panel-api/cache') {
    const b = await readBody(req);
    if (typeof b.on === 'boolean') db.cacheOn = b.on;
    if ([60, 300, 600, 900].indexOf(Number(b.ttl)) >= 0) db.cacheTtl = Number(b.ttl);
    if (b.clear) cacheClear();
    log('cache', '接口缓存 ' + (db.cacheOn ? '开启' : '关闭') + ' · ' + db.cacheTtl + 's' + (b.clear ? ' · 已清空' : ''));
    saveDb();
    return json(res, 200, { ok: true, cache: cacheStats() });
  }
  if (p === '/panel-api/accountmode') {
    const b = await readBody(req);
    if (['device', 'rr'].indexOf(b.mode) >= 0) {
      db.accountMode = b.mode;
      db.accMap = {};
      log('account', '账号分配方式改为：' + (b.mode === 'device' ? '按设备固定分配' : '每次轮询'));
      saveDb();
    }
    return json(res, 200, { ok: true, mode: db.accountMode || 'device' });
  }
  if (p === '/panel-api/security') {
    if (req.method === 'POST') {
      const b = await readBody(req);
      ['rlOn', 'driftOn', 'driftAuto', 'gateBrowse'].forEach((k) => {
        if (b && typeof b[k] === 'boolean') db[k] = b[k];
      });
      const nums = {
        rlDevPerMin: [10, 100000], rlIpPerMin: [10, 100000], rlAnonPerMin: [10, 100000],
        rlAccPerHour: [10, 200000], driftSegMax: [2, 50],
      };
      Object.keys(nums).forEach((k) => {
        if (!b || b[k] === undefined || b[k] === '') return;
        const v = Number(b[k]);
        if (!isFinite(v)) return;
        db[k] = Math.min(nums[k][1], Math.max(nums[k][0], Math.round(v)));
      });
      normalizeSecurity();
      log('security', '防刷设置已更新：限流' + (db.rlOn ? '开' : '关')
        + ' · 设备 ' + db.rlDevPerMin + '/分 · IP ' + db.rlIpPerMin + '/分 · 裸请求 ' + db.rlAnonPerMin + '/分 · 单号取流 ' + db.rlAccPerHour + '/时');
      saveDb();
    }
    const susN = db.devices.filter((d) => !d.orphan && d.suspect).length;
    return json(res, 200, {
      ok: true,
      rlOn: db.rlOn !== false,
      rlDevPerMin: db.rlDevPerMin, rlIpPerMin: db.rlIpPerMin,
      rlAnonPerMin: db.rlAnonPerMin, rlAccPerHour: db.rlAccPerHour,
      driftOn: db.driftOn !== false, driftSegMax: db.driftSegMax, driftAuto: !!db.driftAuto,
      gateBrowse: db.gateBrowse !== false,
      suspect: susN,
      rlStats: { total: MET.rl, ip: MET.rlIp, dev: MET.rlDev, anon: MET.rlAnon, acc: MET.rlAcc },
    });
  }
  if (p === '/panel-api/devices/clearsuspect') {
    const b = await readBody(req);
    const d = db.devices.find((x) => x.id === b.id);
    if (d) {
      delete d.suspect;
      if (b.clearLog) IPLOG.delete(d.id);
      log('security', '已清除可疑标记：' + (d.name || d.code || ''));
      saveDb();
    }
    return json(res, 200, { ok: true });
  }
  if (p === '/panel-api/devices') {
    const showAll = url.searchParams.get('all') === '1';
    const real = db.devices.filter((d) => !d.orphan);
    const shown = showAll ? db.devices : real;
    return json(res, 200, {
      ok: true,
      gateOn: db.gateOn !== false,
      gateLevel: db.gateLevel || 'content',
      authMode: db.authMode || 'self',
      selfCode: db.selfCode || '',
      pending: real.filter((d) => d.status === 'pending').length,
      orphan: db.devices.filter((d) => d.orphan).length,
      total: real.length,
      list: shown.map(publicDev),
      authUrl: authUrlOf(),
    });
  }
  if (p === '/panel-api/devices/purge') {
    const n = db.devices.filter((d) => d.orphan).length;
    db.devices = db.devices.filter((d) => !d.orphan);
    log('device', '清理无标识的历史设备记录 ' + n + ' 条');
    saveDb();
    return json(res, 200, { ok: true, n });
  }
  /* 一键清理未授权设备：默认连「已拒绝」一起清，mode=pending 时只清待授权。
   * 已授权（status=ok）与隐藏的无效记录（orphan）都不动，orphan 另有单独按钮。 */
  if (p === '/panel-api/devices/clearunauth') {
    const b = await readBody(req).catch(() => ({}));
    const onlyPending = b && b.mode === 'pending';
    const kill = db.devices.filter((d) => !d.orphan && d.status !== 'ok'
      && (onlyPending ? d.status === 'pending' : true));
    const ids = new Set(kill.map((d) => d.id));
    const macs = new Set(), dids = new Set();
    kill.forEach((d) => {
      if (d.mac) macs.add(d.mac);
      (d.macs || []).forEach((m) => { if (m) macs.add(m); });
      if (d.did) dids.add(d.did);
      (d.dids || []).forEach((v) => { if (v) dids.add(v); });
    });
    const pend = kill.filter((d) => d.status === 'pending').length;
    const deny = kill.filter((d) => d.status === 'deny').length;
    db.devices = db.devices.filter((d) => !ids.has(d.id));
    /* 清掉 IP→标识 记忆里指向这些设备的残留，避免刚删完又被同一台认回去 */
    if (db.ipmac) {
      Object.keys(db.ipmac).forEach((k) => {
        const x = db.ipmac[k];
        if (!x) { delete db.ipmac[k]; return; }
        if ((x.mac && macs.has(x.mac)) || (x.did && dids.has(x.did))) delete db.ipmac[k];
      });
    }
    ids.forEach((id) => IPLOG.delete(id));
    log('device', '一键清理未授权设备 ' + kill.length + ' 条（待授权 ' + pend + ' · 已拒绝 ' + deny + '）');
    saveDb();
    return json(res, 200, { ok: true, n: kill.length, pending: pend, deny, left: db.devices.filter((d) => !d.orphan).length });
  }
  /* ---------------- 黑名单：IP / 设备标识 ---------------- */
  if (p === '/panel-api/blocks') {
    const ips = Object.keys(db.blockIp || {}).map((k) => Object.assign({ ip: k }, db.blockIp[k]));
    ips.sort((a, b) => (b.lastAt || b.at || 0) - (a.lastAt || a.at || 0));
    const devs = Object.keys(db.blockDev || {}).map((k) => Object.assign({ key: k }, db.blockDev[k]));
    devs.sort((a, b) => (b.lastAt || b.at || 0) - (a.lastAt || a.at || 0));
    return json(res, 200, {
      ok: true, ips, devs,
      auto: { on: db.autoBlkOn !== false, num: autoBlkTh(), ip: db.autoBlkIp !== false },
      autoPending: db.devices.filter((d) => !d.orphan && d.status !== 'ok' && (d.okReq || 0) > 0).length,
    });
  }
  if (p === '/panel-api/autoblk') {
    const b = await readBody(req).catch(() => ({}));
    if (b && typeof b.on === 'boolean') db.autoBlkOn = b.on;
    if (b && typeof b.ip === 'boolean') db.autoBlkIp = b.ip;
    if (b && b.num !== undefined && b.num !== '' && b.num !== null) {
      const v = Number(b.num);
      if (isFinite(v)) db.autoBlkNum = Math.min(1000000, Math.max(10, Math.round(v)));
    }
    normalizeSecurity();
    log('security', '未授权自动封禁：' + (db.autoBlkOn !== false ? '开' : '关')
      + ' · 阈值 ' + autoBlkTh() + ' 次 · ' + (db.autoBlkIp !== false ? '连 IP 一起封' : '只封设备'));
    saveDb();
    return json(res, 200, { ok: true, on: db.autoBlkOn !== false, num: autoBlkTh(), ip: db.autoBlkIp !== false });
  }
  if (p === '/panel-api/blocks/add') {
    const b = await readBody(req).catch(() => ({}));
    const note = String((b && b.note) || '').slice(0, 60);
    const now = Date.now();
    const out = { ip: 0, dev: 0 };
    const putIp = (raw) => {
      const ip = String(raw || '').trim().replace(/^::ffff:/, '');
      if (!/^[0-9a-fA-F:.]{3,45}$/.test(ip) || !/\d/.test(ip)) return false;
      db.blockIp = db.blockIp || {};
      const old = db.blockIp[ip];
      db.blockIp[ip] = {
        at: (old && old.at) || now, hits: (old && old.hits) || 0,
        lastAt: (old && old.lastAt) || 0, note: note || (old && old.note) || '',
      };
      out.ip++;
      return true;
    };
    const putDev = (type, raw) => {
      const val = type === 'mac' ? normMac(raw) : normDid(raw);
      if (!val) return false;
      db.blockDev = db.blockDev || {};
      const k = blkKey(type, val);
      const old = db.blockDev[k];
      if (!old) { db.blockDev[k] = { type, value: val, at: now, hits: 0, lastAt: 0, note }; out.dev++; }
      else if (note) old.note = note;
      return true;
    };
    /* 整台设备一起拉黑：它上报过的所有 MAC / 标识都进黑名单，顺带标成已拒绝 */
    const putDevice = (d, withIp) => {
      if (!d) return 0;
      let n = 0;
      [d.mac].concat(d.macs || []).filter(Boolean).forEach((v) => { if (putDev('mac', v)) n++; });
      [d.did].concat(d.dids || []).filter(Boolean).forEach((v) => { if (putDev('did', v)) n++; });
      if (withIp) [d.ip].concat(d.ips || []).filter(Boolean).forEach((v) => putIp(v));
      if (d.status !== 'deny') { d.status = 'deny'; d.actAt = now; }
      return n;
    };
    if (b.kind === 'ip') {
      if (!putIp(b.value)) return json(res, 200, { ok: false, msg: 'IP 填得不对' });
    } else if (b.kind === 'dev') {
      const raw = String(b.value || '').trim();
      const asMac = normMac(raw), asDid = normDid(raw);
      if (asMac) putDev('mac', asMac);
      else if (asDid) putDev('did', asDid);
      else return json(res, 200, { ok: false, msg: 'MAC / 设备标识格式不对' });
    } else if (b.kind === 'code') {
      const code = String(b.value || '').trim();
      const d = db.devices.find((x) => String(x.code || '') === code && !x.orphan);
      if (!d) return json(res, 200, { ok: false, msg: '没有设备码为 ' + code + ' 的设备' });
      if (!putDevice(d, !!b.withIp)) return json(res, 200, { ok: false, msg: '这台设备没上报过 MAC / 标识，请改用它当前的 IP 拉黑' });
    } else if (b.kind === 'device') {
      const d = db.devices.find((x) => x.id === b.id);
      if (!d) return json(res, 200, { ok: false, msg: '设备不存在' });
      if (!putDevice(d, !!b.withIp)) return json(res, 200, { ok: false, msg: '这台设备没上报过 MAC / 标识，请改用它当前的 IP 拉黑' });
    } else {
      return json(res, 200, { ok: false, msg: '类型不对' });
    }
    log('device', '加入黑名单：IP ' + out.ip + ' 条 · 设备标识 ' + out.dev + ' 条' + (note ? '（' + note + '）' : ''));
    saveDb();
    return json(res, 200, { ok: true, ip: out.ip, dev: out.dev });
  }
  if (p === '/panel-api/blocks/remove') {
    const b = await readBody(req).catch(() => ({}));
    let n = 0;
    if (b.key) {
      const k = String(b.key);
      if (k.indexOf('ip|') === 0) {
        const ip = k.slice(3);
        if (db.blockIp && db.blockIp[ip]) { delete db.blockIp[ip]; n++; }
      } else if (db.blockDev && db.blockDev[k]) { delete db.blockDev[k]; n++; }
    }
    if (b.kind === 'device' && b.id) {
      const d = db.devices.find((x) => x.id === b.id);
      if (d && db.blockDev) {
        const ks = [d.mac].concat(d.macs || []).filter(Boolean).map((v) => blkKey('mac', normMac(v)))
          .concat([d.did].concat(d.dids || []).filter(Boolean).map((v) => blkKey('did', normDid(v))));
        ks.forEach((k) => { if (k && db.blockDev[k]) { delete db.blockDev[k]; n++; } });
      }
    }
    log('device', '移出黑名单 ' + n + ' 条');
    // 手动移出后给这些设备一次重新计数的机会，否则它一发请求就又被自动封回去
    if (n) {
      db.devices.forEach((d) => {
        if (!d.autoBlk) return;
        const ks = [d.mac].concat(d.macs || []).filter(Boolean).map((v) => blkKey('mac', normMac(v)))
          .concat([d.did].concat(d.dids || []).filter(Boolean).map((v) => blkKey('did', normDid(v))));
        const left = ks.filter((k) => k && db.blockDev[k]).length;
        if (!left) { delete d.autoBlk; d.okReq = 0; }
      });
    }
    saveDb();
    return json(res, 200, { ok: true, n });
  }
  if (p === '/panel-api/authmode') {
    const b = await readBody(req);
    if (['manual', 'self', 'auto'].indexOf(b.mode) >= 0) db.authMode = b.mode;
    if (b.regen) db.selfCode = String(Math.floor(100000 + Math.random() * 900000));
    else if (b.code && /^\d{4,8}$/.test(String(b.code))) db.selfCode = String(b.code);
    const name = { manual: '手动放行', self: '自助授权码', auto: '新设备自动放行' }[db.authMode] || db.authMode;
    log('gate', '授权方式改为：' + name + (b.regen ? '（已换新自助码）' : ''));
    saveDb();
    return json(res, 200, { ok: true, mode: db.authMode, selfCode: db.selfCode || '' });
  }
  if (p === '/panel-api/devices/approve' || p === '/panel-api/devices/deny' || p === '/panel-api/devices/delete') {
    const b = await readBody(req);
    const act = p.split('/').pop();
    if (act === 'delete') {
      db.devices = db.devices.filter((d) => d.id !== b.id);
    } else {
      const d = db.devices.find((x) => x.id === b.id);
      if (!d) return json(res, 200, { ok: false, msg: '设备不存在' });
      d.status = act === 'approve' ? 'ok' : 'deny';
      d.actAt = Date.now();
      if (act === 'approve') { d.okReq = 0; delete d.autoBlk; }   // 放行后不再按未授权计数
      log('device', (act === 'approve' ? '放行' : '拒绝') + '设备 ' + d.name + ' (' + d.ip + ')');
    }
    saveDb();
    return json(res, 200, { ok: true });
  }
  if (p === '/panel-api/devices/approveall') {
    let n = 0;
    db.devices.forEach((d) => { if (!d.orphan && d.status === 'pending') { d.status = 'ok'; d.actAt = Date.now(); d.okReq = 0; delete d.autoBlk; n++; } });
    log('device', '批量放行 ' + n + ' 台设备');
    saveDb();
    return json(res, 200, { ok: true, n });
  }
  if (p === '/panel-api/devices/clear') {
    db.devices = db.devices.filter((d) => d.status === 'ok' && !d.orphan);
    saveDb();
    return json(res, 200, { ok: true });
  }
  if (p === '/panel-api/gate') {
    const b = await readBody(req);
    if (typeof b.on === 'boolean') db.gateOn = b.on;
    if (b.level === 'all' || b.level === 'content') db.gateLevel = b.level;
    log('gate', '授权闸 ' + (db.gateOn ? '开启' : '关闭') + ' · 级别 ' + db.gateLevel);
    saveDb();
    return json(res, 200, { ok: true, gateOn: db.gateOn, gateLevel: db.gateLevel });
  }
  if (p === '/panel-api/quality') {
    const b = await readBody(req);
    if (['4k', '1080', 'auto'].includes(b.mode)) {
      db.qualityMode = b.mode;
      const name = { '4k': '4K 优先（按最高画质取流）', '1080': '最高 1080P', auto: '跟随盒子客户端' }[b.mode];
      log('quality', '播放画质切换为：' + name);
      saveDb();
    }
    return json(res, 200, { ok: true, mode: db.qualityMode || '4k' });
  }
  if (p === '/panel-api/share') {
    const b = await readBody(req);
    if (['off', 'stealth', 'full'].includes(b.mode)) {
      db.shareMode = b.mode;
      const name = { off: '纯游客（不用任何账号）', stealth: '用账号但隐藏身份', full: '直接用账号（会显示会员号）' }[b.mode];
      log('share', '账号使用方式切换为：' + name);
      saveDb();
    }
    return json(res, 200, { ok: true, mode: db.shareMode || 'off' });
  }
  if (p === '/panel-api/accounts') {
    return json(res, 200, { ok: true, list: db.accounts.map(publicAcc) });
  }
  if (p === '/panel-api/accounts/delete') {
    const b = await readBody(req);
    db.accounts = db.accounts.filter((a) => a.id !== b.id);
    saveDb();
    return json(res, 200, { ok: true });
  }
  if (p === '/panel-api/accounts/check') {
    const b = await readBody(req);
    const acc = db.accounts.find((a) => a.id === b.id);
    if (!acc) return json(res, 200, { ok: false, msg: '不存在' });
    await checkAccount(acc);
    saveDb();
    return json(res, 200, { ok: true, account: publicAcc(acc) });
  }
  if (p === '/panel-api/accounts/checkall') {
    for (const a of db.accounts) await checkAccount(a);
    saveDb();
    return json(res, 200, { ok: true, list: db.accounts.map(publicAcc) });
  }
  if (p === '/panel-api/accounts/paste') {
    const b = await readBody(req);
    const map = parseCookie(b.cookie || '');
    if (!map.SESSDATA) return json(res, 200, { ok: false, msg: 'Cookie 里没有 SESSDATA' });
    const acc = addAccountFromCookieMap(map, 'manual');
    await checkAccount(acc);
    saveDb();
    return json(res, 200, { ok: true, account: publicAcc(acc) });
  }
  if (p === '/panel-api/qr/new') {
    try {
      const q = await qrNew();
      return json(res, 200, { ok: true, key: q.key, url: q.url });
    } catch (e) { return json(res, 200, { ok: false, msg: e.message }); }
  }
  if (p === '/panel-api/qr/poll') {
    try {
      const r = await qrPoll(url.searchParams.get('key') || '');
      return json(res, 200, Object.assign({ ok: true }, r));
    } catch (e) { return json(res, 200, { ok: false, msg: e.message }); }
  }
  if (p === '/panel-api/sms/send') {
    const b = await readBody(req);
    if (!/^1\d{10}$/.test(b.tel || '')) return json(res, 200, { ok: false, msg: '手机号格式不对' });
    try { return json(res, 200, await smsSend(b.tel)); } catch (e) { return json(res, 200, { ok: false, msg: e.message }); }
  }
  if (p === '/panel-api/sms/verify') {
    const b = await readBody(req);
    try { return json(res, 200, await smsVerify(b.tel, b.code, b.extra)); } catch (e) { return json(res, 200, { ok: false, msg: e.message }); }
  }
  if (p === '/panel-api/logs') {
    return json(res, 200, { ok: true, list: db.logs.slice(0, 100) });
  }
  return json(res, 404, { ok: false, msg: 'not found' });
}

function publicDev(d) {
  const macs = (d.macs || []).filter(Boolean);
  if (d.mac && macs.indexOf(d.mac) < 0) macs.unshift(d.mac);
  const dids = (d.dids || []).filter(Boolean);
  if (d.did && dids.indexOf(d.did) < 0) dids.unshift(d.did);
  return {
    id: d.id, ip: d.ip || '', name: cleanLabel(d.name), code: d.code || '',
    mac: d.mac || '', macs: macs, did: d.did || '', dids: dids,
    model: cleanLabel(d.model || (d.name && d.name !== '未知机型' ? d.name : '')),
    ips: d.ips || (d.ip ? [d.ip] : []),
    status: d.status || 'pending', req: d.req || 0, blocked: d.blocked || 0,
    okReq: d.okReq || 0, autoBlk: d.autoBlk || null,
    inBlock: !!blkDevOf(d),
    kind: d.kind || 'app',
    firstAt: d.firstAt || 0, lastAt: d.lastAt || 0, actAt: d.actAt || 0,
    ua: (d.ua || '').slice(0, 120),
    stable: !!(macs.length || dids.length),
    orphan: !!d.orphan,
    suspect: d.suspect ? { at: d.suspect.at || 0, segs: d.suspect.segs || 0, hitAt: d.suspect.hitAt || 0 } : null,
    rl: d.rl || 0,
    segs24: devSegs(d).size,
  };
}

function publicAcc(a) {
  return {
    id: a.id, name: cleanLabel(a.name), mid: a.mid || '', face: a.face || '', valid: a.valid !== false,
    vip: !!a.vip, vipDue: a.vipDue || 0, vipLabel: a.vipLabel || '', level: a.level || 0,
    source: a.source || '', addedAt: a.addedAt || 0, lastCheck: a.lastCheck || 0, err: a.err || '',
  };
}

/* ---------------- 定时校验 ---------------- */
function scheduleChecks() {
  setInterval(async () => {
    for (const a of db.accounts) {
      if (Date.now() - (a.lastCheck || 0) > 6 * 3600e3) await checkAccount(a);
    }
    saveDb();
  }, 3600e3);
}

/* ---------------- 启动 ---------------- */
setupFileLog();
loadDb();
/* 数据文件含全部会员 Cookie，权限收紧到只有服务账号可读（每次启动都修一遍） */
try { fs.chmodSync(DATA_FILE, 0o600); } catch (e) { /* ignore */ }
function onRequest(req, res) {
  const url = new URL(req.url, 'http://x');
  if (url.pathname === '/status' || url.pathname === '/status/' || url.pathname === '/status-api') {
    try { handleStatus(req, res, url); } catch (e) { try { json(res, 500, { ok: false, msg: 'status unavailable' }); } catch (_) {} }
    return;
  }
  if (url.pathname === '/panel' || url.pathname.startsWith('/panel') || url.pathname === '/panel-api' || url.pathname.startsWith('/panel-api/') || url.pathname === '/auth' || url.pathname === '/auth/' || url.pathname.startsWith('/auth-api/') || url.pathname.startsWith('/relay-api/')) {
    handlePanel(req, res, url).catch((e) => { try { json(res, 500, { ok: false, msg: e.message }); } catch (_) {} });
    return;
  }
  proxy(req, res);
}
const listenPorts = Array.from(new Set([PORT].concat(Object.keys(PORT_UPSTREAM).map(Number)))).sort((a, b) => a - b);
for (const p of listenPorts) {
  const s = http.createServer(onRequest);
  s.on('error', (e) => console.error('[bili-relay] listen ' + p + ' failed: ' + e.message));
  s.listen(p, BIND, () => console.log('[bili-relay] listening on ' + BIND + ':' + p + (PORT_UPSTREAM[p] ? ' -> ' + UPSTREAM[PORT_UPSTREAM[p]] : ' (按 Host 分流)')));
}
scheduleChecks();
