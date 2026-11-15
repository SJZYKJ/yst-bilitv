'use strict';

function macsOf(device) {
  return [device && device.mac].concat((device && device.macs) || [])
    .map((v) => String(v || '').toLowerCase())
    .filter((v, i, a) => /^[0-9a-f]{12}$/.test(v) && a.indexOf(v) === i);
}

function findDeviceByBuvid(devices, pathStr) {
  let buvid = '';
  try {
    const u = new URL(String(pathStr || '/'), 'http://relay.local');
    buvid = String(u.searchParams.get('buvid') || '').toLowerCase();
  } catch (_) { return null; }
  if (buvid.length < 12) return null;
  for (const device of devices || []) {
    for (const mac of macsOf(device)) {
      if (buvid.includes(mac)) return device;
    }
  }
  return null;
}

function shouldPreferBuvidDevice(current, byBuvid) {
  if (!byBuvid || byBuvid === current) return false;
  if (!current) return true;
  return byBuvid.status === 'ok' && current.status !== 'ok';
}

function addUnique(target, values, limit) {
  for (const raw of values) {
    const value = String(raw || '');
    if (value && target.indexOf(value) < 0) target.push(value);
  }
  while (target.length > limit) target.shift();
}

function mergeSplitIdentity(target, split) {
  if (!target || !split || target === split) return false;
  if (target.status !== 'ok' || split.status !== 'pending') return false;
  if (macsOf(split).length) return false;
  target.macs = target.macs || [];
  target.dids = target.dids || [];
  target.ips = target.ips || [];
  addUnique(target.dids, [split.did].concat(split.dids || []), 8);
  addUnique(target.ips, [split.ip].concat(split.ips || []), 12);
  target.req = (target.req || 0) + (split.req || 0);
  target.blocked = (target.blocked || 0) + (split.blocked || 0);
  if (split.firstAt && (!target.firstAt || split.firstAt < target.firstAt)) target.firstAt = split.firstAt;
  if (split.lastAt && (!target.lastAt || split.lastAt > target.lastAt)) target.lastAt = split.lastAt;
  return true;
}

module.exports = { findDeviceByBuvid, shouldPreferBuvidDevice, mergeSplitIdentity };
