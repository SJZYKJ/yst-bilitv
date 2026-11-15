'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { findDeviceByBuvid, shouldPreferBuvidDevice, mergeSplitIdentity } = require('../device-identity');

function dev(overrides) {
  return Object.assign({ id: '', status: 'pending', mac: '', macs: [], did: '', dids: [], ip: '', ips: [], req: 0, blocked: 0 }, overrides);
}

test('matches a known 12-hex MAC embedded in buvid', () => {
  const authorized = dev({ id: 'auth', status: 'ok', mac: 'b79185e8d920' });
  const pending = dev({ id: 'pending', did: 'ixygfs1odxnyfcqtkhmrhfwmqbegese' });
  assert.equal(findDeviceByBuvid([pending, authorized], '/x/tv/card/feed_v2?buvid=XX9D0B79185E8D920DC956676C705635ED7A0'), authorized);
});

test('does not match partial or malformed device identifiers', () => {
  const d = dev({ id: 'x', status: 'ok', mac: 'b79185e8d92' });
  assert.equal(findDeviceByBuvid([d], '/x?buvid=XX9D0B79185E8D920DC'), null);
  assert.equal(findDeviceByBuvid([dev({ mac: 'zzzzzzzzzzzz' })], '/x?buvid=zzzzzzzzzzzz'), null);
});

test('prefers authorized buvid match over a pending did split record', () => {
  const authorized = dev({ id: 'auth', status: 'ok', mac: 'b79185e8d920' });
  const pending = dev({ id: 'pending', status: 'pending', did: 'newdid' });
  assert.equal(shouldPreferBuvidDevice(pending, authorized), true);
  assert.equal(shouldPreferBuvidDevice(authorized, pending), false);
});

test('merges split pending identity into authorized record without downgrading status', () => {
  const authorized = dev({ id: 'auth', status: 'ok', mac: 'b79185e8d920', did: 'olddid', dids: ['olddid'], ips: ['34.81.241.59'], req: 10, blocked: 1 });
  const pending = dev({ id: 'pending', status: 'pending', did: 'newdid', dids: ['newdid'], ips: ['111.55.223.19'], req: 5, blocked: 2 });
  assert.equal(mergeSplitIdentity(authorized, pending), true);
  assert.equal(authorized.status, 'ok');
  assert.deepEqual(authorized.dids.sort(), ['newdid', 'olddid']);
  assert.deepEqual(authorized.ips.sort(), ['111.55.223.19', '34.81.241.59']);
  assert.equal(authorized.req, 15);
  assert.equal(authorized.blocked, 3);
});

test('does not merge another authorized record or a split record with its own MAC', () => {
  assert.equal(mergeSplitIdentity(dev({ status: 'ok' }), dev({ status: 'ok', did: 'x' })), false);
  assert.equal(mergeSplitIdentity(dev({ status: 'ok' }), dev({ status: 'pending', mac: '001122334455' })), false);
});
