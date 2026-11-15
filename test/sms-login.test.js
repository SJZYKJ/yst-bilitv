'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { buildSmsSendPayload, buildSmsLoginPayload, collectCookieMap } = require('../sms-login');

test('builds Bilibili web SMS send payload from a manual GeeTest solution', () => {
  const got = buildSmsSendPayload(
    { token: 'token-1', challenge: 'challenge-1' },
    '18685845929',
    { geetest_challenge: 'challenge-1', geetest_validate: 'validate-1', geetest_seccode: 'seccode-1|jordan' },
  );
  assert.deepEqual(got, {
    cid: '86', tel: '18685845929', source: 'main_web', token: 'token-1',
    challenge: 'challenge-1', validate: 'validate-1', seccode: 'seccode-1|jordan',
  });
});

test('rejects missing or mismatched GeeTest results', () => {
  assert.throws(() => buildSmsSendPayload({ token: 't', challenge: 'c' }, '18685845929', {}), /滑块/);
  assert.throws(() => buildSmsSendPayload(
    { token: 't', challenge: 'c' }, '18685845929',
    { geetest_challenge: 'wrong', geetest_validate: 'v', geetest_seccode: 's' },
  ), /失效/);
});

test('builds web SMS login payload with the server-side captcha key', () => {
  assert.deepEqual(buildSmsLoginPayload({ tel: '18685845929', captchaKey: 'captcha-key' }, '123456'), {
    cid: '86', tel: '18685845929', code: '123456', source: 'main_web', captcha_key: 'captcha-key', keep: 'true',
  });
});

test('collects login cookies from Set-Cookie and cookie_info without exposing headers', () => {
  const got = collectCookieMap([
    'SESSDATA=sess; Path=/; HttpOnly',
    'bili_jct=csrf; Path=/',
  ], { cookie_info: { cookies: [{ name: 'DedeUserID', value: '123' }] } });
  assert.deepEqual(got, { SESSDATA: 'sess', bili_jct: 'csrf', DedeUserID: '123' });
});
