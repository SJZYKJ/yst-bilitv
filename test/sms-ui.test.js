'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const html = fs.readFileSync(path.join(__dirname, '..', 'public', 'index.html'), 'utf8');

test('SMS panel embeds manual GeeTest and sends only after success', () => {
  assert.match(html, /static\.geetest\.com\/static\/tools\/gt\.js/);
  assert.match(html, /function prepareSmsCaptcha\(\)/);
  assert.match(html, /captcha\.onSuccess\(\(\)=>sendSms\(captcha\.getValidate\(\)\)\)/);
  assert.match(html, /\/panel-api\/sms\/captcha/);
  assert.match(html, /flowId:smsFlowId/);
  assert.doesNotMatch(html, /纯接口过不去/);
});

test('inline panel scripts parse successfully', () => {
  const scripts = [...html.matchAll(/<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi)].map((m) => m[1]);
  assert.ok(scripts.length > 0);
  for (const source of scripts) assert.doesNotThrow(() => new Function(source));
});
