'use strict';

function digits(value) {
  return String(value || '').replace(/\D/g, '');
}

function buildSmsSendPayload(session, tel, solution) {
  const phone = digits(tel);
  if (!/^1\d{10}$/.test(phone)) throw new Error('手机号格式不对');
  const state = session || {};
  const solved = solution || {};
  const challenge = String(solved.geetest_challenge || solved.challenge || '');
  const validate = String(solved.geetest_validate || solved.validate || '');
  const seccode = String(solved.geetest_seccode || solved.seccode || '');
  if (!challenge || !validate || !seccode) throw new Error('请先完成滑块验证码');
  if (!state.challenge || challenge !== String(state.challenge)) throw new Error('滑块验证码已失效，请重新获取');
  if (!state.token) throw new Error('验证码会话已失效，请重新获取');
  return {
    cid: '86', tel: phone, source: 'main_web', token: String(state.token),
    challenge, validate, seccode,
  };
}

function buildSmsLoginPayload(session, code) {
  const state = session || {};
  const sms = digits(code);
  if (!/^\d{4,8}$/.test(sms)) throw new Error('短信验证码格式不对');
  if (!/^1\d{10}$/.test(String(state.tel || '')) || !state.captchaKey) throw new Error('短信验证会话已失效，请重新发送');
  return {
    cid: '86', tel: String(state.tel), code: sms, source: 'main_web',
    captcha_key: String(state.captchaKey), keep: 'true',
  };
}

function collectCookieMap(setCookie, data) {
  const out = {};
  const lines = Array.isArray(setCookie) ? setCookie : (setCookie ? [setCookie] : []);
  for (const line of lines) {
    const first = String(line || '').split(';')[0];
    const i = first.indexOf('=');
    if (i > 0) out[first.slice(0, i).trim()] = first.slice(i + 1).trim();
  }
  const cookies = data && data.cookie_info && Array.isArray(data.cookie_info.cookies) ? data.cookie_info.cookies : [];
  for (const item of cookies) {
    if (item && item.name) out[String(item.name)] = String(item.value || '');
  }
  return out;
}

module.exports = { buildSmsSendPayload, buildSmsLoginPayload, collectCookieMap };
