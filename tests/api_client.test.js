'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const STATIC_JS = path.join(__dirname, '..', 'web', 'static', 'js');

// Loads api.js into a sandbox where fetch/window are injected per test, the
// same way a browser page provides them.
function loadAPIClient() {
  const sandbox = { window: {}, URLSearchParams };
  vm.createContext(sandbox);
  vm.runInContext(
    fs.readFileSync(path.join(STATIC_JS, 'api.js'), 'utf8'),
    sandbox,
    { filename: 'api.js' },
  );
  return sandbox;
}

test('named timezone formatting handles DST while retaining offset compatibility', () => {
  const sandbox = loadAPIClient();
  sandbox.meridianSetTimezoneName('America/New_York');
  assert.equal(sandbox.meridianFormatDateTime(Date.UTC(2026, 6, 1, 16, 0, 0), false), '2026-07-01 12:00');
  assert.equal(sandbox.meridianParseDateOnly('2026-07-01'), Date.UTC(2026, 6, 1, 4, 0, 0));
  assert.equal(sandbox.meridianParseDateOnly('2026-07-01', true), Date.UTC(2026, 6, 2, 3, 59, 59, 999));
  assert.match(sandbox.meridianTimezoneLabel(), /America\/New_York/);
  const legacy = loadAPIClient();
  legacy.meridianSetTimezoneOffset(480);
  assert.equal(legacy.meridianFormatDateTime(Date.UTC(2026, 0, 1, 0, 0, 0), false), '2026-01-01 08:00');
});

test('401 on a protected call logs out, reloads, and stops the request flow', async () => {
  const sandbox = loadAPIClient();
  let reloads = 0;
  let logoutCalled = false;
  let bodyParsed = false;
  sandbox.window.location = { reload() { reloads++; } };
  sandbox.fetch = async (url) => {
    if (String(url).endsWith('/api/auth/logout')) {
      logoutCalled = true;
      return { status: 200, ok: true, json: async () => ({}) };
    }
    return {
      status: 401,
      ok: false,
      statusText: 'Unauthorized',
      json: async () => {
        bodyParsed = true;
        return { error: 'session expired' };
      },
    };
  };

  const result = await vm.runInContext('API.request("GET", "/api/dashboard")', sandbox);

  assert.equal(logoutCalled, true, 'logout must be triggered on 401');
  assert.equal(reloads, 1, 'page must reload on 401');
  assert.equal(bodyParsed, false, 'the stale 401 body must not be parsed after logout/reload');
  assert.equal(result, undefined, 'the request must terminate instead of resolving with a value');
});

test('401 on the login endpoint is an ordinary failure the caller can report', async () => {
  const sandbox = loadAPIClient();
  let reloads = 0;
  sandbox.window.location = { reload() { reloads++; } };
  sandbox.fetch = async () => ({
    status: 401,
    ok: false,
    statusText: 'Unauthorized',
    json: async () => ({ error: '用户名或密码错误' }),
  });

  await assert.rejects(
    vm.runInContext('API.request("POST", "/api/auth/login", { username: "a", password: "b" })', sandbox),
    /用户名或密码错误/,
  );
  assert.equal(reloads, 0, 'a failed login must not reload the page');
});

test('429 errors retain the server retry interval for the login countdown', async () => {
  const sandbox = loadAPIClient();
  sandbox.fetch = async () => ({
    status: 429,
    ok: false,
    statusText: 'Too Many Requests',
    headers: { get(name) { return name === 'Retry-After' ? '60' : null; } },
    json: async () => ({
      error: 'too many login attempts; try again later',
      retry_after_seconds: 60,
    }),
  });

  let failure;
  try {
    await vm.runInContext('API.login("admin", "wrong password")', sandbox);
  } catch (error) {
    failure = error;
  }
  assert.equal(failure.status, 429);
  assert.equal(failure.retryAfterSeconds, 60);
  assert.match(failure.message, /too many login attempts/);
});

test('dynamic discovery API calls use the exact authenticated paths and verbs', async () => {
  const sandbox = loadAPIClient();
  const requests = [];
  sandbox.fetch = async (url, options) => {
    requests.push({ url, options });
    return {
      status: 200,
      ok: true,
      json: async () => ({ observations: [], dropped_observations: 0 }),
    };
  };

  await vm.runInContext('API.getDynamicProfiles()', sandbox);
  await vm.runInContext('API.getDynamicObservations("site/42 ?")', sandbox);
  await vm.runInContext('API.deleteDynamicObservations("site/42 ?")', sandbox);

  assert.deepEqual(requests.map(request => [request.options.method, request.url]), [
    ['GET', '/api/dynamic-profiles'],
    ['GET', '/api/sites/site%2F42%20%3F/dynamic-observations'],
    ['DELETE', '/api/sites/site%2F42%20%3F/dynamic-observations'],
  ]);
  for (const request of requests) {
    assert.equal(request.options.credentials, 'same-origin');
    assert.equal(request.options.body, undefined, 'read/clear calls must not send a request body');
    assert.equal(Object.keys(request.options.headers).length, 0);
  }
});

test('account API reads and updates the authenticated administrator', async () => {
  const sandbox = loadAPIClient();
  const requests = [];
  sandbox.fetch = async (url, options) => {
    requests.push({ url: String(url), options });
    return {
      status: 200,
      ok: true,
      statusText: 'OK',
      json: async () => ({ username: 'renamed-admin', role: '管理员' }),
    };
  };

  await vm.runInContext('API.getAccount()', sandbox);
  await vm.runInContext(`API.updateAccount({
    username: "renamed-admin",
    current_password: "current password",
    new_password: "new password value"
  })`, sandbox);

  assert.deepEqual(requests.map(request => [request.options.method, request.url]), [
    ['GET', '/api/account'],
    ['PUT', '/api/account'],
  ]);
  assert.equal(requests[0].options.body, undefined);
  assert.deepEqual(JSON.parse(requests[1].options.body), {
    username: 'renamed-admin',
    current_password: 'current password',
    new_password: 'new password value',
  });
});

test('dashboard trends API encodes a custom minute-precision time range', async () => {
  const sandbox = loadAPIClient();
  const requests = [];
  sandbox.fetch = async (url) => {
    requests.push(String(url));
    return { status: 200, ok: true, json: async () => ({ points: [] }) };
  };

  await vm.runInContext('API.dashboardTrends("all", "custom", "2026-08-18T09:05", "2026-08-18T12:34")', sandbox);
  assert.equal(
    requests[0],
    '/api/dashboard-trends?site_id=all&range=custom&start=2026-08-18T09%3A05&end=2026-08-18T12%3A34',
  );
});

test('mobile credential inputs disable keyboard text transformations', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'web', 'static', 'index.html'), 'utf8');

  for (const id of ['inp-username', 'inp-password', 'inp-setup-token', 'account-username', 'account-current-password', 'account-new-password', 'account-confirm-password']) {
    const source = id.startsWith('account-')
      ? fs.readFileSync(path.join(__dirname, '..', 'web', 'static', 'js', 'pages', 'account.js'), 'utf8')
      : html;
    const input = source.match(new RegExp(`<input\\b(?=[^>]*\\bid="${id}")[^>]*>`));
    assert.ok(input, `missing ${id} input`);
    assert.match(input[0], /\bautocapitalize="none"/);
    assert.match(input[0], /\bautocorrect="off"/);
    assert.match(input[0], /\bspellcheck="false"/);
  }
});

test('setup password validation matches the server UTF-8 byte contract', () => {
  const sandbox = loadAPIClient();
  const invalid = '管理员密码必须为 12-72 字节';
  const validate = password => vm.runInContext(
    `adminPasswordValidationError(${JSON.stringify(password)})`,
    sandbox,
  );

  assert.equal(validate('12345678901'), invalid);
  assert.equal(validate('123456789012'), '');
  assert.equal(validate('密码'), invalid);
  assert.equal(validate('密码密码'), '');
  assert.equal(validate('🙂🙂'), invalid);
  assert.equal(validate('🙂🙂🙂'), '');
  assert.equal(validate('x'.repeat(72)), '');
  assert.equal(validate('x'.repeat(73)), invalid);
});
