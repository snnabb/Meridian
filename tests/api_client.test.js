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
  const sandbox = { window: {} };
  vm.createContext(sandbox);
  vm.runInContext(
    fs.readFileSync(path.join(STATIC_JS, 'api.js'), 'utf8'),
    sandbox,
    { filename: 'api.js' },
  );
  return sandbox;
}

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
