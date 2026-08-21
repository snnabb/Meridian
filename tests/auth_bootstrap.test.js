'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const STATIC_ROOT = path.join(__dirname, '..', 'web', 'static');
const STATIC_JS = path.join(STATIC_ROOT, 'js');

class FakeClassList {
  constructor() {
    this.names = new Set();
  }

  add(...names) {
    names.forEach(name => this.names.add(name));
  }

  remove(...names) {
    names.forEach(name => this.names.delete(name));
  }

  contains(name) {
    return this.names.has(name);
  }
}

class FakeElement {
  constructor(id) {
    this.id = id;
    this.value = '';
    this.textContent = '';
    this.innerHTML = '';
    this.hidden = false;
    this.disabled = false;
    this.required = false;
    this.type = 'text';
    this.autocomplete = '';
    this.scrollTop = 0;
    this.isConnected = true;
    this.classList = new FakeClassList();
    this.attributes = new Map();
    this.listeners = new Map();
  }

  addEventListener(type, listener) {
    this.listeners.set(type, listener);
  }

  dispatch(type, init = {}) {
    const listener = this.listeners.get(type);
    if (!listener) return undefined;
    const event = Object.assign({
      target: this,
      currentTarget: this,
      defaultPrevented: false,
      preventDefault() { this.defaultPrevented = true; },
    }, init);
    return listener.call(this, event);
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  getAttribute(name) {
    return this.attributes.has(name) ? this.attributes.get(name) : null;
  }

  removeAttribute(name) {
    this.attributes.delete(name);
  }

  focus() {
    this.ownerDocument.activeElement = this;
  }
}

class FakeDocument {
  constructor() {
    this.elements = new Map();
    this.listeners = new Map();
    this.activeElement = null;
    this.body = new FakeElement('body');
    this.body.ownerDocument = this;
    this.body.classList.add('auth-checking');

    const ids = [
      'page-login', 'app-shell', 'loginForm', 'login-footer', 'btn-login',
      'inp-username', 'admin-username-help', 'inp-password', 'admin-password-help',
      'confirm-password-group', 'inp-confirm-password', 'setup-token-group',
      'inp-setup-token', 'btn-toggle-setup-token', 'auth-check-status',
      'auth-check-message', 'btn-auth-retry', 'login-rate-limit', 'modal-overlay', 'modal-body',
      'modal-close', 'avatar-btn', 'page-diagnostics',
    ];
    for (const id of ids) {
      const element = new FakeElement(id);
      element.ownerDocument = this;
      this.elements.set(id, element);
    }

    for (const id of [
      'login-footer', 'admin-username-help', 'admin-password-help',
      'confirm-password-group', 'setup-token-group', 'btn-auth-retry',
    ]) {
      this.getElementById(id).hidden = true;
    }
    this.getElementById('btn-login').disabled = true;
    this.getElementById('btn-login').textContent = '正在检查...';
    this.getElementById('auth-check-message').textContent = '正在检查初始化状态...';
    this.getElementById('loginForm').setAttribute('aria-busy', 'true');
    this.getElementById('auth-check-status').setAttribute('role', 'status');
    this.getElementById('modal-overlay').setAttribute('aria-hidden', 'true');
    this.getElementById('inp-username').required = true;
    this.getElementById('inp-username').autocomplete = 'username';
    this.getElementById('inp-password').required = true;
    this.getElementById('inp-password').type = 'password';
    this.getElementById('inp-password').autocomplete = 'current-password';
    this.getElementById('inp-confirm-password').type = 'password';
    this.getElementById('inp-confirm-password').autocomplete = 'new-password';
    this.getElementById('inp-setup-token').type = 'password';
    this.getElementById('btn-toggle-setup-token').setAttribute('aria-pressed', 'false');
    this.getElementById('btn-toggle-setup-token').setAttribute('aria-label', '显示初始化令牌');
  }

  getElementById(id) {
    return this.elements.get(id) || null;
  }

  addEventListener(type, listener) {
    this.listeners.set(type, listener);
  }
}

function flushTasks() {
  return new Promise(resolve => setImmediate(resolve));
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, resolve, reject };
}

function loadAuthHarness(options = {}) {
  const document = new FakeDocument();
  const checks = (options.checks || [{
    needs_setup: true,
    authenticated: false,
    mode: 'single_admin',
    jwt_secret_ephemeral: false,
    setup_token_required: true,
  }]).slice();
  const state = {
    checkCalls: 0,
    setups: [],
    logins: [],
    sessions: [],
    successes: [],
    errors: [],
    infos: [],
  };
  const setupHandler = typeof options.setupHandler === 'function'
    ? options.setupHandler
    : username => ({ username });
  const loginHandler = typeof options.loginHandler === 'function'
    ? options.loginHandler
    : username => ({ username });
  let checkIndex = 0;
  let timerId = 0;
  let nowMs = 1_800_000_000_000;
  const timers = new Map();

  const sandbox = {
    document,
    console,
    confirm: () => false,
    Date: class extends Date { static now() { return nowMs; } },
    setInterval(callback) { const id = ++timerId; timers.set(id, callback); return id; },
    clearInterval(id) { timers.delete(id); },
    loadDashboardData() {},
    stopDashSSE() {},
    stopTrafficRefresh() {},
    renderDashboard() {},
    renderSites() {},
    renderTraffic() {},
    renderDiag() {},
    Router: {
      current: 'dashboard',
      register() {},
      init() {},
      resolve() {},
    },
    Toast: {
      success(message) { state.successes.push(message); },
      error(message) { state.errors.push(message); },
      info(message) { state.infos.push(message); },
    },
    apiBridge: {
      checkSetup() {
        state.checkCalls++;
        const index = Math.min(checkIndex++, checks.length - 1);
        const next = checks[index];
        return typeof next === 'function' ? next() : next;
      },
      setup(username, password, setupToken) {
        state.setups.push({ username, password, setupToken });
        return setupHandler(username, password, setupToken);
      },
      login(username, password) {
        state.logins.push({ username, password });
        return loginHandler(username, password);
      },
      logout() {},
      recordSession(data) { state.sessions.push(data); },
    },
  };
  sandbox.window = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(
    fs.readFileSync(path.join(STATIC_JS, 'api.js'), 'utf8'),
    sandbox,
    { filename: 'api.js' },
  );
  vm.runInContext(`
    API.checkSetup = () => apiBridge.checkSetup();
    API.setup = (username, password, setupToken) => apiBridge.setup(username, password, setupToken);
    API.login = (username, password) => apiBridge.login(username, password);
    API.logout = () => apiBridge.logout();
    const originalSetSession = API.setSession.bind(API);
    API.setSession = data => {
      apiBridge.recordSession(data);
      originalSetSession(data);
    };
  `, sandbox);
  vm.runInContext(
    fs.readFileSync(path.join(STATIC_JS, 'app.js'), 'utf8'),
    sandbox,
    { filename: 'app.js' },
  );

  return {
    document,
    state,
    get(id) { return document.getElementById(id); },
    advance(milliseconds) {
      nowMs += milliseconds;
      for (const callback of [...timers.values()]) callback();
    },
  };
}

async function attemptSetup(overrides = {}) {
  const harness = loadAuthHarness({
    checks: [{
      needs_setup: true,
      authenticated: false,
      mode: 'single_admin',
      setup_token_required: false,
    }],
  });
  await flushTasks();
  const username = overrides.username === undefined ? 'admin' : overrides.username;
  const password = overrides.password === undefined ? 'correct horse battery' : overrides.password;
  const confirmation = overrides.confirmation === undefined ? password : overrides.confirmation;
  const setupToken = overrides.setupToken === undefined ? 'operator-entered-token' : overrides.setupToken;
  harness.get('inp-username').value = username;
  harness.get('inp-password').value = password;
  harness.get('inp-confirm-password').value = confirmation;
  harness.get('inp-setup-token').value = setupToken;
  await harness.get('loginForm').dispatch('submit');
  return harness;
}

test('auth check is authoritative and a failed check can be retried', async () => {
  const firstCheck = deferred();
  const harness = loadAuthHarness({
    checks: [
      () => firstCheck.promise,
      {
        needs_setup: true,
        authenticated: false,
        mode: 'single_admin',
        setup_token_required: false,
        setup_token: 'server-token-that-must-not-be-revealed',
      },
    ],
  });

  assert.equal(harness.get('btn-login').disabled, true);
  assert.equal(harness.get('btn-login').textContent, '正在检查...');
  assert.equal(harness.get('loginForm').getAttribute('aria-busy'), 'true');
  assert.equal(harness.get('auth-check-status').hidden, false);
  assert.equal(harness.document.body.classList.contains('auth-checking'), true);

  firstCheck.reject(new Error('offline'));
  await flushTasks();
  assert.equal(harness.get('btn-login').disabled, true);
  assert.equal(harness.get('btn-login').textContent, '状态检查失败');
  assert.match(harness.get('auth-check-message').textContent, /初始化状态检查失败/);
  assert.equal(harness.get('auth-check-status').getAttribute('role'), 'alert');
  assert.equal(harness.get('btn-auth-retry').hidden, false);
  assert.equal(harness.get('btn-auth-retry').disabled, false);
  assert.equal(harness.document.body.classList.contains('auth-checking'), false);
  assert.equal(harness.get('setup-token-group').hidden, true);

  const retry = harness.get('btn-auth-retry').dispatch('click');
  assert.equal(harness.get('btn-login').textContent, '正在检查...');
  assert.equal(harness.get('btn-login').disabled, true);
  await retry;

  assert.equal(harness.state.checkCalls, 2);
  assert.equal(harness.get('btn-login').textContent, '创建管理员');
  assert.equal(harness.get('btn-login').disabled, false);
  assert.equal(harness.get('setup-token-group').hidden, false);
  assert.equal(harness.get('inp-setup-token').required, true);
  assert.equal(harness.get('inp-setup-token').value, '', 'auth-check data must never populate the token input');
});

test('setup and existing-admin login remain separate with no manual register path', async () => {
  const setup = loadAuthHarness({
    checks: [{ needs_setup: true, authenticated: false, mode: 'single_admin', setup_token_required: false }],
  });
  await flushTasks();
  assert.equal(setup.get('confirm-password-group').hidden, false);
  assert.equal(setup.get('inp-confirm-password').required, true);
  assert.equal(setup.get('setup-token-group').hidden, false);
  assert.equal(setup.get('inp-setup-token').required, true);
  assert.equal(setup.get('inp-password').autocomplete, 'new-password');
  assert.equal(setup.document.body.classList.contains('auth-checking'), false);

  const login = loadAuthHarness({
    checks: [{ needs_setup: false, authenticated: false, mode: 'single_admin' }],
  });
  await flushTasks();
  assert.equal(login.get('btn-login').textContent, '登录');
  assert.equal(login.get('confirm-password-group').hidden, true);
  assert.equal(login.get('inp-confirm-password').required, false);
  assert.equal(login.get('setup-token-group').hidden, true);
  assert.equal(login.get('inp-setup-token').required, false);
  assert.equal(login.get('inp-password').autocomplete, 'current-password');
  assert.equal(login.document.body.classList.contains('auth-checking'), false);
  assert.doesNotMatch(login.get('login-footer').innerHTML, /创建管理员|link-register|<a\b/);

  login.get('inp-username').value = 'u'.repeat(65);
  login.get('inp-password').value = 'p'.repeat(73);
  await login.get('loginForm').dispatch('submit');
  assert.deepEqual(login.state.logins, [{ username: 'u'.repeat(65), password: 'p'.repeat(73) }],
    'login performs only the generic nonempty-field check');
});

test('rate-limited login shows and completes the server countdown', async () => {
  const rateLimitError = new Error('too many login attempts; try again later');
  rateLimitError.status = 429;
  rateLimitError.retryAfterSeconds = 60;
  const harness = loadAuthHarness({
    checks: [{ needs_setup: false, authenticated: false, mode: 'single_admin' }],
    loginHandler() { return Promise.reject(rateLimitError); },
  });
  await flushTasks();
  harness.get('inp-username').value = 'admin';
  harness.get('inp-password').value = 'wrong password';
  await harness.get('loginForm').dispatch('submit');

  assert.equal(harness.state.errors.at(-1), '登录尝试次数过多，请在 60 秒后重试');
  assert.equal(harness.get('btn-login').disabled, true);
  assert.equal(harness.get('btn-login').textContent, '60 秒后重试');
  assert.equal(harness.get('login-rate-limit').hidden, false);
  assert.match(harness.get('login-rate-limit').textContent, /60 秒后/);

  harness.advance(1000);
  assert.equal(harness.get('btn-login').textContent, '59 秒后重试');
  harness.advance(59000);
  assert.equal(harness.get('btn-login').disabled, false);
  assert.equal(harness.get('btn-login').textContent, '登录');
  assert.equal(harness.get('login-rate-limit').hidden, true);
});

test('a setup conflict rechecks once and switches the stale client to login', async () => {
  const recheck = deferred();
  const harness = loadAuthHarness({
    checks: [
      { needs_setup: true, authenticated: false, mode: 'single_admin' },
      () => recheck.promise,
    ],
    setupHandler() {
      return Promise.reject(new Error('管理员已由其他客户端创建'));
    },
  });
  await flushTasks();

  harness.get('inp-username').value = 'race-admin';
  harness.get('inp-password').value = 'correct horse battery';
  harness.get('inp-confirm-password').value = 'correct horse battery';
  harness.get('inp-setup-token').value = 'operator-entered-token';

  const submission = harness.get('loginForm').dispatch('submit');
  await flushTasks();

  assert.deepEqual(harness.state.errors, ['管理员已由其他客户端创建']);
  assert.equal(harness.state.checkCalls, 2, 'the failed setup starts one authoritative recheck');
  assert.equal(harness.get('btn-login').disabled, true);
  assert.equal(harness.get('btn-login').textContent, '正在检查...');
  assert.equal(harness.get('loginForm').getAttribute('aria-busy'), 'true');

  await harness.get('loginForm').dispatch('submit');
  assert.equal(harness.state.setups.length, 1, 'a second submit is ignored during the recheck');
  assert.equal(harness.state.checkCalls, 2, 'a second submit does not start another recheck');
  assert.deepEqual(harness.state.errors, ['管理员已由其他客户端创建']);

  recheck.resolve({ needs_setup: false, authenticated: false, mode: 'single_admin' });
  await submission;

  assert.equal(harness.state.checkCalls, 2, 'exactly one recheck follows the failed setup');
  assert.equal(harness.get('btn-login').textContent, '登录');
  assert.equal(harness.get('btn-login').disabled, false);
  assert.equal(harness.get('confirm-password-group').hidden, true);
  assert.equal(harness.get('inp-confirm-password').required, false);
  assert.equal(harness.get('inp-confirm-password').value, '');
  assert.equal(harness.get('setup-token-group').hidden, true);
  assert.equal(harness.get('inp-setup-token').required, false);
  assert.equal(harness.get('inp-setup-token').value, '');
  assert.equal(harness.get('link-register'), null);
  assert.doesNotMatch(harness.get('login-footer').innerHTML, /创建管理员|link-register|<a\b/);
  assert.deepEqual(harness.state.errors, ['管理员已由其他客户端创建']);
});

test('a rejected setup token rechecks once and preserves setup fields for correction', async () => {
  const harness = loadAuthHarness({
    checks: [
      { needs_setup: true, authenticated: false, mode: 'single_admin' },
      { needs_setup: true, authenticated: false, mode: 'single_admin' },
    ],
    setupHandler() {
      return Promise.reject(new Error('初始化令牌无效'));
    },
  });
  await flushTasks();

  harness.get('inp-username').value = 'admin-to-correct';
  harness.get('inp-password').value = 'correct horse battery';
  harness.get('inp-confirm-password').value = 'correct horse battery';
  harness.get('inp-setup-token').value = 'wrong-operator-token';
  await harness.get('loginForm').dispatch('submit');

  assert.equal(harness.state.checkCalls, 2, 'exactly one recheck follows the failed setup');
  assert.deepEqual(harness.state.errors, ['初始化令牌无效']);
  assert.equal(harness.get('btn-login').textContent, '创建管理员');
  assert.equal(harness.get('btn-login').disabled, false);
  assert.equal(harness.get('loginForm').getAttribute('aria-busy'), 'false');
  assert.equal(harness.get('confirm-password-group').hidden, false);
  assert.equal(harness.get('setup-token-group').hidden, false);
  assert.equal(harness.get('inp-username').value, 'admin-to-correct');
  assert.equal(harness.get('inp-password').value, 'correct horse battery');
  assert.equal(harness.get('inp-confirm-password').value, 'correct horse battery');
  assert.equal(harness.get('inp-setup-token').value, 'wrong-operator-token');
});

test('setup requires a matching password and a user-entered token', async () => {
  const missingToken = await attemptSetup({ setupToken: '   ' });
  assert.equal(missingToken.state.setups.length, 0);
  assert.equal(missingToken.state.errors.at(-1), '请填写初始化令牌');

  const mismatch = await attemptSetup({ confirmation: 'different valid password' });
  assert.equal(mismatch.state.setups.length, 0);
  assert.equal(mismatch.state.errors.at(-1), '两次输入的密码不一致');
});

test('setup username validation enforces exact 1-64 UTF-8 byte boundaries', async () => {
  const cases = [
    { username: '', accepted: false },
    { username: 'a', accepted: true },
    { username: 'a'.repeat(64), accepted: true },
    { username: 'a'.repeat(65), accepted: false },
    { username: '界'.repeat(21), accepted: true },
    { username: '界'.repeat(22), accepted: false },
    { username: '🙂'.repeat(16), accepted: true },
    { username: '🙂'.repeat(17), accepted: false },
  ];

  for (const contract of cases) {
    const harness = await attemptSetup({ username: contract.username });
    assert.equal(harness.state.setups.length, contract.accepted ? 1 : 0, JSON.stringify(contract));
    if (!contract.accepted) {
      assert.equal(harness.state.errors.at(-1), '管理员用户名必须为 1-64 个 UTF-8 字节');
    }
  }
});

test('setup password validation enforces exact 12-72 UTF-8 byte boundaries', async () => {
  const cases = [
    { password: '🙂'.repeat(2), accepted: false },
    { password: '🙂'.repeat(3), accepted: true },
    { password: '🙂'.repeat(18), accepted: true },
    { password: '🙂'.repeat(19), accepted: false },
  ];

  for (const contract of cases) {
    const harness = await attemptSetup({ password: contract.password });
    assert.equal(harness.state.setups.length, contract.accepted ? 1 : 0, JSON.stringify(contract));
    if (!contract.accepted) {
      assert.equal(harness.state.errors.at(-1), '管理员密码必须为 12-72 字节');
    }
  }
});

test('setup token show-hide control exposes only the value entered in this browser', async () => {
  const harness = loadAuthHarness({
    checks: [{
      needs_setup: true,
      authenticated: false,
      setup_token_required: true,
      setup_token: 'server-token-that-must-stay-server-side',
    }],
  });
  await flushTasks();

  const input = harness.get('inp-setup-token');
  const toggle = harness.get('btn-toggle-setup-token');
  assert.equal(input.value, '');
  assert.equal(input.type, 'password');
  input.value = 'operator-entered-token';

  toggle.dispatch('click');
  assert.equal(input.type, 'text');
  assert.equal(input.value, 'operator-entered-token');
  assert.equal(toggle.getAttribute('aria-pressed'), 'true');
  assert.equal(toggle.getAttribute('aria-label'), '隐藏初始化令牌');
  assert.equal(toggle.textContent, '隐藏');

  toggle.dispatch('click');
  assert.equal(input.type, 'password');
  assert.equal(toggle.getAttribute('aria-pressed'), 'false');
  assert.equal(toggle.getAttribute('aria-label'), '显示初始化令牌');
  assert.equal(toggle.textContent, '显示');
});

test('auth markup carries pending-only root recovery help and no register switch', () => {
  const html = fs.readFileSync(path.join(STATIC_ROOT, 'index.html'), 'utf8');
  assert.match(html, /仅在初始化仍待完成时，root 才可从 \/opt\/meridian\/\.env 恢复现有 SETUP_TOKEN/);
  assert.match(html, /id="btn-toggle-setup-token"[^>]*aria-controls="inp-setup-token"[^>]*aria-pressed="false"/);
  assert.match(html, /id="btn-login" disabled>正在检查\.\.\.<\/button>/);
  assert.doesNotMatch(html, /id="link-register"/);
});
