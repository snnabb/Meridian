'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const STATIC_JS = path.join(__dirname, '..', 'web', 'static', 'js');

function readScript(relativePath) {
  return fs.readFileSync(path.join(STATIC_JS, relativePath), 'utf8');
}

function loadInto(sandbox, ...relativePaths) {
  for (const relativePath of relativePaths) {
    vm.runInContext(readScript(relativePath), sandbox, { filename: relativePath });
  }
}

function okJson(body) {
  return { status: 200, ok: true, statusText: 'OK', json: async () => body };
}

function makeCanvasContext() {
  return {
    scale() {}, clearRect() {}, beginPath() {}, moveTo() {}, lineTo() {},
    quadraticCurveTo() {}, stroke() {}, fill() {}, save() {}, restore() {},
    closePath() {}, fillText() {},
    createLinearGradient() { return { addColorStop() {} }; },
  };
}

function makeElement(id, opts) {
  opts = opts || {};
  return {
    id,
    value: opts.value !== undefined ? opts.value : '',
    innerHTML: '',
    textContent: '',
    style: {},
    hidden: false,
    required: false,
    disabled: false,
    onchange: null,
    className: '',
    dataset: {},
    classList: { add() {}, remove() {}, toggle() {} },
    setAttribute() {},
    addEventListener() {},
    focus() {},
    getContext() { return makeCanvasContext(); },
    parentElement: { clientWidth: 800 },
    isConnected: true,
    scrollTop: 0,
    width: undefined,
    height: undefined,
  };
}

function makeDocument(elementsById) {
  const elements = new Map(Object.entries(elementsById || {}));
  return {
    getElementById(id) { return elements.get(id) || null; },
    querySelectorAll() { return []; },
    addEventListener() {},
    body: { classList: { add() {}, remove() {} } },
    activeElement: null,
  };
}

// Loads api.js + dashboard.js (for formatBytes) + traffic.js into one sandbox,
// the way index.html evaluates them as classic <script> tags sharing a global.
function makeTrafficHarness(options) {
  options = options || {};
  const elements = {
    'page-traffic': makeElement('page-traffic'),
    'traffic-site-select': makeElement('traffic-site-select', { value: '1' }),
    'traffic-hours-select': makeElement('traffic-hours-select', { value: '24' }),
    'traffic-totals': makeElement('traffic-totals'),
    trafficChart: makeElement('trafficChart'),
  };

  const intervals = [];
  const cleared = [];
  const calls = [];
  let nextTimerId = 1;
  let resizeListeners = 0;

  const sandbox = {
    window: {
      addEventListener(name) { if (name === 'resize') resizeListeners++; },
      devicePixelRatio: 1,
    },
    document: makeDocument(elements),
    Toast: { error() {}, success() {}, info() {} },
    console,
    fetch: async (url, opts) => {
      calls.push(String(url));
      if (options.fetch) return options.fetch(url, opts);
      return okJson({});
    },
    setInterval(cb, ms) { const id = nextTimerId++; intervals.push({ id, ms, cb }); return id; },
    clearInterval(id) { cleared.push(id); },
    setTimeout() { return 0; },
    clearTimeout() {},
    confirm: () => true,
    Router: { current: 'traffic' },
  };
  vm.createContext(sandbox);
  loadInto(sandbox, 'api.js', 'pages/dashboard.js', 'pages/traffic.js');
  return { sandbox, elements, intervals, cleared, calls, resizeListeners };
}

test('getTrafficSnapshot calls the additive snapshot endpoint; getTraffic is kept', async () => {
  const calls = [];
  const sandbox = {
    window: {},
    fetch: async (url) => { calls.push(String(url)); return okJson({ snapshot: { traffic_used: 7 }, logs: [] }); },
  };
  vm.createContext(sandbox);
  loadInto(sandbox, 'api.js');

  const data = await vm.runInContext('API.getTrafficSnapshot(7, 24)', sandbox);
  assert.equal(calls[0], '/api/traffic/7/snapshot?hours=24');
  assert.equal(data.snapshot.traffic_used, 7);
  assert.deepEqual(data.logs, []);

  await vm.runInContext('API.getTraffic(7, 24)', sandbox);
  assert.equal(calls[1], '/api/traffic/7?hours=24', 'legacy getTraffic must remain available unchanged');

  await vm.runInContext('API.getTrafficSnapshot(3)', sandbox);
  assert.equal(calls[2], '/api/traffic/3/snapshot?hours=24', 'hours must default to 24');
});

test('traffic page paints totals from the snapshot and the chart from merged logs in one request', async () => {
  const recordedAt = new Date(Date.now() - 3600000).toISOString();
  const h = makeTrafficHarness({
    fetch: async (url) => {
      if (String(url) === '/api/traffic/1/snapshot?hours=24') {
        return okJson({
          snapshot: {
            id: 1, name: 'Alpha', running: true, traffic_used: 1000000, traffic_quota: 5000000,
            persisted_traffic: 0, bytes_in: 1000000, bytes_out: 0, requests: 3,
          },
          logs: [{ id: 9, site_id: 1, bytes_in: 400000, bytes_out: 600000, recorded_at: recordedAt }],
        });
      }
      return okJson({});
    },
  });

  await vm.runInContext('loadTrafficChart()', h.sandbox);

  assert.deepEqual(
    h.calls,
    ['/api/traffic/1/snapshot?hours=24'],
    'the chart must load from a single snapshot request, not a second listSites call',
  );
  const totals = h.elements['traffic-totals'].innerHTML;
  assert.ok(totals.includes(h.sandbox.formatBytes(400000)), 'inbound total must come from the returned logs');
  assert.ok(totals.includes(h.sandbox.formatBytes(600000)), 'outbound total must come from the returned logs');
  assert.ok(totals.includes(h.sandbox.formatBytes(1000000)), 'cumulative total must come from snapshot.traffic_used');
  assert.ok(
    totals.includes('额度') && totals.includes(h.sandbox.formatBytes(5000000)),
    'quota line must come from snapshot.traffic_quota',
  );
  assert.equal(h.elements.trafficChart.width, 800, 'chart must be drawn from the merged logs');
});

test('no quota line is rendered when the site has no quota', async () => {
  const h = makeTrafficHarness({
    fetch: async (url) => {
      if (String(url) === '/api/traffic/1/snapshot?hours=24') {
        return okJson({ snapshot: { traffic_used: 42, traffic_quota: 0 }, logs: [] });
      }
      return okJson({});
    },
  });

  await vm.runInContext('loadTrafficChart()', h.sandbox);

  const totals = h.elements['traffic-totals'].innerHTML;
  assert.ok(totals.includes(h.sandbox.formatBytes(42)), 'cumulative total must still render');
  assert.ok(!totals.includes('额度'), 'a zero quota must not render a quota line');
});

test('traffic refresh timer ticks every 15s and only while the traffic route is active', () => {
  const h = makeTrafficHarness();
  vm.runInContext('startTrafficRefresh()', h.sandbox);
  assert.equal(h.intervals.length, 1);
  assert.equal(h.intervals[0].ms, 15000);

  const tick = h.intervals[0].cb;
  h.sandbox.Router.current = 'dashboard';
  tick();
  assert.equal(h.calls.length, 0, 'timer must not fetch while another route is active');

  h.sandbox.Router.current = 'traffic';
  tick();
  assert.equal(h.calls.length, 1);
  assert.equal(h.calls[0], '/api/traffic/1/snapshot?hours=24');

  vm.runInContext('stopTrafficRefresh()', h.sandbox);
  assert.deepEqual(h.cleared, [h.intervals[0].id], 'stopTrafficRefresh must clear the interval');
});

test('renderTraffic restarts the timer and never re-registers the resize listener', async () => {
  const h = makeTrafficHarness({
    fetch: async (url) => {
      if (String(url) === '/api/sites') return okJson([{ id: 1, name: 'Alpha' }]);
      if (String(url) === '/api/traffic/1/snapshot?hours=24') return okJson({ snapshot: { traffic_used: 0, traffic_quota: 0 }, logs: [] });
      return okJson({});
    },
  });
  assert.equal(h.resizeListeners, 1, 'resize must be registered once when the script loads');

  await vm.runInContext('renderTraffic()', h.sandbox);
  assert.equal(h.intervals.length, 1);
  assert.equal(h.intervals[0].ms, 15000);

  await vm.runInContext('renderTraffic()', h.sandbox);
  assert.equal(h.intervals.length, 2);
  assert.deepEqual(h.cleared, [h.intervals[0].id], 'a re-render must stop the previous timer before starting a new one');
  assert.equal(h.resizeListeners, 1, 're-rendering must not add another resize listener');
});

test('leaving the traffic route stops the refresh timer; staying keeps it', () => {
  const cleared = [];
  let nextTimerId = 1;
  const sandbox = {
    window: { addEventListener() {} },
    document: {
      getElementById() { return null; },
      querySelectorAll() { return []; },
    },
    location: { hash: '#traffic' },
    console,
    setInterval() { return nextTimerId++; },
    clearInterval(id) { cleared.push(id); },
  };
  vm.createContext(sandbox);
  loadInto(sandbox, 'pages/traffic.js', 'router.js');

  vm.runInContext('Router.resolve()', sandbox);
  assert.equal(vm.runInContext('Router.current', sandbox), 'traffic');
  vm.runInContext('startTrafficRefresh()', sandbox);
  const timerId = nextTimerId - 1;

  sandbox.location.hash = '#traffic';
  vm.runInContext('Router.resolve()', sandbox);
  assert.deepEqual(cleared, [], 'staying on traffic must keep the timer alive');

  sandbox.location.hash = '#sites';
  vm.runInContext('Router.resolve()', sandbox);
  assert.deepEqual(cleared, [timerId], 'leaving traffic must stop the refresh timer');
});

test('logout tears down the traffic refresh timer', async () => {
  const elementIds = [
    'page-login', 'app-shell', 'login-footer', 'btn-login', 'setup-token-group',
    'setup-token-input', 'inp-setup-token', 'modal-overlay', 'modal-close',
    'loginForm', 'avatar-btn', 'inp-username', 'inp-password',
  ];
  const elements = {};
  const listeners = {};
  for (const id of elementIds) {
    const el = makeElement(id);
    el.addEventListener = (event, cb) => {
      (listeners[id] = listeners[id] || {})[event] = cb;
    };
    elements[id] = el;
  }

  const calls = [];
  const cleared = [];
  let nextTimerId = 1;
  const sandbox = {
    window: { addEventListener() {} },
    document: makeDocument(elements),
    Toast: { error() {}, success() {}, info() {} },
    console,
    confirm: () => true,
    // app.js assigns window.closeModal but reads the bare global at load time
    // (modal-close click handler), which this sandbox must provide up front.
    closeModal() {},
    fetch: async (url) => { calls.push(String(url)); return okJson({}); },
    setInterval() { return nextTimerId++; },
    clearInterval(id) { cleared.push(id); },
    setTimeout() { return 0; },
    clearTimeout() {},
    location: { hash: '#dashboard' },
  };
  vm.createContext(sandbox);
  // app.js runs checkAuth() at load; the stub reports an unauthenticated session.
  loadInto(sandbox, 'api.js', 'pages/dashboard.js', 'pages/traffic.js', 'app.js');

  vm.runInContext('startTrafficRefresh()', sandbox);
  const timerId = nextTimerId - 1;

  await listeners['avatar-btn'].click();

  assert.deepEqual(cleared, [timerId], 'logout must stop the traffic refresh timer');
  assert.ok(calls.includes('/api/auth/logout'), 'logout must POST the session away');
  assert.equal(vm.runInContext('API.authenticated', sandbox), false);
});

test('a late snapshot response cannot paint over a different route', async () => {
  const h = makeTrafficHarness();
  let resolveFetch;
  const gate = new Promise(resolve => { resolveFetch = resolve; });
  h.sandbox.fetch = async () => gate;

  const pending = vm.runInContext('loadTrafficChart()', h.sandbox);
  h.sandbox.Router.current = 'sites';
  resolveFetch(okJson({ snapshot: { traffic_used: 999999 }, logs: [] }));
  await pending;

  assert.equal(h.elements['traffic-totals'].innerHTML, '', 'a response arriving after leaving must not paint totals');
  assert.equal(h.elements.trafficChart.width, undefined, 'a response arriving after leaving must not draw the chart');
});

test('a late snapshot response cannot paint over a different site selection', async () => {
  const h = makeTrafficHarness();
  let resolveFetch;
  const gate = new Promise(resolve => { resolveFetch = resolve; });
  h.sandbox.fetch = async () => gate;

  const pending = vm.runInContext('loadTrafficChart()', h.sandbox);
  h.elements['traffic-site-select'].value = '2';
  resolveFetch(okJson({ snapshot: { traffic_used: 999999 }, logs: [] }));
  await pending;

  assert.equal(h.elements['traffic-totals'].innerHTML, '', 'a response for the old selection must not paint');
  assert.equal(h.elements.trafficChart.width, undefined);
});

test('site list responses arriving after leaving the route are dropped', async () => {
  const h = makeTrafficHarness();
  let resolveFetch;
  const gate = new Promise(resolve => { resolveFetch = resolve; });
  h.sandbox.fetch = async () => gate;

  const pending = vm.runInContext('loadTrafficSites()', h.sandbox);
  h.sandbox.Router.current = 'sites';
  h.sandbox.fetch = async () => { h.calls.push('fetched'); return gate; };
  resolveFetch(okJson([{ id: 1, name: 'Alpha' }]));
  await pending;

  assert.equal(h.elements['traffic-site-select'].innerHTML, '', 'sites must not populate after leaving the page');
  assert.deepEqual(h.calls, [], 'no chart request may follow a dropped site list');
});

test('site list populates the select and auto-loads the chart for the first site', async () => {
  const h = makeTrafficHarness({
    fetch: async (url) => {
      if (String(url) === '/api/sites') return okJson([{ id: 1, name: 'Alpha' }]);
      return okJson({ snapshot: { traffic_used: 0, traffic_quota: 0 }, logs: [] });
    },
  });

  await vm.runInContext('loadTrafficSites()', h.sandbox);

  assert.ok(h.elements['traffic-site-select'].innerHTML.includes('Alpha'), 'select must be populated with the site name');
  assert.deepEqual(h.calls, ['/api/sites', '/api/traffic/1/snapshot?hours=24'], 'populating must trigger one chart load');
});

test('dashboard table paints live traffic_used and the running badge from one /api/sites request', async () => {
  const elements = {
    'dash-table': makeElement('dash-table'),
  };
  const calls = [];
  const sandbox = {
    window: {},
    document: makeDocument(elements),
    console,
    Toast: { error() {}, success() {}, info() {} },
    fetch: async (url) => {
      calls.push(String(url));
      return okJson([
        { id: 1, name: 'Alpha', target_url: 'http://a.example', ua_mode: 'infuse', listen_port: 8001, running: true, traffic_used: 1048576 },
        { id: 2, name: 'Beta', target_url: 'http://b.example', ua_mode: 'web', listen_port: 8002, running: false, traffic_used: 0 },
      ]);
    },
    Router: { current: 'dashboard' },
    setInterval() { return 1; },
    clearInterval() {},
    setTimeout() { return 0; },
    clearTimeout() {},
  };
  vm.createContext(sandbox);
  loadInto(sandbox, 'api.js', 'pages/dashboard.js');

  await vm.runInContext('loadDashboardTable()', sandbox);

  assert.deepEqual(calls, ['/api/sites'], 'the dashboard table must load from exactly one /api/sites request');
  const html = elements['dash-table'].innerHTML;
  assert.ok(html.includes('Alpha') && html.includes('Beta'), 'every site must be rendered');
  assert.ok(html.includes(sandbox.formatBytes(1048576)), 'the authoritative traffic_used must be formatted into the row');
  assert.ok(html.includes('运行中') && html.includes('已停止'), 'the running flag must drive the status badge');
});
