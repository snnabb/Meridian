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

test('minute series fills missing buckets, aggregates requests, and preserves totals when compacted', () => {
  const sandbox = {
    window: { addEventListener() {} },
    document: {},
    console,
  };
  vm.createContext(sandbox);
  loadInto(sandbox, 'pages/traffic.js');

  const now = Date.UTC(2026, 7, 6, 12, 34, 45);
  const series = sandbox.buildMinuteTrafficSeries([
    { recorded_at_ms: now - 60_000, bytes_in: 100, bytes_out: 20, requests: 2 },
    { recorded_at_ms: now, bytes_in: 300, bytes_out: 40, requests: 4 },
  ], 1, now);

  assert.equal(series.minuteCount, 60);
  assert.equal(series.inbound.reduce((sum, value) => sum + value, 0), 400);
  assert.equal(series.outbound.reduce((sum, value) => sum + value, 0), 60);
  assert.equal(series.requests.reduce((sum, value) => sum + value, 0), 6);
  assert.equal(series.inbound[58], 100);
  assert.equal(series.inbound[59], 300);
  assert.equal(series.inbound.slice(0, 58).every(value => value === 0), true);

  const compacted = sandbox.compactTrafficSeries(series, 20);
  assert.equal(compacted.inbound.reduce((sum, value) => sum + value, 0), 400);
  assert.equal(compacted.outbound.reduce((sum, value) => sum + value, 0), 60);
  assert.equal(compacted.requests.reduce((sum, value) => sum + value, 0), 6);
  assert.equal(compacted.timestamps[0], series.start + 2 * 60_000);
  assert.equal(compacted.timestamps.at(-1), series.end);
});

test('traffic wall-clock fallback does not interpret a stored Z as a UTC instant', () => {
  const sandbox = {
    window: { addEventListener() {} },
    document: {},
    console,
  };
  vm.createContext(sandbox);
  loadInto(sandbox, 'pages/traffic.js');

  const expectedLocal = new Date(2026, 7, 6, 12, 34, 0).getTime();
  assert.equal(
    sandbox.trafficLogTimestamp({ recorded_at: '2026-08-06T12:34:00Z' }),
    expectedLocal,
  );
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

test('the retired traffic route redirects to the dashboard', () => {
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
  assert.equal(sandbox.location.hash, 'dashboard');
  assert.equal(vm.runInContext('Router.current', sandbox), null);
  assert.deepEqual(cleared, []);
});

test('logout tears down the traffic refresh timer', async () => {
  const elementIds = [
    'page-login', 'app-shell', 'login-footer', 'btn-login', 'setup-token-group',
    'setup-token-input', 'inp-setup-token', 'modal-overlay', 'modal-close',
    'loginForm', 'avatar-btn', 'mobile-logout', 'avatar-initial', 'sidebar-username', 'sidebar-version', 'mobile-version', 'inp-username', 'inp-password',
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
    fetch: async (url) => { calls.push(String(url)); return okJson({ app_version: 'v1.8.3' }); },
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

  await sandbox.window.logoutMeridian();

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
    's-cache': makeElement('s-cache'),
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
        { id: 1, name: 'Alpha', target_url: 'http://a.example', ua_mode: 'infuse', listen_port: 8001, running: true, traffic_used: 1048576, cache_size_bytes: 2048 },
        { id: 2, name: 'Beta', target_url: 'http://b.example', ua_mode: 'web', listen_port: 8002, running: false, traffic_used: 0, cache_size_bytes: 1024 },
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
  assert.ok(html.indexOf('Alpha') < html.indexOf('Beta'), 'dashboard rows must preserve the persisted /api/sites order');
  assert.ok(html.includes(sandbox.formatBytes(1048576)), 'the authoritative traffic_used must be formatted into the row');
  assert.ok(html.includes(sandbox.formatBytes(2048)), 'each site cache size must be formatted into the row');
  assert.equal(elements['s-cache'].textContent, sandbox.formatBytes(3072), 'the dashboard cache card must sum every site');
  assert.ok(html.includes('运行中') && html.includes('已停止'), 'the running flag must drive the status badge');
  assert.ok(html.includes('↓ 0 B/s') && html.includes('↑ 0 B/s'), 'the table must show a stable zero rate before the first SSE sample');
  assert.ok(!html.includes('dashboard-speed-placeholder'), 'the dashboard must not flash a placeholder while sampling');
});

test('dashboard live speed uses consecutive bidirectional SSE counters and rejects negative resets', async () => {
  const elements = { 'dash-table': makeElement('dash-table'), 's-cache': makeElement('s-cache') };
  let now = 1000;
  const sandbox = {
    window: {}, document: makeDocument(elements), console,
    Date: { now: () => now },
    Toast: { error() {}, success() {}, info() {} },
    fetch: async () => okJson([{ id: 1, name: 'Alpha', target_url: 'http://a.example', ua_mode: 'infuse', listen_port: 8001, running: true, traffic_used: 300, cache_size_bytes: 0 }]),
    Router: { current: 'dashboard' },
    setInterval() { return 1; }, clearInterval() {}, setTimeout() { return 0; }, clearTimeout() {},
  };
  vm.createContext(sandbox);
  loadInto(sandbox, 'api.js', 'pages/dashboard.js');
  await vm.runInContext('loadDashboardTable()', sandbox);

  vm.runInContext('updateDashboardSiteSpeeds([{id:1, cumulative_bytes_in:100, cumulative_bytes_out:200, bytes_in:100, bytes_out:200, traffic_used:300}])', sandbox);
  assert.ok(elements['dash-table'].innerHTML.includes('↓ 0 B/s'));
  now = 3000;
  vm.runInContext('updateDashboardSiteSpeeds([{id:1, cumulative_bytes_in:2148, cumulative_bytes_out:1048776, bytes_in:2148, bytes_out:1048776, traffic_used:1050924}])', sandbox);
  const html = elements['dash-table'].innerHTML;
  assert.ok(html.includes('↓ 512 KB/s'), html);
  assert.ok(html.includes('↑ 1 KB/s'), html);

  await vm.runInContext('loadDashboardTable()', sandbox);
  const refreshedHTML = elements['dash-table'].innerHTML;
  assert.ok(refreshedHTML.includes('↓ 512 KB/s'), 'periodic site refresh must preserve the last live download speed');
  assert.ok(refreshedHTML.includes('↑ 1 KB/s'), 'periodic site refresh must preserve the last live upload speed');
  assert.ok(!refreshedHTML.includes('dashboard-speed-placeholder'), 'refreshing site metadata must not flash the speed placeholder');

  now = 5000;
  vm.runInContext('updateDashboardSiteSpeeds([{id:1, cumulative_bytes_in:1, cumulative_bytes_out:1, bytes_in:1, bytes_out:1, traffic_used:2}])', sandbox);
  assert.ok(elements['dash-table'].innerHTML.includes('↓ 0 B/s'), 'counter reset must render zero instead of a negative speed or placeholder');
  assert.ok(!elements['dash-table'].innerHTML.includes('dashboard-speed-placeholder'));
});

test('dashboard keeps SSE samples that arrive before the site list and across partial payloads', async () => {
  const elements = { 'dash-table': makeElement('dash-table'), 's-cache': makeElement('s-cache') };
  let now = 1000;
  const sandbox = {
    window: {}, document: makeDocument(elements), console,
    Date: { now: () => now },
    Toast: { error() {}, success() {}, info() {} },
    fetch: async () => okJson([{ id: 1, name: 'Alpha', target_url: 'http://a.example', ua_mode: 'infuse', listen_port: 8001, running: true, traffic_used: 300, cache_size_bytes: 0 }]),
    Router: { current: 'dashboard' },
    setInterval() { return 1; }, clearInterval() {}, setTimeout() { return 0; }, clearTimeout() {},
  };
  vm.createContext(sandbox);
  loadInto(sandbox, 'api.js', 'pages/dashboard.js');

  vm.runInContext('updateDashboardSiteSpeeds([{id:1, cumulative_bytes_in:100, cumulative_bytes_out:200, bytes_in:100, bytes_out:200, traffic_used:300}])', sandbox);
  await vm.runInContext('loadDashboardTable()', sandbox);
  assert.ok(elements['dash-table'].innerHTML.includes('↓ 0 B/s'), 'the first pre-list sample should render a stable zero rate');

  now = 2000;
  vm.runInContext('updateDashboardSiteSpeeds([])', sandbox);
  now = 3000;
  vm.runInContext('updateDashboardSiteSpeeds([{id:1, cumulative_bytes_in:2148, cumulative_bytes_out:1048776, bytes_in:0, bytes_out:0, traffic_used:1050924}])', sandbox);
  assert.ok(elements['dash-table'].innerHTML.includes('↓ 512 KB/s'), 'the sample received before /api/sites must be used');
  assert.ok(elements['dash-table'].innerHTML.includes('↑ 1 KB/s'), 'the bidirectional sample must be retained');
});

test('dashboard trends use pointer interaction and dashed crosshairs', () => {
  const source = readScript('pages/dashboard.js');
  const css = readScript('../css/style.css');
  assert.match(source, /addEventListener\('pointermove'/);
  assert.match(source, /addEventListener\('pointerup'/);
  assert.match(source, /const clearHover = \(\) =>/);
  assert.match(source, /pointercancel', clearHover/);
  assert.match(source, /setLineDash\(\[5, 4\]\)/);
  assert.match(source, /const ticks = 6/);
  assert.match(source, /dashboardRoundRect/);
  assert.match(source, /dashboardRealtimeTrendSamples/);
  assert.match(source, /dashboardTimeLabelIndexes\(points\.length, plotW, dashboardTrendState\.range\)/);
  assert.doesNotMatch(source, /实时（请求采样）/);
  assert.match(css, /touch-action:\s*none/);
  assert.match(css, /cursor:\s*default/);
});

test('dashboard trend pointer coordinates use the plot bounds and keep the crosshair on the pointer', () => {
  const { sandbox } = makeTrafficHarness();
  const state = vm.runInContext(`dashboardTrendPointerState(
    { left: 100, top: 50, width: 300, height: 200 },
    { width: 300, height: 200, left: 60, top: 14, plotW: 228, plotH: 156 },
    { clientX: 160, clientY: 50 },
    7
  )`, sandbox);
  assert.equal(state.x, 60, 'the left edge of the plot should be the minimum crosshair X');
  assert.equal(state.y, 14, 'the top edge of the plot should be the minimum crosshair Y');
  assert.equal(state.index, 0, 'the first sample should be selected at the plot start');

  const right = vm.runInContext(`dashboardTrendPointerState(
    { left: 100, top: 50, width: 300, height: 200 },
    { width: 300, height: 200, left: 60, top: 14, plotW: 228, plotH: 156 },
    { clientX: 400, clientY: 250 },
    7
  )`, sandbox);
  assert.equal(right.x, 288, 'the right edge of the plot should be the maximum crosshair X');
  assert.equal(right.y, 170, 'the bottom edge of the plot should be the maximum crosshair Y');
  assert.equal(right.index, 6, 'the last sample should be selected at the plot end');
});

test('dashboard trend tooltip avoids the pointer and flips at chart edges', () => {
  const { sandbox } = makeTrafficHarness();
  const rightEdge = vm.runInContext('dashboardTooltipPosition(270, 100, 300, 200, 100, 50)', sandbox);
  assert.equal(rightEdge.left, 156, 'the tooltip should move to the pointer left when the right side is full');
  assert.equal(rightEdge.top, 36, 'the tooltip should sit above the pointer when there is room');
  const topEdge = vm.runInContext('dashboardTooltipPosition(100, 10, 300, 200, 100, 50)', sandbox);
  assert.equal(topEdge.left, 114, 'the tooltip should default to the pointer right');
  assert.equal(topEdge.top, 24, 'the tooltip should move below the pointer at the top edge');
  const css = readScript('../css/style.css');
  assert.match(css, /\.dashboard-chart-tooltip[^\n]*transform:\s*none/);
  assert.match(css, /\.dashboard-chart-tooltip[^\n]*pointer-events:\s*none/);
  assert.match(css, /\.dashboard-trend-card\s*\{[^}]*overflow:\s*visible/);
  assert.match(css, /\.dashboard-trend-grid\s*\{[^}]*position:\s*relative[^}]*z-index:\s*3/);
  assert.match(css, /\.dashboard-insights-grid,\s*\.dashboard-site-status\s*\{[^}]*position:\s*relative[^}]*z-index:\s*1/);
});

test('dashboard trend tooltip keeps long content outside the pointer without clipping', () => {
  const { sandbox } = makeTrafficHarness();
  const middle = vm.runInContext('dashboardTooltipPosition(150, 100, 300, 200, 360, 300)', sandbox);
  assert.equal(middle.top, 114, 'a long tooltip should move below a middle pointer');
  assert.equal(middle.maxHeight, undefined, 'the tooltip should not receive a height limit');
  assert.ok(middle.top >= 100 + 14, 'the tooltip should keep a gap below the pointer');
  const top = vm.runInContext('dashboardTooltipPosition(150, 20, 300, 200, 360, 300)', sandbox);
  assert.equal(top.top, 34, 'a top-edge pointer should use the space below it');
  assert.equal(top.maxHeight, undefined, 'the tooltip should remain fully visible instead of scrolling');
});

test('dashboard zero-value trend scales never render negative or invalid labels', () => {
  const { sandbox } = makeTrafficHarness();
  const scale = vm.runInContext('dashboardRequestScale(0)', sandbox);
  assert.deepEqual({ max: scale.max, step: scale.step, ticks: scale.ticks }, { max: 6, step: 1, ticks: 6 });
  assert.equal(vm.runInContext('formatBytes(-5)', sandbox), '0 B');
  assert.equal(vm.runInContext('formatBytes(Number.NaN)', sandbox), '0 B');
  assert.equal(vm.runInContext('formatBytes(Number.POSITIVE_INFINITY)', sandbox), '0 B');
  assert.equal(vm.runInContext('dashboardTrendValueLabel(0, "requests")', sandbox), '0');
});

test('global traffic settings expose reset and no-reset billing cycles', () => {
  const source = readScript('pages/global-settings.js');
  assert.match(source, /setting-traffic-reset-day/);
  assert.match(source, /traffic_reset_day\s*=\s*numericSetting\('setting-traffic-reset-day'/);
  assert.match(source, /短月自动使用该月最后一天/);
  assert.match(source, /不重置（累计流量）/);
  assert.match(source, /s\.traffic_reset_day == null \? 1 : s\.traffic_reset_day/);
});
