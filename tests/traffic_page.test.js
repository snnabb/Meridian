'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const STATIC_JS = path.join(__dirname, '..', 'web', 'static', 'js');
function loadInto(sandbox, ...files) {
  for (const file of files) vm.runInContext(fs.readFileSync(path.join(STATIC_JS, file), 'utf8'), sandbox, { filename: file });
}
function okJson(body) { return { status: 200, ok: true, statusText: 'OK', json: async () => body }; }
async function flushTraffic() {
  await new Promise(resolve => setImmediate(resolve));
  await new Promise(resolve => setImmediate(resolve));
}

function makeContext() {
  const calls = [];
  const record = name => (...args) => { calls.push({ name, args }); };
  return {
    calls,
    scale: record('scale'), clearRect: record('clearRect'), beginPath: record('beginPath'),
    moveTo: record('moveTo'), lineTo: record('lineTo'), quadraticCurveTo: record('quadraticCurveTo'), bezierCurveTo: record('bezierCurveTo'),
    stroke: record('stroke'), fill: record('fill'), arc: record('arc'), fillText: record('fillText'),
    save: record('save'), restore: record('restore'), closePath: record('closePath'),
    createLinearGradient(...args) {
      calls.push({ name: 'createLinearGradient', args });
      return { addColorStop: record('addColorStop') };
    },
  };
}
function makeElement(id, value) {
  const listeners = {}, classes = new Set(), attributes = {}, capturedPointers = new Set();
  const context = makeContext();
  return {
    id, value: value || '', innerHTML: '', textContent: '', className: '', hidden: false, style: {}, width: undefined, height: undefined,
    parentElement: { clientWidth: 800 }, rect: { left: 0, width: 800 }, context,
    captureCalls: [], releaseCalls: [],
    classList: {
      add(...names) { names.forEach(name => classes.add(name)); },
      remove(...names) { names.forEach(name => classes.delete(name)); },
      contains(name) { return classes.has(name); },
      toggle(name, force) {
        const enabled = force === undefined ? !classes.has(name) : !!force;
        if (enabled) classes.add(name); else classes.delete(name);
        return enabled;
      },
    },
    setAttribute(name, next) { attributes[name] = String(next); this[name] = String(next); },
    removeAttribute(name) { delete attributes[name]; delete this[name]; },
    getAttribute(name) { return Object.prototype.hasOwnProperty.call(attributes, name) ? attributes[name] : null; },
    addEventListener(name, cb) { listeners[name] = cb; },
    dispatch(name, event) {
      if (!listeners[name]) return undefined;
      const next = event || {};
      if (!next.type) next.type = name;
      if (!next.preventDefault) next.preventDefault = function preventDefault() { this.defaultPrevented = true; };
      next.currentTarget = this;
      return listeners[name](next);
    },
    focus(options) { this.focused = true; this.focusOptions = options; },
    getBoundingClientRect() { return this.rect; },
    getContext() { return context; },
    setPointerCapture(pointerId) { capturedPointers.add(pointerId); this.captureCalls.push(pointerId); },
    hasPointerCapture(pointerId) { return capturedPointers.has(pointerId); },
    releasePointerCapture(pointerId) { capturedPointers.delete(pointerId); this.releaseCalls.push(pointerId); },
    losePointerCapture(pointerId) {
      if (!capturedPointers.delete(pointerId)) return;
      this.dispatch('lostpointercapture', { pointerId });
    },
    listeners,
  };
}
function harness(fetchImpl) {
  const elements = {
    'page-traffic': makeElement('page-traffic'),
    'traffic-site-select': makeElement('traffic-site-select', '1'),
    'traffic-hours-select': makeElement('traffic-hours-select', '1440'),
    'traffic-chart-status': makeElement('traffic-chart-status'),
    'traffic-chart-status-message': makeElement('traffic-chart-status-message'),
    'traffic-chart-retry': makeElement('traffic-chart-retry'),
    'traffic-point-detail': makeElement('traffic-point-detail'),
    'traffic-totals': makeElement('traffic-totals'),
    trafficChart: makeElement('trafficChart'),
  };
  const calls = [], intervals = [], cleared = [];
  let timer = 0, resizeListeners = 0;
  const sandbox = {
    window: { devicePixelRatio: 1, addEventListener(name) { if (name === 'resize') resizeListeners++; } },
    document: { getElementById(id) { return elements[id] || null; }, querySelectorAll() { return []; }, body: { classList: { add() {}, remove() {} } } },
    Router: { current: 'traffic' }, Toast: { error() {}, success() {}, info() {} }, console,
    fetch: async (url, opts) => { calls.push(String(url)); return fetchImpl ? fetchImpl(url, opts) : okJson([]); },
    setInterval(cb, ms) { const id = ++timer; intervals.push({ id, cb, ms }); return id; },
    clearInterval(id) { cleared.push(id); }, setTimeout() { return 0; }, clearTimeout() {}, confirm() { return true; },
  };
  vm.createContext(sandbox);
  loadInto(sandbox, 'api.js', 'pages/dashboard.js', 'pages/traffic.js');
  return { sandbox, elements, calls, intervals, cleared, get resizeListeners() { return resizeListeners; } };
}

function bucket(minute, incoming, outgoing, requests, extra) {
  return Object.assign({ minute_start_unix: minute, bytes_in: incoming, bytes_out: outgoing, requests }, extra || {});
}
function countVerticalSegments(calls) {
  return calls.reduce((count, call, index) => {
    const previous = calls[index - 1];
    if (call.name !== 'lineTo' || !previous || previous.name !== 'moveTo') return count;
    const vertical = Math.abs(call.args[0] - previous.args[0]) < 1e-9
      && Math.abs(call.args[1] - previous.args[1]) > 1e-9;
    return count + (vertical ? 1 : 0);
  }, 0);
}

test('traffic render starts refresh before issuing its live site request', async () => {
  const h = harness(async url => String(url) === '/api/sites'
    ? okJson([{ id: 1, name: 'Ready' }])
    : okJson([]));
  vm.runInContext('renderTraffic()', h.sandbox);
  await flushTraffic();
  assert.match(h.elements['traffic-site-select'].innerHTML, /Ready/);
  assert.ok(h.calls.includes('/api/traffic/1/timeline?minutes=1440'));
});
test('API timeline helper uses the exact minute endpoint and default range', async () => {
  const calls = [];
  const sandbox = { window: {}, fetch: async url => { calls.push(String(url)); return okJson([]); } };
  vm.createContext(sandbox); loadInto(sandbox, 'api.js');
  await vm.runInContext('API.getTrafficTimeline(7, 360)', sandbox);
  await vm.runInContext('API.getTrafficTimeline(8)', sandbox);
  assert.deepEqual(calls, ['/api/traffic/7/timeline?minutes=360', '/api/traffic/8/timeline?minutes=1440']);
});

test('chart makes one request, keeps exact public buckets, and starts without a minute selection', async () => {
  const h = harness(async () => okJson([
    bucket(60, 100, 200, 1, { site_id: 99, client_ip: 'secret', name: 'private' }),
    bucket(120, 300, 400, 2),
  ]));
  await vm.runInContext('loadTrafficChart()', h.sandbox);
  assert.deepEqual(h.calls, ['/api/traffic/1/timeline?minutes=1440']);
  assert.equal(h.elements.trafficChart.width, 800);
  assert.equal(vm.runInContext('trafficChartState.selectedTimestamp', h.sandbox), null);
  assert.equal(h.elements['traffic-point-detail'].hidden, true);
  assert.equal(h.elements.trafficChart.getAttribute('aria-valuetext'), null);
  assert.equal(countVerticalSegments(h.elements.trafficChart.context.calls), 0);
  assert.equal(h.elements.trafficChart.context.calls.filter(call => call.name === 'arc').length, 0);
  const safe = JSON.parse(vm.runInContext('JSON.stringify(trafficChartState.buckets)', h.sandbox));
  assert.deepEqual(Object.keys(safe[0]).sort(), ['bytes_in', 'bytes_out', 'minute_start_unix', 'requests']);
  assert.equal(safe.length, 2);
  assert.equal(safe[0].minute_start_unix, 60);
  assert.ok(!h.elements['traffic-point-detail'].innerHTML.includes('secret'));
});

test('all four range cards sum every API bucket before and after point selection', async () => {
  const contracts = {
    60: { label: '最近 1 小时', incoming: 40, outgoing: 60, requests: 3, buckets: [bucket(1, 10, 20, 1), bucket(2, 30, 40, 2)] },
    360: { label: '最近 6 小时', incoming: 10, outgoing: 12, requests: 14, buckets: [bucket(3, 3, 4, 5), bucket(4, 7, 8, 9)] },
    1440: { label: '最近 24 小时', incoming: 400, outgoing: 600, requests: 3, buckets: [bucket(5, 100, 200, 1), bucket(6, 300, 400, 2)] },
    10080: { label: '最近 7 天', incoming: 900, outgoing: 400, requests: 23, buckets: [bucket(7, 500, 100, 11), bucket(8, 400, 300, 12)] },
  };
  const h = harness(async url => {
    const match = /minutes=(\d+)/.exec(String(url));
    return okJson(contracts[match[1]].buckets);
  });

  for (const [minutes, contract] of Object.entries(contracts)) {
    h.elements['traffic-hours-select'].value = minutes;
    await vm.runInContext('loadTrafficChart({ resetSelection: true })', h.sandbox);
    const beforeSelection = h.elements['traffic-totals'].innerHTML;
    assert.ok(beforeSelection.includes(`${contract.label} · 入站总量</div><div class="total-value">${contract.incoming} B</div>`));
    assert.ok(beforeSelection.includes(`${contract.label} · 出站总量</div><div class="total-value">${contract.outgoing} B</div>`));
    assert.ok(beforeSelection.includes(`${contract.label} · 请求总数</div><div class="total-value">${contract.requests}</div>`));
    assert.equal(vm.runInContext('trafficChartState.selectedTimestamp', h.sandbox), null);

    vm.runInContext('selectTrafficPoint(0)', h.sandbox);
    assert.equal(h.elements['traffic-totals'].innerHTML, beforeSelection);
    assert.equal(vm.runInContext('trafficChartState.selectedTimestamp', h.sandbox), contract.buckets[0].minute_start_unix);
    assert.match(h.elements['traffic-point-detail'].innerHTML, new RegExp(`请求 ${contract.buckets[0].requests}`));
  }
});

test('site and range resets clear a pinned minute immediately and after the response', async () => {
  const waiting = [];
  let request = 0;
  const h = harness(async () => {
    request++;
    if (request === 1) return okJson([bucket(60, 1, 2, 3), bucket(120, 4, 5, 6)]);
    return new Promise(resolve => waiting.push(resolve));
  });
  await vm.runInContext('loadTrafficChart()', h.sandbox);
  vm.runInContext('selectTrafficPoint(1)', h.sandbox);

  h.elements.trafficChart.context.calls.length = 0;
  h.elements['traffic-hours-select'].value = '60';
  const rangeRequest = vm.runInContext('loadTrafficChart({ resetSelection: true })', h.sandbox);
  assert.equal(vm.runInContext('trafficChartState.selectedTimestamp', h.sandbox), null);
  assert.equal(h.elements['traffic-point-detail'].hidden, true);
  waiting.shift()(okJson([bucket(180, 7, 8, 9), bucket(240, 10, 11, 12)]));
  await rangeRequest;
  assert.equal(vm.runInContext('trafficChartState.selectedTimestamp', h.sandbox), null);
  assert.equal(countVerticalSegments(h.elements.trafficChart.context.calls), 0);

  vm.runInContext('selectTrafficPoint(1)', h.sandbox);
  h.elements.trafficChart.context.calls.length = 0;
  h.elements['traffic-site-select'].value = '2';
  const siteRequest = vm.runInContext('loadTrafficChart({ resetSelection: true })', h.sandbox);
  assert.equal(vm.runInContext('trafficChartState.selectedTimestamp', h.sandbox), null);
  assert.equal(h.elements['traffic-point-detail'].hidden, true);
  waiting.shift()(okJson([bucket(300, 13, 14, 15)]));
  await siteRequest;
  assert.equal(vm.runInContext('trafficChartState.selectedTimestamp', h.sandbox), null);
  assert.equal(countVerticalSegments(h.elements.trafficChart.context.calls), 0);
});
test('zero-traffic chart renders defined byte-axis labels', async () => {
  const h = harness(async () => okJson([bucket(60, 0, 0, 0)]));
  const labels = [];
  h.elements.trafficChart.getContext = () => ({
    ...makeContext(),
    fillText(value) { labels.push(String(value)); },
  });
  await vm.runInContext('loadTrafficChart()', h.sandbox);
  assert.equal(labels.slice(0, 5).some(label => label.includes('undefined')), false);
  assert.deepEqual(labels.slice(0, 5), ['5 B', '3 B', '2 B', '1 B', '0 B']);
});

test('traffic series use bounded five-point cubic smoothing without mutating source buckets', async () => {
  const points = [
    bucket(60, 0, 300, 1), bucket(120, 400, 50, 2),
    bucket(180, 25, 275, 3), bucket(240, 350, 100, 4),
  ];
  const h = harness(async () => okJson(points));
  await vm.runInContext('loadTrafficChart()', h.sandbox);
  const before = vm.runInContext('JSON.stringify(trafficChartState.buckets)', h.sandbox);
  const smoothedIncoming = JSON.parse(vm.runInContext(
    "JSON.stringify([0, 1, 2, 3].map(index => smoothedTrafficValue(trafficChartState.buckets, 'bytes_in', index)))",
    h.sandbox,
  ));
  assert.deepEqual(smoothedIncoming, [0, 178.125, 218.75, 350]);

  const calls = h.elements.trafficChart.context.calls;
  const curves = calls.filter(call => call.name === 'bezierCurveTo');
  assert.equal(curves.length, 2 * (points.length - 1));
  assert.equal(calls.filter(call => call.name === 'quadraticCurveTo').length, 0);
  assert.equal(calls.filter(call => call.name === 'lineTo').length, 5);

  const seriesStarts = calls.filter(call => call.name === 'moveTo').slice(-2);
  assert.equal(seriesStarts.length, 2);
  for (let series = 0; series < 2; series++) {
    let previousX = seriesStarts[series].args[0];
    let previousY = seriesStarts[series].args[1];
    for (const curve of curves.slice(series * (points.length - 1), (series + 1) * (points.length - 1))) {
      const [control1X, control1Y, control2X, control2Y, currentX, currentY] = curve.args;
      assert.ok(curve.args.every(Number.isFinite));
      assert.ok(control1X >= previousX && control1X <= currentX);
      assert.ok(control2X >= previousX && control2X <= currentX);
      const lowerY = Math.min(previousY, currentY), upperY = Math.max(previousY, currentY);
      assert.ok(control1Y >= lowerY && control1Y <= upperY);
      assert.ok(control2Y >= lowerY && control2Y <= upperY);
      assert.ok(currentX >= 64 && currentX <= 768);
      assert.ok(currentY >= 20 && currentY <= 236);
      previousX = currentX;
      previousY = currentY;
    }
  }

  vm.runInContext('drawTrafficChart(trafficChartState.buckets)', h.sandbox);
  assert.equal(vm.runInContext('JSON.stringify(trafficChartState.buckets)', h.sandbox), before);
  assert.equal(JSON.parse(before).length, points.length);
});

test('mobile chart limits timestamp labels before they overlap', async () => {
  const h = harness(async () => okJson([
    bucket(60, 1, 2, 3), bucket(120, 4, 5, 6), bucket(180, 7, 8, 9),
    bucket(240, 10, 11, 12), bucket(300, 13, 14, 15),
  ]));
  h.elements.trafficChart.rect.width = 328;
  h.elements.trafficChart.parentElement.clientWidth = 328;
  await vm.runInContext('loadTrafficChart()', h.sandbox);
  const mobileLabels = h.elements.trafficChart.context.calls.filter(call => call.name === 'fillText');
  assert.equal(mobileLabels.length, 7, 'five y-axis labels plus two timestamp labels');

  h.elements.trafficChart.context.calls.length = 0;
  h.elements.trafficChart.rect.width = 500;
  vm.runInContext('drawTrafficChart(trafficChartState.buckets)', h.sandbox);
  const widerLabels = h.elements.trafficChart.context.calls.filter(call => call.name === 'fillText');
  assert.equal(widerLabels.length, 8, 'a wider chart can show three timestamp labels');
});

test('loading, empty, error, and retry states are explicit', async () => {
  let reject;
  const pendingResponse = new Promise((resolve, rejectPromise) => { reject = rejectPromise; });
  const h = harness(async () => pendingResponse);
  const pending = vm.runInContext('loadTrafficChart()', h.sandbox);
  assert.match(h.elements['traffic-chart-status'].className, /loading/);
  reject(new Error('offline'));
  await pending;
  assert.match(h.elements['traffic-chart-status'].className, /error/);
  assert.equal(h.elements['traffic-chart-retry'].hidden, false);
  assert.equal(vm.runInContext('typeof trafficRetryAction', h.sandbox), 'function');

  h.sandbox.fetch = async url => { h.calls.push(String(url)); return okJson([bucket(60, 0, 0, 0)]); };
  await vm.runInContext('trafficRetryAction()', h.sandbox);
  assert.match(h.elements['traffic-chart-status'].className, /empty/);
  assert.match(h.elements['traffic-chart-status-message'].textContent, /暂无/);
});

test('stale response cannot paint after site selection changes', async () => {
  let resolve;
  const gate = new Promise(next => { resolve = next; });
  const h = harness(async () => gate);
  const pending = vm.runInContext('loadTrafficChart()', h.sandbox);
  h.elements['traffic-site-select'].value = '2';
  resolve(okJson([bucket(60, 99, 88, 1)]));
  await pending;
  assert.equal(h.elements['traffic-totals'].innerHTML, '');
  assert.equal(h.elements.trafficChart.width, undefined);
});

test('refresh is one 15-second timer and teardown clears it and invalidates late requests', async () => {
  let resolve;
  const gate = new Promise(next => { resolve = next; });
  const h = harness(async () => gate);
  vm.runInContext('startTrafficRefresh()', h.sandbox);
  assert.equal(h.intervals.length, 1);
  assert.equal(h.intervals[0].ms, 15000);
  const pending = vm.runInContext('loadTrafficChart()', h.sandbox);
  vm.runInContext('stopTrafficRefresh()', h.sandbox);
  assert.deepEqual(h.cleared, [h.intervals[0].id]);
  resolve(okJson([bucket(60, 1, 2, 3)]));
  await pending;
  assert.equal(h.elements['traffic-totals'].innerHTML, '');
});
test('stale site list cannot overwrite a newer traffic-page instance', async () => {
  let resolveFirst;
  let siteRequests = 0;
  const h = harness(async url => {
    if (String(url) === '/api/sites') {
      siteRequests++;
      if (siteRequests === 1) return new Promise(resolve => { resolveFirst = resolve; });
      return okJson([{ id: 2, name: 'Fresh' }]);
    }
    return okJson([]);
  });
  const stale = vm.runInContext('loadTrafficSites()', h.sandbox);
  vm.runInContext('stopTrafficRefresh()', h.sandbox);
  const fresh = vm.runInContext('loadTrafficSites()', h.sandbox);
  await fresh;
  resolveFirst(okJson([{ id: 1, name: 'Stale' }]));
  await stale;
  assert.match(h.elements['traffic-site-select'].innerHTML, /Fresh/);
  assert.doesNotMatch(h.elements['traffic-site-select'].innerHTML, /Stale/);
});

test('pointermove without a press never selects a minute', async () => {
  const h = harness(async url => String(url) === '/api/sites'
    ? okJson([{ id: 1, name: 'Ready' }])
    : okJson([bucket(60, 1, 2, 3), bucket(120, 4, 5, 6), bucket(180, 7, 8, 9)]));
  vm.runInContext('renderTraffic()', h.sandbox);
  await flushTraffic();
  h.elements.trafficChart.dispatch('pointermove', { pointerId: 5, pointerType: 'mouse', clientX: 400 });
  assert.equal(vm.runInContext('trafficChartState.selectedTimestamp', h.sandbox), null);
  assert.equal(h.elements['traffic-point-detail'].hidden, true);
  assert.equal(h.elements.trafficChart.focused, undefined);
  assert.deepEqual(h.elements.trafficChart.captureCalls, []);
});

test('press-drag scrubbing clamps exact buckets and clears every capture lifecycle', async () => {
  const h = harness(async url => String(url) === '/api/sites'
    ? okJson([{ id: 1, name: 'Ready' }])
    : okJson([bucket(60, 1, 2, 3), bucket(120, 4, 5, 6), bucket(180, 7, 8, 9)]));
  vm.runInContext('renderTraffic()', h.sandbox);
  await flushTraffic();
  const canvas = h.elements.trafficChart;

  const touchDown = { pointerId: 10, pointerType: 'touch', button: 0, clientX: -500 };
  canvas.dispatch('pointerdown', touchDown);
  assert.equal(vm.runInContext('trafficChartState.selectedTimestamp', h.sandbox), 60);
  assert.equal(vm.runInContext('trafficChartState.scrubPointerId', h.sandbox), 10);
  assert.equal(canvas.hasPointerCapture(10), true);
  assert.equal(canvas.classList.contains('is-scrubbing'), true);
  assert.equal(canvas.focused, true);
  assert.equal(touchDown.defaultPrevented, true);

  canvas.dispatch('pointermove', { pointerId: 10, pointerType: 'touch', clientX: 5000 });
  assert.equal(vm.runInContext('trafficChartState.selectedTimestamp', h.sandbox), 180);
  assert.match(h.elements['traffic-point-detail'].innerHTML, /请求 9/);
  canvas.dispatch('pointermove', { pointerId: 99, pointerType: 'touch', clientX: -500 });
  assert.equal(vm.runInContext('trafficChartState.selectedTimestamp', h.sandbox), 180);
  canvas.dispatch('pointerup', { pointerId: 10, pointerType: 'touch', clientX: 5000 });
  assert.equal(vm.runInContext('trafficChartState.scrubPointerId', h.sandbox), null);
  assert.equal(canvas.hasPointerCapture(10), false);
  assert.equal(canvas.classList.contains('is-scrubbing'), false);
  canvas.dispatch('pointermove', { pointerId: 10, pointerType: 'touch', clientX: -500 });
  assert.equal(vm.runInContext('trafficChartState.selectedTimestamp', h.sandbox), 180);

  canvas.dispatch('pointerdown', { pointerId: 11, pointerType: 'mouse', button: 0, clientX: 400 });
  assert.equal(vm.runInContext('trafficChartState.selectedTimestamp', h.sandbox), 120);
  canvas.dispatch('pointercancel', { pointerId: 11, pointerType: 'mouse' });
  assert.equal(vm.runInContext('trafficChartState.scrubPointerId', h.sandbox), null);
  assert.equal(canvas.classList.contains('is-scrubbing'), false);

  canvas.dispatch('pointerdown', { pointerId: 12, pointerType: 'mouse', button: 2, clientX: 5000 });
  assert.equal(vm.runInContext('trafficChartState.selectedTimestamp', h.sandbox), 120);
  assert.equal(canvas.hasPointerCapture(12), false);

  canvas.dispatch('pointerdown', { pointerId: 13, pointerType: 'touch', button: 0, clientX: -500 });
  assert.equal(canvas.hasPointerCapture(13), true);
  canvas.losePointerCapture(13);
  assert.equal(vm.runInContext('trafficChartState.scrubPointerId', h.sandbox), null);
  assert.equal(canvas.classList.contains('is-scrubbing'), false);
  assert.deepEqual(canvas.captureCalls, [10, 11, 13]);
  assert.deepEqual(canvas.releaseCalls, [10, 11]);
});

test('Left Right Home End navigate the pinned point', async () => {
  const h = harness(async () => okJson([bucket(60, 1, 1, 1), bucket(120, 2, 2, 2), bucket(180, 3, 3, 3)]));
  await vm.runInContext('loadTrafficChart()', h.sandbox);
  assert.equal(vm.runInContext('trafficChartState.selectedTimestamp', h.sandbox), null);
  let prevented = 0;
  h.sandbox.keyEvent = { key: 'ArrowLeft', preventDefault() { prevented++; } };
  vm.runInContext('navigateTrafficPoint(keyEvent)', h.sandbox);
  assert.equal(vm.runInContext('trafficChartState.selectedTimestamp', h.sandbox), 120);
  h.sandbox.keyEvent.key = 'Home'; vm.runInContext('navigateTrafficPoint(keyEvent)', h.sandbox);
  assert.equal(vm.runInContext('trafficChartState.selectedTimestamp', h.sandbox), 60);
  h.sandbox.keyEvent.key = 'End'; vm.runInContext('navigateTrafficPoint(keyEvent)', h.sandbox);
  assert.equal(vm.runInContext('trafficChartState.selectedTimestamp', h.sandbox), 180);
  assert.equal(prevented, 3);
});

test('the 15-second same-series refresh preserves a selected timestamp', async () => {
  let call = 0;
  const h = harness(async () => {
    call++;
    return okJson([bucket(60, call, 0, call), bucket(120, call, 0, call), bucket(180, call, 0, call)]);
  });
  vm.runInContext('startTrafficRefresh()', h.sandbox);
  await vm.runInContext('loadTrafficChart()', h.sandbox);
  assert.equal(vm.runInContext('trafficChartState.selectedTimestamp', h.sandbox), null);
  vm.runInContext('selectTrafficPoint(1)', h.sandbox);
  h.intervals[0].cb();
  await flushTraffic();
  assert.equal(call, 2);
  assert.equal(vm.runInContext('trafficChartState.selectedTimestamp', h.sandbox), 120);
  assert.match(h.elements['traffic-point-detail'].innerHTML, /请求 2/);
});

test('same-series refresh keeps a newer selection made while its request is pending', async () => {
  let call = 0;
  let resolveRefresh;
  const points = [bucket(60, 1, 0, 1), bucket(120, 2, 0, 2), bucket(180, 3, 0, 3)];
  const h = harness(async () => {
    call++;
    if (call === 1) return okJson(points);
    return new Promise(resolve => { resolveRefresh = resolve; });
  });
  await vm.runInContext('loadTrafficChart()', h.sandbox);
  vm.runInContext('selectTrafficPoint(0)', h.sandbox);

  const refresh = vm.runInContext('loadTrafficChart()', h.sandbox);
  vm.runInContext('selectTrafficPoint(2)', h.sandbox);
  resolveRefresh(okJson([bucket(60, 10, 0, 10), bucket(120, 20, 0, 20), bucket(180, 30, 0, 30)]));
  await refresh;

  assert.equal(vm.runInContext('trafficChartState.selectedTimestamp', h.sandbox), 180);
  assert.match(h.elements['traffic-point-detail'].innerHTML, /请求 30/);
});

test('traffic interaction stays press-only, smooth, and touch-scrubbable', () => {
  const source = fs.readFileSync(path.join(STATIC_JS, 'pages/traffic.js'), 'utf8');
  const css = fs.readFileSync(path.join(__dirname, '..', 'web', 'static', 'css', 'style.css'), 'utf8');
  assert.ok(!/<table/i.test(source));
  assert.ok(!/mousemove|mouseover|mouseenter/.test(source));
  assert.match(source, /pointerdown/);
  assert.match(source, /pointermove/);
  assert.match(source, /pointercancel/);
  assert.match(source, /lostpointercapture/);
  assert.match(source, /setPointerCapture/);
  assert.match(source, /bezierCurveTo/);
  assert.match(source, /ArrowLeft/);
  assert.match(css, /canvas#trafficChart\s*\{[^}]*touch-action:\s*none/s);
  assert.match(css, /canvas#trafficChart\.is-scrubbing/);
});
