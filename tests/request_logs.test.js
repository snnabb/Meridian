const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

function loadRequestLogHelpers() {
  const sandbox = { console, Date, Number, String, Math };
  vm.createContext(sandbox);
  vm.runInContext(
    fs.readFileSync(path.join(__dirname, '..', 'web', 'static', 'js', 'pages', 'request-logs.js'), 'utf8'),
    sandbox,
  );
  return sandbox;
}

test('request log table keeps P2 fields without COLO columns', () => {
  const source = fs.readFileSync(
    path.join(__dirname, '..', 'web', 'static', 'js', 'pages', 'request-logs.js'),
    'utf8',
  );
  for (const heading of ['节点', '资源类别', '状态', '客户端 IP', '客户端 UA', '上游 UA', '后端地址', '时间线']) {
    assert.match(source, new RegExp(`<th[^>]*>${heading}</th>`));
  }
  assert.doesNotMatch(source, /<th>入站机房<\/th>/);
  assert.doesNotMatch(source, /<th>出站机房<\/th>/);
  assert.match(source, /class="request-log-table"/);
});

test('global log write settings cover every visible request log column', () => {
  const source = fs.readFileSync(
    path.join(__dirname, '..', 'web', 'static', 'js', 'pages', 'global-settings.js'),
    'utf8',
  );
  for (const [id, property] of [
    ['setting-write-node', 'log_write_node'],
    ['setting-write-category', 'log_write_category'],
    ['setting-write-status', 'log_write_status'],
    ['setting-write-ip', 'log_write_client_ip'],
    ['setting-write-ua', 'log_write_ua'],
    ['setting-write-upstream-ua', 'log_write_upstream_ua'],
    ['setting-write-backend-address', 'log_write_backend_address'],
    ['setting-write-timeline', 'log_write_timeline'],
  ]) {
    assert.match(source, new RegExp(id));
    assert.match(source, new RegExp(`s\\.${property} = checkedSetting`));
  }
});

test('global log resource settings cover the complete request taxonomy', () => {
  const source = fs.readFileSync(
    path.join(__dirname, '..', 'web', 'static', 'js', 'pages', 'global-settings.js'),
    'utf8',
  );
  for (const [id, property] of [
    ['setting-write-playback', 'log_write_playback'],
    ['setting-write-video', 'log_write_video'],
    ['setting-write-image', 'log_write_image'],
    ['setting-write-metadata', 'log_write_metadata'],
    ['setting-write-subtitle', 'log_write_subtitle'],
    ['setting-write-asset', 'log_write_asset'],
    ['setting-write-websocket', 'log_write_websocket'],
    ['setting-write-api', 'log_write_api'],
    ['setting-write-auth', 'log_write_auth'],
  ]) {
    assert.match(source, new RegExp(id));
    assert.match(source, new RegExp(`s\\.${property} = checkedSetting`));
  }
});

test('global settings rendering stays scoped to the active page and keeps cached content visible', () => {
  const source = fs.readFileSync(
    path.join(__dirname, '..', 'web', 'static', 'js', 'pages', 'global-settings.js'),
    'utf8',
  );
  assert.match(source, /function bindGlobalSettingsNav\(root = document\)/);
  assert.match(source, /if \(globalSettingsCache\) paintGlobalSettings\(page\);/);
  assert.match(source, /const content = page\.querySelector\('\.settings-content'\);/);
  assert.match(source, /const nav = page\.querySelector\('\.settings-section-nav'\);/);
  assert.doesNotMatch(source, /const content = document\.querySelector\('\.settings-content'\);/);
  assert.match(source, /generation !== globalSettingsLoadGeneration/);
});

test('request log helpers map categories and status colors', () => {
  const sandbox = loadRequestLogHelpers();
  assert.equal(sandbox.requestLogCategoryLabel('playback'), '播放信息');
  assert.equal(sandbox.requestLogCategoryLabel('playback_sync'), '播放状态同步');
  assert.equal(sandbox.requestLogCategoryLabel('video'), '视频流');
  assert.equal(sandbox.requestLogCategoryLabel('stream'), '主视频流');
  assert.equal(sandbox.requestLogCategoryLabel('manifest'), '播放清单');
  assert.equal(sandbox.requestLogCategoryLabel('segment'), '媒体分片');
  assert.equal(sandbox.requestLogCategoryLabel('image'), '图片海报');
  assert.equal(sandbox.requestLogCategoryLabel('metadata'), '媒体元数据');
  assert.equal(sandbox.requestLogCategoryLabel('subtitle'), '字幕');
  assert.equal(sandbox.requestLogCategoryLabel('asset'), '静态资源');
  assert.equal(sandbox.requestLogCategoryLabel('websocket'), 'WebSocket');
  assert.equal(sandbox.requestLogCategoryLabel('api'), '常规 API');
  assert.equal(sandbox.requestLogCategoryLabel('auth'), '用户认证');
  assert.equal(sandbox.requestLogCategoryLabel(''), '—');
  assert.equal(sandbox.requestLogStatusClass(200), 'request-log-status-ok');
  assert.equal(sandbox.requestLogStatusClass(404), 'request-log-status-client');
  assert.equal(sandbox.requestLogStatusClass(503), 'request-log-status-server');
});

test('request log panel exposes only concrete resource-category filters and live refresh', () => {
  const source = fs.readFileSync(
    path.join(__dirname, '..', 'web', 'static', 'js', 'pages', 'request-logs.js'),
    'utf8',
  );
  for (const category of ['playback', 'playback_sync', 'video', 'image', 'asset', 'api', 'auth']) {
    assert.match(source, new RegExp(`value="${category}"`));
  }
  assert.match(source, /value="2xx"/);
  assert.match(source, /value="3xx"/);
  assert.match(source, /value="4xx"/);
  assert.match(source, /value="5xx"/);
  assert.doesNotMatch(source, /request-log-category-pills|request-log-status-pills/);
  assert.match(source, /requestLogRefreshTimer = setInterval/);
  assert.match(source, /Router\.current === 'request-logs'/);
  assert.match(source, /class="request-log-ip mono"/);
  assert.match(source, /class="request-log-region"/);
  assert.match(source, /requestLogLoading/);
  assert.match(source, /previousScrollTop/);
  assert.match(source, /previousScrollTop \+ addedHeight/);
  assert.doesNotMatch(source, /if \(Router\.current === 'request-logs'\) loadRequestLogs\(\);/);
  assert.match(source, /id="request-cache-clear"/);
  assert.match(source, /API\.clearAssetCache\(\)/);
});

test('node-name search is retried with the latest value after an automatic refresh is in flight', async () => {
  const page = { innerHTML: '' };
  const body = {
    innerHTML: '',
    closest() { return scroller; },
    querySelector() { return null; },
  };
  const scroller = { scrollTop: 0, scrollHeight: 0 };
  const elements = {
    'page-request-logs': page,
    'request-log-from': { value: '2026-08-05' },
    'request-log-to': { value: '2026-08-06' },
    'request-log-search': { value: '', oninput: null },
    'request-log-body': body,
    'request-log-summary': { textContent: '' },
    'request-log-refresh': { onclick: null },
    'request-log-clear': { onclick: null },
    'request-cache-clear': { onclick: null },
  };
  const timers = [];
  const calls = [];
  let resolveInitial;
  const initial = new Promise(resolve => { resolveInitial = resolve; });
  let callCount = 0;
  const sandbox = {
    console,
    Date,
    Number,
    String,
    Math,
    document: {
      getElementById(id) { return elements[id] || null; },
      querySelectorAll() { return []; },
    },
    Router: { current: 'request-logs' },
    API: {
      getRequestLogs(filters) {
        calls.push({ ...filters });
        callCount += 1;
        return callCount === 1 ? initial : Promise.resolve({ logs: [], dropped_logs: 0 });
      },
      clearRequestLogs() { return Promise.resolve(); },
      clearAssetCache() { return Promise.resolve(); },
    },
    Toast: { error() {}, success() {} },
    esc(value) { return String(value); },
    confirm() { return true; },
    setTimeout(callback) { timers.push(callback); return timers.length; },
    clearTimeout() {},
    setInterval() { return 1; },
    clearInterval() {},
  };
  vm.createContext(sandbox);
  vm.runInContext(
    fs.readFileSync(path.join(__dirname, '..', 'web', 'static', 'js', 'pages', 'request-logs.js'), 'utf8'),
    sandbox,
  );

  vm.runInContext('renderRequestLogs()', sandbox);
  await Promise.resolve();
  assert.equal(calls.length, 1);
  assert.equal(calls[0].q, '');

  elements['request-log-search'].value = 'edge-renamed';
  elements['request-log-search'].oninput();
  assert.equal(timers.length, 1);
  timers.shift()();

  resolveInitial({ logs: [], dropped_logs: 0 });
  await new Promise(resolve => setImmediate(resolve));
  await Promise.resolve();

  assert.equal(calls.length, 2);
  assert.equal(calls[1].q, 'edge-renamed');
});

test('request log date range covers the selected local days', () => {
  const sandbox = loadRequestLogHelpers();
  const range = sandbox.requestLogRangeMilliseconds('2026-08-04', '2026-08-05');
  assert.ok(Number.isFinite(range.from_ms));
  assert.ok(Number.isFinite(range.to_ms));
  assert.equal(range.to_ms - range.from_ms, (2 * 24 * 60 * 60 * 1000) - 1);
});

test('request log timeline heading aligns with timeline values', () => {
  const source = fs.readFileSync(
    path.join(__dirname, '..', 'web', 'static', 'css', 'style.css'),
    'utf8',
  );
  assert.match(source, /\.request-log-table th\[data-log-field="timeline"\],\s*\.request-log-table td\[data-log-field="timeline"\]\s*\{\s*text-align:\s*right;\s*\}/);
});

test('request log UA width is applied to the live table and handles drag completion', () => {
  const source = fs.readFileSync(
    path.join(__dirname, '..', 'web', 'static', 'js', 'pages', 'request-logs.js'),
    'utf8',
  );
  assert.match(source, /table\.style\.setProperty\('--request-log-ua-width', cssWidth\)/);
  assert.match(source, /col\.request-log-col-ua, col\.request-log-col-upstream-ua, th\[data-log-field="ua"\], th\[data-log-field="upstream-ua"\]/);
  assert.match(source, /uaWidthInput\.oninput = applyUAWidth/);
  assert.match(source, /uaWidthInput\.onchange = applyUAWidth/);
});

test('request log UA width slider stays compact', () => {
  const source = fs.readFileSync(
    path.join(__dirname, '..', 'web', 'static', 'css', 'style.css'),
    'utf8',
  );
  assert.match(source, /\.request-log-ua-width-control\s*\{[^}]*max-width:\s*380px;/s);
  assert.match(source, /\.request-log-ua-width-control input\[type="range"\]\s*\{[^}]*max-width:\s*220px;/s);
});

test('request log filter chips keep centered labels and balanced spacing', () => {
  const source = fs.readFileSync(
    path.join(__dirname, '..', 'web', 'static', 'css', 'style.css'),
    'utf8',
  );
  assert.match(source, /\.request-log-filter-row\s*\{[^}]*padding:\s*10px 0;/s);
  assert.match(source, /\.request-log-pill\s*\{[^}]*display:\s*inline-flex;[^}]*align-items:\s*center;[^}]*justify-content:\s*center;[^}]*padding:\s*7px 16px;[^}]*text-align:\s*center;/s);
});

test('mobile request log table uses fixed readable columns without overlap', () => {
  const source = fs.readFileSync(
    path.join(__dirname, '..', 'web', 'static', 'css', 'style.css'),
    'utf8',
  );
  assert.match(source, /\.request-log-table col\.request-log-col-node,\s*\.request-log-table th:nth-child\(1\)\s*\{\s*width:\s*112px !important;/s);
  assert.match(source, /\.request-log-table col\.request-log-col-category,\s*\.request-log-table th:nth-child\(2\)\s*\{\s*width:\s*144px !important;/s);
  assert.match(source, /\.request-log-table col\.request-log-col-status,\s*\.request-log-table th:nth-child\(3\)\s*\{\s*width:\s*76px !important;/s);
  assert.match(source, /\.request-log-table col\.request-log-col-ip,\s*\.request-log-table th:nth-child\(4\)\s*\{\s*width:\s*170px !important;/s);
  assert.match(source, /\.request-log-table tbody tr\s*\{\s*height:\s*58px;/s);
  assert.match(source, /\.request-log-table th,\s*\.request-log-table td\s*\{[^}]*overflow:\s*hidden;[^}]*padding:\s*10px 12px;[^}]*font-size:\s*13px;[^}]*line-height:\s*1\.3;/s);
  assert.match(source, /\.request-log-category,\s*\.request-log-node,\s*\.request-log-status\s*\{\s*white-space:\s*nowrap;/s);
  assert.match(source, /\.request-log-table th\s*\{[^}]*font-size:\s*12px;[^}]*white-space:\s*nowrap;/s);
});

test('request log timeline uses concise Chinese relative time', () => {
  const sandbox = loadRequestLogHelpers();
  const now = Date.parse('2026-08-05T12:00:00Z');
  assert.equal(sandbox.requestLogRelativeTime(0, now), '—');
  assert.equal(sandbox.requestLogRelativeTime(now - 30_000, now), '刚刚');
  assert.equal(sandbox.requestLogRelativeTime(now - 5 * 60_000, now), '5 分钟前');
  assert.equal(sandbox.requestLogRelativeTime(now - 2 * 60 * 60_000, now), '2 小时前');
  assert.equal(sandbox.requestLogRelativeTime(now - 3 * 24 * 60 * 60_000, now), '3 天前');
});
