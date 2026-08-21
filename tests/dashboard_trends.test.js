'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const dashboardSource = fs.readFileSync(
  path.join(__dirname, '..', 'web', 'static', 'js', 'pages', 'dashboard.js'),
  'utf8',
);

test('dashboard trend controls expose a minute-precision custom range', () => {
  assert.match(dashboardSource, /<option value="month">本月<\/option>/);
  assert.match(dashboardSource, /<option value="custom">自定义<\/option>/);
  assert.match(dashboardSource, /type="datetime-local"[^>]*id="dashboard-trend-start"[^>]*step="60"/);
  assert.match(dashboardSource, /type="datetime-local"[^>]*id="dashboard-trend-end"[^>]*step="60"/);
  assert.match(dashboardSource, /id="dashboard-trend-apply"/);
});

test('dashboard custom range validates ordering before loading', () => {
  assert.match(dashboardSource, /结束时间必须晚于开始时间/);
  assert.match(dashboardSource, /dashboardTrendState\.customStart = current\.start/);
  assert.match(dashboardSource, /dashboardTrendState\.customEnd = current\.end/);
});

test('dashboard trend tooltip lists all site names or only the selected site', () => {
  assert.match(dashboardSource, /site_series/);
  assert.match(dashboardSource, /dashboardTrendState\.siteId === 'all'/);
  assert.match(dashboardSource, /dashboardTrendMetricLine/);
  assert.match(dashboardSource, /series\.site_name/);
  assert.match(dashboardSource, /selectedOption\?\.textContent/);
});

test('dashboard realtime trend keeps historical points after a page refresh', () => {
  assert.match(dashboardSource, /function dashboardTrendRealtimeOffset\(\)/);
  assert.match(dashboardSource, /historicalPoints\.slice\(0, offset\)\.concat\(realtimePoints\)/);
  assert.match(dashboardSource, /if \(!realtimePoints\.length \|\| !historicalPoints\.length\) return realtimePoints\.length \? realtimePoints : historicalPoints/);
});

test('dashboard trend rendering clamps invalid values and bounds smoothing controls', () => {
  assert.match(dashboardSource, /function dashboardSafeNonNegative\(value\)/);
  assert.match(dashboardSource, /Number\.isFinite\(numeric\)/);
  assert.match(dashboardSource, /Math\.max\(minY, Math\.min\(maxY/);
  assert.match(dashboardSource, /if \(liveMap\.size > 0\) appendRealtimeTrendSample/);
  assert.match(dashboardSource, /const unit = units\[i\] \|\| units\[0\]/);
  assert.match(dashboardSource, /bucketSeconds > 0 && bucketSeconds < 3600/);
});

test('dashboard renders a numeric zero over the initial placeholder', () => {
  const element = { style: {}, textContent: '—' };
  const sandbox = {
    document: {
      getElementById(id) {
        return id === 's-total' ? element : null;
      },
    },
    setTimeout(callback) { callback(); },
  };
  vm.runInNewContext(dashboardSource, sandbox, { filename: 'dashboard.js' });

  sandbox.animateValue('s-total', 0);
  assert.equal(element.textContent, '0');
});
