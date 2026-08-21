'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const ROOT = path.join(__dirname, '..');
const indexSource = fs.readFileSync(path.join(ROOT, 'web/static/index.html'), 'utf8');
const appSource = fs.readFileSync(path.join(ROOT, 'web/static/js/app.js'), 'utf8');
const dashboardSource = fs.readFileSync(path.join(ROOT, 'web/static/js/pages/dashboard.js'), 'utf8');
const cssSource = fs.readFileSync(path.join(ROOT, 'web/static/css/style.css'), 'utf8');

test('GitHub project link points to the official repository', () => {
  assert.match(indexSource, /class="github-project-link" href="https:\/\/github\.com\/snnabb\/Meridian"/);
  assert.doesNotMatch(indexSource, /github\.com\/chanhui800\/Meridian/);
});

test('site modal resets overlay and content scroll on every open', () => {
  assert.match(appSource, /function resetModalScroll\(\)/);
  assert.match(appSource, /overlay\.scrollTop = 0/);
  assert.match(appSource, /body\.scrollTop = 0/);
  assert.match(appSource, /requestAnimationFrame\(resetModalScroll\)/);
});

test('site modal applies and removes its responsive modal class', () => {
  assert.match(appSource, /activeModalClass/);
  assert.match(appSource, /modal\.classList\.add\(activeModalClass\)/);
  assert.match(appSource, /modal\.classList\.remove\(activeModalClass\)/);
});

test('dashboard trends trace smooth curves instead of only straight segments', () => {
  assert.match(dashboardSource, /function dashboardTraceSmoothLine\(ctx, points\)/);
  assert.match(dashboardSource, /ctx\.bezierCurveTo\(/);
  assert.match(dashboardSource, /dashboardTraceSmoothLine\(ctx, pointsOnCanvas\)/);
});

test('mobile navigation keeps the header and drawer available', () => {
  assert.match(cssSource, /@media \(max-width: 768px\)[\s\S]*?\.app-header \{[\s\S]*?display: flex;[\s\S]*?\.sidebar \{[\s\S]*?display: flex;/);
  assert.match(cssSource, /#app-shell\.sidebar-expanded \.sidebar \{ transform: translateX\(0\); \}/);
});
test('upstream header rows do not inherit the browser fieldset frame', () => {
  assert.match(cssSource, /\.form-list-row\.upstream-header-row[\s\S]*?border: 0;/);
  assert.match(cssSource, /\.site-config-modal \.upstream-line-labels,[\s\S]*?grid-template-columns: 76px minmax\(150px, \.8fr\)/);
  assert.match(cssSource, /grid-template-areas: "enabled" "name" "address" "port" "latency" "actions"/);
});

test('dashboard assets use a cache-busting revision after chart and mobile fixes', () => {
  assert.match(indexSource, /(?:\?v=1\.12\.2|v1\.12\.2)/);
});

test('desktop sidebar uses the state variable for real width changes', () => {
  assert.match(cssSource, /@media \(min-width: 769px\)[\s\S]*?#app-shell\.sidebar-expanded \{[\s\S]*?--sidebar-w: 208px;/);
  assert.match(cssSource, /#app-shell\.active \.sidebar \{[\s\S]*?width: var\(--sidebar-w\) !important;/);
  assert.match(cssSource, /#app-shell\.active \.main \{[\s\S]*?margin-left: var\(--sidebar-w\) !important;/);
  assert.match(cssSource, /\.app-header-copy h1 \{[\s\S]*?font-size: 17px !important;/);
});

test('mobile upstream rows give address and port separate full-width rows', () => {
  assert.match(cssSource, /grid-template-areas: "enabled" "name" "address" "port" "latency" "actions" !important;/);
  assert.match(cssSource, /\.site-config-modal \.upstream-line-field:nth-child\(3\) \{ grid-area: address !important;/);
  assert.match(cssSource, /\.site-config-modal \.upstream-line-field:nth-child\(4\) \{ grid-area: port !important;/);
});

test('dashboard selectors retain a visible dropdown affordance after theme overrides', () => {
  assert.match(cssSource, /\.dashboard-trend-controls \.form-select \{[\s\S]*?background-image: url\(/);
  assert.match(cssSource, /\.dashboard-trend-controls \.form-select \{[\s\S]*?background-position: right 14px center/);
  assert.match(cssSource, /\.dashboard-trend-toolbar \{[\s\S]*?padding-bottom: 30px !important;/);
  assert.match(cssSource, /\.dashboard-trend-controls \.form-select \{[\s\S]*?min-height: 48px !important;/);
  assert.match(cssSource, /\.dashboard-trend-controls \.form-select \{[\s\S]*?padding: 10px 52px 10px 16px !important;/);
  assert.match(cssSource, /\.dashboard-trend-controls \.form-select \{[\s\S]*?line-height: 1\.5 !important;/);
});

test('document scrolling stays on the root for iOS status-bar tap-to-top', () => {
  assert.match(cssSource, /Keep document scrolling on the root element[\s\S]*?html \{[\s\S]*?overflow-y: auto !important;[\s\S]*?-webkit-overflow-scrolling: touch;/);
  assert.match(cssSource, /Keep document scrolling on the root element[\s\S]*?body \{[\s\S]*?overflow-y: visible !important;/);
});

test('desktop trend text and line actions keep readable dimensions', () => {
  assert.match(cssSource, /Final desktop trend-field contract[\s\S]*?min-height: 48px !important;/);
  assert.match(cssSource, /Final desktop trend-field contract[\s\S]*?padding: 10px 52px 10px 16px !important;/);
  assert.match(cssSource, /@media \(min-width: 769px\)[\s\S]*?\.site-config-modal \.upstream-lines-buttons > button[\s\S]*?height: 36px;/);
});

test('site editor latency colors survive the modal value override', () => {
  assert.match(cssSource, /\.site-config-modal \.upstream-line-latency\.good \{ color: var\(--green\); \}/);
  assert.match(cssSource, /\.site-config-modal \.upstream-line-latency\.warn \{ color: var\(--orange\); \}/);
  assert.match(cssSource, /\.site-config-modal \.upstream-line-latency\.bad \{ color: var\(--red\); \}/);
});
