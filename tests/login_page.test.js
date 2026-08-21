'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const root = path.join(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'web', 'static', 'index.html'), 'utf8');
const app = fs.readFileSync(path.join(root, 'web', 'static', 'js', 'app.js'), 'utf8');
const css = fs.readFileSync(path.join(root, 'web', 'static', 'css', 'style.css'), 'utf8').replace(/\r\n/g, '\n');

test('login notifications remain outside the hidden application shell', () => {
  assert.match(
    html,
    /<\/div>\s*<!-- Login errors must remain visible while the application shell is hidden\. -->\s*<div id="toast-container" aria-live="polite"><\/div>/,
  );
  assert.equal((html.match(/id="toast-container"/g) || []).length, 1);
});

test('login failures show Chinese credential and rate-limit messages', () => {
  assert.match(app, /return '用户名或密码错误'/);
  assert.match(app, /登录尝试次数过多，请在 \$\{Math\.ceil\(seconds\)\} 秒后重试/);
  assert.match(app, /loginButtonEl\.textContent = `\$\{remaining\} 秒后重试`/);
  assert.match(app, /Toast\.error\(loginErrorMessage\(err\)\)/);
});

test('error notifications keep red text after the shared toast theme override', () => {
  const sharedToastRule = css.lastIndexOf('.toast,\nhtml[data-theme="light"] .toast');
  const errorToastRule = css.lastIndexOf('.toast.error,\nhtml[data-theme="light"] .toast.error');
  assert.ok(sharedToastRule >= 0);
  assert.ok(errorToastRule > sharedToastRule);
  assert.match(css.slice(errorToastRule, errorToastRule + 180), /color:\s*var\(--red\)/);
});
