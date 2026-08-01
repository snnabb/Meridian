let dashSSE = null;
let dashAbortController = null;
let dashRetryTimer = null;

function renderDashboard() {
  const page = document.getElementById('page-dashboard');
  page.innerHTML = `
    <h1 class="section-title fade-up">仪表盘</h1>
    <p class="section-sub fade-up stagger-1">Emby 反代服务运行概览 <span class="live-indicator" id="sse-status">● 实时</span></p>
    <div class="stats-row" id="dash-stats">
      <div class="stat-card c-blue fade-up stagger-1">
        <div class="stat-icon-wrap blue">
          <svg viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
        </div>
        <div class="stat-number" id="s-total">—</div>
        <div class="stat-title">站点总数</div>
      </div>
      <div class="stat-card c-green fade-up stagger-2">
        <div class="stat-icon-wrap green">
          <svg viewBox="0 0 24 24"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
        </div>
        <div class="stat-number" id="s-running">—</div>
        <div class="stat-title">运行中</div>
      </div>
      <div class="stat-card c-teal fade-up stagger-3">
        <div class="stat-icon-wrap teal">
          <svg viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
        </div>
        <div class="stat-number" id="s-traffic">0 B</div>
        <div class="stat-title">总流量</div>
      </div>
      <div class="stat-card c-orange fade-up stagger-4">
        <div class="stat-icon-wrap orange">
          <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
        </div>
        <div class="stat-number" id="s-uptime">—</div>
        <div class="stat-title">运行时长</div>
      </div>
    </div>
    <div class="glass-card fade-up stagger-4">
      <div class="glass-card-header">
        <div class="glass-card-title"><span class="live-dot"></span>站点实时状态</div>
        <div class="glass-card-title" style="font-size:.72rem;color:var(--white-38)" id="s-requests">0 请求</div>
      </div>
      <div style="overflow-x:auto">
        <table>
          <thead><tr>
            <th>站点</th><th>状态</th><th>回源地址</th><th>UA 模式</th><th>端口</th><th>已用流量</th>
          </tr></thead>
          <tbody id="dash-table"></tbody>
        </table>
      </div>
    </div>
  `;

  startDashSSE();
  loadDashboardTable();
}

function startDashSSE() {
  stopDashSSE();
  startFetchSSE();
}

function queueDashSSERetry() {
  if (dashRetryTimer) clearTimeout(dashRetryTimer);
  dashRetryTimer = setTimeout(() => {
    if (Router.current === 'dashboard' && API.authenticated) startFetchSSE();
  }, 5000);
}

async function startFetchSSE() {
  const statusEl = document.getElementById('sse-status');
  const controller = new AbortController();
  dashAbortController = controller;

  try {
    const resp = await fetch('/api/events', {
      credentials: 'same-origin',
      signal: controller.signal,
    });

    if (resp.status === 401) {
      await API.logout();
      window.location.reload();
      return;
    }
    if (!resp.ok) throw new Error('SSE failed');
    if (dashAbortController !== controller) return;

    if (statusEl) statusEl.style.color = 'var(--green)';

    const reader = resp.body.getReader();
    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
      const { done, value } = await reader.read();
      if (done || controller.signal.aborted) break;

      buffer += decoder.decode(value, { stream: true });
      const lines = buffer.split('\n');
      buffer = lines.pop();

      for (const line of lines) {
        if (!line.startsWith('data: ')) continue;
        try {
          updateDashboardLive(JSON.parse(line.slice(6)));
        } catch (e) {
          // Skip malformed chunks and keep stream alive.
        }
      }
    }

    if (!controller.signal.aborted && dashAbortController === controller && Router.current === 'dashboard') {
      if (statusEl) statusEl.style.color = 'var(--red)';
      queueDashSSERetry();
    }
  } catch (e) {
    if (controller.signal.aborted || dashAbortController !== controller) return;
    console.warn('SSE connection lost, retrying in 5s...', e);
    if (statusEl) statusEl.style.color = 'var(--red)';
    queueDashSSERetry();
  }
}

function updateDashboardLive(stats) {
  animateValue('s-total', stats.total_sites || 0);
  animateValue('s-running', stats.running_sites || 0);

  const trafficEl = document.getElementById('s-traffic');
  if (trafficEl) trafficEl.textContent = formatBytes(stats.total_traffic || 0);

  const uptimeEl = document.getElementById('s-uptime');
  if (uptimeEl) uptimeEl.textContent = formatUptime(stats.uptime_seconds || 0);

  const requestsEl = document.getElementById('s-requests');
  if (requestsEl) requestsEl.textContent = formatNumber(stats.total_requests || 0) + ' 请求';
}

function formatUptime(seconds) {
  if (seconds < 60) return seconds + 's';
  if (seconds < 3600) return Math.floor(seconds / 60) + '分';
  if (seconds < 86400) return Math.floor(seconds / 3600) + '时' + Math.floor((seconds % 3600) / 60) + '分';
  return Math.floor(seconds / 86400) + '天' + Math.floor((seconds % 86400) / 3600) + '时';
}

function formatNumber(n) {
  return n.toLocaleString();
}

function animateValue(id, newVal) {
  const el = document.getElementById(id);
  if (!el) return;
  const current = parseInt(el.textContent, 10) || 0;
  if (current === newVal) return;
  el.textContent = newVal;
  el.style.transition = 'transform .15s';
  el.style.transform = 'scale(1.08)';
  setTimeout(() => { el.style.transform = ''; }, 150);
}

function stopDashSSE() {
  if (dashRetryTimer) {
    clearTimeout(dashRetryTimer);
    dashRetryTimer = null;
  }
  if (dashAbortController) {
    dashAbortController.abort();
    dashAbortController = null;
  }
  if (dashSSE) {
    dashSSE.close();
    dashSSE = null;
  }
}

async function loadDashboardTable() {
  try {
    const sites = await API.listSites();
    const tbody = document.getElementById('dash-table');
    if (!tbody) return;

    if (!sites || sites.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--white-38);padding:40px">暂无站点，前往站点管理添加</td></tr>';
      return;
    }

    tbody.innerHTML = sites.map(s => `
      <tr>
        <td style="font-weight:600">${esc(s.name)}</td>
        <td><span class="status-badge"><span class="status-led ${s.running ? 'on' : 'off'}"></span>${s.running ? '运行中' : '已停止'}</span></td>
        <td class="mono">${esc(s.target_url)}</td>
        <td><span class="pill ${uaClassMap[s.ua_mode] || 'pill-blue'}">${esc(uaNameMap[s.ua_mode] || s.ua_mode)}</span></td>
        <td class="mono">:${s.listen_port}</td>
        <td>${formatBytes(s.traffic_used)}</td>
      </tr>
    `).join('');
  } catch (e) {
    console.error('Dashboard table load error:', e);
  }
}

async function loadDashboardData() {
  loadDashboardTable();
}

const uaClassMap = { infuse: 'pill-blue', web: 'pill-green', client: 'pill-orange', custom: 'pill-purple' };
const uaNameMap = { infuse: 'Infuse', web: 'Web', client: '客户端', custom: '自定义' };

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return (bytes / Math.pow(1024, i)).toFixed(i > 1 ? 1 : 0) + ' ' + units[i];
}
