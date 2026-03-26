// Dashboard page
function renderDashboard() {
  const page = document.getElementById('page-dashboard');
  page.innerHTML = `
    <h1 class="section-title fade-up">仪表盘</h1>
    <p class="section-sub fade-up stagger-1">Emby 反代服务运行概览</p>
    <div class="stats-row" id="dash-stats"></div>
    <div class="glass-card fade-up stagger-4">
      <div class="glass-card-header">
        <div class="glass-card-title"><span class="live-dot"></span>站点实时状态</div>
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
  loadDashboardData();
}

const uaClassMap = { 'infuse': 'pill-blue', 'web': 'pill-green', 'client': 'pill-orange' };
const uaNameMap = { 'infuse': 'Infuse', 'web': 'Web', 'client': '客户端' };

function formatBytes(bytes) {
  if (!bytes || bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return (bytes / Math.pow(1024, i)).toFixed(i > 1 ? 1 : 0) + ' ' + units[i];
}

async function loadDashboardData() {
  try {
    const [stats, sites] = await Promise.all([API.dashboard(), API.listSites()]);

    document.getElementById('dash-stats').innerHTML = `
      <div class="stat-card c-blue fade-up stagger-1">
        <div class="stat-icon-wrap blue">
          <svg viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>
        </div>
        <div class="stat-number">${stats.total_sites || 0}</div>
        <div class="stat-title">站点总数</div>
      </div>
      <div class="stat-card c-green fade-up stagger-2">
        <div class="stat-icon-wrap green">
          <svg viewBox="0 0 24 24"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
        </div>
        <div class="stat-number">${stats.running_sites || 0}</div>
        <div class="stat-title">运行中</div>
      </div>
      <div class="stat-card c-teal fade-up stagger-3">
        <div class="stat-icon-wrap teal">
          <svg viewBox="0 0 24 24"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>
        </div>
        <div class="stat-number">${formatBytes(stats.total_traffic || 0)}</div>
        <div class="stat-title">总流量</div>
      </div>
      <div class="stat-card c-orange fade-up stagger-4">
        <div class="stat-icon-wrap orange">
          <svg viewBox="0 0 24 24"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>
        </div>
        <div class="stat-number">${stats.online_sites || 0}</div>
        <div class="stat-title">已启用</div>
      </div>
    `;

    const tbody = document.getElementById('dash-table');
    if (!sites || sites.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align:center;color:var(--white-38);padding:40px">暂无站点，前往站点管理添加</td></tr>';
      return;
    }

    tbody.innerHTML = sites.map(s => `
      <tr>
        <td style="font-weight:600">${esc(s.name)}</td>
        <td><span class="status-badge"><span class="status-led ${s.running ? 'on' : 'off'}"></span>${s.running ? '运行中' : '已停止'}</span></td>
        <td class="mono">${esc(s.target_url)}</td>
        <td><span class="pill ${uaClassMap[s.ua_mode] || 'pill-blue'}">${uaNameMap[s.ua_mode] || s.ua_mode}</span></td>
        <td class="mono">:${s.listen_port}</td>
        <td>${formatBytes(s.traffic_used)}</td>
      </tr>
    `).join('');
  } catch (e) {
    console.error('Dashboard load error:', e);
  }
}

function esc(str) {
  const d = document.createElement('div');
  d.textContent = str;
  return d.innerHTML;
}
