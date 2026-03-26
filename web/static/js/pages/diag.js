// Diagnostics page
function renderDiag() {
  const page = document.getElementById('page-diagnostics');
  page.innerHTML = `
    <h1 class="section-title fade-up">故障诊断</h1>
    <p class="section-sub fade-up stagger-1">检测站点健康状态与配置正确性</p>
    <div class="diag-toolbar fade-up stagger-1">
      <select class="form-select" id="diag-select">
        <option value="">加载中...</option>
      </select>
      <button class="btn-scan" id="btn-scan">开始诊断</button>
    </div>
    <div class="diag-grid" id="diag-grid">
      <div style="grid-column:1/-1;text-align:center;color:var(--white-38);padding:60px">
        选择站点并点击「开始诊断」
      </div>
    </div>
  `;

  loadDiagSites();
  document.getElementById('btn-scan').onclick = runDiag;
}

async function loadDiagSites() {
  try {
    const sites = await API.listSites();
    const sel = document.getElementById('diag-select');
    if (!sites || sites.length === 0) {
      sel.innerHTML = '<option value="">暂无站点</option>';
      return;
    }
    sel.innerHTML = sites.map(s => `<option value="${s.id}">${esc(s.name)}</option>`).join('');
  } catch (e) {
    Toast.error('加载站点失败');
  }
}

async function runDiag() {
  const siteId = document.getElementById('diag-select').value;
  if (!siteId) { Toast.error('请选择一个站点'); return; }

  const btn = document.getElementById('btn-scan');
  btn.textContent = '扫描中…';
  btn.classList.add('running');

  try {
    const result = await API.diagSite(siteId);

    const h = result.health;
    const t = result.tls;
    const hd = result.headers;
    const p = result.proxy;

    const statusClass = v => v === 'online' || v === true ? 'good' : v === 'error' ? 'warn' : 'bad';
    const statusText = v => v === 'online' ? '在线' : v === 'error' ? '异常' : '离线';

    document.getElementById('diag-grid').innerHTML = `
      <!-- Health -->
      <div class="diag-card fade-up stagger-2">
        <div class="diag-head">
          <div class="diag-icon" style="background:var(--green-dim)">
            <svg viewBox="0 0 24 24" style="stroke:var(--green)"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
          </div>
          <div>
            <div class="diag-title">回源健康</div>
            <div class="diag-subtitle">源站连通性检测</div>
          </div>
        </div>
        <div class="diag-rows">
          <div class="diag-row"><span class="diag-key">连接状态</span><span class="diag-val ${statusClass(h.status)}">${statusText(h.status)}</span></div>
          <div class="diag-row"><span class="diag-key">Emby 版本</span><span class="diag-val">${h.emby_version || '—'}</span></div>
          <div class="diag-row"><span class="diag-key">响应延迟</span><span class="diag-val ${h.latency_ms < 100 ? 'good' : h.latency_ms < 300 ? 'warn' : 'bad'}">${h.latency_ms}ms</span></div>
          ${h.error ? `<div class="diag-row"><span class="diag-key">错误</span><span class="diag-val bad" style="font-size:.72rem;max-width:200px;word-break:break-all">${esc(h.error)}</span></div>` : ''}
        </div>
      </div>

      <!-- TLS -->
      <div class="diag-card fade-up stagger-3">
        <div class="diag-head">
          <div class="diag-icon" style="background:rgba(10,132,255,.15)">
            <svg viewBox="0 0 24 24" style="stroke:var(--blue)"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
          </div>
          <div>
            <div class="diag-title">TLS 状态</div>
            <div class="diag-subtitle">证书有效性验证</div>
          </div>
        </div>
        <div class="diag-rows">
          ${t.enabled ? `
            <div class="diag-row"><span class="diag-key">证书状态</span><span class="diag-val ${t.valid ? 'good' : 'bad'}">${t.valid ? '有效' : '无效'}</span></div>
            <div class="diag-row"><span class="diag-key">颁发机构</span><span class="diag-val">${esc(t.issuer || '—')}</span></div>
            <div class="diag-row"><span class="diag-key">过期时间</span><span class="diag-val ${t.days_left < 30 ? 'warn' : 'good'}">${t.expires_at || '—'}${t.days_left ? ' (' + t.days_left + ' 天)' : ''}</span></div>
          ` : `
            <div class="diag-row"><span class="diag-key">TLS</span><span class="diag-val" style="color:var(--white-38)">未启用 (HTTP)</span></div>
          `}
        </div>
      </div>

      <!-- Headers -->
      <div class="diag-card fade-up stagger-4">
        <div class="diag-head">
          <div class="diag-icon" style="background:var(--teal-dim)">
            <svg viewBox="0 0 24 24" style="stroke:var(--teal)"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
          </div>
          <div>
            <div class="diag-title">请求头验证</div>
            <div class="diag-subtitle">UA 伪装检测</div>
          </div>
        </div>
        <div class="diag-rows">
          <div class="diag-row"><span class="diag-key">UA 伪装</span><span class="diag-val ${hd.ua_applied ? 'good' : 'bad'}">${hd.ua_applied ? '已生效' : '未生效'}</span></div>
          <div class="diag-row"><span class="diag-key">当前 UA</span><span class="diag-val" style="font-size:.72rem">${esc(hd.current_ua)}</span></div>
          <div class="diag-row"><span class="diag-key">Client 字段</span><span class="diag-val">${esc(hd.client_field)}</span></div>
        </div>
      </div>

      <!-- Proxy -->
      <div class="diag-card fade-up stagger-5">
        <div class="diag-head">
          <div class="diag-icon" style="background:var(--orange-dim)">
            <svg viewBox="0 0 24 24" style="stroke:var(--orange)"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
          </div>
          <div>
            <div class="diag-title">代理状态</div>
            <div class="diag-subtitle">反向代理运行信息</div>
          </div>
        </div>
        <div class="diag-rows">
          <div class="diag-row"><span class="diag-key">代理运行</span><span class="diag-val ${p.running ? 'good' : 'bad'}">${p.running ? '运行中' : '已停止'}</span></div>
          <div class="diag-row"><span class="diag-key">监听端口</span><span class="diag-val">${p.listen_port}</span></div>
        </div>
      </div>
    `;
  } catch (e) {
    Toast.error('诊断失败: ' + e.message);
  } finally {
    btn.classList.remove('running');
    btn.textContent = '开始诊断';
  }
}
