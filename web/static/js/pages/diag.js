// Diagnostics page
function renderDiag() {
  const page = document.getElementById('page-diagnostics');
  page.innerHTML = `
    <h1 class="section-title fade-up">故障诊断</h1>
    <p class="section-sub fade-up stagger-1">查看主回源、播放回源、上游证书和代理配置状态</p>
    <div class="diag-toolbar fade-up stagger-1">
      <select class="form-select" id="diag-select">
        <option value="">加载中...</option>
      </select>
      <button class="btn-scan" id="btn-scan">开始诊断</button>
    </div>
    <div class="diag-grid" id="diag-grid">
      <div class="diag-card diag-card-wide fade-up stagger-2">
        <div class="diag-empty">选择站点后开始诊断</div>
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
  if (!siteId) {
    Toast.error('请选择一个站点');
    return;
  }

  const btn = document.getElementById('btn-scan');
  btn.textContent = '诊断中...';
  btn.classList.add('running');

  try {
    const result = await API.diagSite(siteId);
    const upstreams = result.upstreams || {};
    const primary = upstreams.primary || {};
    const playback = upstreams.playback || {};
    const headers = result.headers || {};
    const proxy = result.proxy || {};

    const notes = [
      playbackNote(playback, primary),
      '健康表示上游可达性与探针结果，不是完整业务可用性证明。',
      'TLS 展示的是上游站点证书，不是 Meridian 自己监听端口的证书。',
    ];

    const cards = [
      renderDiagNotes(notes),
      renderHealthCard('主回源健康', '主回源可达性与探针结果', primary, 'stagger-2'),
      renderTLSCard('主回源 TLS', '主回源上游站点证书信息', primary, 'stagger-3'),
    ];

    if (playback.show_health) {
      cards.push(renderHealthCard('播放回源健康', '播放、转码、直链上游的可达性与探针结果', playback, 'stagger-4'));
    }
    if (playback.show_tls) {
      cards.push(renderTLSCard('播放回源 TLS', '播放回源上游站点证书信息', playback, 'stagger-5'));
    }

    cards.push(renderHeadersCard(headers, 'stagger-5'));
    cards.push(renderProxyCard(proxy, 'stagger-6'));

    document.getElementById('diag-grid').innerHTML = cards.filter(Boolean).join('');
  } catch (e) {
    Toast.error('诊断失败: ' + e.message);
  } finally {
    btn.classList.remove('running');
    btn.textContent = '开始诊断';
  }
}

function renderDiagNotes(notes) {
  return `
    <div class="diag-card diag-card-wide fade-up stagger-2">
      <div class="diag-head">
        <div class="diag-icon" style="background:rgba(191,90,242,.16)">
          <svg viewBox="0 0 24 24" style="stroke:var(--purple)"><path d="M12 16v.01"/><path d="M12 8a4 4 0 0 1 4 4c0 2-1.5 2.8-2.3 3.6-.5.5-.7.9-.7 1.4"/><circle cx="12" cy="12" r="10"/></svg>
        </div>
        <div>
          <div class="diag-title">诊断说明</div>
          <div class="diag-subtitle">播放回源关系和诊断语义由后端结构化返回</div>
        </div>
      </div>
      <div class="diag-note-list">
        ${notes.map(note => `<div class="diag-note-item">${esc(note)}</div>`).join('')}
      </div>
    </div>
  `;
}

function renderHealthCard(title, subtitle, upstream, staggerClass) {
  const health = upstream.health || {};
  const probe = health.probe || {};
  const latency = typeof health.latency_ms === 'number' ? health.latency_ms : 0;
  return `
    <div class="diag-card fade-up ${staggerClass}">
      <div class="diag-head">
        <div class="diag-icon" style="background:var(--green-dim)">
          <svg viewBox="0 0 24 24" style="stroke:var(--green)"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>
        </div>
        <div>
          <div class="diag-title">${title}</div>
          <div class="diag-subtitle">${subtitle}</div>
        </div>
      </div>
      <div class="diag-rows">
        <div class="diag-row"><span class="diag-key">实际目标</span><span class="diag-val diag-wrap">${diagText(upstream.effective_url, '未配置')}</span></div>
        <div class="diag-row"><span class="diag-key">连接状态</span><span class="diag-val ${statusClass(health.status)}">${statusText(health.status)}</span></div>
        <div class="diag-row"><span class="diag-key">Emby 版本</span><span class="diag-val">${diagText(health.emby_version)}</span></div>
        <div class="diag-row"><span class="diag-key">响应延迟</span><span class="diag-val ${latencyClass(latency)}">${latency}ms</span></div>
        <div class="diag-row"><span class="diag-key">探针类型</span><span class="diag-val">${probeLabel(probe)}</span></div>
        <div class="diag-row"><span class="diag-key">探针请求</span><span class="diag-val diag-wrap">${diagText(probeRequestText(probe))}</span></div>
        ${typeof probe.http_status === 'number' && probe.http_status > 0 ? `<div class="diag-row"><span class="diag-key">探针响应</span><span class="diag-val">${probe.http_status}</span></div>` : ''}
        ${health.error ? `<div class="diag-row"><span class="diag-key">探针结果</span><span class="diag-val bad diag-wrap">${esc(health.error)}</span></div>` : ''}
      </div>
    </div>
  `;
}

function renderTLSCard(title, subtitle, upstream, staggerClass) {
  const tls = upstream.tls || {};
  const daysLeft = typeof tls.days_left === 'number' ? tls.days_left : null;
  const expiresText = tls.expires_at ? `${tls.expires_at}${daysLeft !== null ? ` (${daysLeft} 天)` : ''}` : '未获取';

  return `
    <div class="diag-card fade-up ${staggerClass}">
      <div class="diag-head">
        <div class="diag-icon" style="background:rgba(10,132,255,.15)">
          <svg viewBox="0 0 24 24" style="stroke:var(--blue)"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
        </div>
        <div>
          <div class="diag-title">${title}</div>
          <div class="diag-subtitle">${subtitle}</div>
        </div>
      </div>
      <div class="diag-rows">
        <div class="diag-row"><span class="diag-key">实际目标</span><span class="diag-val diag-wrap">${diagText(upstream.effective_url, '未配置')}</span></div>
        ${tls.enabled ? `
          <div class="diag-row"><span class="diag-key">证书状态</span><span class="diag-val ${tls.valid ? 'good' : 'bad'}">${tls.valid ? '有效' : '无效或已过期'}</span></div>
          <div class="diag-row"><span class="diag-key">颁发机构</span><span class="diag-val diag-wrap">${diagText(tls.issuer)}</span></div>
          <div class="diag-row"><span class="diag-key">到期时间</span><span class="diag-val ${daysLeft !== null && daysLeft < 30 ? 'warn' : 'good'}">${diagText(expiresText)}</span></div>
          ${tls.error ? `<div class="diag-row"><span class="diag-key">TLS 结果</span><span class="diag-val bad diag-wrap">${esc(tls.error)}</span></div>` : ''}
        ` : `
          <div class="diag-row"><span class="diag-key">TLS</span><span class="diag-val" style="color:var(--white-38)">该上游未使用 HTTPS</span></div>
        `}
      </div>
    </div>
  `;
}

function renderHeadersCard(headers, staggerClass) {
  return `
    <div class="diag-card fade-up ${staggerClass}">
      <div class="diag-head">
        <div class="diag-icon" style="background:var(--teal-dim)">
          <svg viewBox="0 0 24 24" style="stroke:var(--teal)"><path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>
        </div>
        <div>
          <div class="diag-title">请求头配置</div>
          <div class="diag-subtitle">Meridian 发往上游时将带上的 UA / Client</div>
        </div>
      </div>
      <div class="diag-rows">
        <div class="diag-row"><span class="diag-key">UA 改写</span><span class="diag-val ${headers.ua_applied ? 'good' : 'bad'}">${headers.ua_applied ? '已启用' : '未启用'}</span></div>
        <div class="diag-row"><span class="diag-key">当前 UA</span><span class="diag-val diag-wrap">${diagText(headers.current_ua)}</span></div>
        <div class="diag-row"><span class="diag-key">Client 字段</span><span class="diag-val">${diagText(headers.client_field)}</span></div>
      </div>
    </div>
  `;
}

function renderProxyCard(proxy, staggerClass) {
  return `
    <div class="diag-card fade-up ${staggerClass}">
      <div class="diag-head">
        <div class="diag-icon" style="background:var(--orange-dim)">
          <svg viewBox="0 0 24 24" style="stroke:var(--orange)"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
        </div>
        <div>
          <div class="diag-title">代理状态</div>
          <div class="diag-subtitle">Meridian 本地反代进程与监听状态</div>
        </div>
      </div>
      <div class="diag-rows">
        <div class="diag-row"><span class="diag-key">代理运行</span><span class="diag-val ${proxy.running ? 'good' : 'bad'}">${proxy.running ? '运行中' : '已停止'}</span></div>
        <div class="diag-row"><span class="diag-key">监听端口</span><span class="diag-val">${proxy.listen_port || '--'}</span></div>
        <div class="diag-row"><span class="diag-key">总请求数</span><span class="diag-val">${typeof proxy.total_requests === 'number' ? proxy.total_requests : '--'}</span></div>
      </div>
    </div>
  `;
}

function playbackNote(playback, primary) {
  if (playback.using_fallback) {
    return `播放回源未单独配置，当前回退到主回源 ${primary.effective_url || '--'}，因此不重复展示播放健康或播放 TLS。`;
  }
  if (playback.same_as_primary) {
    return `播放回源已配置，但与主回源相同，当前复用主回源诊断结果，不重复展示完全相同的诊断块。`;
  }
  const probe = playback.health && playback.health.probe ? playback.health.probe : {};
  if (probe.kind === 'playback_path') {
    const probeText = probeRequestText(probe) || 'HEAD 播放路径探针';
    if (playback.show_tls) {
      return `播放回源是独立 HTTPS 上游：${playback.effective_url || '--'}。当前健康块使用 ${probeText} 做轻量播放路径探针，不代表完整播放一定成功。`;
    }
    return `播放回源是独立上游：${playback.effective_url || '--'}。当前健康块使用 ${probeText} 做轻量播放路径探针，不代表完整播放一定成功。`;
  }
  if (playback.show_tls) {
    return `播放回源是独立 HTTPS 上游：${playback.effective_url || '--'}，因此会单独展示播放健康和播放 TLS。`;
  }
  return `播放回源是独立上游：${playback.effective_url || '--'}。该上游未使用 HTTPS，因此只展示播放健康。`;
}

function probeLabel(probe) {
  if (!probe || !probe.kind) return '--';
  if (probe.kind === 'playback_path') return '播放路径轻量探针';
  if (probe.kind === 'reachability_fallback') return '可达性回退探针';
  if (probe.kind === 'metadata_api') return 'Metadata / API 探针';
  return probe.kind;
}

function probeRequestText(probe) {
  if (!probe) return '';
  const method = probe.method || '';
  const url = probe.url || '';
  if (!method && !url) return '';
  return `${method} ${url}`.trim();
}

function statusClass(value) {
  if (value === 'online' || value === true) return 'good';
  if (value === 'error') return 'warn';
  return 'bad';
}

function statusText(value) {
  if (value === 'online') return '在线';
  if (value === 'error') return '探针异常';
  return '离线';
}

function latencyClass(value) {
  if (typeof value !== 'number') return '';
  if (value < 100) return 'good';
  if (value < 300) return 'warn';
  return 'bad';
}

function diagText(value, fallback = '--') {
  if (value === undefined || value === null || value === '') {
    return fallback;
  }
  return esc(String(value));
}
