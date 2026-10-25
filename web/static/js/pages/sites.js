// Sites management page
let siteSortingCleanup = null;
let sitesLoadGeneration = 0;
let siteToolMenuCleanup = null;
function siteQuotaSummary(site) {
  const used = Math.max(0, Number(site.monthly_traffic) || 0);
  const quota = Math.max(0, Number(site.traffic_quota) || 0);
  return {
    used,
    remaining: quota > 0 ? Math.max(0, quota - used) : null,
    percent: quota > 0 ? Math.min(100, used / quota * 100) : 0,
    reset: Number(site.traffic_reset_day) === 0 ? '不自动重置' :
      (site.traffic_reset_at ? new Date(site.traffic_reset_at).toLocaleString('zh-CN', { hour12: false }) : '—'),
    billing: site.traffic_billing_mode === 'outbound' ? '仅出站' : '双向流量',
  };
}
function normalizeAccountRenewalDays(value) {
  const text = String(value ?? '').trim();
  if (!/^\d+$/.test(text)) return 0;
  const days = Number(text);
  return Number.isSafeInteger(days) && days >= 1 && days <= 3650 ? days : 0;
}
function formatAccountExpiryDate(value) {
  const text = String(value ?? '').trim();
  if (!text) return '';
  const match = text.match(/^(\d{4}-\d{2}-\d{2})/);
  return match ? match[1] : text;
}
function renderSites() {
  const page = document.getElementById('page-sites');
  if (!page) return;
  if (!page.querySelector('#sites-grid')) {
    page.innerHTML = `
      <div class="page-toolbar sites-toolbar">
        <button class="btn-add" id="btn-add-site">
          <svg viewBox="0 0 24 24"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
          添加站点
        </button>
        <details class="sites-tool-menu">
          <summary class="btn-ghost">导入</summary>
          <div class="sites-tool-menu-popover">
            <button type="button" class="btn-ghost" data-site-import-format="json">JSON 配置</button>
            <button type="button" class="btn-ghost" data-site-import-format="csv">CSV 表格</button>
          </div>
        </details>
        <details class="sites-tool-menu">
          <summary class="btn-ghost">导出</summary>
          <div class="sites-tool-menu-popover">
            <button type="button" class="btn-ghost" data-site-export-format="json">JSON 配置</button>
            <button type="button" class="btn-ghost" data-site-export-format="csv">CSV 表格</button>
            <div class="sites-tool-menu-label">客户端线路</div>
            <button type="button" class="btn-ghost" data-site-export-format="client" data-site-export-mode="multi">多线路</button>
            <button type="button" class="btn-ghost" data-site-export-format="client" data-site-export-mode="original">原线路</button>
            <button type="button" class="btn-ghost" data-site-export-format="client" data-site-export-mode="proxy">反代线路</button>
          </div>
        </details>
        <input id="site-import-file" type="file" accept=".json,.csv,text/csv,application/json" hidden>
        <label class="sites-search"><span class="sr-only">搜索站点</span><svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><line x1="16" y1="16" x2="21" y2="21"/></svg><input id="sites-search" type="search" placeholder="搜索站点名称或回源地址"></label>
        <select class="form-select account-lifecycle-filter" id="account-lifecycle-filter" aria-label="账号生命周期筛选">
          <option value="">账号：全部</option>
          <option value="expiring">即将到期</option>
          <option value="expired">已到期</option>
          <option value="disabled">站点已停用</option>
          <option value="no-reminder">未设置提醒</option>
          <option value="active">正常</option>
        </select>
        <button class="btn-ghost btn-test-all" id="btn-test-all-sites"><span aria-hidden="true">⌁</span> 全部测速</button>
        <button class="btn-ghost" id="btn-account-reminder-history">提醒记录</button>
        <button class="btn-ghost" id="btn-site-templates">配置模板</button>
        <button class="btn-ghost" id="btn-sites-bulk">批量操作</button>
        <div class="toolbar-info" id="sites-count"></div>
      </div>
      <div class="site-account-reminders" id="site-account-reminders" hidden></div>
      <div class="sites-grid" id="sites-grid"></div>
    `;

    bindSiteToolMenus(page);
    document.getElementById('btn-add-site').onclick = () => showSiteModal();
    document.getElementById('btn-test-all-sites').onclick = testAllSitesLatency;
    document.getElementById('btn-account-reminder-history').onclick = showAccountReminderRecords;
    document.getElementById('btn-site-templates').onclick = showSiteTemplates;
    document.getElementById('btn-sites-bulk').onclick = showSiteBulk;
    document.getElementById('sites-search').addEventListener('input', event => filterSiteCards(event.target.value));
    document.getElementById('account-lifecycle-filter').addEventListener('change', () => loadSiteAccountReminders());
    document.querySelectorAll('[data-site-import-format]').forEach(button => {
      button.onclick = () => {
        const input = document.getElementById('site-import-file');
        if (!input) return;
        input.dataset.format = button.dataset.siteImportFormat;
        input.value = '';
        input.click();
      };
    });
    document.querySelectorAll('[data-site-export-format]').forEach(button => {
      button.onclick = () => downloadSiteData(button.dataset.siteExportFormat, button.dataset.siteExportMode || '');
    });
    document.getElementById('site-import-file').addEventListener('change', importSiteDataFile);
  }
  loadSites();
}

function bindSiteToolMenus(page) {
  siteToolMenuCleanup?.();
  const controller = new AbortController();
  const options = { signal: controller.signal };
  const menus = [...page.querySelectorAll('.sites-tool-menu')];
  let pinned = null;
  const setOpen = (menu, open) => {
    menu.open = open;
    menu.querySelector('summary').setAttribute('aria-expanded', String(open));
  };
  const closeAll = () => { pinned = null; menus.forEach(menu => setOpen(menu, false)); };
  menus.forEach(menu => {
    const summary = menu.querySelector('summary');
    setOpen(menu, false);
    menu.addEventListener('pointerenter', event => {
      if (event.pointerType !== 'mouse' || (pinned && pinned !== menu)) return;
      menus.forEach(other => { if (other !== menu) setOpen(other, false); });
      setOpen(menu, true);
    }, options);
    menu.addEventListener('pointerleave', event => {
      if (event.pointerType === 'mouse' && pinned !== menu) setOpen(menu, false);
    }, options);
    summary.addEventListener('click', event => {
      event.preventDefault();
      const alreadyPinned = pinned === menu;
      closeAll();
      if (!alreadyPinned) { pinned = menu; setOpen(menu, true); }
    }, options);
    menu.addEventListener('click', event => {
      if (event.target.closest('button[data-site-import-format], button[data-site-export-format]')) closeAll();
    }, options);
    menu.addEventListener('keydown', event => {
      if (event.key === 'Escape') { event.stopPropagation(); closeAll(); summary.focus(); }
    }, options);
    menu.addEventListener('focusout', event => {
      if (pinned !== menu && !menu.contains(event.relatedTarget) && !menu.matches(':hover')) setOpen(menu, false);
    }, options);
  });
  document.addEventListener('pointerdown', event => {
    if (!menus.some(menu => menu.contains(event.target))) closeAll();
  }, options);
  siteToolMenuCleanup = () => { closeAll(); controller.abort(); };
}

async function loadSites() {
  const generation = ++sitesLoadGeneration;
  try {
	const [sites, capabilities] = await Promise.all([API.listSites(), API.ingressCapabilities()]);
	if (generation !== sitesLoadGeneration || Router.current !== 'sites') return;
	siteIngressCapabilities = normalizeSiteCapabilities(capabilities);
    siteWorkflowSites = sites;
    siteSelection = new Set([...siteSelection].filter(id => sites.some(s => s.id === id)));
    document.getElementById('sites-count').innerHTML = `共 <strong>${sites.length}</strong> 个站点`;
    loadSiteAccountReminders();

    const grid = document.getElementById('sites-grid');
    const searchQuery = document.getElementById('sites-search')?.value || '';
    if (!sites || sites.length === 0) {
      grid.innerHTML = '<div class="empty-state"><span class="empty-state-icon"><svg viewBox="0 0 24 24"><rect x="3" y="4" width="18" height="6" rx="2"/><rect x="3" y="14" width="18" height="6" rx="2"/><path d="M7 7h.01M7 17h.01"/></svg></span><h2>暂无站点</h2><p>点击“添加站点”连接 Emby 服务。</p></div>';
      filterSiteCards(searchQuery);
      return;
    }

	grid.innerHTML = sites.map((s, i) => {
      const quota = siteQuotaSummary(s);
      const pct = quota.percent;
      const pctClass = pct > 85 ? 'danger' : pct > 50 ? 'warn' : 'normal';
		const upstreamHeaderCount = Array.isArray(s.upstream_headers) ? s.upstream_headers.length : 0;
		const accessAddress = siteAccessAddress(s, siteIngressCapabilities);

      return `
      <div class="site-card" data-site-id="${s.id}" data-site-search="${esc(`${s.name} ${s.target_url} ${s.public_host || ''}`.toLowerCase())}">
        <div class="site-top">
          <div class="site-heading">
            <input type="checkbox" data-site-select="${s.id}" aria-label="选择 ${esc(s.name)}" ${siteSelection.has(s.id) ? 'checked' : ''}>
            <button type="button" class="site-drag-handle" data-site-drag-handle aria-label="拖拽调整 ${esc(s.name)} 的顺序" title="拖拽调整顺序">
              <svg viewBox="0 0 20 20" aria-hidden="true"><circle cx="7" cy="5" r="1.25"></circle><circle cx="13" cy="5" r="1.25"></circle><circle cx="7" cy="10" r="1.25"></circle><circle cx="13" cy="10" r="1.25"></circle><circle cx="7" cy="15" r="1.25"></circle><circle cx="13" cy="15" r="1.25"></circle></svg>
            </button>
            <div class="site-heading-content"><div class="site-name">${esc(s.name)}</div><span class="pill ${uaClassMap[s.ua_mode] || 'pill-blue'}">${esc(uaNameMap[s.ua_mode] || s.ua_mode)}</span></div>
          </div>
          <div class="site-card-state">
            <span class="site-mode-badge">${siteIngressModeLabel(s)}</span>
            <span class="status-badge site-status">
              <span class="status-led ${s.running ? 'on' : 'off'}"></span>
              ${s.running ? '运行中' : '已停止'}
            </span>
          </div>
        </div>
        <div class="site-latency-line"><span>回源延迟</span><strong class="site-latency" id="site-latency-${s.id}">未测试</strong></div>
		<div class="site-rows">
		  <div class="site-row site-access-row">
		    <span class="site-row-label">访问地址</span>
		    <span class="site-access-value"><span class="mono site-access-address is-hidden" data-access-address="${esc(accessAddress)}">********</span><button type="button" class="icon-button site-access-toggle" data-site-action="access" data-site-id="${s.id}" aria-label="显示访问地址" title="显示访问地址">◉</button><button type="button" class="icon-button site-access-copy" data-site-action="copy" data-site-id="${s.id}" aria-label="复制访问地址" title="复制访问地址"><svg viewBox="0 0 24 24" aria-hidden="true"><rect x="9" y="9" width="10" height="10" rx="2"></rect><path d="M6 15H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v1"></path></svg></button></span>
		  </div>
          <div class="site-row site-upstream-row">
            <span class="site-row-label">主回源地址</span>
            <span class="mono">${esc(s.target_url)}</span>
          </div>
		  ${upstreamHeaderCount > 0 ? `
		  <div class="site-row">
			<span class="site-row-label">上游请求头</span>
			<span>${upstreamHeaderCount} 个（加密）</span>
		  </div>` : ''}
          ${s.traffic_quota > 0 ? `
          <div class="progress-wrap">
            <div class="progress-labels">
              <span>本周期 ${formatBytes(quota.used)} / ${formatBytes(s.traffic_quota)}</span>
              <span>剩余 ${formatBytes(quota.remaining)}</span>
            </div>
            <div class="progress-track">
              <div class="progress-fill ${pctClass}" style="width:${Math.min(pct, 100)}%"></div>
            </div>
          </div>
          ` : `
          <div class="site-row">
            <span class="site-row-label">本周期流量</span>
            <span>${formatBytes(quota.used)} · 不限额</span>
          </div>
          `}
          <div class="site-row"><span class="site-row-label">下次重置</span><span title="按服务器计费时区重置，时间以当前浏览器时区显示">${esc(quota.reset)}</span></div>
          <div class="site-row"><span class="site-row-label">累计流量</span><span>${formatBytes(s.traffic_used)} · ${esc(quota.billing)}</span></div>
          ${s.total_speed_limit > 0 ? `<div class="site-row"><span class="site-row-label">总下载限速</span><span>${s.total_speed_limit} Mbps</span></div>` : ''}
        </div>
        <div class="site-actions">
          <button class="btn-ghost site-action-test" data-site-action="latency" data-site-id="${s.id}">测速</button>
          <button class="btn-ghost" data-site-action="toggle" data-site-id="${s.id}" ${normalizedIngressMode(s) === 'unset' ? 'disabled title="请先编辑并配置入口"' : ''}>${normalizedIngressMode(s) === 'unset' ? '待配置' : (s.enabled ? '停用' : '启用')}</button>
          <button class="btn-ghost" data-site-action="edit" data-site-id="${s.id}">编辑</button>
          <button class="btn-ghost" data-site-action="duplicate" data-site-id="${s.id}">复制</button>
          <button class="btn-ghost" data-site-action="template" data-site-id="${s.id}">存为模板</button>
          <button class="btn-ghost danger" data-site-action="delete" data-site-id="${s.id}">删除</button>
        </div>
      </div>`;
    }).join('');

    const sitesById = new Map(sites.map(site => [site.id, site]));
    grid.querySelectorAll('[data-site-action]').forEach(button => {
      button.addEventListener('click', () => {
        const id = Number(button.dataset.siteId);
        const site = sitesById.get(id);
        if (!site) return;
		if (button.dataset.siteAction === 'latency') testSiteLatency(id, button);
		if (button.dataset.siteAction === 'access') toggleSiteAccessAddress(button);
		if (button.dataset.siteAction === 'copy') copySiteAccessAddress(button);
		if (button.dataset.siteAction === 'toggle') toggleSiteAction(id);
        if (button.dataset.siteAction === 'edit') showSiteModal(site);
        if (button.dataset.siteAction === 'duplicate') showSiteModal(siteDraft(site));
        if (button.dataset.siteAction === 'template') saveSiteTemplate(site);
        if (button.dataset.siteAction === 'delete') deleteSiteAction(id, site.name);
      });
    });
    grid.querySelectorAll('[data-site-select]').forEach(input => {
      input.onchange = () => { const id = Number(input.dataset.siteSelect); if (input.checked) siteSelection.add(id); else siteSelection.delete(id); updateSiteSelectionCount(); };
    });
    updateSiteSelectionCount();
    setupSiteSorting(grid);
    filterSiteCards(searchQuery);
  } catch (e) {
    Toast.error('加载站点失败: ' + e.message);
  }
}

function downloadSiteData(format, mode) {
  document.getElementById('modal-title').textContent = '导出站点';
  document.getElementById('modal-body').innerHTML = `
    <p>格式：${esc(format === 'client' ? '客户端文本 · ' + ({original: '原线路', proxy: '反代线路', multi: '多线路'}[mode] || '多线路') : format.toUpperCase())}。所有站点都会保留，包括没有账号的站点。</p>
    <label class="form-group"><input type="checkbox" id="export-accounts" checked> 包含账号信息</label>
    <label class="form-group"><input type="checkbox" id="export-passwords"> 包含登录密码和安全密码</label>`;
  document.getElementById('modal-footer').innerHTML = '<button class="btn-modal secondary" id="export-cancel">取消</button><button class="btn-modal primary" id="export-confirm">下载文件</button>';
  const accounts = document.getElementById('export-accounts');
  const passwords = document.getElementById('export-passwords');
  accounts.onchange = () => { passwords.disabled = !accounts.checked; if (!accounts.checked) passwords.checked = false; };
  document.getElementById('export-cancel').onclick = closeModal;
  document.getElementById('export-confirm').onclick = async event => {
    event.currentTarget.disabled = true;
    try { await downloadSiteDataFile(format, mode, { include_accounts: accounts.checked, include_passwords: passwords.checked && accounts.checked }); closeModal(); }
    catch (error) { Toast.error(error.message || '导出失败'); event.target.disabled = false; }
  };
  openModal({ closeOnBackdrop: false });
}

async function downloadSiteDataFile(format, mode, options) {
  try {
    const blob = await API.exportSiteData(format, format === 'client' ? mode : '', options);
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = `meridian-sites.${format === 'csv' ? 'csv' : format === 'client' ? 'txt' : 'json'}`;
    link.click();
    URL.revokeObjectURL(link.href);
  } catch (error) {
    throw error;
  }
}

async function importSiteDataFile(event) {
  const input = event.currentTarget;
  const file = input.files && input.files[0];
  if (!file) return;
  try {
    const data = await file.text();
    const format = input.dataset.format || (file.name.toLowerCase().endsWith('.csv') ? 'csv' : 'json');
    await showSiteImportPreview(format, data);
  } catch (error) {
    Toast.error(error.message || '导入失败');
  } finally {
    input.value = '';
  }
}

async function showSiteImportPreview(format, data) {
  let actions = {};
  let duplicateAction = 'skip';
  let preview;
  let generation = 0;
  const refresh = async () => {
    const current = ++generation;
    const confirm = document.getElementById('import-confirm');
    if (confirm) confirm.disabled = true;
    const next = await API.importSiteData(format, data, { preview: true, duplicate_action: duplicateAction, actions });
    if (current !== generation) return;
    preview = next;
    document.getElementById('modal-title').textContent = '导入预览';
    document.getElementById('modal-body').innerHTML = `
      <p>共 ${preview.items.length} 个站点。新增站点默认停用；更新保留启停状态。未提供密码时保留已有密码。</p>
      <label class="form-group">重复站点默认处理<select class="form-select" id="import-duplicates">
        <option value="skip">跳过</option><option value="update">更新已有站点</option><option value="new">另建站点</option>
      </select></label>
      <div class="site-import-list">${preview.items.map(item => `
        <div class="site-import-row">
          <strong>${esc(item.name)}</strong><div class="mono">${esc(item.target_url)}</div>
          <div>${item.account_count} 个账号${item.duplicate_names.length ? ` · 已匹配：${esc(item.duplicate_names.join('、'))}` : ' · 新站点'}</div>
          ${item.action === 'skip' ? '' : `<div>入口：${esc(({path: '路径', host: '域名', both: '域名', port: '独立端口'})[item.ingress_mode] || item.ingress_mode)} ${esc(item.path_prefix || item.public_host || '')} · 端口 ${item.listen_port}</div>`}
          <label>处理方式<select class="form-select" data-import-index="${item.index}">
            <option value="new" ${item.action === 'new' ? 'selected' : ''}>新增</option>
            <option value="update" ${item.action === 'update' ? 'selected' : ''} ${item.duplicate_names.length !== 1 ? 'disabled' : ''}>更新</option>
            <option value="skip" ${item.action === 'skip' ? 'selected' : ''}>跳过</option>
          </select></label>
          ${item.error ? `<p class="site-import-error">${esc(item.error)}</p>` : ''}
        </div>`).join('')}</div>`;
    document.getElementById('modal-footer').innerHTML = '<button class="btn-modal secondary" id="import-cancel">取消</button><button class="btn-modal primary" id="import-confirm">确认导入</button>';
    const policy = document.getElementById('import-duplicates');
    policy.value = duplicateAction;
    policy.onchange = async () => { duplicateAction = policy.value; actions = {}; try { await refresh(); } catch (error) { Toast.error(error.message); } };
    document.querySelectorAll('[data-import-index]').forEach(select => {
      select.onchange = async () => { actions[select.dataset.importIndex] = select.value; try { await refresh(); } catch (error) { Toast.error(error.message); } };
    });
    document.getElementById('import-cancel').onclick = () => { generation++; closeModal(); };
    const button = document.getElementById('import-confirm');
    button.disabled = !preview.valid;
    button.onclick = async () => {
      button.disabled = true;
      button.textContent = '导入中…';
      try {
        const result = await API.importSiteData(format, data, { duplicate_action: duplicateAction, actions, preview_token: preview.preview_token });
        const summary = `新增 ${result.created_sites}、更新 ${result.updated_sites}、跳过 ${result.skipped_sites}、失败 ${result.failed_sites}`;
        if (result.failed_sites) {
          document.getElementById('modal-body').innerHTML = `<p>${esc(summary)}</p>${result.items.filter(item => item.error).map(item => `<p>${esc(item.name)}：${esc(item.error)}</p>`).join('')}`;
          button.hidden = true;
        } else { closeModal(); Toast.success(summary); }
        await loadSites();
      } catch (error) {
        Toast.error(error.message || '导入失败');
        try { await refresh(); } catch (_) { button.textContent = '请重新导入'; }
      }
    };
  };
  await refresh();
  openModal({ closeOnBackdrop: false });
}

async function loadSiteAccountReminders() {
  const target = document.getElementById('site-account-reminders');
  if (!target || !API.getAccountReminders) return;
  try {
    const filter = document.getElementById('account-lifecycle-filter')?.value || '';
    const rows = API.getAccountRemindersFiltered ? await API.getAccountRemindersFiltered(filter) : await API.getAccountReminders();
    if (!rows.length) {
      target.hidden = true;
      target.innerHTML = '';
      return;
    }
    target.hidden = false;
    target.innerHTML = `<span class="site-account-reminder-label">账号 ${filter === 'expired' ? '已到期' : filter === 'expiring' ? '即将到期' : filter === 'disabled' ? '所在站点已停用' : filter === 'no-reminder' ? '未设置提醒' : '状态'}</span>${rows.sort((a, b) => a.days_left - b.days_left).slice(0, 12).map(row => `<span class="reminder-pill ${row.status}">${esc(row.site_name)} · ${esc(row.account.account_name)} · ${row.status === 'expired' ? '已到期' : row.status === 'disabled' ? '站点停用' : !row.reminder_enabled ? '未设置提醒' : `剩余 ${row.days_left} 天`}</span>`).join('')}`;
  } catch (_) {
    target.hidden = true;
  }
}

async function showAccountReminderRecords() {
  if (!API.getAccountReminderRecords) return;
  try {
    const records = await API.getAccountReminderRecords();
    document.getElementById('modal-body').innerHTML = `
      <h2>提醒发送记录</h2>
      <p class="form-help">这里保留每次发送尝试和失败原因；账号密码不会出现在记录中。处理或忽略后，该到期批次不会再次发送。</p>
      <div class="account-reminder-history">${records.length ? records.map((record, index) => `<div class="account-reminder-history-row ${record.status === 'failed' ? 'is-failed' : ''}"><strong>${esc(record.site_name)} · ${esc(record.account_name)}</strong><span>${record.status === 'failed' ? '发送失败' : '发送成功'} · 到期日 ${esc(formatAccountExpiryDate(record.expires_at))} · 提前 ${record.reminder_days} 天 · ${esc(record.attempted_at || record.sent_at || '')}${record.error ? ` · ${esc(record.error)}` : ''}${record.action ? ` · 已${record.action === 'handled' ? '处理' : record.action === 'ignored' ? '忽略' : '延后'}` : ''}</span>${record.status === 'sent' && !record.action ? `<div class="account-reminder-history-actions"><button type="button" class="btn-ghost" data-reminder-action="handled" data-reminder-index="${index}">已处理</button><button type="button" class="btn-ghost" data-reminder-action="ignored" data-reminder-index="${index}">忽略本次</button><button type="button" class="btn-ghost" data-reminder-action="snoozed" data-reminder-index="${index}">明天再提醒</button></div>` : ''}</div>`).join('') : '<div class="form-help">暂无提醒发送记录。</div>'}</div>`;
    document.getElementById('modal-footer').innerHTML = '<button class="btn-modal secondary" id="account-reminder-history-close">关闭</button>';
    document.getElementById('account-reminder-history-close').onclick = closeModal;
    document.querySelectorAll('[data-reminder-action]').forEach(button => {
      button.onclick = async () => {
        const record = records[Number(button.dataset.reminderIndex)];
        if (!record) return;
        button.disabled = true;
        try {
          await API.saveAccountReminderAction({ account_id: record.account_id, expires_at: record.expires_at, reminder_days: record.reminder_days, action: button.dataset.reminderAction });
          Toast.success(button.dataset.reminderAction === 'handled' ? '已标记处理' : button.dataset.reminderAction === 'snoozed' ? '明天再提醒' : '已忽略本次提醒');
          await showAccountReminderRecords();
          loadSiteAccountReminders();
        } catch (error) { button.disabled = false; Toast.error(error.message || '提醒动作保存失败'); }
      };
    });
    openModal({ closeOnBackdrop: true });
  } catch (error) {
    Toast.error(error.message || '提醒记录读取失败');
  }
}

function filterSiteCards(query) {
  const needle = String(query || '').trim().toLowerCase();
  const grid = document.getElementById('sites-grid');
  if (!grid) return;
  grid.classList.toggle('is-filtered', !!needle);
  grid.querySelectorAll('.site-card').forEach(card => {
    card.hidden = !!needle && !String(card.dataset.siteSearch || '').includes(needle);
  });
  grid.querySelectorAll('[data-site-drag-handle]').forEach(handle => {
    handle.disabled = !!needle;
    handle.title = needle ? '清除搜索后可调整顺序' : '拖拽调整顺序';
  });
}

function siteOrderFromGrid(grid) {
  return [...grid.querySelectorAll('.site-card[data-site-id]')]
    .map(card => Number(card.dataset.siteId))
    .filter(Number.isSafeInteger);
}

function captureSiteDropSlots(grid, draggedCard) {
  const scrollX = typeof window !== 'undefined' ? (window.scrollX || 0) : 0;
  const scrollY = typeof window !== 'undefined' ? (window.scrollY || 0) : 0;
  return [...grid.children]
    .filter(node => node !== draggedCard && !node.hidden)
    .map(node => {
      const rect = node.getBoundingClientRect();
      return {
        x: rect.left + rect.width / 2 + scrollX,
        y: rect.top + rect.height / 2 + scrollY,
        width: Math.max(rect.width, 1),
        height: Math.max(rect.height, 1),
      };
    });
}

function moveSitePlaceholderAtPoint(grid, draggedCard, placeholder, dropSlots, clientX, clientY) {
  if (!placeholder || !dropSlots.length) return;
  const scrollX = typeof window !== 'undefined' ? (window.scrollX || 0) : 0;
  const scrollY = typeof window !== 'undefined' ? (window.scrollY || 0) : 0;
  const pointerX = clientX + scrollX;
  const pointerY = clientY + scrollY;
  let desiredIndex = 0;
  let nearestDistance = Number.POSITIVE_INFINITY;
  dropSlots.forEach((slot, index) => {
    const dx = (pointerX - slot.x) / slot.width;
    const dy = (pointerY - slot.y) / slot.height;
    const distance = dx * dx + dy * dy;
    if (distance < nearestDistance) {
      desiredIndex = index;
      nearestDistance = distance;
    }
  });

  const orderedCards = [...grid.querySelectorAll('.site-card[data-site-id]')]
    .filter(card => card !== draggedCard);
  const reference = orderedCards[desiredIndex] || null;
  if (reference !== placeholder.nextSibling) grid.insertBefore(placeholder, reference);
}

function positionDraggedSiteCard(card, clientX, clientY, offsetX, offsetY) {
  card.style.left = `${clientX - offsetX}px`;
  card.style.top = `${clientY - offsetY}px`;
  card.style.transform = 'translate3d(0, 0, 0)';
}

async function persistSiteOrder(grid) {
  const siteIds = siteOrderFromGrid(grid);
  const nextOrder = siteIds.join(',');
  if (!siteIds.length || nextOrder === grid.dataset.siteOrder) return;
  grid.classList.add('is-saving-order');
  try {
    await API.reorderSites(siteIds);
    grid.dataset.siteOrder = nextOrder;
    Toast.success('站点顺序已保存，仪表盘已同步');
  } catch (error) {
    Toast.error('保存站点顺序失败: ' + error.message);
    await loadSites();
  } finally {
    grid.classList.remove('is-saving-order');
  }
}

function setupSiteSorting(grid) {
  if (typeof siteSortingCleanup === 'function') siteSortingCleanup();
  const cards = [...grid.querySelectorAll('.site-card[data-site-id]')];
  grid.dataset.siteOrder = siteOrderFromGrid(grid).join(',');
  let draggedCard = null;
  let placeholder = null;
  let dragOffsetX = 0;
  let dragOffsetY = 0;
  let dropSlots = [];
  let activeHandle = null;
  let activePointerId = null;

  const beginDrag = (card, event) => {
    const rect = card.getBoundingClientRect();
    draggedCard = card;
    dragOffsetX = event.clientX - rect.left;
    dragOffsetY = event.clientY - rect.top;
    placeholder = document.createElement('div');
    placeholder.className = 'site-card-placeholder';
    placeholder.setAttribute('aria-hidden', 'true');
    placeholder.style.height = `${rect.height}px`;
    grid.insertBefore(placeholder, card);

    card.style.position = 'fixed';
    card.style.left = `${rect.left}px`;
    card.style.top = `${rect.top}px`;
    card.style.width = `${rect.width}px`;
    card.style.height = `${rect.height}px`;
    card.style.margin = '0';
    card.style.transform = 'translate3d(0, 0, 0)';
    card.classList.add('is-dragging');
    grid.classList.add('is-reordering');
    document.body.classList.add('is-site-dragging');
    dropSlots = captureSiteDropSlots(grid, card);
  };
  const finishDrag = card => {
    if (draggedCard !== card) return;
    if (placeholder && placeholder.parentElement === grid) grid.insertBefore(card, placeholder);
    if (placeholder) placeholder.remove();
    placeholder = null;
    dropSlots = [];
    card.style.position = '';
    card.style.left = '';
    card.style.top = '';
    card.style.width = '';
    card.style.height = '';
    card.style.margin = '';
    card.style.transform = '';
    card.classList.remove('is-dragging');
    grid.classList.remove('is-reordering');
    document.body.classList.remove('is-site-dragging');
    draggedCard = null;
    void persistSiteOrder(grid);
  };

  const movePointer = event => {
    if (!draggedCard) return;
    if (event.type === 'pointermove' && activePointerId !== null && event.pointerId !== activePointerId) return;
    if (event.cancelable) event.preventDefault();
    positionDraggedSiteCard(draggedCard, event.clientX, event.clientY, dragOffsetX, dragOffsetY);
    const edge = 64;
    if (typeof window !== 'undefined' && window.scrollBy) {
      if (event.clientY < edge) window.scrollBy(0, -12);
      if (event.clientY > window.innerHeight - edge) window.scrollBy(0, 12);
    }
    moveSitePlaceholderAtPoint(grid, draggedCard, placeholder, dropSlots, event.clientX, event.clientY);
  };

  const finishPointer = event => {
    if (!draggedCard) return;
    if (event.type.startsWith('pointer') && activePointerId !== null && event.pointerId !== activePointerId) return;
    const card = draggedCard;
    if (activeHandle && activePointerId !== null && activeHandle.releasePointerCapture && activeHandle.hasPointerCapture) {
      try {
        if (activeHandle.hasPointerCapture(activePointerId)) activeHandle.releasePointerCapture(activePointerId);
      } catch (_) {}
    }
    activeHandle = null;
    activePointerId = null;
    finishDrag(card);
  };

  cards.forEach(card => {
    const handle = card.querySelector('[data-site-drag-handle]');
    if (!handle) return;

    handle.addEventListener('pointerdown', event => {
      if (handle.disabled || (Number.isFinite(event.button) && event.button !== 0)) return;
      event.preventDefault();
      activeHandle = handle;
      activePointerId = event.pointerId;
      beginDrag(card, event);
      if (handle.setPointerCapture) {
        try { handle.setPointerCapture(event.pointerId); } catch (_) {}
      }
    });
  });

  window.addEventListener('pointermove', movePointer, { passive: false });
  window.addEventListener('pointerup', finishPointer);
  window.addEventListener('pointercancel', finishPointer);
  // Mouse fallbacks cover browsers and automation surfaces that begin with a
  // PointerEvent but only deliver compatibility mouse movement afterwards.
  window.addEventListener('mousemove', movePointer, { passive: false });
  window.addEventListener('mouseup', finishPointer);
  siteSortingCleanup = () => {
    window.removeEventListener('pointermove', movePointer);
    window.removeEventListener('pointerup', finishPointer);
    window.removeEventListener('pointercancel', finishPointer);
    window.removeEventListener('mousemove', movePointer);
    window.removeEventListener('mouseup', finishPointer);
    if (draggedCard) finishPointer({ type: 'pointercancel', pointerId: activePointerId });
    siteSortingCleanup = null;
  };
}

async function testSiteLatency(id, button) {
  const value = document.getElementById(`site-latency-${id}`);
  if (button) button.disabled = true;
  if (value) value.textContent = '测速中…';
  try {
    const result = await API.diagSite(id);
    const health = result && result.upstreams && result.upstreams.primary
      ? result.upstreams.primary.health || {}
      : (result && result.health) || {};
    if (health.status === 'online' && Number.isFinite(Number(health.latency_ms))) {
      const latency = Number(health.latency_ms);
      if (value) {
        value.textContent = `${latency} ms`;
        value.className = `site-latency ${latency < 200 ? 'good' : latency < 800 ? 'warn' : 'bad'}`;
      }
    } else {
      throw new Error(health.error || '回源不可用');
    }
  } catch (error) {
    if (value) {
      value.textContent = '测速失败';
      value.className = 'site-latency bad';
      value.title = error.message || '测速失败';
    }
  } finally {
    if (button) button.disabled = false;
  }
}

async function testAllSitesLatency() {
  const button = document.getElementById('btn-test-all-sites');
  if (!button || button.disabled) return;
  button.disabled = true;
  button.textContent = '全部测速中…';
  const buttons = [...document.querySelectorAll('[data-site-action="latency"]')];
  await Promise.all(buttons.map(siteButton => testSiteLatency(Number(siteButton.dataset.siteId), siteButton)));
  button.disabled = false;
  button.textContent = '全部测速';
}

function customUAFormState(mode, site) {
  const isCustom = mode === 'custom';
  return {
    visible: isCustom,
    required: isCustom,
    customUserAgent: isCustom && site ? (site.custom_user_agent || '') : '',
    customClient: isCustom && site ? (site.custom_client || '') : '',
    customVersion: isCustom && site ? (site.custom_version || '') : '',
  };
}

function buildCustomUAPayload(mode, customUserAgent, customClient, customVersion) {
  if (mode !== 'custom') {
    return {
      custom_user_agent: '',
      custom_client: '',
      custom_version: '',
    };
  }
  return {
    custom_user_agent: String(customUserAgent || '').trim(),
    custom_client: String(customClient || '').trim(),
    custom_version: String(customVersion || '').trim(),
  };
}

function buildUpstreamHeaderPayload(headers) {
	return headers
		.filter(header => header.configured || String(header.name || '').trim() || String(header.value || '').trim())
		.map(header => ({
			name: String(header.name || '').trim(),
			value: String(header.value || '').trim(),
		}));
}

const DEFAULT_MAX_PLAYBACK_ADDRESSES = 128;

function normalizeStreamHosts(value) {
	let hosts = value;
	if (typeof hosts === 'string') {
		try {
			hosts = JSON.parse(hosts || '[]');
		} catch (_) {
			return [];
		}
	}
	if (!Array.isArray(hosts)) return [];
	return hosts
		.filter(host => typeof host === 'string' && host.trim())
		.map(host => host.trim());
}

function normalizeSiteCapabilities(value) {
	const capabilities = value && typeof value === 'object' ? value : {};
	const requestedMax = Number(capabilities.max_playback_addresses);
	const directPort = Number(capabilities.domain_prefix_port);
	const normalized = {
		host_only_available: capabilities.host_only_available !== false,
		upstream_headers_available: capabilities.upstream_headers_available !== false,
		max_playback_addresses: Number.isInteger(requestedMax) && requestedMax > 0
			? requestedMax
			: DEFAULT_MAX_PLAYBACK_ADDRESSES,
	};
	// Keep the legacy capability object's enumerable shape stable for embedded
	// clients while exposing the new fields to the UI.
	Object.defineProperties(normalized, {
		domain_prefix_available: { value: capabilities.domain_prefix_available === undefined ? undefined : capabilities.domain_prefix_available === true, enumerable: false },
		route_domain: { value: String(capabilities.route_domain || '').trim().toLowerCase(), enumerable: false },
		panel_tls_enabled: { value: capabilities.panel_tls_enabled === true, enumerable: false },
		external_proxy: { value: capabilities.external_proxy === true, enumerable: false },
		domain_prefix_port: { value: Number.isInteger(directPort) && directPort >= 1 && directPort <= 65535 ? directPort : null, enumerable: false },
        site_listener_scheme: { value: capabilities.site_listener_scheme === 'https' ? 'https' : capabilities.site_listener_scheme === 'http' ? 'http' : capabilities.panel_tls_enabled === true ? 'https' : 'http', enumerable: false },
		path_ingress_available: { value: capabilities.path_ingress_available !== false, enumerable: false },
		panel_access_url: { value: String(capabilities.panel_access_url || '').replace(/\/$/, ''), enumerable: false },
	});
	return normalized;
}

const DYNAMIC_PROFILE_IDS = ['safe', 'compatible', 'extreme'];
const DYNAMIC_SOURCE_IDS = ['redirect', 'playback_info', 'hls', 'dash'];
const DEFAULT_DYNAMIC_SOURCE_IDS = ['redirect', 'playback_info'];
const ADVANCED_DYNAMIC_SOURCE_IDS = ['hls', 'dash'];
const DYNAMIC_SOURCE_LABELS = {
	redirect: 'HTTP 30x',
	playback_info: 'PlaybackInfo',
	hls: 'HLS',
	dash: 'DASH',
};
const DYNAMIC_PROFILE_SOURCE_IDS = {
	safe: ['redirect', 'playback_info'],
	compatible: [...DYNAMIC_SOURCE_IDS],
	extreme: [...DYNAMIC_SOURCE_IDS],
};
const DYNAMIC_PROFILE_LABELS = {
	safe: 'Safe（安全）',
	compatible: 'Compatible（兼容）',
	extreme: 'Extreme（极限）',
};
const DYNAMIC_PROFILE_NETWORK_DEFAULTS = {
	safe: { allowed_schemes: ['https'], allowed_ports: [443], allow_any_port: false },
	compatible: { allowed_schemes: ['http', 'https'], allowed_ports: [], allow_any_port: true },
	extreme: { allowed_schemes: ['http', 'https'], allowed_ports: [], allow_any_port: true },
};
const DYNAMIC_LIMIT_FIELDS = [
	'allowed_schemes',
	'allowed_ports',
	'allow_any_port',
	'max_redirects',
	'max_authorities',
	'max_active_capabilities',
	'max_urls_per_response',
	'max_body_bytes',
	'max_dns_ips',
	'max_new_authorities_per_minute',
	'max_streams',
	'idle_expiry_seconds',
	'absolute_lifetime_seconds',
];
const DYNAMIC_GLOBAL_LIMIT_FIELDS = [
	'max_authorities',
	'max_active_capabilities',
	'max_streams',
	'max_new_authorities_per_minute',
	'max_dns_workers',
	'max_concurrent_parses',
	'max_site_concurrent_parses',
	'max_parse_memory_bytes',
	'max_site_parse_memory_bytes',
	'max_capability_memory_bytes',
	'max_site_capability_memory_bytes',
	'max_parse_depth',
	'max_string_bytes',
	'max_target_url_bytes',
];
const DYNAMIC_FEATURES = [
	['redirect_discovery', 'HTTP 30x 发现', true],
	['playback_info', 'PlaybackInfo 改写', true],
	['hls', 'HLS 解析', true],
	['dash', 'DASH 解析', true],
	['private_targets', '私网目标', false],
	['custom_ca', '自定义 CA', false],
	['raw_fallback', '原始响应回退', false],
];
const DYNAMIC_OBSERVATION_REASON_CODES = new Set([
	'redirect_allowed',
	'candidate_allowed',
	'invalid_location',
	'unsupported_status',
	'redirect_loop',
	'hop_limit',
	'redirect_timeout',
	'scheme_denied',
	'port_denied',
	'domain_denied',
	'https_downgrade_denied',
	'self_target',
	'dns_failure',
	'address_denied',
	'dial_failure',
	'tls_failure',
	'capacity_limit',
	'rate_limit',
	'parse_failure',
	'request_unclassified',
	'structured_body_limit',
	'playback_info_denied',
	'hls_feature_denied',
	'dash_feature_denied',
	'redirect_body_replay_denied',
	'capability_invalid',
	'capability_expired',
	'response_failure',
	'runtime_unavailable',
]);

function hasOwnDynamicField(value, field) {
	return Object.prototype.hasOwnProperty.call(value, field);
}

function isStructuredDiscoveryContract(value) {
	if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
	if (value.stage !== 'structured-discovery' || typeof value.available !== 'boolean' || typeof value.key_configured !== 'boolean') return false;
	if (value.available !== value.key_configured) return false;
	if (!value.global_limits || typeof value.global_limits !== 'object' || Array.isArray(value.global_limits)) return false;
	if (!DYNAMIC_GLOBAL_LIMIT_FIELDS.every(field => hasOwnDynamicField(value.global_limits, field) && Number.isInteger(value.global_limits[field]) && value.global_limits[field] > 0)) return false;
	if (!Array.isArray(value.profiles) || value.profiles.length !== DYNAMIC_PROFILE_IDS.length) return false;

	const profiles = new Map(value.profiles.map(profile => [profile && profile.id, profile]));
	if (profiles.size !== DYNAMIC_PROFILE_IDS.length) return false;
	return DYNAMIC_PROFILE_IDS.every(id => {
		const profile = profiles.get(id);
		if (!profile || typeof profile.label !== 'string' || typeof profile.recommended !== 'boolean') return false;
		if (!profile.limits || typeof profile.limits !== 'object' || Array.isArray(profile.limits)) return false;
		if (!DYNAMIC_LIMIT_FIELDS.every(field => hasOwnDynamicField(profile.limits, field))) return false;
		if (!Array.isArray(profile.limits.allowed_schemes) || profile.limits.allowed_schemes.length === 0 || !profile.limits.allowed_schemes.every(scheme => scheme === 'http' || scheme === 'https')) return false;
		if (!Array.isArray(profile.limits.allowed_ports) || !profile.limits.allowed_ports.every(port => Number.isInteger(port) && port > 0 && port <= 65535)) return false;
		if (typeof profile.limits.allow_any_port !== 'boolean') return false;
		if (!DYNAMIC_LIMIT_FIELDS.slice(3).every(field => {
			const limit = profile.limits[field];
			const countCanBeUnlimited = id === 'extreme' && (field === 'max_redirects' || field === 'max_urls_per_response');
			return Number.isInteger(limit) && (limit > 0 || countCanBeUnlimited && limit === 0);
		})) return false;
		if (!profile.features || typeof profile.features !== 'object' || Array.isArray(profile.features)) return false;
		return DYNAMIC_FEATURES.every(([field, , expected]) => {
			const profileExpected = id === 'safe' && (field === 'hls' || field === 'dash') ? false : expected;
			return hasOwnDynamicField(profile.features, field) && profile.features[field] === profileExpected;
		});
	});
}

function normalizeDynamicProfiles(value) {
	const recognized = isStructuredDiscoveryContract(value);
	const sourceProfiles = recognized
		? new Map(value.profiles.map(profile => [profile.id, profile]))
		: new Map();
	return {
		stage: 'structured-discovery',
		available: recognized && value.available === true,
		key_configured: recognized && value.key_configured === true,
		recognized,
		profiles: DYNAMIC_PROFILE_IDS.map(id => {
			const profile = sourceProfiles.get(id);
			return {
				id,
				label: profile ? profile.label : DYNAMIC_PROFILE_LABELS[id],
				recommended: profile ? profile.recommended : id === 'compatible',
				limits: profile ? profile.limits : DYNAMIC_PROFILE_NETWORK_DEFAULTS[id],
				features: profile ? profile.features : {},
			};
		}),
		global_limits: recognized ? value.global_limits : {},
	};
}

async function loadDynamicProfiles() {
	try {
		return normalizeDynamicProfiles(await API.getDynamicProfiles());
	} catch (_) {
		return normalizeDynamicProfiles(null);
	}
}

function normalizeDynamicProfile(value) {
	const profile = String(value || '').trim().toLowerCase();
	return DYNAMIC_PROFILE_IDS.includes(profile) ? profile : 'compatible';
}

function normalizeUpstreamScheme(value) {
	return String(value || '').trim().toLowerCase() === 'http' ? 'http' : 'https';
}

function defaultUpstreamPort(value) {
	return normalizeUpstreamScheme(value) === 'http' ? '8096' : '443';
}

function splitUpstreamTargetAddress(value, fallbackScheme = 'https') {
	const raw = String(value || '').trim();
	const normalizedFallback = normalizeUpstreamScheme(fallbackScheme);
	if (!raw) {
		return { scheme: normalizedFallback, address: '', port: defaultUpstreamPort(normalizedFallback) };
	}
	const explicitScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw);
	try {
		const parsed = new URL(explicitScheme ? raw : `http://${raw}`);
		let scheme = explicitScheme ? parsed.protocol.replace(':', '').toLowerCase() : (parsed.port === '443' ? 'https' : 'http');
		if (scheme !== 'http' && scheme !== 'https') throw new Error('unsupported upstream scheme');
		const hostname = parsed.hostname.startsWith('[')
			? parsed.hostname
			: (parsed.hostname.includes(':') ? `[${parsed.hostname}]` : parsed.hostname);
		if (!hostname || parsed.username || parsed.password || parsed.hash) throw new Error('invalid upstream address');
		const pathname = parsed.pathname === '/' ? '' : parsed.pathname;
		return {
			scheme,
			address: `${hostname}${pathname}${parsed.search}`,
			// Existing URLs without a port use the protocol's actual default.
			// The 8096 suggestion only applies to newly entered HTTP servers.
			port: parsed.port || (scheme === 'http' ? '80' : '443'),
		};
	} catch (_) {
		return { scheme: normalizedFallback, address: raw, port: defaultUpstreamPort(normalizedFallback) };
	}
}

function joinUpstreamTargetAddress(scheme, address, port) {
	const normalizedScheme = normalizeUpstreamScheme(scheme);
	const rawAddress = String(address || '').trim();
	if (!rawAddress || /[\\\s]/.test(rawAddress)) return '';
	const targetPort = parseBoundedInteger(String(port ?? '').trim() || defaultUpstreamPort(normalizedScheme), 1, 65535);
	if (targetPort === null) return '';
	const explicitScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(rawAddress);
	try {
		const parsed = new URL(explicitScheme ? rawAddress : `${normalizedScheme}://${rawAddress}`);
		if (!['http:', 'https:'].includes(parsed.protocol) || !parsed.hostname || parsed.username || parsed.password || parsed.hash) return '';
		parsed.protocol = `${normalizedScheme}:`;
		parsed.port = String(targetPort);
		const normalized = parsed.toString();
		return parsed.pathname === '/' && !parsed.search ? normalized.replace(/\/$/, '') : normalized;
	} catch (_) {
		return '';
	}
}

function dynamicSourcesForProfile(value) {
	return [...DYNAMIC_PROFILE_SOURCE_IDS[normalizeDynamicProfile(value)]];
}


function normalizeDynamicDiscoverySources(value, profile = 'compatible') {
	if (normalizeDynamicProfile(profile) === 'extreme') return [...DYNAMIC_SOURCE_IDS];
	const allowed = new Set(dynamicSourcesForProfile(profile));
	if (!Array.isArray(value)) return DEFAULT_DYNAMIC_SOURCE_IDS.filter(source => allowed.has(source));
	const selected = new Set(value.map(source => String(source || '').trim().toLowerCase()));
	return DYNAMIC_SOURCE_IDS.filter(source => allowed.has(source) && selected.has(source));
}

function normalizeDynamicDomainRules(value) {
	if (!Array.isArray(value)) return [];
	return value.flatMap(rule => {
		if (!rule || typeof rule !== 'object' || Array.isArray(rule)) return [];
		const type = String(rule.type || '').trim().toLowerCase();
		const host = String(rule.value || '').trim().toLowerCase();
		if ((type !== 'exact' && type !== 'suffix') || !host) return [];
		return [{ type, value: host }];
	});
}

function isPlausibleSafeDynamicDNSRule(rule) {
	const normalized = normalizeDynamicDomainRules([rule])[0];
	if (!normalized) return false;
	let host = normalized.value;
	if (host.startsWith('.') || host.includes('*') || /[\s/\\@?#:%]/.test(host)) return false;
	host = host.replace(/\.$/, '');
	if (!host) return false;
	let asciiHost;
	try {
		asciiHost = new URL(`https://${host}/`).hostname.toLowerCase();
	} catch (_) {
		return false;
	}
	if (!asciiHost || asciiHost.startsWith('[') || /^\d+(?:\.\d+){3}$/.test(asciiHost)) return false;
	const labels = asciiHost.split('.');
	if (labels.length < 2 || !/[a-z]/.test(labels[labels.length - 1])) return false;
	return labels.every(label => label.length > 0 && label.length <= 63 && !label.startsWith('-') && !label.endsWith('-') && /^[a-z0-9-]+$/.test(label));
}

function hasRequiredSafeDynamicRules(profile, rules) {
	return normalizeDynamicProfile(profile) !== 'safe' || normalizeDynamicDomainRules(rules).some(isPlausibleSafeDynamicDNSRule);
}

function normalizeDynamicSitePolicy(site) {
	const value = site && typeof site === 'object' ? site : {};
	const revision = value.dynamic_policy_revision;
	const profile = normalizeDynamicProfile(value.dynamic_profile);
	return {
		dynamic_discovery_enabled: value.dynamic_discovery_enabled === true,
		dynamic_profile: profile,
		dynamic_discovery_sources: normalizeDynamicDiscoverySources(value.dynamic_discovery_sources, profile),
		dynamic_domain_rules: normalizeDynamicDomainRules(value.dynamic_domain_rules),
		dynamic_allow_https_downgrade: profile === 'extreme' || value.dynamic_allow_https_downgrade === true,
		dynamic_policy_revision: Number.isInteger(revision) && revision > 0 ? revision : 1,
	};
}

function buildDynamicPolicyPayload(policy, capabilities) {
	const normalized = normalizeDynamicSitePolicy(policy);
	const dynamicCapabilities = normalizeDynamicProfiles(capabilities);
	if (!dynamicCapabilities.recognized) return {};
	return {
	        dynamic_discovery_enabled: normalized.dynamic_discovery_enabled,
		dynamic_profile: normalized.dynamic_profile,
		dynamic_domain_rules: normalized.dynamic_domain_rules,
		dynamic_allow_https_downgrade: normalized.dynamic_allow_https_downgrade,
	};
}

function renderDynamicProfileOptions(capabilities, selectedProfile) {
	const dynamicCapabilities = normalizeDynamicProfiles(capabilities);
	const normalizedSelected = normalizeDynamicProfile(selectedProfile);
	return dynamicCapabilities.profiles.map(profile => `
		<option value="${esc(profile.id)}" ${profile.id === normalizedSelected ? 'selected' : ''}>${esc(profile.label)}${profile.recommended ? '（推荐）' : ''}</option>
	`).join('');
}

function renderDynamicProfileSummaries(capabilities) {
	const dynamicCapabilities = normalizeDynamicProfiles(capabilities);
	return dynamicCapabilities.profiles.map(profile => {
		const schemes = Array.isArray(profile.limits.allowed_schemes)
			? profile.limits.allowed_schemes.map(scheme => String(scheme).toUpperCase()).join('/')
			: '—';
		const ports = profile.limits.allow_any_port === true
			? '全部端口'
			: (Array.isArray(profile.limits.allowed_ports) ? profile.limits.allowed_ports.join(', ') : '—');
		const sources = dynamicSourcesForProfile(profile.id).map(source => DYNAMIC_SOURCE_LABELS[source]).join(' + ');
		const compatibility = profile.id === 'extreme'
			? '；全部发现来源与 HTTPS 降级开启；单份响应地址数与重定向跳数不设固定上限，寻址总超时 60 秒；支持扩展 PlaybackInfo/HLS/DASH 格式，保留资源预算与循环检测'
			: '；使用严格协议字段与已审核结构';
		const accent = profile.id === 'safe' ? 'var(--green)' : profile.id === 'compatible' ? 'var(--orange)' : 'var(--red)';
		return `<div class="form-help" data-profile-summary="${esc(profile.id)}" style="padding:8px 10px;margin-top:6px;border:1px solid ${accent};border-radius:6px;background:var(--surface-hover);color:var(--white-87)"><strong style="color:${accent}">${esc(profile.label)}</strong>：${esc(sources)}；仅公网 ${esc(schemes)}，端口 ${esc(ports)}${esc(compatibility)}</div>`;
	}).join('');
}

function renderDynamicRuleRows(rules) {
	const rows = Array.isArray(rules) ? rules : [];
	return rows.map((rule, index) => {
		const type = rule && rule.type === 'suffix' ? 'suffix' : 'exact';
		const value = rule && rule.value !== undefined ? rule.value : '';
		return `
		<div class="m-dynamic-rule-row" data-idx="${index}">
		  <select class="form-select modal-select m-dynamic-rule-type" data-idx="${index}">
			<option value="exact" ${type === 'exact' ? 'selected' : ''}>精确</option>
			<option value="suffix" ${type === 'suffix' ? 'selected' : ''}>后缀</option>
		  </select>
		  <input type="text" class="form-input m-dynamic-rule-value" data-idx="${index}" value="${esc(value)}" placeholder="media.example.com" maxlength="253" autocapitalize="none" autocorrect="off" spellcheck="false" style="flex:1">
		  <button type="button" class="btn-ghost danger m-dynamic-rule-remove" data-idx="${index}" >删除</button>
		</div>`;
	}).join('');
}

function renderDynamicStatus(capabilities) {
	const dynamicCapabilities = normalizeDynamicProfiles(capabilities);
	const keyStatus = !dynamicCapabilities.recognized ? '未知' : dynamicCapabilities.key_configured ? '已配置' : '未配置';
	if (!dynamicCapabilities.recognized) return '<span class="form-help">自动发现能力不可用，请检查后端版本。</span>';
	return `<span class="form-help">自动发现：${dynamicCapabilities.available ? '已可用' : '未启用'} · DYNAMIC_ROUTE_KEY：${keyStatus} · 默认处理 HTTP 30x 和 PlaybackInfo</span>`;
}

function dynamicProfileRiskNotice(profile) {
	const normalized = normalizeDynamicProfile(profile);
	switch (normalized) {
	case 'compatible':
		return {
			level: 'compatible',
			badge: '默认',
			color: 'var(--orange)',
			background: 'var(--orange-dim)',
			message: '适合大多数后端，支持严格 HTTP 30x、PlaybackInfo、HLS 和 DASH；仍拒绝私网、特殊地址和未验证拨号。',
		};
	case 'extreme':
		return {
			level: 'extreme',
			badge: '高风险',
			color: 'var(--red)',
			background: 'var(--red-dim)',
			message: '除放大公网 authority、动态流和生命周期上限外，还会对 CONNECT/Upgrade/保留路径之外的数据面方法和路径处理 30x/303，并可能把有界请求体重放到上游指定且通过安全校验的公网目标；同时启用 PlaybackInfo、HLS 与 DASH 扩展兼容。仍不开放隧道、私网、自定义 CA、原始地址回退或未签名 target。进入此档必须勾选确认、输入站点名称并通过弹窗。',
		};
	default:
		return {
			level: 'safe',
			badge: '推荐',
			color: 'var(--green)',
			background: 'var(--green-dim)',
			message: '仅允许 HTTPS:443，且未知目标必须命中精确或后缀 DNS 域名规则。',
		};
	}
}

function renderDynamicProfileRisk(profile) {
	const notice = dynamicProfileRiskNotice(profile);
	const badgeTextColor = notice.level === 'extreme' ? '#fff' : '#111';
	return `<div class="form-help" data-profile-risk="${esc(notice.level)}" style="padding:8px 10px;border:1px solid ${notice.color};border-radius:8px;background:${notice.background};color:var(--white-87)"><span data-profile-risk-badge="${esc(notice.level)}" style="display:inline-block;padding:2px 7px;border-radius:999px;background:${notice.color};color:${badgeTextColor};font-weight:800;margin-right:5px">${esc(notice.badge)}</span>${esc(notice.message)}</div>`;
}

function dynamicProfileConfirmationRequirement(initialPolicy, nextPolicy) {
	const initial = normalizeDynamicSitePolicy(initialPolicy);
	const next = normalizeDynamicSitePolicy(nextPolicy);
	if (!next.dynamic_discovery_enabled) return 'none';
	if (next.dynamic_profile === 'extreme' && (!initial.dynamic_discovery_enabled || initial.dynamic_profile !== 'extreme')) return 'extreme';
	return 'none';
}

function confirmDynamicProfileChange(initialPolicy, nextPolicy, siteName, extremeAcknowledged, extremeTypedName) {
	const requirement = dynamicProfileConfirmationRequirement(initialPolicy, nextPolicy);
	if (requirement === 'extreme') {
		if (!extremeAcknowledged) return { ok: false, requirement, error: '启用 Extreme 前必须勾选高风险确认' };
		if (String(extremeTypedName || '').trim() !== String(siteName || '').trim()) return { ok: false, requirement, error: '启用 Extreme 时必须准确输入站点名称' };
		const accepted = window.confirm('Extreme（极限）会启用全数据面 30x/303、受限请求体重放和更宽的 PlaybackInfo/HLS/DASH 兼容，并显著放大公网发现与并发上限。请求体可能被重放到上游指定且通过安全校验的公网目标；仍不启用私网、自定义 CA、原始地址回退或未签名 target。确定继续吗？');
		return { ok: accepted, requirement, error: '' };
	}
	return { ok: true, requirement, error: '' };
}

function renderDynamicEnableControl(capabilities, policy) {
	const dynamicCapabilities = normalizeDynamicProfiles(capabilities);
	const dynamicPolicy = normalizeDynamicSitePolicy(policy);
	const enableEditable = dynamicCapabilities.recognized && (dynamicCapabilities.available || dynamicPolicy.dynamic_discovery_enabled);
	return `
		<label class="site-dynamic-toggle" style="display:inline-flex;align-items:center;gap:10px;cursor:pointer;"><input type="checkbox" id="m-dynamic-enabled" style="margin:0;width:17px;height:17px;flex-shrink:0;cursor:pointer;" ${dynamicPolicy.dynamic_discovery_enabled ? 'checked' : ''} ${enableEditable ? '' : 'disabled'}><span style="line-height:1.2;">启用自动发现</span></label>
	`;
}

function privacySafeObservationAuthority(value) {
	if (typeof value !== 'string') return '—';
	const match = /^(https?):\/\/(\[[0-9a-f:.]+\]|[a-z0-9.-]+):([0-9]{1,5})$/i.exec(value.trim());
	if (!match) return '—';
	const port = Number(match[3]);
	if (!Number.isInteger(port) || port < 1 || port > 65535) return '—';
	const host = match[2].toLowerCase();
	if (!host.startsWith('[')) {
		const labels = host.split('.');
		if (!labels.every(label => label.length > 0 && label.length <= 63 && !label.startsWith('-') && !label.endsWith('-') && /^[a-z0-9-]+$/.test(label))) return '—';
	}
	try {
		new URL(`${match[1].toLowerCase()}://${host}:${port}/`);
	} catch (_) {
		return '—';
	}
	return `${match[1].toLowerCase()}://${host}:${port}`;
}

function privacySafeObservationReason(value) {
	return typeof value === 'string' && DYNAMIC_OBSERVATION_REASON_CODES.has(value) ? value : '—';
}

function formatObservationTimestamp(value) {
	if (!Number.isSafeInteger(value) || value < 0) return '—';
	return meridianFormatDateTime(value);
}

function normalizeDynamicObservationsResponse(value) {
	const response = value && typeof value === 'object' && !Array.isArray(value) ? value : {};
	const observations = Array.isArray(response.observations) ? response.observations : [];
	return {
		observations: observations.map(observation => {
			const item = observation && typeof observation === 'object' && !Array.isArray(observation) ? observation : {};
			return {
				authority: privacySafeObservationAuthority(item.canonical_authority),
				source: DYNAMIC_SOURCE_IDS.includes(item.source) ? item.source : '—',
				decision: item.decision === 'allowed' || item.decision === 'denied' ? item.decision : '—',
				reason: privacySafeObservationReason(item.reason_code),
				firstSeen: formatObservationTimestamp(item.first_seen_ms),
				lastSeen: formatObservationTimestamp(item.last_seen_ms),
				count: Number.isSafeInteger(item.count) && item.count > 0 ? item.count : '—',
			};
		}),
		dropped: Number.isSafeInteger(response.dropped_observations) && response.dropped_observations >= 0
			? response.dropped_observations
			: '—',
	};
}

function renderDynamicObservations(value) {
	const response = normalizeDynamicObservationsResponse(value);
	const rows = response.observations.map(observation => `
		<tr>
		  <td>${esc(observation.authority)}</td>
		  <td>${esc(observation.source)}</td>
		  <td>${esc(observation.decision)}</td>
		  <td>${esc(observation.reason)}</td>
		  <td>${esc(observation.firstSeen)}</td>
		  <td>${esc(observation.lastSeen)}</td>
		  <td>${esc(observation.count)}</td>
		</tr>
	`).join('');
	return `
		<div class="form-help">已丢弃观察记录：${esc(response.dropped)}</div>
		${rows ? `
		<div style="overflow-x:auto;margin-top:8px">
		  <table>
			<thead><tr><th>规范化权威</th><th>来源</th><th>决策</th><th>原因代码</th><th>首次观察</th><th>最近观察</th><th>次数</th></tr></thead>
			<tbody>${rows}</tbody>
		  </table>
		</div>` : '<div class="form-help" style="margin-top:8px">暂无观察记录。</div>'}
	`;
}

function renderDynamicObservationsPanel(supported) {
	return `
		<div style="margin-top:16px;padding-top:12px;border-top:1px solid var(--glass-border)">
		  <label>自动发现观察记录</label>
		  <div class="form-help">仅显示目标域名与处理结果，不包含令牌或请求内容。</div>
		  <div style="display:flex;gap:8px;margin-top:8px">
			<button type="button" class="btn-ghost" id="m-refresh-dynamic-observations" ${supported ? '' : 'disabled'}>刷新</button>
			<button type="button" class="btn-ghost danger" id="m-clear-dynamic-observations" ${supported ? '' : 'disabled'}>清空</button>
		  </div>
		  <div id="m-dynamic-observations" style="margin-top:8px">${supported ? '<div class="form-help">正在读取观察记录…</div>' : '<div class="form-help">当前后端不提供自动发现观察记录。</div>'}</div>
		</div>
	`;
}

function playbackAddressCount(playbackTargetURL, streamHosts) {
	return normalizeStreamHosts(streamHosts).length + (String(playbackTargetURL || '').trim() ? 1 : 0);
}

function canAddPlaybackAddress(currentStreamHostCount, maxPlaybackAddresses, hasPlaybackTarget = false) {
	const current = Number(currentStreamHostCount);
	const maximum = Number(maxPlaybackAddresses);
	if (!Number.isFinite(current) || !Number.isFinite(maximum) || current < 0 || maximum < 1) return false;
	return current + (hasPlaybackTarget ? 1 : 0) < maximum;
}

function renderUpstreamHeaderRows(headers, upstreamHeadersAvailable) {
	return headers.map((header, idx) => `
		<fieldset class="form-list-row upstream-header-row">
		  <legend class="sr-only">上游请求头 ${idx + 1}</legend>
		  <label class="sr-only" for="m-upstream-header-name-${idx}">请求头名称</label>
		  <input type="text" class="form-input m-upstream-header-name" id="m-upstream-header-name-${idx}" data-idx="${idx}" value="${esc(header.name)}" placeholder="Header 名称" maxlength="64" autocapitalize="none" autocorrect="off" spellcheck="false" ${upstreamHeadersAvailable ? '' : 'disabled'}>
		  <label class="sr-only" for="m-upstream-header-value-${idx}">请求头值</label>
		  <input type="password" class="form-input m-upstream-header-value" id="m-upstream-header-value-${idx}" data-idx="${idx}" value="" placeholder="${header.configured ? '已配置；留空保持不变' : 'Header 值'}" maxlength="1024" autocomplete="new-password" ${upstreamHeadersAvailable ? '' : 'disabled'}>
		  <button type="button" class="btn-ghost danger form-row-action m-upstream-header-remove" data-idx="${idx}" aria-label="删除上游请求头 ${idx + 1}">删除</button>
		</fieldset>
	`).join('');
}

function normalizedIngressMode(site) {
	const mode = String((site && site.ingress_mode) || '').trim().toLowerCase();
	if (mode === 'unset' || mode === 'port' || mode === 'path' || mode === 'host' || mode === 'both') return mode;
	return site && String(site.public_host || '').trim() ? 'host' : 'port';
}

function ingressFormState(mode) {
	const normalized = ['unset', 'port', 'path', 'host', 'both'].includes(mode) ? mode : 'host';
	if (normalized === 'unset' || !mode) {
		return {
			mode: normalized,
			showPublicHost: false,
			requirePublicHost: false,
			requireListenPort: false,
			showPathPrefix: false,
			requirePathPrefix: false,
			portLabel: '监听端口',
			warning: '该站点来自其他服务器，原入口不适用于当前环境。请选择可用入口并保存后再启用。',
		};
	}
	return {
		mode: normalized,
		showPublicHost: normalized === 'host' || normalized === 'both',
		requirePublicHost: normalized === 'host' || normalized === 'both',
		showPathPrefix: normalized === 'path',
		requirePathPrefix: normalized === 'path',
		requireListenPort: normalized === 'port' || normalized === 'both',
		portLabel: normalized === 'host' || normalized === 'path' ? '共享面板端口' : '监听端口',
		warning: normalized === 'port'
			? '独立端口需要单独放行；若域名经过 CDN，请确认 CDN 支持该端口。'
			: normalized === 'path'
				? '复用面板域名和端口，客户端地址需保留路径。'
			: normalized === 'both'
				? '兼容模式会同时开放独立端口和共享域名，建议迁移到单一入口。'
				: '域名前缀复用共享入口，不会绑定站点端口；入口需有匹配的 TLS 泛域名证书。',
	};
}

function buildIngressPayload(mode, port, publicHost, routePrefix, routeDomain, pathPrefix) {
	const state = ingressFormState(mode);
	const parsedPort = parseBoundedInteger(port, 1, 65535);
	const prefix = String(routePrefix || '').trim().toLowerCase();
	const generatedHost = state.showPublicHost && prefix && routeDomain
		? `${prefix}.${String(routeDomain).trim().toLowerCase()}`
		: String(publicHost || '').trim();
	return {
		ingress_mode: state.mode,
		listen_port: Number.isInteger(parsedPort) ? parsedPort : 0,
		public_host: state.showPublicHost ? generatedHost : '',
		path_prefix: state.showPathPrefix ? String(pathPrefix || '').trim() : '',
		...(state.showPublicHost && prefix ? { route_prefix: prefix } : {}),
	};
}

function defaultIngressMode() { return 'path'; }

function canUseDomainPrefix(capabilities, site) {
	return capabilities.host_only_available && capabilities.domain_prefix_available === true &&
		(capabilities.panel_tls_enabled === true || capabilities.external_proxy === true || Boolean(site && String(site.public_host || '').trim()));
}

function siteAccessAddress(site, capabilities) {
	const mode = normalizedIngressMode(site);
    if (mode === 'unset') return '';
	const locationObject = typeof window !== 'undefined' && window.location
		? window.location
		: { protocol: 'http:', hostname: '127.0.0.1', port: '' };
	const protocol = capabilities && capabilities.panel_tls_enabled ? 'https' : locationObject.protocol.replace(':', '') || 'http';
	if (mode === 'port') {
		const host = locationObject.hostname || '127.0.0.1';
		// External HTTPS terminates at the panel's reverse proxy, not at a
		// dedicated site listener. Only native panel TLS covers these ports.
		const listenerProtocol = capabilities?.site_listener_scheme || (capabilities?.panel_tls_enabled === true ? 'https' : 'http');
		const port = parseBoundedInteger(site.listen_port, 1, 65535);
        return port === null ? '' : `${listenerProtocol}://${host.includes(':') && !host.startsWith('[') ? `[${host}]` : host}:${port}`;
	}
	if (mode === 'path') {
		// Path ingress is reached through the same public origin the operator is
		// currently using. The configured panel listener may be loopback or an
		// internal reverse-proxy upstream and must never leak into the address.
		const base = `${locationObject.protocol || `${protocol}:`}//${locationObject.host || locationObject.hostname || '127.0.0.1'}`.replace(/\/$/, '');
		const prefix = String(site.path_prefix || '').trim().replace(/^\/+|\/+$/g, '');
		return prefix ? `${base}/${prefix}/` : '';
	}
	const host = String(site.public_host || '').trim();
	const panelPort = parseBoundedInteger(capabilities?.domain_prefix_port, 1, 65535) || locationObject.port || (protocol === 'https' ? '443' : '80');
	return host ? `${protocol}://${host}:${panelPort}` : '';
}

function toggleSiteAccessAddress(button) {
	const row = button.closest('.site-access-row');
	const value = row && row.querySelector('[data-access-address]');
	if (!value) return;
	const hidden = value.classList.toggle('is-hidden');
	value.textContent = hidden ? '********' : value.dataset.accessAddress;
	button.setAttribute('aria-label', hidden ? '显示访问地址' : '隐藏访问地址');
	button.setAttribute('title', hidden ? '显示访问地址' : '隐藏访问地址');
}

async function copySiteAccessAddress(button) {
	const row = button.closest('.site-access-row');
	const value = row && row.querySelector('[data-access-address]');
	const address = String(value && value.dataset.accessAddress || '').trim();
	if (!address) {
		Toast.error('当前站点没有可复制的访问地址');
		return;
	}

	try {
		if (typeof navigator !== 'undefined' && navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
			await navigator.clipboard.writeText(address);
		} else {
			if (typeof document === 'undefined' || typeof document.execCommand !== 'function') throw new Error('clipboard unavailable');
			const input = document.createElement('textarea');
			input.value = address;
			input.setAttribute('readonly', '');
			input.style.position = 'fixed';
			input.style.opacity = '0';
			document.body.appendChild(input);
			input.select();
			const copied = document.execCommand('copy');
			input.remove();
			if (!copied) throw new Error('copy failed');
		}
		Toast.success('访问地址已复制');
	} catch (_) {
		Toast.error('复制失败，请手动复制访问地址');
	}
}

let siteIngressCapabilities = normalizeSiteCapabilities({});

function siteIngressModeLabel(site) {
	const labels = { unset: '入口未配置', port: '独立端口', path: '路径', host: '域名前缀', both: '域名前缀（兼容）' };
	return labels[normalizedIngressMode(site)] || labels.unset;
}

function routePrefixForSite(site, routeDomain) {
	if (!site || normalizedIngressMode(site) !== 'host') return '';
	const host = String(site.public_host || '').trim().toLowerCase();
	const domain = String(routeDomain || '').trim().toLowerCase();
	if (!host || !domain || !host.endsWith(`.${domain}`)) return '';
	const prefix = host.slice(0, -(domain.length + 1));
	return prefix.includes('.') ? '' : prefix;
}

function normalizedTargetAuthority(value) {
	let candidate = String(value || '').trim().replaceAll('：', ':');
	if (!candidate) return '';
	if (!candidate.includes('://')) {
		const authority = candidate.split(/[/?#]/, 1)[0];
		candidate = authority.endsWith(':443') ? `https://${candidate}` : `http://${candidate}`;
	}
	try {
		const parsed = new URL(candidate);
		const scheme = parsed.protocol.toLowerCase();
		if (scheme !== 'http:' && scheme !== 'https:') return '';
		const defaultPort = scheme === 'https:' ? '443' : '80';
		return `${scheme}//${parsed.hostname.toLowerCase()}:${parsed.port || defaultPort}`;
	} catch (_) {
		return '';
	}
}

function showPanelCertificateModal() { Router.navigate('settings-tls'); }

async function showSiteModal(site) {
  const isEdit = !!site?.id;
  const hasValues = !!site;
  const title = isEdit ? '编辑站点' : '添加站点';
	let siteCapabilities;
	let dynamicCapabilities;
	let existingAccounts = [];
	try {
		[siteCapabilities, dynamicCapabilities, existingAccounts] = await Promise.all([
			API.ingressCapabilities().then(normalizeSiteCapabilities),
			loadDynamicProfiles(),
			isEdit ? API.listSiteAccounts(site.id) : Promise.resolve([]),
		]);
	} catch (error) {
		Toast.error(`无法读取站点能力：${error.message}`);
		return;
	}
	dynamicCapabilities = normalizeDynamicProfiles(dynamicCapabilities);
	const upstreamHeadersAvailable = siteCapabilities.upstream_headers_available;
	const domainPrefixAvailable = siteCapabilities.domain_prefix_available === true;
	const canUseHostIngress = canUseDomainPrefix(siteCapabilities, site);
	const domainPrefixExample = siteAccessAddress({ ingress_mode: 'host', public_host: `前缀.${siteCapabilities.route_domain || 'example.com'}` }, siteCapabilities);
	const dynamicPolicy = normalizeDynamicSitePolicy(hasValues ? site : {
		dynamic_discovery_enabled: Boolean(dynamicCapabilities && dynamicCapabilities.available),
		dynamic_profile: 'compatible',
		dynamic_domain_rules: [],
		dynamic_allow_https_downgrade: true,
	});
	let dynamicRules = [...dynamicPolicy.dynamic_domain_rules];
	let modalAccounts = Array.isArray(existingAccounts) ? existingAccounts.map(account => ({ ...account })) : [];
	let nextDraftAccountID = -1;
  const primaryTarget = splitUpstreamTargetAddress(hasValues ? site.target_url : '', 'http');
  document.getElementById('modal-title').textContent = title;
  document.getElementById('modal-body').innerHTML = `
    <div class="site-modal-tabs" id="site-modal-tabs" role="tablist">
      <button type="button" class="site-modal-tab active" data-tab="basic" role="tab" id="site-tab-basic" aria-controls="site-panel-basic" aria-selected="true" tabindex="0">基本配置</button>
      <button type="button" class="site-modal-tab" data-tab="lines" role="tab" id="site-tab-lines" aria-controls="site-panel-lines" aria-selected="false" tabindex="-1">播放设置</button>
      <button type="button" class="site-modal-tab" data-tab="advanced" role="tab" id="site-tab-advanced" aria-controls="site-panel-advanced" aria-selected="false" tabindex="-1">高级策略</button>
    </div>
    <div class="site-modal-panel active" id="site-panel-basic" role="tabpanel" aria-labelledby="site-tab-basic">
      <div class="form-group">
        <label for="m-name">站点名称</label>
        <input type="text" class="form-input" id="m-name" value="${hasValues ? esc(site.name) : ''}" placeholder="如：Emby-US-01" maxlength="100" required>
      </div>
	${!isEdit ? `<details class="form-group site-form-wide site-launch-import" id="m-launch-import">
	  <summary>从开号信息填充</summary>
	  <div class="site-launch-import-body">
	    <textarea class="form-input" id="m-launch-message" rows="5" placeholder="粘贴包含站点名称、用户名、密码和线路的开号信息"></textarea>
	    <div class="site-inline-actions"><button type="button" class="btn-ghost" id="m-launch-parse">解析并填充</button><span class="form-help" id="m-launch-result"></span></div>
	  </div>
	</details>` : ''}
	<div class="form-group">
	  <label for="m-ingress-mode">入口模式</label>
	  <select class="form-select modal-select" id="m-ingress-mode" required>
		${isEdit && normalizedIngressMode(site) === 'unset' ? '<option value="unset" disabled>未配置（请选择）</option>' : ''}
		<option value="host" ${canUseHostIngress ? '' : 'disabled'}>域名前缀${canUseHostIngress ? '' : '（需配置 HTTPS 入口和节点基础域名）'}</option>
		<option value="path">路径前缀（复用现有地址和证书）</option>
		<option value="port">独立端口</option>
	  </select>
	  <div class="form-help" id="m-ingress-warning"></div>

	</div>
	<div class="form-group" id="m-port-group">
	  <label id="m-port-label" for="m-port">监听端口</label>
	  <input type="number" class="form-input" id="m-port" value="${hasValues && ['port', 'both'].includes(normalizedIngressMode(site)) ? site.listen_port : ''}" placeholder="如：8001" min="1" max="65535" step="1" inputmode="numeric">
	  <div class="form-help" id="m-port-help"></div>
	</div>
	<div class="form-group" id="m-public-host-group">
	  <label for="m-route-prefix">域名前缀</label>
	  <input type="text" class="form-input" id="m-route-prefix" value="${hasValues ? esc(routePrefixForSite(site, siteCapabilities.route_domain)) : ''}" placeholder="如：123" autocapitalize="none" autocorrect="off" spellcheck="false" maxlength="63">
	  <input type="hidden" id="m-public-host" value="${hasValues ? esc(site.public_host || '') : ''}">
	  <div class="form-help">访问地址为 ${esc(domainPrefixExample)}。复用此入口端口，不会另外开放站点端口；请将对应域名解析到服务器。</div>
	</div>
	<div class="form-group" id="m-path-prefix-group" hidden>
	  <label for="m-path-prefix">路径前缀</label>
	  <input type="text" class="form-input" id="m-path-prefix" value="${hasValues ? esc(String(site.path_prefix || '').replace(/^\//, '')) : ''}" placeholder="如：emby" autocapitalize="none" autocorrect="off" spellcheck="false" maxlength="64">
	</div>
      <div class="form-group site-form-wide site-upstream-main" id="m-upstream-lines">
        <label>主地址</label>
        <div class="upstream-line site-upstream-line is-primary" data-line="primary">
          <label class="site-primary-protocol" for="m-target-scheme"><span>协议</span><select class="form-select" id="m-target-scheme"><option value="http">HTTP</option><option value="https">HTTPS</option></select></label>
          <label class="site-primary-address" for="m-target-address"><span>地址</span><input type="text" class="form-input upstream-line-address" id="m-target-address" value="${esc(primaryTarget.address)}" placeholder="emby.example.com 或 IP，可带 /emby" required maxlength="2048" inputmode="url" autocomplete="off" autocapitalize="none" spellcheck="false"></label>
          <label class="site-primary-port" for="m-target-port"><span>端口</span><input type="number" class="form-input upstream-line-port" id="m-target-port" value="${primaryTarget.port}" min="1" max="65535" step="1" inputmode="numeric" required></label>
          <span class="upstream-line-latency" hidden></span>
        </div>
        <div class="form-help">粘贴完整链接可自动识别协议与端口。</div>
        <details class="site-failover-options" ${hasValues && site.failover_lines?.length ? 'open' : ''}>
          <summary>备用地址（可选）</summary>
          <div id="m-failover-lines"></div>
          <button type="button" class="btn-ghost" id="m-add-failover-line">添加备用地址</button>
        </details>
        <button type="button" class="btn-ghost" id="m-test-all-lines">测试连接</button>
      </div>
	  <details class="form-group site-form-wide site-accounts-module" id="m-account-options" ${modalAccounts.length ? 'open' : ''}>
	    <summary>站点账号 <span class="site-account-count" id="m-account-count"></span></summary>
	    <div class="site-accounts-body">
	      <div id="m-account-list" class="site-account-list"></div>
	      <div class="site-account-form">
	        <input type="hidden" id="m-account-id">
	        <div class="site-account-fields">
	          <label>账号名称<input type="text" class="form-input" id="m-account-name" placeholder="可与用户名相同" maxlength="128"></label>
	          <label>用户名<input type="text" class="form-input" id="m-account-username" placeholder="可与账号名称相同" maxlength="128"></label>
	          <label>登录密码<input type="text" class="form-input" id="m-account-password" autocomplete="off" spellcheck="false"></label>
	          <label>安全密码<input type="text" class="form-input" id="m-account-security" autocomplete="off" spellcheck="false"></label>
	          <label>到期时间<input type="date" class="form-input" id="m-account-expires"></label>
	          <label>提前提醒（天）<input type="number" class="form-input" id="m-account-reminder" min="0" max="3650" step="1" placeholder="留空关闭，0 为到期时"></label>
	          <label>备注<input type="text" class="form-input" id="m-account-note" maxlength="2000"></label>
	        </div>
	        <div class="site-inline-actions"><button type="button" class="btn-ghost" id="m-account-save">添加账号</button><button type="button" class="btn-ghost" id="m-account-reset">清空</button><span class="form-help" id="m-account-hint">只填日期时按全局时区的 00:00 计算；提前提醒通过 TG Bot 向管理员发送，每次到期只提醒一次。${isEdit ? '修改后请保存账号。' : '账号随站点一起保存；解析只填入表单，可以先修改提醒。'}</span></div>
	      </div>
	    </div>
	  </details>
    </div>
    <div class="site-modal-panel" id="site-panel-lines" role="tabpanel" aria-labelledby="site-tab-lines">
      <div class="form-group">
        <label for="m-playback-routing-mode">播放回源模式</label>
        <select class="form-select" id="m-playback-routing-mode">
          <option value="auto" ${dynamicCapabilities.available ? '' : 'disabled'}>自动发现</option>
          <option value="manual">手动填写</option>
          <option value="direct">直连播放</option>
        </select>
        <div class="form-help" id="m-playback-mode-help"></div>
      </div>
		<div class="form-group site-form-wide playback-targets-group" id="m-manual-playback">
		  <label for="m-playback-target">播放回源地址</label>
		  <input type="text" class="form-input" id="m-playback-target" value="${hasValues ? esc(site.playback_target_url || '') : ''}" placeholder="如：playback.example.com 或 https://playback.example.com:443" inputmode="url" autocapitalize="none" autocorrect="off" spellcheck="false" maxlength="2048">
		  <div class="form-help">留空使用主地址；未写协议时，443 端口使用 HTTPS，其余使用 HTTP。</div>
		  <div class="stream-hosts-wrap" style="margin-top: 14px;">
		    <div class="stream-hosts-head" style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px;">
		      <span style="font-size:12px; font-weight: 600; color: var(--white-87);">额外播放/串流节点</span>
		      <button type="button" class="btn-ghost" id="m-add-stream-host" style="font-size:12px; padding: 3px 9px;">+ 添加播放节点</button>
		    </div>
		    <div id="m-stream-hosts-list" style="display: flex; flex-direction: column; gap: 8px;"></div>
		  </div>
		</div>

		<details class="form-group site-form-wide site-dynamic-card" id="m-auto-options"><summary>自动发现选项</summary>
		  ${dynamicCapabilities.available ? '' : renderDynamicStatus(dynamicCapabilities)}
		  <div class="site-dynamic-row">

		    <label class="site-dynamic-profile"><span>兼容级别</span><select class="form-select modal-select" id="m-dynamic-profile" ${dynamicCapabilities.recognized ? '' : 'disabled'}>${renderDynamicProfileOptions(dynamicCapabilities, dynamicPolicy.dynamic_profile)}</select></label>
		  </div>
			  <div class="site-dynamic-help" id="m-dynamic-help">兼容模式默认处理 HTTP 30x、PlaybackInfo、HLS 和 DASH；仍拒绝私网与回环目标。</div>
		  <div class="site-dynamic-extreme" id="m-dynamic-extreme-confirm" hidden>
		    <label class="site-dynamic-check"><input type="checkbox" id="m-dynamic-extreme-ack"><span>我了解 Extreme 会放宽动态兼容范围</span></label>
		    <input type="text" class="form-input" id="m-dynamic-extreme-name" placeholder="输入站点名称确认" autocomplete="off">
		  </div>
			  <details class="site-dynamic-advanced">
			    <summary>安全规则与观察记录</summary>
			    <div class="site-dynamic-advanced-body">
			      <div class="site-dynamic-rules-head"><span>Safe 域名规则</span><button type="button" class="btn-ghost" id="m-add-dynamic-rule">添加规则</button></div>
		      <div id="m-dynamic-rules"></div>
		      ${isEdit ? renderDynamicObservationsPanel(dynamicCapabilities.recognized && dynamicCapabilities.available) : ''}
		    </div>
		  </details>
		</details>
    </div>
    <div class="site-modal-panel" id="site-panel-advanced" role="tabpanel" aria-labelledby="site-tab-advanced">
			<details class="form-group site-form-wide site-header-options" id="m-header-options" ${hasValues && site.upstream_headers?.length ? 'open' : ''}>
          <summary>自定义请求头</summary>
          <div class="site-header-options-body">
		  <div id="m-upstream-headers"></div>
		  <button type="button" class="btn-ghost upstream-header-add" id="m-add-upstream-header" ${upstreamHeadersAvailable ? '' : 'disabled'}>+ 添加请求头</button>
		  <div class="form-help">加密保存，仅发送到主回源。</div>
		  ${upstreamHeadersAvailable ? '' : '<div class="form-help" style="color:var(--orange)">当前部署未配置 UPSTREAM_HEADER_KEY，不能新增、重命名或修改 Header 值；仍可删除旧配置。配置密钥并重启后可恢复编辑。</div>'}
		</div>
        </details>
      <div class="site-settings-grid">
    <div class="form-group">
      <label for="m-ua">UA 模式</label>
      <select class="form-select modal-select" id="m-ua">
        <option value="passthrough" ${(!hasValues || site.ua_mode === 'passthrough') ? 'selected' : ''}>透传（保留客户端身份）</option>
        <option value="infuse" ${hasValues && site.ua_mode === 'infuse' ? 'selected' : ''}>Infuse</option>
        <option value="web" ${hasValues && site.ua_mode === 'web' ? 'selected' : ''}>Web</option>
        <option value="client" ${hasValues && site.ua_mode === 'client' ? 'selected' : ''}>客户端</option>
        <option value="custom">自定义客户端</option>
      </select>
    </div>
    <div class="form-group" id="m-custom-ua-group" hidden>
      <label for="m-custom-ua">自定义身份</label>
      <input type="text" class="form-input" id="m-custom-ua" placeholder="User-Agent" maxlength="1024" autocapitalize="none" autocorrect="off" spellcheck="false">
      <input type="text" class="form-input" id="m-custom-client" placeholder="Emby Client" maxlength="128" autocapitalize="none" autocorrect="off" spellcheck="false" style="margin-top:8px">
      <input type="text" class="form-input" id="m-custom-version" placeholder="Emby Version" maxlength="64" autocapitalize="none" autocorrect="off" spellcheck="false" style="margin-top:8px">
      <div class="form-help">只改写 User-Agent、Client、Version；Device 与 DeviceId 保持不变。</div>
    </div>
    <div class="form-group">
      <label for="m-client-ip-mode">真实客户端 IP 透传</label>
      <select class="form-select modal-select" id="m-client-ip-mode">
        <option value="both" ${!hasValues || !site.client_ip_mode || site.client_ip_mode === 'both' ? 'selected' : ''}>透传 X-Real-IP 和 X-Forwarded-For（推荐）</option>
        <option value="real_ip" ${hasValues && site.client_ip_mode === 'real_ip' ? 'selected' : ''}>仅保留 X-Real-IP</option>
        <option value="none" ${hasValues && site.client_ip_mode === 'none' ? 'selected' : ''}>强制不透传（慎用）</option>
      </select>
    </div>
    <section class="form-group cache-limit-group" data-cache-panel aria-labelledby="m-cache-panel-title">
      <div class="site-cache-panel-heading">
        <div>
          <h3 id="m-cache-panel-title">缓存图片与静态资源</h3>
          <p>媒体流和私有响应不缓存。</p>
        </div>
        <select class="form-select modal-select" id="m-asset-cache" aria-label="缓存图片与静态资源">
          <option value="off" ${!hasValues || !site.asset_cache_enabled ? 'selected' : ''}>关闭</option>
          <option value="on" ${hasValues && site.asset_cache_enabled ? 'selected' : ''}>开启</option>
        </select>
      </div>
      <div class="site-cache-options" id="m-cache-options" hidden>
        <details class="site-cache-rules-group" id="m-cache-rules-group">
          <summary>自定义缓存规则（可选）</summary>
          <div class="site-cache-rules-body">
            <textarea class="form-input" id="m-cache-rules" rows="3" maxlength="4096" spellcheck="false">${esc(hasValues ? (site.asset_cache_rules || '*/file/*\n*/emby/Items/*/Images/*') : '*/file/*\n*/emby/Items/*/Images/*')}</textarea>
            <div class="form-help">仅在需要覆盖默认的图片和静态资源路径时修改；每行一条，支持 * 通配。</div>
          </div>
        </details>
        <div class="cache-limit-grid">
          <label for="m-cache-ttl">缓存时间（小时）</label>
          <input type="number" class="form-input" id="m-cache-ttl" min="1" max="720" step="1" inputmode="numeric" required value="${hasValues ? Math.max(1, Math.round((site.asset_cache_ttl_sec || 86400) / 3600)) : 24}">
          <label for="m-cache-max">容量上限（MB）</label>
          <input type="number" class="form-input" id="m-cache-max" min="1" max="20480" step="1" inputmode="numeric" required value="${hasValues ? Math.max(1, Math.round((site.asset_cache_max_bytes || 536870912) / 1048576)) : 512}">
        </div>
      </div>
    </section>
    <div class="form-group">
      <label for="m-quota">流量额度 (GB, 0=不限)</label>
      <input type="number" class="form-input" id="m-quota" value="${hasValues ? Math.round((site.traffic_quota || 0) / 1073741824) : 0}" placeholder="0" min="0" max="8589934591" step="1" inputmode="numeric" required>
    </div>
    <div class="form-group">
      <label for="m-speed">单连接限速 (Mbps, 0=不限)</label>
      <input type="number" class="form-input" id="m-speed" value="${hasValues ? (site.speed_limit || 0) : 0}" placeholder="0" min="0" max="1000000" step="1" inputmode="numeric" required>
      <div class="form-help">限制单个连接的下行速度，修改后对新请求生效，上传不受影响。</div>
      </div>
      <div class="form-group">
        <label for="m-total-speed">站点总下载限速 (Mbps, 0=不限)</label>
        <input type="number" class="form-input" id="m-total-speed" value="${hasValues ? (site.total_speed_limit || 0) : 0}" min="0" max="1000000" step="1" inputmode="numeric" required>
        <div class="form-help">所有连接共享，修改立即影响正在进行的下载。仅限制经本站代理的下载，上传、直连和跳转到上游的媒体不计入；允许约 32 KiB 短时突发，不保证客户端间公平分配。</div>
      </div>
      </div>
    </div>
  `;

  document.getElementById('modal-footer').innerHTML = `
    <div class="site-account-save-notice" id="m-account-save-notice" role="status" aria-live="polite" hidden>账号有未保存的修改，请先保存账号或放弃修改。<button type="button" class="btn-ghost" id="m-account-review">查看账号</button></div>
    <button class="btn-modal secondary" id="m-cancel">取消</button>
    <button class="btn-modal primary" id="m-submit">${isEdit ? '保存' : '创建'}</button>
  `;

  if (typeof document.querySelectorAll === 'function') {
    const tabs = [...document.querySelectorAll('.site-modal-tab')];
    const selectTab = tab => {
      tabs.forEach(button => {
        const active = button === tab;
        button.classList.toggle('active', active);
        button.setAttribute('aria-selected', String(active));
        button.tabIndex = active ? 0 : -1;
        document.getElementById('site-panel-' + button.dataset.tab)?.classList.toggle('active', active);
      });
      document.getElementById('modal-body').scrollTop = 0;
    };
    tabs.forEach((tab, index) => {
      tab.addEventListener('click', () => selectTab(tab));
      tab.addEventListener('keydown', event => {
        const next = event.key === 'ArrowRight' ? (index + 1) % tabs.length
          : event.key === 'ArrowLeft' ? (index + tabs.length - 1) % tabs.length
          : event.key === 'Home' ? 0 : event.key === 'End' ? tabs.length - 1 : -1;
        if (next < 0) return;
        event.preventDefault();
        selectTab(tabs[next]);
        tabs[next].focus();
      });
    });
  }

  document.getElementById('m-cancel').addEventListener('click', closeModal);

	const primaryAddressInput = document.getElementById('m-target-address');
  const primarySchemeInput = document.getElementById('m-target-scheme');
  const primaryPortInput = document.getElementById('m-target-port');
  primarySchemeInput.value = primaryTarget.scheme;
  let previousPrimaryScheme = primaryTarget.scheme;
  const syncPrimaryAddress = () => {
    const raw = primaryAddressInput.value.trim();
    const authority = raw.split(/[/?#]/)[0];
    const explicitScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw);
    const explicitPort = /(?:\]|[^:]):\d+$/.test(authority);
    if (!explicitScheme && !explicitPort) return;
    const normalized = normalizeSiteUpstreamAddress(explicitScheme ? raw : `${primarySchemeInput.value}://${raw}`);
    if (!normalized) return;
    const parts = splitUpstreamTargetAddress(normalized, primarySchemeInput.value);
    primarySchemeInput.value = parts.scheme;
    primaryAddressInput.value = parts.address;
    primaryPortInput.value = parts.port;
    previousPrimaryScheme = parts.scheme;
  };
  primaryAddressInput.addEventListener('change', syncPrimaryAddress);
  primarySchemeInput.onchange = () => {
    const oldPort = primaryPortInput.value.trim();
    if (!oldPort || oldPort === defaultUpstreamPort(previousPrimaryScheme) || oldPort === (previousPrimaryScheme === 'http' ? '80' : '443')) {
      primaryPortInput.value = defaultUpstreamPort(primarySchemeInput.value);
    }
    previousPrimaryScheme = primarySchemeInput.value;
  };
  const primaryTargetURL = () => {
    syncPrimaryAddress();
    return joinUpstreamTargetAddress(primarySchemeInput.value, primaryAddressInput.value, primaryPortInput.value);
  };

  const accountList = document.getElementById('m-account-list');
  const accountCount = document.getElementById('m-account-count');
  const accountFormIDs = ['m-account-id', 'm-account-name', 'm-account-username', 'm-account-password', 'm-account-security', 'm-account-expires', 'm-account-reminder', 'm-account-note'];
  let accountFormOriginal = null;
  let saving = false;
  let accountSaving = false;
  const accountFingerprint = () => JSON.stringify(accountFormIDs.map(id => {
    const input = document.getElementById(id);
    const value = input?.value || '';
    return [id === 'm-account-password' || id === 'm-account-security' ? value : value.trim(), !!input?.validity?.badInput];
  }));
  let accountBaseline = accountFingerprint();
  const accountFormDirty = () => accountFingerprint() !== accountBaseline;
  function hasPendingAccountChanges() {
    return accountFormDirty() || (!isEdit && accountFormOriginal && !accountFormOriginal.id);
  }
  function guardAccountRenewal() {
    if (!hasPendingAccountChanges()) return true;
    Toast.error('当前账号有未保存的修改，请先保存账号或放弃修改');
    reviewPendingAccount();
    return false;
  }
  function reviewPendingAccount() {
    document.getElementById('site-tab-basic')?.click();
    document.getElementById('m-account-options').open = true;
    document.getElementById('m-account-save').scrollIntoView({ block: 'center', behavior: 'smooth' });
    document.getElementById('m-account-save').focus({ preventScroll: true });
  }
  function refreshAccountSaveState() {
    const pending = isEdit && accountFormDirty();
    const button = document.getElementById('m-submit');
    if (button) {
      button.disabled = saving || accountSaving || pending;
      button.title = pending ? '请先保存账号，或放弃账号修改' : '';
    }
    document.getElementById('m-account-save-notice').hidden = !pending;
    document.getElementById('m-account-reset').textContent = pending ? '放弃修改' : '清空';
  }
  accountFormIDs.forEach(id => {
    document.getElementById(id).addEventListener('input', refreshAccountSaveState);
    document.getElementById(id).addEventListener('change', refreshAccountSaveState);
  });
  document.getElementById('m-account-review').onclick = reviewPendingAccount;
  function fillModalAccountForm(account) {
    accountFormOriginal = { ...account };
    const values = [account.id || '', account.account_name || '', account.username || '', account.password || '', account.security_password || '', formatAccountExpiryDate(account.expires_at), account.reminder_days ?? '', account.note || ''];
    accountFormIDs.forEach((id, index) => { document.getElementById(id).value = values[index]; });
    document.getElementById('m-account-save').textContent = isEdit ? '保存账号' : '确认账号信息';
    accountBaseline = accountFingerprint();
    refreshAccountSaveState();
  }
  function resetModalAccountForm() {
    accountFormOriginal = null;
    accountFormIDs.forEach(id => { const input = document.getElementById(id); if (input) input.value = ''; });
    const save = document.getElementById('m-account-save');
    if (save) save.textContent = '添加账号';
    accountBaseline = accountFingerprint();
    refreshAccountSaveState();
  }
  function renderModalAccounts() {
    if (!accountList) return;
    if (accountCount) accountCount.textContent = modalAccounts.length ? `（${modalAccounts.length} 个）` : '';
    if (!modalAccounts.length) {
      accountList.innerHTML = '<div class="form-help">暂无账号，可在下方添加。</div>';
      return;
    }
    accountList.innerHTML = modalAccounts.map(account => `<div class="site-account-row">
      <div><strong>${esc(account.account_name || account.username || '未命名账号')}${!isEdit ? ' · 待保存' : ''}</strong><span>${esc(account.username || account.account_name || '')}</span></div>
      <div class="site-account-row-meta"><span>登录密码：<code>${esc(account.password || '未填写')}</code> · 安全密码：<code>${esc(account.security_password || '未填写')}</code>${account.expires_at ? ` · 到期日：${esc(formatAccountExpiryDate(account.expires_at))}` : ''}${account.reminder_days != null ? ` · 提前 ${esc(String(account.reminder_days))} 天提醒` : ''}${account.lifecycle ? ` · ${esc({active:'正常', expiring:'即将到期', expired:'已到期', unknown:'日期无效'}[account.lifecycle] || account.lifecycle)}` : ''}</span><div class="site-account-row-actions"><button type="button" class="icon-button" data-modal-account-edit="${account.id || ''}" title="编辑账号">编辑</button>${isEdit && Number(account.id) > 0 ? `<button type="button" class="icon-button" data-modal-account-renew="${account.id}" title="选择续期时长">续期</button>` : ''}<button type="button" class="icon-button danger" data-modal-account-delete="${account.id || ''}" title="删除账号">删除</button></div></div>${isEdit && Number(account.id) > 0 ? `<div class="account-renewal-picker" data-renewal-picker="${account.id}" hidden><span class="form-help">选择续期时长</span><div class="account-renewal-presets"><button type="button" class="btn-ghost" data-renewal-account="${account.id}" data-renewal-days="30">一月</button><button type="button" class="btn-ghost" data-renewal-account="${account.id}" data-renewal-days="90">一季度</button><button type="button" class="btn-ghost" data-renewal-account="${account.id}" data-renewal-days="365">一年</button><button type="button" class="btn-ghost" data-renewal-account="${account.id}" data-renewal-custom-toggle>自定义</button></div><div class="account-renewal-custom" data-renewal-custom hidden><label>自定义天数<input class="form-input" type="number" min="1" max="3650" step="1" inputmode="numeric" data-renewal-custom-input placeholder="1–3650"></label><button type="button" class="btn-ghost" data-renewal-account="${account.id}" data-renewal-custom-submit>确认续期</button></div></div>` : ''}
    </div>`).join('');
    accountList.querySelectorAll('[data-modal-account-edit]').forEach(button => {
      button.onclick = () => {
        const account = modalAccounts.find(row => String(row.id || '') === String(button.dataset.modalAccountEdit));
        if (!account) return;
        if ((accountFormDirty() || (!isEdit && accountFormOriginal && !accountFormOriginal.id)) && !confirm('当前账号有未保存的修改，放弃后切换账号？')) return;
        fillModalAccountForm(account);
      };
    });
    accountList.querySelectorAll('[data-modal-account-delete]').forEach(button => {
      button.onclick = async () => {
        const accountID = Number(button.dataset.modalAccountDelete);
        const index = modalAccounts.findIndex(row => Number(row.id) === accountID);
        if (index < 0) return;
        if (!confirm('确认删除这个账号？')) return;
        try {
          if (isEdit && accountID > 0) await API.deleteSiteAccount(site.id, accountID);
          if (document.getElementById('m-account-list') !== accountList) return;
          modalAccounts.splice(index, 1);
          // Deleting another row must not discard the account currently being edited.
          if (Number(document.getElementById('m-account-id')?.value || 0) === accountID) resetModalAccountForm();
          renderModalAccounts();
          loadSiteAccountReminders();
          Toast.success('账号已删除');
        } catch (error) { Toast.error(error.message || '删除账号失败'); }
      };
    });
    const findRenewalPicker = accountID => [...accountList.querySelectorAll('[data-renewal-picker]')]
      .find(picker => String(picker.dataset.renewalPicker) === String(accountID));
    const setRenewalPickerBusy = (picker, busy) => {
      if (!picker) return;
      picker.querySelectorAll('button, input').forEach(control => { control.disabled = busy; });
    };
    const renewModalAccount = async (accountID, days, trigger) => {
      if (!guardAccountRenewal()) return;
      const normalizedDays = normalizeAccountRenewalDays(days);
      if (!normalizedDays) { Toast.error('续期天数应为 1–3650 的整数'); return; }
      const picker = findRenewalPicker(accountID);
      setRenewalPickerBusy(picker, true);
      if (trigger) trigger.disabled = true;
      try {
        const result = await API.renewSiteAccount(site.id, accountID, normalizedDays);
        const index = modalAccounts.findIndex(row => Number(row.id) === accountID);
        if (index >= 0 && result.account) modalAccounts[index] = { ...modalAccounts[index], ...result.account };
        const editingID = Number(document.getElementById('m-account-id')?.value || 0);
        if (editingID === accountID && index >= 0) fillModalAccountForm(modalAccounts[index]);
        renderModalAccounts();
        loadSiteAccountReminders();
        Toast.success(`已续期 ${normalizedDays} 天，到期日 ${formatAccountExpiryDate(result.renewal?.new_expires_at)}`);
      } catch (error) {
        setRenewalPickerBusy(picker, false);
        if (trigger) trigger.disabled = false;
        Toast.error(error.message || '续期失败');
      }
    };
    accountList.querySelectorAll('[data-modal-account-renew]').forEach(button => {
      button.onclick = () => {
        if (!guardAccountRenewal()) return;
        const picker = findRenewalPicker(button.dataset.modalAccountRenew);
        if (!picker) return;
        accountList.querySelectorAll('[data-renewal-picker]').forEach(other => {
          if (other !== picker) other.hidden = true;
        });
        picker.hidden = !picker.hidden;
        if (!picker.hidden) picker.querySelector('[data-renewal-days]')?.focus();
      };
    });
    accountList.querySelectorAll('[data-renewal-days]').forEach(button => {
      button.onclick = () => renewModalAccount(Number(button.dataset.renewalAccount), button.dataset.renewalDays, button);
    });
    accountList.querySelectorAll('[data-renewal-custom-toggle]').forEach(button => {
      button.onclick = () => {
        if (!guardAccountRenewal()) return;
        const picker = findRenewalPicker(button.dataset.renewalAccount);
        const custom = picker?.querySelector('[data-renewal-custom]');
        if (!custom) return;
        custom.hidden = !custom.hidden;
        if (!custom.hidden) custom.querySelector('input')?.focus();
      };
    });
    accountList.querySelectorAll('[data-renewal-custom-submit]').forEach(button => {
      button.onclick = () => {
        const picker = findRenewalPicker(button.dataset.renewalAccount);
        const input = picker?.querySelector('[data-renewal-custom-input]');
        renewModalAccount(Number(button.dataset.renewalAccount), input?.value || '', button);
      };
    });
    accountList.querySelectorAll('[data-renewal-custom-input]').forEach(input => {
      input.addEventListener('keydown', event => {
        if (event.key !== 'Enter') return;
        event.preventDefault();
        input.closest('[data-renewal-picker]')?.querySelector('[data-renewal-custom-submit]')?.click();
      });
    });
  }
  async function saveModalAccount(showNotice = true) {
    if (accountSaving || !validateFields(document.getElementById('m-account-options'))) return false;
    const id = Number(document.getElementById('m-account-id')?.value || 0);
    const data = {
      account_name: document.getElementById('m-account-name')?.value.trim() || '',
      username: document.getElementById('m-account-username')?.value.trim() || '',
      password: document.getElementById('m-account-password')?.value || '',
      security_password: document.getElementById('m-account-security')?.value || '',
      expires_at: document.getElementById('m-account-expires')?.value || '',
      note: document.getElementById('m-account-note')?.value.trim() || '',
    };
    const reminder = document.getElementById('m-account-reminder')?.value.trim() || '';
    if (reminder && (!/^\d+$/.test(reminder) || Number(reminder) > 3650)) { Toast.error('提前提醒天数应为 0–3650'); return false; }
    data.reminder_days = reminder === '' ? null : Number(reminder);
    data.clear_reminder = reminder === '';
    data.clear_password = data.password === '';
    data.clear_security_password = data.security_password === '';
    data.clear_expires_at = data.expires_at === '';
    data.clear_note = data.note === '';
    const original = accountFormOriginal || modalAccounts.find(row => Number(row.id) === id);
    if (original && data.expires_at === String(original.expires_at || '').slice(0, 10)) data.expires_at = original.expires_at;
    if (!data.account_name && !data.username) { Toast.error('请填写账号名称或用户名'); return false; }
    accountSaving = true;
    const locked = [...accountFormIDs, 'm-account-save', 'm-account-reset'].map(id => document.getElementById(id));
    locked.forEach(input => { input.disabled = true; });
    refreshAccountSaveState();
    try {
      if (isEdit) {
        const saved = id ? await API.updateSiteAccount(site.id, id, data) : await API.createSiteAccount(site.id, data);
        if (document.getElementById('m-account-save') !== locked[accountFormIDs.length]) return true;
        const index = modalAccounts.findIndex(row => Number(row.id) === id);
        if (index >= 0) modalAccounts[index] = saved;
        else modalAccounts.push(saved);
      } else {
        const draft = { ...data, password_configured: !!data.password, security_password_configured: !!data.security_password };
        const index = modalAccounts.findIndex(row => Number(row.id) === id && id < 0);
        if (index >= 0) modalAccounts[index] = { ...modalAccounts[index], ...draft };
        else modalAccounts.push({ ...draft, id: nextDraftAccountID-- });
      }
      resetModalAccountForm();
      renderModalAccounts();
      loadSiteAccountReminders();
      if (showNotice) Toast.success(isEdit ? '账号已保存' : '账号信息已确认，创建站点后生效');
      return true;
    } catch (error) { Toast.error(error.message || '保存账号失败'); return false; }
    finally {
      accountSaving = false;
      locked.forEach(input => { input.disabled = false; });
      if (document.getElementById('m-account-save') === locked[accountFormIDs.length]) refreshAccountSaveState();
    }
  }
  document.getElementById('m-account-save')?.addEventListener('click', () => saveModalAccount());
  document.getElementById('m-account-reset')?.addEventListener('click', resetModalAccountForm);
  renderModalAccounts();
	const failoverLinesContainer = document.getElementById('m-failover-lines');
	let failoverLines = hasValues && Array.isArray(site.failover_lines)
		? site.failover_lines.map(line => ({name: line.name || '', url: line.url || '', enabled: line.enabled !== false}))
		: (hasValues && Array.isArray(site.failover_targets) ? site.failover_targets.map((url, index) => ({name:`备用 ${index+1}`,url,enabled:true})) : []);
	function lineActionIcon(kind) {
		if (kind === 'up') return '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m18 15-6-6-6 6"/></svg>';
		if (kind === 'down') return '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>';
		if (kind === 'remove') return '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 6h18M8 6V4h8v2m-9 0 1 14h8l1-14M10 10v6m4-6v6"/></svg>';
		return '';
	}

	function renderFailoverLines() {
		failoverLinesContainer.innerHTML = failoverLines.map((line,index) => `<div class="upstream-line site-upstream-line" data-line-index="${index}">
          <label class="site-backup-enable"><input class="upstream-line-toggle" type="checkbox" ${line.enabled ? 'checked' : ''}><span>备用 ${index+1}</span></label>
          <input class="form-input upstream-line-address" value="${esc(line.url)}" placeholder="https://backup.example.com" inputmode="url" maxlength="2048" aria-label="备用地址 ${index+1}" ${line.enabled ? 'required' : 'disabled'}>
          <span class="upstream-line-latency">--</span>
          <div class="upstream-line-actions">
            <button type="button" class="icon-button upstream-line-move-up" aria-label="上移" ${index===0?'disabled':''}>${lineActionIcon('up')}</button>
            <button type="button" class="icon-button upstream-line-move-down" aria-label="下移" ${index===failoverLines.length-1?'disabled':''}>${lineActionIcon('down')}</button>
            <button type="button" class="icon-button upstream-line-remove" aria-label="删除">${lineActionIcon('remove')}</button>
          </div>
        </div>`).join('');
        failoverLinesContainer.querySelectorAll('.upstream-line').forEach(row => {
          const index=Number(row.dataset.lineIndex);
          row.querySelector('.upstream-line-toggle').onchange = e => {failoverLines[index].enabled=e.target.checked;renderFailoverLines();};
          row.querySelector('.upstream-line-address').oninput = e => {failoverLines[index].url=e.target.value;};
          row.querySelector('.upstream-line-remove').onclick = () => {failoverLines.splice(index,1);renderFailoverLines();};
          for(const [name,delta] of [['up',-1],['down',1]]) row.querySelector('.upstream-line-move-'+name).onclick=()=>{[failoverLines[index],failoverLines[index+delta]]=[failoverLines[index+delta],failoverLines[index]];renderFailoverLines();};
        });
	}

	async function testUpstreamLine(row, addressInput) {
		const latency = row.querySelector('.upstream-line-latency');
    latency.hidden = false;
    if (addressInput === primaryAddressInput) syncPrimaryAddress();
		if (!validateFields(row)) {
			latency.textContent = '请检查输入';
			latency.className = 'upstream-line-latency bad';
			return;
		}
		const targetURL = addressInput === primaryAddressInput ? primaryTargetURL() : normalizeSiteUpstreamAddress(addressInput.value);
		if (!targetURL) {
			latency.textContent = '请填写地址';
			latency.className = 'upstream-line-latency bad';
			return;
		}
		latency.textContent = '测试中…';
		latency.className = 'upstream-line-latency';
		try {
			const result = await API.testUpstream(targetURL);
			if (result && result.status === 'online') {
				const latencyMs = Number(result.latency_ms);
				if (!Number.isFinite(latencyMs) || latencyMs < 0) throw new Error('测速结果无效');
				latency.textContent = `${latencyMs} ms`;
				latency.className = `upstream-line-latency ${latencyMs < 200 ? 'good' : latencyMs < 800 ? 'warn' : 'bad'}`;
			} else {
				throw new Error((result && result.error) || '线路不可用');
			}
		} catch (error) {
			latency.textContent = '失败';
			latency.className = 'upstream-line-latency bad';
			latency.title = error.message || '线路测试失败';
		}
	}

	renderFailoverLines();
	document.getElementById('m-add-failover-line').onclick = () => {
		if (failoverLines.length >= 7) {
			Toast.error('最多添加 7 条备用线路');
			return;
		}
		failoverLines.push({ name: `备用 ${failoverLines.length + 1}`, url: '', enabled: true });
		renderFailoverLines();
		const inputs = failoverLinesContainer.querySelectorAll('.upstream-line-address');
		if (inputs.length) inputs[inputs.length - 1].focus();
	};
	document.getElementById('m-test-all-lines').onclick = async event => {
		const button = event.currentTarget;
		button.disabled = true;
		button.textContent = '测试中…';
		const rows = [...document.querySelectorAll('#m-upstream-lines .upstream-line')].filter(row => {
			if (row.dataset.line === 'primary') return true;
			const index = Number(row.dataset.lineIndex);
			return failoverLines[index] && failoverLines[index].enabled;
		});
		for (const row of rows) {
			await testUpstreamLine(row, row.querySelector('.upstream-line-address'));
		}
		button.disabled = false;
		button.textContent = '测试连接';
	};

	const ingressSelect = document.getElementById('m-ingress-mode');
	const publicHostGroup = document.getElementById('m-public-host-group');
	const publicHostInput = document.getElementById('m-public-host');
	const routePrefixInput = document.getElementById('m-route-prefix');
	const pathPrefixGroup = document.getElementById('m-path-prefix-group');
	const pathPrefixInput = document.getElementById('m-path-prefix');
	const portInput = document.getElementById('m-port');
	const portLabel = document.getElementById('m-port-label');
	const portHelp = document.getElementById('m-port-help');
	const ingressWarning = document.getElementById('m-ingress-warning');
	ingressSelect.value = hasValues ? normalizedIngressMode(site) : defaultIngressMode(siteCapabilities);
	function updateIngressFields() {
		const state = ingressFormState(ingressSelect.value);
		publicHostGroup.hidden = !state.showPublicHost;
		publicHostInput.required = state.requirePublicHost;
		routePrefixInput.required = state.requirePublicHost && domainPrefixAvailable;
		routePrefixInput.disabled = !state.showPublicHost;
		pathPrefixGroup.hidden = !state.showPathPrefix;
		pathPrefixInput.required = state.requirePathPrefix;
		pathPrefixInput.disabled = !state.showPathPrefix;
		portInput.required = state.requireListenPort;
		portInput.disabled = !state.requireListenPort;
		document.getElementById('m-port-group').hidden = !state.requireListenPort;
		portLabel.textContent = state.portLabel;
		portHelp.textContent = state.requireListenPort
			? '填写 1–65535 之间的整数，并确保端口未被占用。'
			: '共享入口不会另外开放站点端口。';
		ingressWarning.textContent = state.warning;
		if (state.mode === 'host' && siteCapabilities.external_proxy) ingressWarning.textContent = '当前由外部代理提供 HTTPS。请在代理中配置节点泛域名证书并转发这些域名；Meridian 不会自动修改外部代理。';
	}
	updateIngressFields();
	ingressSelect.addEventListener('change', updateIngressFields);
	if (!isEdit) {
	  document.getElementById('m-launch-parse')?.addEventListener('click', async () => {
	    const result = document.getElementById('m-launch-result');
	    const text = document.getElementById('m-launch-message')?.value.trim() || '';
	    if (!text) { Toast.error('请先粘贴开号信息'); return; }
      const parseButton = document.getElementById('m-launch-parse');
      const activeForm = document.getElementById('m-submit');
      if (parseButton.disabled) return;
      parseButton.disabled = true;
	    try {
	      const parsed = await API.parseSiteMessage(text);
      if (document.getElementById('m-submit') !== activeForm) return;
	      document.getElementById('m-name').value = parsed.name || '';
	      const target = splitUpstreamTargetAddress(parsed.target_url || '', 'http');
	      primarySchemeInput.value = target.scheme;
	      primaryAddressInput.value = target.address;
	      primaryPortInput.value = target.port;
      failoverLines = (parsed.failover_targets || []).map((url, index) => ({name: `备用 ${index + 1}`, url, enabled: true}));
      renderFailoverLines();
	      ingressSelect.value = parsed.ingress_mode || 'path';
	      pathPrefixInput.value = String(parsed.path_prefix || '').replace(/^\//, '');
	      updateIngressFields();
      // Recognition fills the editable form; only an explicit save stages the account.
      resetModalAccountForm();
      const recognized = Array.isArray(parsed.accounts) ? parsed.accounts[0] : null;
      if (recognized) {
        const existing = modalAccounts.find(account => account.username === recognized.username);
        fillModalAccountForm({ ...recognized, id: existing?.id });
      }
      result.textContent = recognized ? '已识别，尚未保存。请在下方核对账号、到期时间和提前提醒，再创建站点。' : '已识别站点线路，未找到账号信息。请检查后创建。';
	      document.getElementById('m-account-options')?.setAttribute('open', '');
	    } catch (error) {
	      result.textContent = error.message || '解析失败';
	    } finally { parseButton.disabled = false; }
	  });
	}

	const uaSelect = document.getElementById('m-ua');
  const clientIPModeSelect = document.getElementById('m-client-ip-mode');
  const playbackRoutingSelect = document.getElementById('m-playback-routing-mode');
  const assetCacheSelect = document.getElementById('m-asset-cache');
  const cacheOptionsGroup = document.getElementById('m-cache-options');
  const cacheRulesGroup = document.getElementById('m-cache-rules-group');
  const customUAGroup = document.getElementById('m-custom-ua-group');
  const customUAInputs = [
    document.getElementById('m-custom-ua'),
    document.getElementById('m-custom-client'),
    document.getElementById('m-custom-version'),
  ];
  const initialUAState = customUAFormState(hasValues ? site.ua_mode : 'passthrough', site);
  uaSelect.value = hasValues && site.ua_mode ? site.ua_mode : 'passthrough';
  clientIPModeSelect.value = hasValues && ['both', 'real_ip', 'none'].includes(site.client_ip_mode) ? site.client_ip_mode : 'both';
  playbackRoutingSelect.value = hasValues ? sitePlaybackRoutingMode(site) : dynamicCapabilities.available ? 'auto' : 'manual';
  customUAInputs[0].value = initialUAState.customUserAgent;
  customUAInputs[1].value = initialUAState.customClient;
  customUAInputs[2].value = initialUAState.customVersion;

  const syncAssetCacheFields = () => {
    const enabled = assetCacheSelect?.value === 'on';
    if (cacheOptionsGroup) cacheOptionsGroup.hidden = !enabled;
    if (cacheRulesGroup) {
      cacheRulesGroup.hidden = !enabled;
      if (!enabled) cacheRulesGroup.open = false;
    }
  };
  syncAssetCacheFields();
  assetCacheSelect?.addEventListener('change', syncAssetCacheFields);

  function toggleCustomUAFields() {
    const state = customUAFormState(uaSelect.value);
    customUAGroup.hidden = !state.visible;
    if (state.visible) {
      if (typeof customUAGroup.style?.removeProperty === 'function') customUAGroup.style.removeProperty('display');
      else if (customUAGroup.style) customUAGroup.style.display = '';
    } else if (typeof customUAGroup.style?.setProperty === 'function') {
      customUAGroup.style.setProperty('display', 'none', 'important');
    } else if (customUAGroup.style) {
      customUAGroup.style.display = 'none';
    }
    if (typeof customUAGroup.setAttribute === 'function') customUAGroup.setAttribute('aria-hidden', state.visible ? 'false' : 'true');
    customUAInputs.forEach(input => {
      input.required = state.required;
      if (!state.visible) input.value = '';
    });
  }
  toggleCustomUAFields();
  uaSelect.addEventListener('change', toggleCustomUAFields);


	  const dynamicProfileSelect = document.getElementById('m-dynamic-profile');
	  const dynamicHelp = document.getElementById('m-dynamic-help');
	  const dynamicRulesContainer = document.getElementById('m-dynamic-rules');
  const dynamicRulesButton = document.getElementById('m-add-dynamic-rule');
  const dynamicInitialPolicy = { ...dynamicPolicy };
  const renderDynamicRules = () => {
    if (!dynamicRulesContainer) return;
    dynamicRulesContainer.innerHTML = renderDynamicRuleRows(dynamicRules);
    dynamicRulesContainer.querySelectorAll('.m-dynamic-rule-type').forEach(input => {
      input.onchange = () => { dynamicRules[Number(input.dataset.idx)].type = input.value; };
    });
    dynamicRulesContainer.querySelectorAll('.m-dynamic-rule-value').forEach(input => {
      input.oninput = () => { dynamicRules[Number(input.dataset.idx)].value = input.value; };
    });
    dynamicRulesContainer.querySelectorAll('.m-dynamic-rule-remove').forEach(button => {
      button.onclick = () => { dynamicRules.splice(Number(button.dataset.idx), 1); renderDynamicRules(); };
    });
	  };
	  const syncDynamicControls = () => {
	    const profile = normalizeDynamicProfile(dynamicProfileSelect?.value || dynamicPolicy.dynamic_profile);
	    const extremeConfirm = document.getElementById('m-dynamic-extreme-confirm');
	    if (extremeConfirm) extremeConfirm.hidden = profile !== 'extreme' || playbackRoutingSelect.value !== 'auto';
	    if (dynamicHelp) dynamicHelp.textContent = profile === 'safe'
	      ? 'Safe：处理 HTTP 30x 与 PlaybackInfo，仅允许 HTTPS:443，并要求命中明确的域名规则。'
	      : profile === 'extreme'
	        ? 'Extreme：全部发现来源、HTTP(S)、有效端口和 HTTPS 降级开启。单份响应地址数与重定向跳数不设固定上限；寻址总超时 60 秒，保留资源预算和循环检测。'
	        : 'Compatible：处理 HTTP 30x、PlaybackInfo、HLS 与 DASH并允许受控 HTTPS 降级；仍拒绝私网与回环目标。';
	  };
  if (dynamicRulesButton) dynamicRulesButton.onclick = () => {
    dynamicRules.push({ type: 'exact', value: '' });
    renderDynamicRules();
    const last = dynamicRulesContainer?.querySelector('.m-dynamic-rule-value:last-child');
    if (last) last.focus();
  };
  if (dynamicProfileSelect) dynamicProfileSelect.onchange = syncDynamicControls;
  const syncPlaybackMode = () => {
    const mode = playbackRoutingSelect.value;
    document.getElementById('m-manual-playback').hidden = mode !== 'manual';
    document.getElementById('m-auto-options').hidden = mode !== 'auto';
    document.getElementById('m-playback-mode-help').textContent = mode === 'direct'
      ? '视频、HLS/DASH 播放地址交给客户端直连；登录、海报图片和其他接口继续通过 Meridian。'
      : mode === 'manual' ? '使用指定的播放回源与已知节点代理视频，主地址负责登录、海报和其他接口。'
      : '自动识别播放回源、重定向及 HLS/DASH 地址，并通过 Meridian 代理播放。';
    syncDynamicControls();
  };
  playbackRoutingSelect.onchange = syncPlaybackMode;
  syncPlaybackMode();
  renderDynamicRules();
  syncDynamicControls();
  if (isEdit && dynamicCapabilities.recognized && dynamicCapabilities.available) {
    const refreshObservations = async () => {
      const target = document.getElementById('m-dynamic-observations');
      if (!target || !API.getDynamicObservations) return;
      target.innerHTML = '<div class="form-help">正在读取观察记录…</div>';
      try { target.innerHTML = renderDynamicObservations(await API.getDynamicObservations(site.id)); } catch (error) { target.innerHTML = `<div class="form-help" style="color:var(--red)">${esc(error.message)}</div>`; }
    };
    document.getElementById('m-refresh-dynamic-observations')?.addEventListener('click', refreshObservations);
    document.getElementById('m-clear-dynamic-observations')?.addEventListener('click', async () => {
      try { await API.deleteDynamicObservations(site.id); await refreshObservations(); Toast.success('观察记录已清空'); } catch (error) { Toast.error(error.message); }
    });
    refreshObservations();
  }

  const upstreamHeadersContainer = document.getElementById('m-upstream-headers');
  let upstreamHeaders = hasValues && Array.isArray(site.upstream_headers) && site.upstream_headers.length
    ? site.upstream_headers.map(header => ({ name: header.name || '', value: '', configured: !!header.configured }))
    : [{ name: '', value: '', configured: false }];

  function renderUpstreamHeaders() {
    upstreamHeadersContainer.innerHTML = renderUpstreamHeaderRows(upstreamHeaders, upstreamHeadersAvailable);
    upstreamHeadersContainer.querySelectorAll('.m-upstream-header-name').forEach(input => {
      input.oninput = () => { upstreamHeaders[Number(input.dataset.idx)].name = input.value; };
    });
    upstreamHeadersContainer.querySelectorAll('.m-upstream-header-value').forEach(input => {
      input.oninput = () => { upstreamHeaders[Number(input.dataset.idx)].value = input.value; };
    });
    upstreamHeadersContainer.querySelectorAll('.m-upstream-header-remove').forEach(button => {
      button.onclick = () => {
        upstreamHeaders.splice(Number(button.dataset.idx), 1);
        renderUpstreamHeaders();
      };
    });
  }
  renderUpstreamHeaders();

  const addUpstreamHeaderButton = document.getElementById('m-add-upstream-header');
  addUpstreamHeaderButton.onclick = () => {
    if (!upstreamHeadersAvailable) {
      Toast.error('请先配置 UPSTREAM_HEADER_KEY 并重启 Meridian');
      return;
    }
    if (upstreamHeaders.length >= 16) {
      Toast.error('每个站点最多配置 16 个上游请求头');
      return;
    }
    upstreamHeaders.push({ name: '', value: '', configured: false });
    renderUpstreamHeaders();
    const inputs = upstreamHeadersContainer.querySelectorAll('.m-upstream-header-name');
    if (inputs.length) inputs[inputs.length - 1].focus();
  };

  let configuredStreamHosts = hasValues ? normalizeStreamHosts(site.stream_hosts) : [];
  const playbackTargetInput = document.getElementById('m-playback-target');
  function renderStreamHostRows() {
    const container = document.getElementById('m-stream-hosts-list');
    if (!container) return;
    if (!configuredStreamHosts.length) {
      container.innerHTML = '<div style="font-size:12px; color: var(--white-38); padding: 4px 0;">暂无额外播放节点（按需添加）</div>';
      return;
    }
    container.innerHTML = configuredStreamHosts.map((host, idx) => `
      <div class="stream-host-row" style="display: flex; gap: 8px; align-items: center;">
        <input type="text" class="form-input m-stream-host-input" data-idx="${idx}" value="${esc(host)}" placeholder="如：https://stream2.example.com:443" inputmode="url" autocapitalize="none" autocorrect="off" spellcheck="false" maxlength="2048" style="flex: 1;">
        <button type="button" class="btn-ghost danger m-remove-stream-host" data-idx="${idx}" style="padding: 6px 12px; font-size:12px; min-height: 38px;">删除</button>
      </div>
    `).join('');
    container.querySelectorAll('.m-remove-stream-host').forEach(btn => {
      btn.onclick = () => {
        const idx = Number(btn.dataset.idx);
        configuredStreamHosts.splice(idx, 1);
        renderStreamHostRows();
      };
    });
    container.querySelectorAll('.m-stream-host-input').forEach(input => {
      input.oninput = () => {
        const idx = Number(input.dataset.idx);
        configuredStreamHosts[idx] = input.value.trim();
      };
    });
  }

  const addStreamHostButton = document.getElementById('m-add-stream-host');
  if (addStreamHostButton) {
    addStreamHostButton.onclick = () => {
      const maxLimit = siteCapabilities && siteCapabilities.max_playback_addresses ? siteCapabilities.max_playback_addresses : 128;
      const hasPlaybackTarget = Boolean(playbackTargetInput && playbackTargetInput.value.trim());
      if (!canAddPlaybackAddress(configuredStreamHosts.length, maxLimit, hasPlaybackTarget)) {
        Toast.error('已达到最大播放节点数量上限');
        return;
      }
      configuredStreamHosts.push('');
      renderStreamHostRows();
      const inputs = document.querySelectorAll('.m-stream-host-input');
      if (inputs.length) inputs[inputs.length - 1].focus();
    };
  }
  renderStreamHostRows();

  const modalBody = document.getElementById('modal-body');
  bindFieldValidation(modalBody);
  const submitButton = document.getElementById('m-submit');
  refreshAccountSaveState();
  submitButton.onclick = async () => {
    if (accountSaving || saving) return;
    if (isEdit && accountFormDirty()) { refreshAccountSaveState(); reviewPendingAccount(); return; }
    syncPrimaryAddress();
    if (!validateFields(modalBody)) return;
    const uaMode = uaSelect.value;
    const customUAPayload = buildCustomUAPayload(
      uaMode,
      customUAInputs[0].value,
      customUAInputs[1].value,
      customUAInputs[2].value,
    );
		const ingressPayload = buildIngressPayload(
		  ingressSelect.value,
		  portInput.disabled ? '' : portInput.value,
		  publicHostInput.value,
		  routePrefixInput.value,
		  siteCapabilities.route_domain,
		  pathPrefixInput.value,
		);
				const primaryURL = primaryTargetURL();
				if (!primaryURL) return rejectField(primaryAddressInput, '请填写有效的 HTTP / HTTPS 回源地址');
                const invalidBackup = failoverLines.findIndex(line => line.enabled !== false && !normalizeSiteUpstreamAddress(line.url));
                if (invalidBackup >= 0) return rejectField(failoverLinesContainer.querySelector(`[data-line-index="${invalidBackup}"] .upstream-line-address`), '请填写有效的 HTTP / HTTPS 备用地址');
				const playbackTargetURL = playbackRoutingSelect.value === 'manual' && playbackTargetInput ? playbackTargetInput.value.trim() : '';
				const streamHostValues = playbackRoutingSelect.value === 'manual' ? normalizeStreamHosts(configuredStreamHosts) : [];
				const maxPlaybackAddresses = siteCapabilities && siteCapabilities.max_playback_addresses
					? siteCapabilities.max_playback_addresses
					: DEFAULT_MAX_PLAYBACK_ADDRESSES;
				if (playbackAddressCount(playbackTargetURL, streamHostValues) > maxPlaybackAddresses) {
					Toast.error('播放回源地址和播放节点总数超过上限');
					return;
				}
			const nextDynamicProfile = playbackRoutingSelect.value === 'direct' ? 'compatible' : normalizeDynamicProfile(dynamicProfileSelect?.value || dynamicPolicy.dynamic_profile);
			const nextDynamicPolicy = {
				dynamic_discovery_enabled: playbackRoutingSelect.value !== 'manual' && dynamicCapabilities.available,
				dynamic_profile: nextDynamicProfile,
				dynamic_domain_rules: dynamicRules,
				dynamic_allow_https_downgrade: nextDynamicProfile !== 'safe',
		};
		const dynamicConfirmation = confirmDynamicProfileChange(
			dynamicInitialPolicy,
			nextDynamicPolicy,
			document.getElementById('m-name').value.trim(),
			document.getElementById('m-dynamic-extreme-ack')?.checked === true,
			document.getElementById('m-dynamic-extreme-name')?.value.trim() || '',
		);
		if (!dynamicConfirmation.ok) {
			if (dynamicConfirmation.error) {
				document.getElementById('site-tab-lines')?.click();
                document.getElementById('m-auto-options').open = true;
				Toast.error(dynamicConfirmation.error);
			}
			return;
		}
		const dynamicPayload = buildDynamicPolicyPayload(nextDynamicPolicy, dynamicCapabilities);
		const data = {
	      name: document.getElementById('m-name').value.trim(),
	      target_url: primaryURL,
		      primary_line_name: hasValues ? site.primary_line_name || '主线路' : '主线路',
		      failover_lines: failoverLines.map((line, index) => ({
		        name: String(line.name || '').trim() || `线路${index + 2}`,
		        url: normalizeSiteUpstreamAddress(line.url),
		        enabled: line.enabled !== false,
		      })),
		      failover_targets: failoverLines.filter(line => line.enabled !== false).map(line => normalizeSiteUpstreamAddress(line.url)).filter(Boolean),
	      playback_target_url: playbackTargetURL,
      playback_mode: 'direct',
		main_video_stream_mode: playbackRoutingSelect.value === 'direct' ? 'direct' : 'proxy',
		stream_hosts: streamHostValues,
			...ingressPayload,
		upstream_headers: buildUpstreamHeaderPayload(upstreamHeaders),
      ua_mode: uaMode,
      client_ip_mode: clientIPModeSelect.value,
      ...customUAPayload,
		...dynamicPayload,
      asset_cache_enabled: document.getElementById('m-asset-cache').value === 'on',
      asset_cache_ttl_sec: (parseBoundedInteger(document.getElementById('m-cache-ttl').value, 1, 720) ?? 24) * 3600,
      asset_cache_max_bytes: (parseBoundedInteger(document.getElementById('m-cache-max').value, 1, 20480) ?? 512) * 1048576,
      asset_cache_rules: document.getElementById('m-cache-rules').value.trim(),
      traffic_quota: Number(document.getElementById('m-quota').value) * 1073741824,
      speed_limit: Number(document.getElementById('m-speed').value),
      total_speed_limit: Number(document.getElementById('m-total-speed').value),
      ...(!isEdit && hasValues ? {
        ping_cache_enabled: !!site.ping_cache_enabled,
        image_cache_enabled: !!site.image_cache_enabled,
        progress_coalescing_enabled: !!site.progress_coalescing_enabled,
      } : {}),
    };

		const listenPortRequired = ingressFormState(data.ingress_mode).requireListenPort;
		if (data.ingress_mode === 'unset') {
		  Toast.error('请选择当前服务器可用的入口模式');
		  return;
		}
		if (!data.name || !data.target_url || (listenPortRequired && !data.listen_port) || (data.ingress_mode === 'host' && !data.route_prefix && !data.public_host) || (data.ingress_mode === 'path' && !data.path_prefix)) {
	      Toast.error('请填写所有必填项');
	      return;
	    }
	  if (uaMode === 'custom' && (!data.custom_user_agent || !data.custom_client || !data.custom_version)) {
      Toast.error('请完整填写自定义 User-Agent、Client 和 Version');
		return;
	  }
	  const invalidHeader = upstreamHeaders.findIndex(header => {
		const name = String(header.name || '').trim();
		const value = String(header.value || '').trim();
		if (!header.configured && !name && !value) return false;
		return !name || (!header.configured && !value);
	  });
		if (invalidHeader >= 0) {
      const field = String(upstreamHeaders[invalidHeader].name || '').trim() ? 'value' : 'name';
      return rejectField(document.getElementById(`m-upstream-header-${field}-${invalidHeader}`), '请完整填写请求头名称和值；已有值可留空保持不变');
		}
			if (data.failover_lines.some(line => !line.url)) {
				const index = data.failover_lines.findIndex(line => !line.url);
				rejectField(failoverLinesContainer.querySelectorAll('.upstream-line-address')[index], '请填写有效的回源地址，或删除此线路');
			return;
		}
		if (data.failover_targets.length > 0 && upstreamHeaders.some(header => String(header.name || '').trim())) {
			Toast.error('备用线路不能与主回源固定请求头同时使用');
			return;
		}
		if (isEdit && normalizedTargetAuthority(site.target_url) !== normalizedTargetAuthority(data.target_url)) {
			const retainedSecret = upstreamHeaders.some(header => header.configured && !String(header.value || '').trim());
			if (retainedSecret) {
				Toast.error('主回源的协议、域名或端口已变化，请重新输入每个已配置的固定请求头，或删除对应行');
				return;
			}
		}

    // Creating the site is an explicit save: include the currently edited account,
    // including reminder changes, even when the user skips the separate account button.
    if (!isEdit && accountFormIDs.slice(1).some(id => document.getElementById(id).value !== '')) {
      if (!(await saveModalAccount(false))) return;
    }
    saving = true;
    submitButton.disabled = true;
    submitButton.textContent = isEdit ? '保存中…' : '创建中…';
    submitButton.setAttribute('aria-busy', 'true');
    try {
      if (isEdit) {
        const impact = await API.previewSite(site.id, data);
        if (impact.restarts && !window.confirm('本次修改需要重启此站点，正在播放的连接可能断开。继续保存？')) return;
        await API.updateSite(site.id, data, impact.fingerprint);
        Toast.success('站点已更新');
      } else {
        const pendingAccounts = modalAccounts.filter(account => Number(account.id) < 0 || !account.id);
        await API.createSite({ ...data, accounts: pendingAccounts.map(account => ({
          account_name: account.account_name || '',
          username: account.username || '',
          password: account.password || '',
          security_password: account.security_password || '',
          expires_at: account.expires_at || '',
          note: account.note || '',
          reminder_days: account.reminder_days ?? null,
        })) });
        Toast.success(pendingAccounts.length ? `站点已创建，已保存 ${pendingAccounts.length} 个账号` : '站点已创建');
      }
      // A user may close this editor and open another while the request runs.
      if (document.getElementById('m-submit') === submitButton) closeModal();
      loadSites();
    } catch (e) {
      Toast.error(e.message);
    } finally {
      saving = false;
      if (document.getElementById('m-submit') === submitButton) refreshAccountSaveState();
      submitButton.textContent = isEdit ? '保存' : '创建';
      submitButton.removeAttribute('aria-busy');
    }
  };

  openModal({ closeOnBackdrop: false, modalClass: 'site-config-modal' });
}

// Global actions
window.toggleSiteAction = async function(id) {
  try {
    const res = await API.toggleSite(id);
    Toast.success(res.enabled ? '站点已启用' : '站点已停用');
    loadSites();
  } catch (e) {
    Toast.error(e.message);
  }
};

window.editSiteAction = async function(id) {
  try {
    const sites = await API.listSites();
    const site = sites.find(s => s.id === id);
    if (site) showSiteModal(site);
  } catch (e) {
    Toast.error(e.message);
  }
};

window.deleteSiteAction = function(id, name) {
  document.getElementById('modal-title').textContent = '确认删除';
  const modalBody = document.getElementById('modal-body');
  modalBody.replaceChildren();
  const message = document.createElement('p');
  message.style.color = 'var(--white-60)';
  message.append('确定要删除站点 ');
  const strong = document.createElement('strong');
  strong.textContent = String(name);
  message.append(strong, ' 吗？此操作不可撤销。');
  modalBody.appendChild(message);
  document.getElementById('modal-footer').innerHTML = `
    <button class="btn-modal secondary" id="delete-cancel">取消</button>
    <button class="btn-modal primary" id="delete-confirm" style="background:var(--red)">删除</button>
  `;
  document.getElementById('delete-cancel').addEventListener('click', closeModal);
  document.getElementById('delete-confirm').addEventListener('click', () => confirmDelete(id));
  openModal({ closeOnBackdrop: true });
};

window.confirmDelete = async function(id) {
  try {
    await API.deleteSite(id);
    Toast.success('站点已删除');
    closeModal();
    loadSites();
  } catch (e) {
    Toast.error(e.message);
  }
};

function normalizeSiteUpstreamAddress(value) {
  let raw = String(value || '').trim().replaceAll('：', ':');
  if (!raw || /[\\\s]/.test(raw)) return '';
  const explicit = raw.includes('://');
  try {
    const parsed = new URL(explicit ? raw : `http://${raw}`);
    if (!explicit && parsed.port === '443') parsed.protocol = 'https:';
    if (!['http:','https:'].includes(parsed.protocol) || !parsed.hostname || parsed.username || parsed.password || parsed.hash || (parsed.port && parseBoundedInteger(parsed.port,1,65535) === null)) return '';
    return parsed.href;
  } catch (_) { return ''; }
}

function sitePlaybackRoutingMode(site) {
  if (site?.main_video_stream_mode === 'direct') return 'direct';
  return site?.dynamic_discovery_enabled ? 'auto' : 'manual';
}
