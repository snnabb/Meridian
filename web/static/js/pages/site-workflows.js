// Site drafts and bulk operations deliberately reuse the ordinary site editor
// and the backend's validated lifecycle commands.
let siteSelection = new Set();
let siteWorkflowSites = [];

function siteDraft(site) {
  const draft = { ...site, name: (site.name || '') + '（副本）',
    ingress_mode: 'path', path_prefix: '', public_host: '', listen_port: 0,
    upstream_headers: [], dynamic_domain_rules: [], accounts: [] };
  for (const key of ['id', 'created_at', 'updated_at', 'traffic_used', 'monthly_traffic',
    'account_count', 'running', 'enabled', 'dynamic_policy_revision']) delete draft[key];
  return draft;
}
function updateSiteSelectionCount() {
  const button = document.getElementById('btn-sites-bulk');
  if (button) button.textContent = siteSelection.size ? '批量操作 · ' + siteSelection.size : '批量操作';
}
function saveSiteTemplate(site) {
  document.getElementById('modal-title').textContent = '保存配置模板';
  document.getElementById('modal-body').innerHTML = '<p>保存此站点的身份、缓存、播放策略和额度限速。模板不包含回源地址、入口、账号、请求头或动态域名规则。</p><label class="form-group">模板名称<input class="form-input" id="template-name" maxlength="100"></label>';
  document.getElementById('template-name').value = site.name;
  document.getElementById('modal-footer').innerHTML = '<button class="btn-modal secondary" id="template-cancel">取消</button><button class="btn-modal primary" id="template-save">保存</button>';
  document.getElementById('template-cancel').onclick = closeModal;
  document.getElementById('template-save').onclick = async event => {
    const button = event.currentTarget; button.disabled = true;
    try {
      await API.request('POST', '/api/site-templates', { site_id: site.id, name: document.getElementById('template-name').value });
      closeModal(); Toast.success('模板已保存');
    } catch (error) { Toast.error(error.message); }
    finally { button.disabled = false; }
  };
  openModal({closeOnBackdrop: true});
}
async function showSiteTemplates() {
  try {
    const templates = await API.request('GET', '/api/site-templates');
    document.getElementById('modal-title').textContent = '配置模板';
    document.getElementById('modal-body').innerHTML = '<p>从站点卡片选择“存为模板”。应用后填写新站点的回源地址和入口，再确认创建。</p>' +
      (templates.length ? templates.map(t => '<div class="site-import-item"><strong>' + esc(t.name) + '</strong> <button class="btn-ghost" data-template-use="' + t.id + '">用此模板添加</button><button class="btn-ghost danger" data-template-delete="' + t.id + '">删除</button></div>').join('') : '<p>还没有模板。</p>');
    document.getElementById('modal-footer').innerHTML = '<button class="btn-modal secondary" id="template-close">关闭</button>';
    document.getElementById('template-close').onclick = closeModal;
    document.querySelectorAll('[data-template-use]').forEach(button => {
      button.onclick = () => {
        const template = templates.find(t => t.id === Number(button.dataset.templateUse));
        if (template) showSiteModal({ ...template.config, name: '', target_url: '', ingress_mode: 'path', playback_mode: 'direct' });
      };
    });
    document.querySelectorAll('[data-template-delete]').forEach(button => {
      button.onclick = async () => {
        if (!window.confirm('删除此模板？已有站点不受影响。')) return;
        button.disabled = true;
        try { await API.request('DELETE', '/api/site-templates?id=' + button.dataset.templateDelete); await showSiteTemplates(); }
        catch (error) { Toast.error(error.message); button.disabled = false; }
      };
    });
    openModal({closeOnBackdrop: true});
  } catch (error) { Toast.error(error.message); }
}
function siteBulkPayload(ids, action, fields) {
  const payload = {site_ids: ids, action};
  if (action === 'limits') {
    for (const [key, multiplier] of [['traffic_quota', 1073741824], ['speed_limit', 1], ['total_speed_limit', 1]]) {
      const raw = String(fields[key] ?? '').trim();
      if (raw === '') continue;
      const number = Number(raw);
      if (!/^\d+$/.test(raw) || !Number.isSafeInteger(number * multiplier) || (multiplier === 1 && number > 1000000)) throw new Error('请输入有效的非负整数；留空保持原值。');
      payload[key] = number * multiplier;
    }
    if (Object.keys(payload).length === 2) throw new Error('请至少填写一项额度或限速。');
  }
  return payload;
}
function showSiteBulk() {
  const ids = [...siteSelection];
  document.getElementById('modal-title').textContent = '批量操作';
  document.getElementById('modal-body').innerHTML = '<p>已选 ' + ids.length + ' 个站点。停用会断开这些站点的播放连接；额度和限速可运行中修改。</p>' +
    '<button class="btn-ghost" id="bulk-all">选择当前筛选结果</button> <button class="btn-ghost" id="bulk-clear">清空选择</button>' +
    '<label class="form-group">操作<select class="form-select" id="bulk-action"><option value="limits">修改额度和限速</option><option value="enable">启用</option><option value="disable">停用</option></select></label>' +
    '<div id="bulk-limits"><p class="form-help">留空保持原值，填 0 取消限制。</p>' +
    [['traffic_quota','站点配额 (GiB)'],['speed_limit','单连接下载 (Mbps)'],['total_speed_limit','站点总下载 (Mbps)']].map(([key,label]) => '<label class="form-group">' + label + '<input type="number" min="0" step="1" class="form-input" data-bulk-field="' + key + '"></label>').join('') + '</div><div id="bulk-results" role="status"></div>';
  document.getElementById('modal-footer').innerHTML = '<button class="btn-modal secondary" id="bulk-cancel">关闭</button><button class="btn-modal primary" id="bulk-preview">预览</button><button class="btn-modal primary" id="bulk-apply" hidden>确认执行</button>';
  document.getElementById('bulk-cancel').onclick = closeModal;
  document.getElementById('bulk-all').onclick = () => {
    document.querySelectorAll('.site-card').forEach(card => {
      if (!card.hidden && card.style.display !== 'none') siteSelection.add(Number(card.dataset.siteId));
    }); loadSites(); showSiteBulk();
  };
  document.getElementById('bulk-clear').onclick = () => { siteSelection.clear(); loadSites(); showSiteBulk(); };
  const previewButton = document.getElementById('bulk-preview'), applyButton = document.getElementById('bulk-apply');
  const action = document.getElementById('bulk-action'), results = document.getElementById('bulk-results');
  let prepared = null;
  const invalidate = () => { prepared = null; applyButton.hidden = true; };
  action.onchange = () => { invalidate(); document.getElementById('bulk-limits').hidden = action.value !== 'limits'; };
  document.querySelectorAll('[data-bulk-field]').forEach(input => input.oninput = invalidate);
  const render = items => { results.innerHTML = items.map(item => '<p>' + esc(item.name || String(item.id)) + '：' + esc(item.error || ({ready:'待执行',unchanged:'无需变更',completed:'成功',failed:'失败'}[item.status] || item.status)) + '</p>').join(''); };
  previewButton.onclick = async () => {
    previewButton.disabled = true; invalidate();
    try {
      const fields = Object.fromEntries([...document.querySelectorAll('[data-bulk-field]')].map(input => [input.dataset.bulkField,input.value]));
      const payload = siteBulkPayload(ids, action.value, fields);
      const preview = await API.request('POST','/api/sites/bulk',{...payload,preview:true});
      render(preview.items);
      if (preview.valid) { prepared = {...payload,preview_token:preview.preview_token}; applyButton.hidden = false; }
    } catch (error) { results.textContent = error.message; }
    finally { previewButton.disabled = false; }
  };
  applyButton.onclick = async () => {
    if (!prepared) return;
    applyButton.disabled = true; previewButton.disabled = true;
    try {
      const result = await API.request('POST','/api/sites/bulk',prepared);
      render(result.items); invalidate(); await loadSites();
    } catch (error) { results.textContent = error.message; invalidate(); }
    finally { applyButton.disabled = false; previewButton.disabled = false; }
  };
  openModal({closeOnBackdrop: true});
}
