let dashSSE = null;
let dashAbortController = null;
let dashRetryTimer = null;
let dashboardTrendResizeObserver = null;
let dashboardTrendState = { siteId: 'all', range: 'realtime', customStart: '', customEnd: '' };
let dashboardTrendCharts = new Map();
let dashboardTrendData = null;
let dashboardSites = [];
let dashboardTrendRequestGeneration = 0;
let dashboardSpeedSamples = new Map();
let dashboardLiveSpeeds = new Map();
let dashboardRealtimeTrendSamples = new Map();
let dashboardRealtimeTrendSiteSamples = new Map();

function renderDashboard() {
  const page = document.getElementById('page-dashboard');
  page.innerHTML = `
    <h1 class="section-title fade-up">仪表盘</h1>
    <p class="section-sub fade-up stagger-1">Emby 反代服务运行概览 <span class="live-indicator" id="sse-status">● 实时</span></p>
    <div class="form-help fade-up stagger-1" style="margin:-4px 0 18px">当前面板域名：<span class="mono" id="s-panel-domain">—</span></div>
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
		<div class="stat-title" id="s-traffic-title">已用流量</div>
      </div>
      <div class="stat-card c-orange fade-up stagger-4">
        <div class="stat-icon-wrap orange">
          <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
        </div>
        <div class="stat-number" id="s-uptime">—</div>
        <div class="stat-title">运行时长</div>
      </div>
      <div class="stat-card c-purple fade-up stagger-5">
        <div class="stat-icon-wrap purple">
          <svg viewBox="0 0 24 24"><ellipse cx="12" cy="5" rx="8" ry="3"/><path d="M4 5v6c0 1.7 3.6 3 8 3s8-1.3 8-3V5"/><path d="M4 11v6c0 1.7 3.6 3 8 3s8-1.3 8-3v-6"/></svg>
        </div>
        <div class="stat-number" id="s-cache">0 B</div>
        <div class="stat-title">累计缓存</div>
      </div>
    </div>
    <div class="dashboard-trend-toolbar fade-up stagger-4">
      <div>
        <div class="glass-card-title">数据趋势</div>
        <div class="dashboard-trend-help" id="dashboard-trend-help">默认显示全部站点；“本月”按自然月 1 日至当前时间统计 · 数据时间 <span id="dashboard-trend-timezone">UTC+08:00</span></div>
      </div>
      <div class="dashboard-trend-controls">
        <div class="dashboard-trend-control"><label for="dashboard-trend-site">站点</label><select id="dashboard-trend-site" class="form-select" aria-label="选择趋势站点"><option value="all">全部站点</option></select></div>
        <div class="dashboard-trend-control"><label for="dashboard-trend-range">时间</label><select id="dashboard-trend-range" class="form-select" aria-label="选择趋势时间范围">
          <option value="realtime">实时</option><option value="hour">1 小时</option><option value="6h">6 小时</option><option value="day">1 天</option><option value="7d">7 天</option><option value="month">本月</option><option value="custom">自定义</option>
        </select></div>
        <div class="dashboard-trend-custom" id="dashboard-trend-custom" hidden>
          <label>开始时间<input type="datetime-local" id="dashboard-trend-start" class="form-input" step="60" aria-label="趋势开始时间"></label>
          <span class="dashboard-trend-custom-separator" aria-hidden="true">至</span>
          <label>结束时间<input type="datetime-local" id="dashboard-trend-end" class="form-input" step="60" aria-label="趋势结束时间"></label>
          <button type="button" class="btn btn-primary dashboard-trend-apply" id="dashboard-trend-apply">应用</button>
        </div>
      </div>
      <div class="dashboard-trend-custom-error" id="dashboard-trend-custom-error" role="alert" aria-live="polite" hidden></div>
    </div>
    <div class="dashboard-trend-grid fade-up stagger-4">
      <section class="dashboard-trend-card" data-dashboard-chart="speed"><div class="glass-card-header"><div><div class="glass-card-title">速度</div><span class="dashboard-trend-unit">时间范围峰值</span></div><strong class="dashboard-trend-summary" id="dashboard-speed-summary">—</strong></div><div class="dashboard-trend-wrap"><canvas id="dashboardSpeedTrend" aria-label="速度趋势图"></canvas><div class="dashboard-chart-tooltip" hidden></div></div><div class="dashboard-trend-legend"><span><i class="download"></i>下载</span><span><i class="upload"></i>上传</span></div></section>
      <section class="dashboard-trend-card" data-dashboard-chart="requests"><div class="glass-card-header"><div><div class="glass-card-title">请求</div><span class="dashboard-trend-unit">时间范围总数</span></div><strong class="dashboard-trend-summary" id="dashboard-requests-summary">—</strong></div><div class="dashboard-trend-wrap"><canvas id="dashboardRequestsTrend" aria-label="请求趋势图"></canvas><div class="dashboard-chart-tooltip" hidden></div></div><div class="dashboard-trend-legend"><span><i class="requests"></i>请求次数</span></div></section>
      <section class="dashboard-trend-card" data-dashboard-chart="traffic"><div class="glass-card-header"><div><div class="glass-card-title">流量</div><span class="dashboard-trend-unit" id="dashboard-traffic-unit">计费流量总数</span></div><strong class="dashboard-trend-summary" id="dashboard-traffic-summary">—</strong></div><div class="dashboard-trend-wrap"><canvas id="dashboardTrafficTrend" aria-label="流量趋势图"></canvas><div class="dashboard-chart-tooltip" hidden></div></div><div class="dashboard-trend-legend"><span><i class="traffic"></i>计费流量</span></div></section>
    </div>
    <div class="dashboard-insights-grid fade-up stagger-5">
      <section class="dashboard-insight-card" id="dashboard-log-health"><div class="dashboard-insight-head"><h2>日志写入</h2><span class="dashboard-health-dot"></span></div><p>正在读取…</p></section>
      <section class="dashboard-insight-card" id="dashboard-schedule-health"><div class="dashboard-insight-head"><h2>定时任务</h2><span class="dashboard-health-dot"></span></div><p>正在读取…</p></section>
    </div>
    <div class="glass-card dashboard-site-status fade-up stagger-5">
      <div class="glass-card-header">
        <div class="glass-card-title"><span class="live-dot"></span>站点实时状态</div>
        <div class="glass-card-title" style="font-size:.72rem;color:var(--white-38)" id="s-requests">0 请求</div>
      </div>
      <div style="overflow-x:auto">
        <table>
          <thead><tr>
            <th>站点</th><th>状态</th><th>回源地址</th><th>UA 模式</th><th>入口</th><th>实时网速</th><th>已用流量</th><th>缓存大小</th>
          </tr></thead>
          <tbody id="dash-table"></tbody>
        </table>
      </div>
    </div>
  `;

  startDashSSE();
  setupDashboardTrendControls();
  observeDashboardTrendResize();
  loadDashboardTable();
  loadDashboardInsights();
  loadDashboardTrends();
}

async function loadDashboardInsights() {
  try {
    const insights = await API.dashboardInsights();
    if (!insights || Router.current !== 'dashboard') return;
    const log = document.querySelector('#dashboard-log-health p');
    const schedule = document.querySelector('#dashboard-schedule-health p');
    const latestLog = insights.latest_log_ms ? meridianFormatDateTime(insights.latest_log_ms) : '暂无记录';
    if (log) log.textContent = insights.log_healthy ? `今日写入 ${formatNumber(insights.log_count_today || 0)} 条 · 最近写入 ${latestLog}` : '已关闭';
    if (schedule) schedule.textContent = insights.schedule_enabled ? `Telegram 日报 · ${insights.schedule_label || '已启用'}` : 'Telegram 日报 · 未启用';
  } catch (error) {
    console.warn('Dashboard insights load error', error);
  }
}

function dashboardRequestScale(maxValue) {
  // Keep six horizontal bands on every chart. Only the step changes with the
	// data range, so cards remain visually comparable while labels stay useful.
	const ticks = 6;
	if (!(maxValue > 0)) return { max: ticks, step: 1, ticks };
  const roughStep = maxValue / ticks;
  const magnitude = Math.pow(10, Math.floor(Math.log10(roughStep)));
  const fraction = roughStep / magnitude;
  const niceFraction = fraction <= 1 ? 1 : fraction <= 2 ? 2 : fraction <= 2.5 ? 2.5 : fraction <= 5 ? 5 : 10;
  const step = niceFraction * magnitude;
  return { max: step * ticks, step, ticks };
}

function dashboardTimeLabelIndexes(pointCount, plotWidth, range) {
  if (pointCount <= 1) return [0];
  const minimumGap = range === 'realtime' ? 70 : 76;
  if (plotWidth < minimumGap * 1.7) return [0];
  const maxLabels = Math.max(2, Math.min(pointCount, Math.floor(plotWidth / minimumGap) + 1));
  const step = Math.max(1, Math.ceil((pointCount - 1) / Math.max(1, maxLabels - 1)));
  const indexes = [0];
  for (let index = step; index < pointCount - 1; index += step) indexes.push(index);
  const lastIndex = pointCount - 1;
  const lastLabelPixelGap = (lastIndex - indexes[indexes.length - 1]) * plotWidth / Math.max(1, lastIndex);
  if (lastLabelPixelGap >= minimumGap || indexes.length === 1) indexes.push(lastIndex);
  return indexes;
}

function dashboardTrendMetricValue(point, metric) {
  if (metric === 'speed') return Math.max(dashboardSafeNonNegative(point?.download_bps), dashboardSafeNonNegative(point?.upload_bps));
  if (metric === 'traffic') return dashboardSafeNonNegative(point?.traffic_bytes);
  return dashboardSafeNonNegative(point?.requests);
}

function dashboardSafeNonNegative(value) {
  const numeric = Number(value);
  return Number.isFinite(numeric) && numeric > 0 ? numeric : 0;
}

function dashboardTrendValueLabel(value, metric) {
  if (metric === 'speed' || metric === 'traffic') return formatBytes(value);
  return formatNumber(Math.round(value));
}

function dashboardTrendPointerState(rect, geometry, event, pointCount) {
  const width = Math.max(1, Number(rect?.width) || 1);
  const height = Math.max(1, Number(rect?.height) || 1);
  const scaleX = Math.max(1, Number(geometry?.width) || width) / width;
  const scaleY = Math.max(1, Number(geometry?.height) || height) / height;
  const rawX = (Number(event?.clientX) - (Number(rect?.left) || 0)) * scaleX;
  const rawY = (Number(event?.clientY) - (Number(rect?.top) || 0)) * scaleY;
  const left = Number(geometry?.left) || 0;
  const top = Number(geometry?.top) || 0;
  const plotW = Math.max(1, Number(geometry?.plotW) || 1);
  const plotH = Math.max(1, Number(geometry?.plotH) || 1);
  const x = Math.max(left, Math.min(left + plotW, Number.isFinite(rawX) ? rawX : left));
  const y = Math.max(top, Math.min(top + plotH, Number.isFinite(rawY) ? rawY : top));
  const index = Math.max(0, Math.min(Math.max(0, pointCount - 1), Math.round(((x - left) / plotW) * Math.max(0, pointCount - 1))));
  return { x, y, index };
}

function dashboardTrendPointerInside(rect, event) {
  if (!rect || !event) return false;
  const x = Number(event.clientX);
  const y = Number(event.clientY);
  if (!Number.isFinite(x) || !Number.isFinite(y)) return false;
  const left = Number(rect.left) || 0;
  const top = Number(rect.top) || 0;
  const right = Number.isFinite(Number(rect.right)) ? Number(rect.right) : left + (Number(rect.width) || 0);
  const bottom = Number.isFinite(Number(rect.bottom)) ? Number(rect.bottom) : top + (Number(rect.height) || 0);
  return x >= left && x <= right && y >= top && y <= bottom;
}

function dashboardTooltipPosition(pointerX, pointerY, wrapWidth, wrapHeight, tooltipWidth, tooltipHeight) {
  const width = Math.max(1, Number(wrapWidth) || 1);
  const height = Math.max(1, Number(wrapHeight) || 1);
  const cardWidth = Math.max(1, Number(tooltipWidth) || 180);
  const cardHeight = Math.max(1, Number(tooltipHeight) || 56);
  const gap = 14;
  const padding = 6;
  const rightSpace = width - pointerX - gap - padding;
  const leftSpace = pointerX - gap - padding;
  const clampLeft = left => Math.max(padding, Math.min(Math.max(padding, width - cardWidth - padding), left));

  // Keep the tooltip beside the pointer whenever possible. This avoids
  // covering the pointer even when the contents contain many site rows.
  if (rightSpace >= cardWidth) {
    let top = pointerY - cardHeight - gap;
    if (top < padding) top = pointerY + gap;
    return { left: clampLeft(pointerX + gap), top };
  }
  if (leftSpace >= cardWidth) {
    let top = pointerY - cardHeight - gap;
    if (top < padding) top = pointerY + gap;
    return { left: clampLeft(pointerX - cardWidth - gap), top };
  }

  // If neither side has enough room, place the full card above or below the
  // pointer. It is intentionally allowed to overflow the chart wrapper so
  // long all-site tooltips keep all rows visible without covering the pointer.
  const aboveSpace = Math.max(0, pointerY - gap - padding);
  const belowSpace = Math.max(0, height - pointerY - gap - padding);
  const below = belowSpace >= aboveSpace;
  return { left: clampLeft(pointerX - cardWidth / 2), top: below ? pointerY + gap : pointerY - cardHeight - gap };
}

function dashboardTrendTimeLabel(timestamp, range) {
  const date = meridianTimezoneDate(timestamp);
  const pad = value => String(value).padStart(2, '0');
  if (range === '7d' || range === 'day' || range === 'month') {
    const bucketSeconds = Number(dashboardTrendData?.bucket_seconds || 0);
    const minute = bucketSeconds > 0 && bucketSeconds < 3600 ? `:${pad(date.getUTCMinutes())}` : ':00';
    return `${date.getUTCMonth() + 1}/${date.getUTCDate()} ${pad(date.getUTCHours())}${minute}`;
  }
  if (range === 'realtime') return `${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())}`;
  if (range === 'custom') return `${date.getUTCMonth() + 1}/${date.getUTCDate()} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}`;
  return `${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}`;
}

function dashboardTrendMetricLine(point, metric) {
  if (!point) return '暂无数据';
  if (metric === 'speed') return `↓ ${formatRate(point.download_bps)} · ↑ ${formatRate(point.upload_bps)}`;
  if (metric === 'requests') return `请求 ${formatNumber(dashboardSafeNonNegative(point.requests))} 次`;
  if (metric === 'traffic') return `流量 ${formatBytes(dashboardSafeNonNegative(point.traffic_bytes))}`;
  return '';
}

function dashboardTrendTooltip(point, metric, range, pointIndex = -1) {
  const time = meridianFormatDateTime(point.timestamp_ms);
  const siteSelect = document.getElementById('dashboard-trend-site');
  const selectedOption = siteSelect?.selectedOptions?.[0];
  const selectedSiteID = dashboardTrendState.siteId === 'all' ? null : String(dashboardTrendState.siteId);
  const allSeries = dashboardTrendData?.site_series || [];
  const realtimeSeries = dashboardRealtimeTrendSiteSamples;
  const siteRows = [];
  if (selectedSiteID === null) {
    const realtimeOffset = dashboardTrendRealtimeOffset();
    const realtimeIndex = pointIndex - realtimeOffset;
    if (range === 'realtime' && realtimeSeries.size && realtimeIndex >= 0) {
      const knownSites = dashboardSites.length ? dashboardSites : allSeries.map(series => ({ id: series.site_id, name: series.site_name }));
      knownSites.forEach(site => {
        const samples = realtimeSeries.get(String(site.id));
        const sample = samples?.[realtimeIndex] || { download_bps: 0, upload_bps: 0, requests: 0, traffic_bytes: 0 };
        siteRows.push(`<div class="dashboard-chart-tooltip-row"><strong>${esc(site.name || `站点 ${site.id}`)}</strong><span>${dashboardTrendMetricLine(sample, metric)}</span></div>`);
      });
    } else {
      allSeries.forEach(series => {
        const sitePoint = series.points?.[pointIndex];
        if (sitePoint) siteRows.push(`<div class="dashboard-chart-tooltip-row"><strong>${esc(series.site_name || `站点 ${series.site_id}`)}</strong><span>${dashboardTrendMetricLine(sitePoint, metric)}</span></div>`);
      });
    }
  } else {
    const siteName = selectedOption?.textContent?.trim() || allSeries.find(series => String(series.site_id) === selectedSiteID)?.site_name || `站点 ${selectedSiteID}`;
    siteRows.push(`<div class="dashboard-chart-tooltip-row"><strong>${esc(siteName)}</strong><span>${dashboardTrendMetricLine(point, metric)}</span></div>`);
  }
  const lines = [`<span>${esc(time)}</span>`];
  if (siteRows.length) lines.push(siteRows.join(''));
  else lines.push(`<div class="dashboard-chart-tooltip-row"><strong>${esc(selectedSiteID === null ? '全部站点' : (selectedOption?.textContent?.trim() || `站点 ${selectedSiteID}`))}</strong><span>${dashboardTrendMetricLine(point, metric)}</span></div>`);
  return lines.join('');
}

function dashboardRealtimeTrendPoints() {
  const key = dashboardTrendState.siteId === 'all' ? 'all' : String(dashboardTrendState.siteId);
  return dashboardRealtimeTrendSamples.get(key) || [];
}

function dashboardTrendRealtimeOffset() {
  const historical = dashboardTrendData?.points || [];
  const realtime = dashboardRealtimeTrendPoints();
  if (dashboardTrendState.range !== 'realtime' || !historical.length || !realtime.length) return historical.length;
  const firstRealtime = Number(realtime[0]?.timestamp_ms || 0);
  return historical.filter(point => Number(point.timestamp_ms || 0) < firstRealtime).length;
}

function dashboardTrendPoints() {
  const historicalPoints = dashboardTrendData?.points || [];
  if (dashboardTrendState.range !== 'realtime') return historicalPoints;
  const realtimePoints = dashboardRealtimeTrendPoints();
  if (!realtimePoints.length || !historicalPoints.length) return realtimePoints.length ? realtimePoints : historicalPoints;
  const offset = dashboardTrendRealtimeOffset();
  return historicalPoints.slice(0, offset).concat(realtimePoints);
}

function dashboardTrendSummary(data) {
  const points = dashboardTrendPoints();
  const downloadPeak = points.reduce((max, point) => Math.max(max, dashboardSafeNonNegative(point.download_bps)), 0);
  const uploadPeak = points.reduce((max, point) => Math.max(max, dashboardSafeNonNegative(point.upload_bps)), 0);
  const requests = points.reduce((sum, point) => sum + dashboardSafeNonNegative(point.requests), 0);
  const traffic = points.reduce((sum, point) => sum + dashboardSafeNonNegative(point.traffic_bytes), 0);
  const speed = document.getElementById('dashboard-speed-summary');
  const request = document.getElementById('dashboard-requests-summary');
  const trafficEl = document.getElementById('dashboard-traffic-summary');
  const unit = document.getElementById('dashboard-traffic-unit');
  if (speed) speed.textContent = `↓ ${formatRate(downloadPeak)} · ↑ ${formatRate(uploadPeak)}`;
  if (request) request.textContent = `${formatNumber(requests)} 次`;
  if (trafficEl) trafficEl.textContent = formatBytes(traffic);
  if (unit) unit.textContent = data?.billing_mode === 'outbound' ? '单向计费流量总数' : '双向计费流量总数';
}

function dashboardUpdateTrendHelp(resetEnabled) {
  const help = document.getElementById('dashboard-trend-help');
  if (!help) return;
  const prefix = resetEnabled
    ? '默认显示全部站点；“本月”为自然月 1 日至当前时间，已用流量按全局重置日统计'
    : '默认显示全部站点；“本月”为自然月 1 日至当前时间，已用流量累计不重置';
  help.textContent = `${prefix} · 数据时间 `;
  const timezone = document.createElement('span');
  timezone.id = 'dashboard-trend-timezone';
  timezone.textContent = meridianTimezoneLabel();
  help.appendChild(timezone);
}

function dashboardRoundRect(ctx, x, y, width, height, radius) {
  if (typeof ctx.roundRect === 'function') {
    ctx.roundRect(x, y, width, height, radius);
    return;
  }
  const r = Math.min(radius, width / 2, height / 2);
  ctx.moveTo(x + r, y);
  ctx.lineTo(x + width - r, y);
  ctx.quadraticCurveTo(x + width, y, x + width, y + r);
  ctx.lineTo(x + width, y + height - r);
  ctx.quadraticCurveTo(x + width, y + height, x + width - r, y + height);
  ctx.lineTo(x + r, y + height);
  ctx.quadraticCurveTo(x, y + height, x, y + height - r);
  ctx.lineTo(x, y + r);
  ctx.quadraticCurveTo(x, y, x + r, y);
  ctx.closePath();
}

function dashboardTraceSmoothLine(ctx, points) {
  if (!points.length) return;
  if (points.length === 1) {
    ctx.moveTo(points[0].x, points[0].y);
    return;
  }
  ctx.moveTo(points[0].x, points[0].y);
  for (let index = 0; index < points.length - 1; index++) {
    const previous = points[index - 1] || points[index];
    const current = points[index];
    const next = points[index + 1];
    const following = points[index + 2] || next;
    const tension = 1 / 6;
    const minX = Math.min(current.x, next.x);
    const maxX = Math.max(current.x, next.x);
    const minY = Math.min(current.y, next.y);
    const maxY = Math.max(current.y, next.y);
    const control1X = Math.max(minX, Math.min(maxX, current.x + (next.x - previous.x) * tension));
    const control1Y = Math.max(minY, Math.min(maxY, current.y + (next.y - previous.y) * tension));
    const control2X = Math.max(minX, Math.min(maxX, next.x - (following.x - current.x) * tension));
    const control2Y = Math.max(minY, Math.min(maxY, next.y - (following.y - current.y) * tension));
    ctx.bezierCurveTo(control1X, control1Y, control2X, control2Y, next.x, next.y);
  }
}

function drawDashboardTrendChart(metric) {
  const chart = dashboardTrendCharts.get(metric);
  const points = dashboardTrendPoints();
  if (!chart || !chart.canvas || !chart.canvas.getContext || !points.length) return;
  const canvas = chart.canvas;
  const wrap = canvas.parentElement;
  const width = Math.max(220, wrap.clientWidth || 320);
  const height = Math.max(190, wrap.clientHeight || 230);
  const ratio = window.devicePixelRatio || 1;
  canvas.width = Math.round(width * ratio); canvas.height = Math.round(height * ratio);
  canvas.style.width = `${width}px`; canvas.style.height = `${height}px`;
  const ctx = canvas.getContext('2d');
  ctx.setTransform(ratio, 0, 0, ratio, 0, 0);
  ctx.clearRect(0, 0, width, height);
  const series = metric === 'speed'
    ? [{ values: points.map(point => dashboardSafeNonNegative(point.download_bps)), color: '#3b9cff' }, { values: points.map(point => dashboardSafeNonNegative(point.upload_bps)), color: '#a78bfa' }]
    : [{ values: points.map(point => dashboardTrendMetricValue(point, metric)), color: metric === 'requests' ? '#3b82f6' : '#10b981' }];
  const scale = dashboardRequestScale(Math.max(0, ...series.flatMap(item => item.values)));
  ctx.font = `${width < 360 ? 10 : 11}px system-ui`;
  const yLabelWidth = Math.max(...Array.from({ length: scale.ticks + 1 }, (_, index) => ctx.measureText(dashboardTrendValueLabel(scale.max - scale.step * index, metric)).width));
  const left = Math.min(Math.max(50, Math.ceil(yLabelWidth) + 16), Math.floor(width * .36));
  const right = 12, top = 14, bottom = 30;
  const plotW = Math.max(1, width - left - right), plotH = Math.max(1, height - top - bottom);
  chart.geometry = { width, height, left, right, top, bottom, plotW, plotH };
  ctx.textBaseline = 'middle';
  ctx.fillStyle = 'var(--white-60)';
  if (ctx.setLineDash) ctx.setLineDash([4, 4]);
  for (let i = 0; i <= scale.ticks; i++) {
    const value = scale.max - scale.step * i;
    const y = top + plotH * i / scale.ticks;
    ctx.strokeStyle = 'rgba(100,116,139,.18)'; ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(left, y); ctx.lineTo(width - right, y); ctx.stroke();
    ctx.textAlign = 'right'; ctx.fillStyle = '#64748b';
    ctx.fillText(dashboardTrendValueLabel(value, metric), left - 7, y);
  }
  if (ctx.setLineDash) ctx.setLineDash([]);
  const canvasSeries = series.map(item => ({ ...item, points: item.values.map((value, index) => ({
    x: left + plotW * index / Math.max(1, points.length - 1),
    y: top + plotH * (1 - (value / (scale.max || 1))),
  })) }));
  canvasSeries.forEach(item => {
    const pointsOnCanvas = item.points;
    ctx.beginPath();
    dashboardTraceSmoothLine(ctx, pointsOnCanvas);
    if (metric !== 'speed') {
      ctx.lineTo(pointsOnCanvas[pointsOnCanvas.length - 1].x, top + plotH); ctx.lineTo(pointsOnCanvas[0].x, top + plotH); ctx.closePath();
      ctx.globalAlpha = .12; ctx.fillStyle = item.color; ctx.fill(); ctx.globalAlpha = 1;
      ctx.beginPath();
      dashboardTraceSmoothLine(ctx, pointsOnCanvas);
    }
    ctx.strokeStyle = item.color; ctx.lineWidth = 2.5; ctx.lineJoin = 'round'; ctx.lineCap = 'round'; ctx.stroke();
  });
  const pointsOnCanvas = canvasSeries[0].points;
  if (chart.hoverIndex >= 0 && pointsOnCanvas[chart.hoverIndex]) {
    const point = pointsOnCanvas[chart.hoverIndex];
    ctx.beginPath(); ctx.arc(point.x, point.y, 4, 0, Math.PI * 2); ctx.fillStyle = '#fff'; ctx.fill(); ctx.strokeStyle = canvasSeries[0].color; ctx.lineWidth = 2; ctx.stroke();
  }
  ctx.fillStyle = '#64748b'; ctx.textAlign = 'center'; ctx.textBaseline = 'alphabetic';
  dashboardTimeLabelIndexes(points.length, plotW, dashboardTrendState.range).forEach(index => {
    const label = dashboardTrendTimeLabel(points[index].timestamp_ms, dashboardTrendState.range);
    const labelWidth = typeof ctx.measureText === 'function' ? ctx.measureText(label).width : label.length * 7;
    const x = Math.max(left + labelWidth / 2, Math.min(width - right - labelWidth / 2, pointsOnCanvas[index].x));
    ctx.fillText(label, x, height - 7);
  });
  if (chart.hoverIndex >= 0 && pointsOnCanvas[chart.hoverIndex]) {
    const point = pointsOnCanvas[chart.hoverIndex];
    const crosshairX = Math.max(left, Math.min(left + plotW, Number.isFinite(Number(chart.hoverX)) ? Number(chart.hoverX) : point.x));
    const crosshairY = Math.max(top, Math.min(top + plotH, Number.isFinite(Number(chart.hoverY)) ? Number(chart.hoverY) : point.y));
    const crosshairColor = 'rgba(71, 85, 105, .62)';
    ctx.save();
    ctx.strokeStyle = crosshairColor;
    ctx.lineWidth = 1;
    if (ctx.setLineDash) ctx.setLineDash([5, 4]);
    ctx.beginPath(); ctx.moveTo(crosshairX, top); ctx.lineTo(crosshairX, top + plotH); ctx.stroke();
    ctx.beginPath(); ctx.moveTo(left, crosshairY); ctx.lineTo(width - right, crosshairY); ctx.stroke();
    if (ctx.setLineDash) ctx.setLineDash([]);
    ctx.font = `${width < 360 ? 11 : 12}px system-ui, sans-serif`;
    const yValue = scale.max * (1 - (crosshairY - top) / Math.max(1, plotH));
    const yLabel = dashboardTrendValueLabel(yValue, metric);
    const measureText = text => typeof ctx.measureText === 'function' ? ctx.measureText(text).width : String(text).length * 7;
    const yLabelWidth = Math.max(54, measureText(yLabel) + 18);
    const yLabelTop = Math.max(2, Math.min(height - 24, crosshairY - 12));
    ctx.fillStyle = '#586ba7';
    ctx.beginPath();
    dashboardRoundRect(ctx, 2, yLabelTop, yLabelWidth, 24, 5);
    ctx.fill();
    ctx.fillStyle = '#fff'; ctx.textAlign = 'left'; ctx.textBaseline = 'middle';
    ctx.fillText(yLabel, 10, yLabelTop + 12);
    const xLabel = dashboardTrendTimeLabel(points[chart.hoverIndex].timestamp_ms, dashboardTrendState.range);
    const xLabelWidth = Math.max(48, measureText(xLabel) + 18);
    const xLabelLeft = Math.max(left, Math.min(width - right - xLabelWidth, crosshairX - xLabelWidth / 2));
    const xLabelTop = height - bottom + 1;
    ctx.fillStyle = '#586ba7';
    ctx.beginPath();
    dashboardRoundRect(ctx, xLabelLeft, xLabelTop, xLabelWidth, 24, 5);
    ctx.fill();
    ctx.fillStyle = '#fff'; ctx.textAlign = 'center';
    ctx.fillText(xLabel, xLabelLeft + xLabelWidth / 2, xLabelTop + 12);
    ctx.restore();
  }
}

function renderDashboardTrendCharts() {
  ['speed', 'requests', 'traffic'].forEach(drawDashboardTrendChart);
}

function dashboardLocalDateTimeValue(date) {
  return meridianDateTimeLocalValue(date);
}

function dashboardDefaultCustomRange() {
  const end = Date.now();
  const start = end - 60 * 60 * 1000;
  return { start: dashboardLocalDateTimeValue(start), end: dashboardLocalDateTimeValue(end) };
}

function dashboardSetCustomRangeControls(visible) {
  const custom = document.getElementById('dashboard-trend-custom');
  const error = document.getElementById('dashboard-trend-custom-error');
  if (custom) custom.hidden = !visible;
  if (!visible && error) {
    error.hidden = true;
    error.textContent = '';
  }
}

function dashboardShowCustomError(message) {
  const error = document.getElementById('dashboard-trend-custom-error');
  if (!error) return;
  error.textContent = message || '';
  error.hidden = !message;
}

function dashboardReadCustomRange() {
  const start = document.getElementById('dashboard-trend-start')?.value || '';
  const end = document.getElementById('dashboard-trend-end')?.value || '';
  if (!start || !end) return { error: '请选择开始时间和结束时间' };
  const startDate = meridianParseDateTimeLocal(start);
  const endDate = meridianParseDateTimeLocal(end);
  if (!Number.isFinite(startDate) || !Number.isFinite(endDate)) {
    return { error: '时间格式无效，请重新选择' };
  }
  if (endDate <= startDate) return { error: '结束时间必须晚于开始时间' };
  return { start, end };
}

function setupDashboardTrendControls() {
  const siteSelect = document.getElementById('dashboard-trend-site');
  const rangeSelect = document.getElementById('dashboard-trend-range');
  if (!siteSelect || !rangeSelect) return;
  siteSelect.onchange = () => { dashboardTrendState.siteId = siteSelect.value; loadDashboardTrends(); };
  const startInput = document.getElementById('dashboard-trend-start');
  const endInput = document.getElementById('dashboard-trend-end');
  const applyButton = document.getElementById('dashboard-trend-apply');
  const customDefault = dashboardDefaultCustomRange();
  if (startInput && !startInput.value) startInput.value = dashboardTrendState.customStart || customDefault.start;
  if (endInput && !endInput.value) endInput.value = dashboardTrendState.customEnd || customDefault.end;
  rangeSelect.onchange = () => {
    dashboardTrendState.range = rangeSelect.value;
    dashboardSetCustomRangeControls(dashboardTrendState.range === 'custom');
    if (dashboardTrendState.range === 'custom') {
      const current = dashboardReadCustomRange();
      if (current.error) {
        dashboardShowCustomError(current.error);
        return;
      }
      dashboardTrendState.customStart = current.start;
      dashboardTrendState.customEnd = current.end;
    } else {
      dashboardShowCustomError('');
    }
    loadDashboardTrends();
  };
  if (applyButton) {
    applyButton.onclick = () => {
      const current = dashboardReadCustomRange();
      if (current.error) {
        dashboardShowCustomError(current.error);
        return;
      }
      dashboardTrendState.customStart = current.start;
      dashboardTrendState.customEnd = current.end;
      dashboardShowCustomError('');
      loadDashboardTrends();
    };
  }
  dashboardSetCustomRangeControls(dashboardTrendState.range === 'custom');
  ['speed', 'requests', 'traffic'].forEach(metric => {
    const canvas = document.getElementById(metric === 'speed' ? 'dashboardSpeedTrend' : metric === 'requests' ? 'dashboardRequestsTrend' : 'dashboardTrafficTrend');
    if (!canvas) return;
    const tooltip = canvas.parentElement.querySelector('.dashboard-chart-tooltip');
    const chart = { canvas, tooltip, hoverIndex: -1, hoverX: null, hoverY: null, pointerActive: false, geometry: null };
    dashboardTrendCharts.set(metric, chart);
    const clearHover = () => {
      chart.pointerActive = false;
      chart.hoverIndex = -1;
      chart.hoverX = null;
      chart.hoverY = null;
      if (tooltip) tooltip.hidden = true;
      drawDashboardTrendChart(metric);
    };
    const updateHover = event => {
      const points = dashboardTrendPoints();
      if (!points.length) return;
      const rect = canvas.getBoundingClientRect();
      // Touch pointer capture continues delivering pointermove events after
      // the finger leaves the canvas. Do not clamp those events to the edge:
      // hide the tooltip until the finger comes back into the chart.
      if (event.pointerType !== 'mouse' && !dashboardTrendPointerInside(rect, event)) {
        clearHover();
        return;
      }
      const geometry = chart.geometry || { width: rect.width, height: rect.height, left: 0, top: 0, plotW: rect.width, plotH: rect.height };
      const pointer = dashboardTrendPointerState(rect, geometry, event, points.length);
      chart.hoverIndex = pointer.index;
      chart.hoverX = pointer.x;
      chart.hoverY = pointer.y;
      if (tooltip) {
        tooltip.innerHTML = dashboardTrendTooltip(points[pointer.index], metric, dashboardTrendState.range, pointer.index);
        tooltip.hidden = false;
        const wrap = canvas.parentElement;
        const wrapRect = wrap?.getBoundingClientRect ? wrap.getBoundingClientRect() : rect;
        const wrapWidth = wrap?.clientWidth || wrapRect.width || geometry.width;
        const wrapHeight = wrap?.clientHeight || wrapRect.height || geometry.height;
        const tooltipPosition = dashboardTooltipPosition(
          event.clientX - (Number(wrapRect.left) || 0),
          event.clientY - (Number(wrapRect.top) || 0),
          wrapWidth,
          wrapHeight,
          tooltip.offsetWidth || 180,
          tooltip.offsetHeight || 56,
        );
        tooltip.style.left = `${tooltipPosition.left}px`;
        tooltip.style.top = `${tooltipPosition.top}px`;
      }
      drawDashboardTrendChart(metric);
    };
    canvas.addEventListener('pointerdown', event => {
      chart.pointerActive = true;
      if (canvas.setPointerCapture) canvas.setPointerCapture(event.pointerId);
      updateHover(event);
    });
    canvas.addEventListener('pointermove', event => {
      if (event.pointerType === 'mouse' || chart.pointerActive) updateHover(event);
    });
    canvas.addEventListener('pointerup', event => {
      if (canvas.releasePointerCapture && canvas.hasPointerCapture?.(event.pointerId)) canvas.releasePointerCapture(event.pointerId);
      clearHover();
    });
    canvas.addEventListener('pointercancel', clearHover);
    canvas.addEventListener('pointerleave', event => {
      if (event.pointerType !== 'mouse') return;
      clearHover();
    });
  });
}

async function loadDashboardTrends() {
  const generation = ++dashboardTrendRequestGeneration;
  const requestState = {
    siteId: dashboardTrendState.siteId,
    range: dashboardTrendState.range,
    customStart: dashboardTrendState.customStart,
    customEnd: dashboardTrendState.customEnd,
  };
  try {
    const data = await API.dashboardTrends(
      requestState.siteId,
      requestState.range,
      requestState.customStart,
      requestState.customEnd,
    );
    if (!data || Router.current !== 'dashboard' || generation !== dashboardTrendRequestGeneration ||
        requestState.siteId !== dashboardTrendState.siteId || requestState.range !== dashboardTrendState.range ||
        requestState.customStart !== dashboardTrendState.customStart || requestState.customEnd !== dashboardTrendState.customEnd) return;
    if (typeof meridianSetTimezoneName === 'function' && data.timezone) meridianSetTimezoneName(data.timezone);
    if (typeof meridianSetTimezoneOffset === 'function') meridianSetTimezoneOffset(data.timezone_offset_minutes);
    const timezone = document.getElementById('dashboard-trend-timezone');
    if (timezone && typeof meridianTimezoneLabel === 'function') timezone.textContent = meridianTimezoneLabel(data.timezone_offset_minutes);
    if (!dashboardTrendState.customStart && !dashboardTrendState.customEnd) {
      const customDefault = dashboardDefaultCustomRange();
      const startInput = document.getElementById('dashboard-trend-start');
      const endInput = document.getElementById('dashboard-trend-end');
      if (startInput) startInput.value = customDefault.start;
      if (endInput) endInput.value = customDefault.end;
    }
    dashboardTrendData = data;
    if (Array.isArray(data.site_series)) {
      data.site_series.forEach(series => {
        if (!dashboardSites.some(site => Number(site.id) === Number(series.site_id))) dashboardSites.push({ id: series.site_id, name: series.site_name });
      });
    }
    dashboardTrendSummary(data);
    renderDashboardTrendCharts();
  } catch (error) {
    console.warn('Dashboard trends load error', error);
  }
}

function loadDashboardTrendSites() {
  const select = document.getElementById('dashboard-trend-site');
  if (!select) return;
  API.listSites().then(sites => {
    if (!select || Router.current !== 'dashboard') return;
    dashboardSites = sites || [];
    select.innerHTML = '<option value="all">全部站点</option>' + dashboardSites.map(site => `<option value="${Number(site.id)}">${esc(site.name)}</option>`).join('');
    select.value = dashboardTrendState.siteId;
  }).catch(error => console.warn('Dashboard trend site list error', error));
}

function updateDashboardTrendRealtime() {
  if (dashboardTrendState.range !== 'realtime' || !dashboardTrendData) return;
  dashboardTrendSummary(dashboardTrendData);
  renderDashboardTrendCharts();
}

function observeDashboardTrendResize() {
  if (dashboardTrendResizeObserver) {
    dashboardTrendResizeObserver.disconnect();
    dashboardTrendResizeObserver = null;
  }
  const wrap = document.querySelector('.dashboard-trend-wrap');
  if (!wrap) return;
  loadDashboardTrendSites();
  if (typeof ResizeObserver !== 'function') return;
  dashboardTrendResizeObserver = new ResizeObserver(() => {
    if (Router.current === 'dashboard') renderDashboardTrendCharts();
  });
  document.querySelectorAll('.dashboard-trend-wrap').forEach(element => dashboardTrendResizeObserver.observe(element));
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
	const panelDomainEl = document.getElementById('s-panel-domain');
	const currentPanelURL = dashboardCurrentPanelURL(stats.panel_access_url);
	if (panelDomainEl && currentPanelURL) panelDomainEl.textContent = currentPanelURL;
  animateValue('s-total', stats.total_sites || 0);
  animateValue('s-running', stats.running_sites || 0);

  const trafficEl = document.getElementById('s-traffic');
  if (trafficEl) trafficEl.textContent = formatBytes(stats.monthly_traffic != null ? stats.monthly_traffic : (stats.total_traffic || 0));
	const resetEnabled = Number(stats.traffic_reset_day == null ? 1 : stats.traffic_reset_day) !== 0;
	const trafficTitle = document.getElementById('s-traffic-title');
	if (trafficTitle) trafficTitle.textContent = '已用流量';
  dashboardUpdateTrendHelp(resetEnabled);

  const uptimeEl = document.getElementById('s-uptime');
  if (uptimeEl) uptimeEl.textContent = formatUptime(stats.uptime_seconds || 0);

  const requestsEl = document.getElementById('s-requests');
  if (requestsEl) requestsEl.textContent = formatNumber(stats.total_requests || 0) + ' 请求';
  updateDashboardSiteSpeeds(stats.live_sites || []);
  updateDashboardTrendRealtime();
}

function updateDashboardSiteSpeeds(liveSites) {
  const now = Date.now();
  const liveMap = new Map();
  const trendDeltas = new Map();
  const rateSamples = new Map();
  let totalDeltaIn = 0;
  let totalDeltaOut = 0;
  let totalRateIn = 0;
  let totalRateOut = 0;
  let totalDeltaRequests = 0;
  for (const site of (liveSites || [])) {
    const siteID = Number(site.id);
    if (!Number.isFinite(siteID)) continue;
    liveMap.set(siteID, site);
    const current = {
      trafficUsed: dashboardSafeNonNegative(site.monthly_traffic != null ? site.monthly_traffic : site.traffic_used),
      bytesIn: dashboardSafeNonNegative(site.cumulative_bytes_in != null ? site.cumulative_bytes_in : (site.bytes_in || site.bytes_in_total)),
      bytesOut: dashboardSafeNonNegative(site.cumulative_bytes_out != null ? site.cumulative_bytes_out : (site.bytes_out || site.bytes_out_total)),
      requests: dashboardSafeNonNegative(site.requests),
      timestamp: now,
    };
    const previous = dashboardSpeedSamples.get(siteID);
    if (!previous) dashboardLiveSpeeds.set(siteID, { down: 0, up: 0 });
    if (previous && current.timestamp > previous.timestamp) {
      const seconds = (current.timestamp - previous.timestamp) / 1000;
      const down = current.bytesOut - previous.bytesOut;
      const up = current.bytesIn - previous.bytesIn;
      if (down >= 0 && up >= 0) {
        const downRate = down / seconds;
        const upRate = up / seconds;
        dashboardLiveSpeeds.set(siteID, { down: downRate, up: upRate });
        rateSamples.set(String(siteID), { download_bps: downRate, upload_bps: upRate });
        totalRateOut += downRate;
        totalRateIn += upRate;
        const requests = Math.max(0, current.requests - previous.requests);
        trendDeltas.set(siteID, { bytesIn: up, bytesOut: down, requests });
        totalDeltaIn += up;
        totalDeltaOut += down;
        totalDeltaRequests += requests;
      } else {
        // A site process restart resets the cumulative runtime counters. Show
        // zero until the next monotonic pair instead of flashing a placeholder.
        dashboardLiveSpeeds.set(siteID, { down: 0, up: 0 });
      }
    }
    // Keep the latest sample even when a later SSE payload omits another site.
    dashboardSpeedSamples.set(siteID, current);
  }
  const sampledAt = now;
  const appendRealtimeTrendSample = (key, sample) => {
    const samples = dashboardRealtimeTrendSamples.get(key) || [];
    const bytesIn = dashboardSafeNonNegative(sample?.bytesIn);
    const bytesOut = dashboardSafeNonNegative(sample?.bytesOut);
    samples.push({
      timestamp_ms: sampledAt,
      download_bps: dashboardSafeNonNegative(sample?.download_bps),
      upload_bps: dashboardSafeNonNegative(sample?.upload_bps),
      bytes_in: bytesIn,
      bytes_out: bytesOut,
      requests: dashboardSafeNonNegative(sample?.requests),
      traffic_bytes: dashboardTrendData?.billing_mode === 'outbound' ? bytesOut : 2 * (bytesIn + bytesOut),
    });
    // Keep the active dashboard session responsive without imposing a time
    // window; the X axis adapts to however many samples are available.
    dashboardRealtimeTrendSamples.set(key, samples.slice(-1800));
  };
  if (liveMap.size > 0) appendRealtimeTrendSample('all', { download_bps: totalRateOut, upload_bps: totalRateIn, bytesIn: totalDeltaIn, bytesOut: totalDeltaOut, requests: totalDeltaRequests });
  for (const siteID of liveMap.keys()) {
    const rate = rateSamples.get(String(siteID)) || {};
    const delta = trendDeltas.get(siteID) || {};
    appendRealtimeTrendSample(String(siteID), { ...rate, ...delta });
    const siteSamples = dashboardRealtimeTrendSiteSamples.get(String(siteID)) || [];
    siteSamples.push({
      timestamp_ms: sampledAt,
      download_bps: dashboardSafeNonNegative(rate.download_bps),
      upload_bps: dashboardSafeNonNegative(rate.upload_bps),
      bytes_in: dashboardSafeNonNegative(delta.bytesIn),
      bytes_out: dashboardSafeNonNegative(delta.bytesOut),
      requests: dashboardSafeNonNegative(delta.requests),
      traffic_bytes: dashboardTrendData?.billing_mode === 'outbound'
        ? dashboardSafeNonNegative(delta.bytesOut)
        : 2 * (dashboardSafeNonNegative(delta.bytesIn) + dashboardSafeNonNegative(delta.bytesOut)),
    });
    dashboardRealtimeTrendSiteSamples.set(String(siteID), siteSamples.slice(-1800));
  }
  dashboardSites = dashboardSites.map(site => {
    const siteID = Number(site.id);
    const live = liveMap.get(siteID);
    if (!live) return site;
    const speed = dashboardLiveSpeeds.get(siteID);
    if (!speed) {
      const { _liveSpeed, ...siteWithoutSpeed } = site;
      return { ...siteWithoutSpeed, ...live };
    }
    return { ...site, ...live, _liveSpeed: speed };
  });
  renderDashboardTableRows();
}

function dashboardCurrentPanelURL(fallback) {
  if (typeof window !== 'undefined' && window.location && /^https?:$/.test(window.location.protocol) && window.location.host) {
    return `${window.location.protocol}//${window.location.host}`;
  }
  return fallback || '';
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
  const nextValue = String(newVal);
  if (el.textContent === nextValue) return;
  el.textContent = nextValue;
  el.style.transition = 'transform .15s';
  el.style.transform = 'scale(1.08)';
  setTimeout(() => { el.style.transform = ''; }, 150);
}

function stopDashSSE() {
  dashboardSpeedSamples = new Map();
  dashboardLiveSpeeds = new Map();
  dashboardRealtimeTrendSamples = new Map();
  dashboardRealtimeTrendSiteSamples = new Map();
  dashboardTrendData = null;
  dashboardTrendCharts = new Map();
  if (dashboardTrendResizeObserver) {
    dashboardTrendResizeObserver.disconnect();
    dashboardTrendResizeObserver = null;
  }
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

    const totalCache = (sites || []).reduce((total, site) => total + Number(site.cache_size_bytes || 0), 0);
    const cacheEl = document.getElementById('s-cache');
    if (cacheEl) cacheEl.textContent = formatBytes(totalCache);

    if (!sites || sites.length === 0) {
      dashboardSites = [];
      tbody.innerHTML = '<tr><td colspan="8" style="text-align:center;color:var(--white-38);padding:40px">暂无站点，前往站点管理添加</td></tr>';
      return;
    }

    const currentSites = new Map(dashboardSites.map(site => [Number(site.id), site]));
    dashboardSites = sites.map(site => {
      const siteID = Number(site.id);
      const current = currentSites.get(siteID);
      const speed = dashboardLiveSpeeds.get(siteID) || (current && current._liveSpeed);
      return speed ? { ...site, _liveSpeed: speed } : site;
    });
    renderDashboardTableRows();
  } catch (e) {
    console.error('Dashboard table load error:', e);
  }
}

function renderDashboardTableRows() {
  const tbody = document.getElementById('dash-table');
  if (!tbody || !dashboardSites.length) return;
  tbody.innerHTML = dashboardSites.map(s => `
      <tr>
        <td style="font-weight:600">${esc(s.name)}</td>
        <td><span class="status-badge"><span class="status-led ${s.running ? 'on' : 'off'}"></span>${s.running ? '运行中' : '已停止'}</span></td>
        <td class="mono">${esc(s.target_url)}</td>
        <td><span class="pill ${uaClassMap[s.ua_mode] || 'pill-blue'}">${esc(uaNameMap[s.ua_mode] || s.ua_mode)}</span></td>
        <td class="mono">${dashboardIngressLabel(s)}</td>
		<td>${dashboardSpeedMarkup(s._liveSpeed)}</td>
        <td>${formatBytes(s.monthly_traffic != null ? s.monthly_traffic : s.traffic_used)}</td>
        <td>${formatBytes(s.cache_size_bytes)}</td>
      </tr>
    `).join('');
}

function dashboardSpeedMarkup(speed) {
  if (!speed) speed = { down: 0, up: 0 };
  return `<span class="dashboard-speed"><span>↓ ${formatRate(speed.down)}</span><span>↑ ${formatRate(speed.up)}</span></span>`;
}

function formatRate(bytesPerSecond) {
  return `${formatBytes(dashboardSafeNonNegative(bytesPerSecond))}/s`;
}

function dashboardIngressLabel(site) {
	const mode = String(site.ingress_mode || (site.public_host ? 'host' : 'port')).toLowerCase();
	if (mode === 'host') return `Host: ${esc(site.public_host || '')}`;
	if (mode === 'path') return `Path: ${esc(site.path_prefix || '')}`;
	if (mode === 'both') return `Host + :${site.listen_port}`;
	return `:${site.listen_port}`;
}

async function loadDashboardData() {
  loadDashboardTable();
  if (Router.current === 'dashboard') loadDashboardTrends();
}

const uaClassMap = { infuse: 'pill-blue', web: 'pill-green', client: 'pill-orange', custom: 'pill-purple', passthrough: 'pill-blue' };
const uaNameMap = { infuse: 'Infuse', web: 'Web', client: '客户端', custom: '自定义', passthrough: '透传' };

function formatBytes(bytes) {
	const value = dashboardSafeNonNegative(bytes);
	if (value === 0) return '0 B';
	const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB'];
	const i = Math.min(units.length - 1, Math.floor(Math.log(value) / Math.log(1024)));
	const unit = units[i] || units[0];
	return (value / Math.pow(1024, i)).toFixed(i > 1 ? 1 : 0) + ' ' + unit;
}
