// Traffic statistics page
function renderTraffic() {
  const page = document.getElementById('page-traffic');
  page.innerHTML = `
    <h1 class="section-title fade-up">流量统计</h1>
    <p class="section-sub fade-up stagger-1">按分钟查看各站点的入站、出站流量与请求数量。</p>
    <div class="controls-row traffic-controls fade-up stagger-1">
      <select class="form-select" id="traffic-site-select" aria-label="选择站点">
        <option value="">加载中...</option>
      </select>
      <select class="form-select" id="traffic-hours-select" aria-label="选择统计时间范围">
        <option value="1">最近 1 小时</option>
        <option value="6">最近 6 小时</option>
        <option value="24" selected>最近 24 小时</option>
        <option value="168">最近 7 天</option>
      </select>
      <span class="traffic-range-note" id="traffic-range-note">分钟级聚合 · 最近 24 小时</span>
    </div>
    <div class="chart-wrap fade-up stagger-2">
      <div class="chart-head">
        <h3>分时流量</h3>
        <div class="chart-legend" aria-label="图表图例">
          <div class="legend-item"><div class="legend-dot in"></div>入站流量</div>
          <div class="legend-item"><div class="legend-dot out"></div>出站流量</div>
          <div class="legend-item"><div class="legend-dot requests"></div>请求数</div>
        </div>
      </div>
      <canvas id="trafficChart"></canvas>
    </div>
    <div class="traffic-totals" id="traffic-totals"></div>
  `;

  loadTrafficSites();

  document.getElementById('traffic-site-select').onchange = loadTrafficChart;
  document.getElementById('traffic-hours-select').onchange = loadTrafficChart;

  startTrafficRefresh();
}

async function loadTrafficSites() {
  try {
    const sites = await API.listSites();
    // The page may have been left (or re-rendered) while the request was in
    // flight; only touch the live DOM when traffic is still the active route.
    if (Router.current !== 'traffic') return;
    const sel = document.getElementById('traffic-site-select');
    if (!sel) return;
    if (!sites || sites.length === 0) {
      sel.innerHTML = '<option value="">暂无站点</option>';
      return;
    }
    sel.innerHTML = sites.map(s => `<option value="${s.id}">${esc(s.name)}</option>`).join('');
    loadTrafficChart();
  } catch (e) {
    Toast.error('加载站点失败');
  }
}

function trafficRangeLabel(hours) {
  switch (Number(hours)) {
  case 1: return '最近 1 小时';
  case 6: return '最近 6 小时';
  case 168: return '最近 7 天';
  default: return '最近 24 小时';
  }
}

function formatTrafficCount(value) {
  return Math.max(0, Number(value) || 0).toLocaleString('zh-CN');
}

async function loadTrafficChart() {
  const siteSelect = document.getElementById('traffic-site-select');
  const hoursSelect = document.getElementById('traffic-hours-select');
  if (!siteSelect || !hoursSelect) return;
  const siteId = siteSelect.value;
  const hours = parseInt(hoursSelect.value, 10) || 24;
  if (!siteId) return;

  try {
    // Single {snapshot, logs} request: snapshot carries the live cumulative
    // total; minute logs include the current pending bucket for a live chart.
    const data = await API.getTrafficSnapshot(siteId, hours);
    if (!data || !trafficChartStillCurrent(siteId, hours)) return;

    const snapshot = data.snapshot || {};
    const logs = data.logs || [];
    const billingMode = data.billing_mode === 'outbound' ? 'outbound' : 'bidirectional';
    const totalIn = logs.reduce((sum, log) => sum + Math.max(0, Number(log.bytes_in) || 0), 0);
    const totalOut = logs.reduce((sum, log) => sum + Math.max(0, Number(log.bytes_out) || 0), 0);
    const billableRange = billingMode === 'outbound' ? totalOut : 2 * (totalIn + totalOut);
    const totalRequests = logs.reduce((sum, log) => sum + Math.max(0, Number(log.requests) || 0), 0);
    const rangeLabel = trafficRangeLabel(hours);
    const rangeNote = document.getElementById('traffic-range-note');
    if (rangeNote) rangeNote.textContent = `分钟级聚合 · ${rangeLabel} · ${billingMode === 'outbound' ? '单向计费（仅出站）' : '双向计费（入站 + 出站）'}`;

    document.getElementById('traffic-totals').innerHTML = `
      <div class="total-card fade-up stagger-2">
        <div class="total-label">${rangeLabel}入站</div>
        <div class="total-value">${formatBytes(totalIn)}</div>
      </div>
      <div class="total-card fade-up stagger-3">
        <div class="total-label">${rangeLabel}出站</div>
        <div class="total-value">${formatBytes(totalOut)}</div>
      </div>
      <div class="total-card fade-up stagger-4">
        <div class="total-label">${rangeLabel}请求数</div>
        <div class="total-value">${formatTrafficCount(totalRequests)}</div>
      </div>
      <div class="total-card fade-up stagger-5">
        <div class="total-label">${rangeLabel}计费流量</div>
        <div class="total-value">${formatBytes(billableRange)}</div>
      </div>
      <div class="total-card fade-up stagger-6">
        <div class="total-label">累计计费流量${billingMode === 'outbound' ? '（单向）' : '（双向）'}</div>
        <div class="total-value">${formatBytes(snapshot.traffic_used || 0)}</div>
        ${snapshot.traffic_quota > 0 ? `<div class="total-delta" style="color:var(--white-38)">额度 ${formatBytes(snapshot.traffic_quota)}</div>` : ''}
      </div>
    `;

    drawTrafficChart(logs, hours);
  } catch (e) {
    console.error('Traffic load error:', e);
  }
}

// A chart request may finish after the user navigated away or switched site/
// hours; those late responses must not paint over the new page or selection.
function trafficChartStillCurrent(siteId, hours) {
  if (Router.current !== 'traffic') return false;
  const sel = document.getElementById('traffic-site-select');
  const hoursSel = document.getElementById('traffic-hours-select');
  return !!sel && !!hoursSel && sel.value === siteId && parseInt(hoursSel.value, 10) === hours;
}

let trafficRefreshTimer = null;

function startTrafficRefresh() {
  stopTrafficRefresh();
  trafficRefreshTimer = setInterval(() => {
    if (Router.current === 'traffic') loadTrafficChart();
  }, 15000);
}

function stopTrafficRefresh() {
  if (!trafficRefreshTimer) return;
  clearInterval(trafficRefreshTimer);
  trafficRefreshTimer = null;
}

// traffic_logs stores a server-local wall-clock minute. Newer API responses
// include recorded_at_ms so the browser can place that bucket on the same
// timeline regardless of its own timezone. Keep a wall-clock parser for
// older servers and legacy responses instead of treating SQLite's trailing Z
// as a real UTC instant.
function trafficLogTimestamp(log) {
  const epoch = Number(log && log.recorded_at_ms);
  if (Number.isFinite(epoch) && epoch > 0) return epoch;
  const value = String(log && log.recorded_at || '').trim();
  const match = /^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d+))?)?/.exec(value);
  if (match) {
    const milliseconds = match[7] ? Number(`0.${match[7]}`) * 1000 : 0;
    return new Date(
      Number(match[1]), Number(match[2]) - 1, Number(match[3]),
      Number(match[4]), Number(match[5]), Number(match[6] || 0), milliseconds,
    ).getTime();
  }
  const parsed = new Date(value).getTime();
  return Number.isFinite(parsed) ? parsed : NaN;
}

function buildMinuteTrafficSeries(logs, hours, nowMilliseconds) {
  const minuteCount = Math.max(1, Math.round((Number(hours) || 24) * 60));
  const end = Math.floor((nowMilliseconds || Date.now()) / 60000) * 60000;
  const start = end - (minuteCount - 1) * 60000;
  const inbound = new Array(minuteCount).fill(0);
  const outbound = new Array(minuteCount).fill(0);
  const requests = new Array(minuteCount).fill(0);

  (logs || []).forEach(log => {
    const timestamp = trafficLogTimestamp(log);
    if (!Number.isFinite(timestamp)) return;
    const index = Math.floor((timestamp - start) / 60000);
    if (index < 0 || index >= minuteCount) return;
    inbound[index] += Math.max(0, Number(log.bytes_in) || 0);
    outbound[index] += Math.max(0, Number(log.bytes_out) || 0);
    requests[index] += Math.max(0, Number(log.requests) || 0);
  });

  return { start, end, minuteCount, inbound, outbound, requests };
}

function compactTrafficSeries(series, maxPoints) {
  const groupSize = Math.max(1, Math.ceil(series.minuteCount / Math.max(1, maxPoints)));
  const result = { timestamps: [], inbound: [], outbound: [], requests: [] };
  for (let offset = 0; offset < series.minuteCount; offset += groupSize) {
    const limit = Math.min(series.minuteCount, offset + groupSize);
    let bytesIn = 0;
    let bytesOut = 0;
    let requestCount = 0;
    for (let index = offset; index < limit; index++) {
      bytesIn += series.inbound[index];
      bytesOut += series.outbound[index];
      requestCount += series.requests[index];
    }
    result.timestamps.push(series.start + (limit - 1) * 60000);
    result.inbound.push(bytesIn);
    result.outbound.push(bytesOut);
    result.requests.push(requestCount);
  }
  return result;
}

function drawTrafficChart(logs, hours) {
  const canvas = document.getElementById('trafficChart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const w = Math.max(260, Number(canvas.parentElement && canvas.parentElement.clientWidth) || 800);
  const h = 260;
  canvas.width = Math.round(w * dpr);
  canvas.height = Math.round(h * dpr);
  canvas.style.width = w + 'px';
  canvas.style.height = h + 'px';
  ctx.scale(dpr, dpr);

  const pad = { top: 20, right: 54, bottom: 38, left: 62 };
  const chartWidth = Math.max(1, w - pad.left - pad.right);
  const chartHeight = Math.max(1, h - pad.top - pad.bottom);
  const lightTheme = document.documentElement && document.documentElement.getAttribute('data-theme') === 'light';
  const gridColor = lightTheme ? 'rgba(15,23,42,.09)' : 'rgba(255,255,255,.07)';
  const labelColor = lightTheme ? 'rgba(71,85,105,.88)' : 'rgba(203,213,225,.72)';
  const inboundColor = lightTheme ? '#2563eb' : '#60a5fa';
  const outboundColor = lightTheme ? '#0891b2' : '#22d3ee';
  const requestColor = lightTheme ? '#9333ea' : '#c084fc';
  const minuteSeries = buildMinuteTrafficSeries(logs, hours, Date.now());
  const maxPoints = Math.max(48, Math.min(360, Math.floor(chartWidth / 3)));
  const series = compactTrafficSeries(minuteSeries, maxPoints);
  const pointCount = series.timestamps.length;
  const maxBytes = Math.max(1, ...series.inbound, ...series.outbound) * 1.15;
  const maxRequests = Math.max(1, ...series.requests) * 1.15;
  const x = index => pad.left + (index / Math.max(1, pointCount - 1)) * chartWidth;
  const byteY = value => pad.top + (1 - value / maxBytes) * chartHeight;
  const requestY = value => pad.top + (1 - value / maxRequests) * chartHeight;

  ctx.clearRect(0, 0, w, h);
  ctx.font = '10px system-ui, sans-serif';
  for (let index = 0; index <= 4; index++) {
    const yy = pad.top + (index / 4) * chartHeight;
    ctx.strokeStyle = gridColor;
    ctx.lineWidth = 1;
    ctx.beginPath();
    ctx.moveTo(pad.left, yy);
    ctx.lineTo(w - pad.right, yy);
    ctx.stroke();

    ctx.fillStyle = labelColor;
    ctx.textAlign = 'right';
    ctx.fillText(formatBytes((4 - index) / 4 * maxBytes), pad.left - 9, yy + 4);
    ctx.textAlign = 'left';
    ctx.fillText(String(Math.round((4 - index) / 4 * maxRequests)), w - pad.right + 9, yy + 4);
  }

  const hasData = series.inbound.some(Boolean) || series.outbound.some(Boolean) || series.requests.some(Boolean);
  if (!hasData) {
    ctx.fillStyle = labelColor;
    ctx.font = '13px system-ui, sans-serif';
    ctx.textAlign = 'center';
    ctx.fillText('当前范围暂无流量数据', w / 2, h / 2);
    return;
  }

  const labelIndexes = [0, .25, .5, .75, 1].map(ratio => Math.round((pointCount - 1) * ratio));
  ctx.fillStyle = labelColor;
  ctx.font = '10px system-ui, sans-serif';
  ctx.textAlign = 'center';
  labelIndexes.forEach(index => {
    const label = Number(hours) >= 168
      ? meridianFormatDate(series.timestamps[index])
      : meridianFormatDateTime(series.timestamps[index], false).slice(11);
    ctx.fillText(label, x(index), h - 12);
  });

  function drawSeries(values, color, yForValue, fillAlpha) {
    ctx.save();
    ctx.beginPath();
    values.forEach((value, index) => {
      const xx = x(index);
      const yy = yForValue(value);
      if (index === 0) ctx.moveTo(xx, yy);
      else ctx.lineTo(xx, yy);
    });
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.lineJoin = 'round';
    ctx.lineCap = 'round';
    ctx.stroke();
    if (fillAlpha !== '00') {
      ctx.lineTo(x(values.length - 1), pad.top + chartHeight);
      ctx.lineTo(x(0), pad.top + chartHeight);
      ctx.closePath();
      const gradient = ctx.createLinearGradient(0, pad.top, 0, pad.top + chartHeight);
      gradient.addColorStop(0, color + fillAlpha);
      gradient.addColorStop(1, color + '00');
      ctx.fillStyle = gradient;
      ctx.fill();
    }
    ctx.restore();
  }

  drawSeries(series.outbound, outboundColor, byteY, '1f');
  drawSeries(series.inbound, inboundColor, byteY, '24');
  drawSeries(series.requests, requestColor, requestY, '00');
}

window.addEventListener('resize', () => {
  if (Router.current === 'traffic') {
    const canvas = document.getElementById('trafficChart');
    if (canvas) loadTrafficChart();
  }
});

window.addEventListener('meridian-theme-change', () => {
  if (Router.current === 'traffic' && document.getElementById('trafficChart')) loadTrafficChart();
});
