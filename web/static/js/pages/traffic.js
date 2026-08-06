// Traffic minute timeline page
let trafficRefreshTimer = null;
let trafficRequestSequence = 0;
let trafficSiteRequestSequence = 0;
let trafficRetryAction = null;
let trafficChartState = { siteId: '', minutes: 1440, buckets: [], selectedTimestamp: null, geometry: null, scrubPointerId: null };

function renderTraffic() {
  const page = document.getElementById('page-traffic');
  page.innerHTML = `
    <h1 class="section-title fade-up">流量统计</h1>
    <p class="section-sub fade-up stagger-1">按分钟查看各站点的流量与请求趋势</p>
    <div class="controls-row traffic-controls fade-up stagger-1" aria-label="流量筛选">
      <label class="traffic-control-label" for="traffic-site-select">站点
        <select class="form-select" id="traffic-site-select"><option value="">加载中...</option></select>
      </label>
      <label class="traffic-control-label" for="traffic-hours-select">时间范围
        <select class="form-select" id="traffic-hours-select">
          <option value="60">最近 1 小时</option><option value="360">最近 6 小时</option>
          <option value="1440" selected>最近 24 小时</option><option value="10080">最近 7 天</option>
        </select>
      </label>
    </div>
    <div class="chart-wrap fade-up stagger-2">
      <div class="chart-head"><h3>每分钟流量</h3><div class="chart-legend" aria-label="图例">
        <div class="legend-item"><span class="legend-dot in"></span>入站流量</div>
        <div class="legend-item"><span class="legend-dot out"></span>出站流量</div>
      </div></div>
      <div class="traffic-chart-status loading" id="traffic-chart-status" role="status" aria-live="polite">
        <span id="traffic-chart-status-message">正在加载流量...</span>
        <button type="button" class="btn-secondary traffic-retry" id="traffic-chart-retry" hidden>重试</button>
      </div>
      <canvas id="trafficChart" tabindex="0" role="img" aria-label="每分钟入站和出站流量平滑趋势曲线，按下并拖动或使用方向键选择具体分钟"></canvas>
      <div class="traffic-axis-label traffic-axis-y">每分钟流量</div>
      <div class="traffic-axis-label traffic-axis-x">时间（本地时区）</div>
      <div class="traffic-point-detail" id="traffic-point-detail" aria-live="polite" hidden></div>
    </div>
    <div class="traffic-totals" id="traffic-totals"></div>`;

  trafficChartState = { siteId: '', minutes: 1440, buckets: [], selectedTimestamp: null, geometry: null, scrubPointerId: null };
  document.getElementById('traffic-site-select').onchange = () => loadTrafficChart({ resetSelection: true });
  document.getElementById('traffic-hours-select').onchange = () => loadTrafficChart({ resetSelection: true });
  document.getElementById('traffic-chart-retry').onclick = () => { if (trafficRetryAction) trafficRetryAction(); };
  const canvas = document.getElementById('trafficChart');
  canvas.addEventListener('pointerdown', beginTrafficScrub);
  canvas.addEventListener('pointermove', continueTrafficScrub);
  canvas.addEventListener('pointerup', endTrafficScrub);
  canvas.addEventListener('pointercancel', endTrafficScrub);
  canvas.addEventListener('lostpointercapture', endTrafficScrub);
  canvas.addEventListener('keydown', navigateTrafficPoint);
  startTrafficRefresh();
  loadTrafficSites();
}

function setTrafficChartStatus(kind, message, retryAction) {
  const status = document.getElementById('traffic-chart-status');
  const messageEl = document.getElementById('traffic-chart-status-message');
  const retry = document.getElementById('traffic-chart-retry');
  if (!status || !messageEl || !retry) return;
  status.className = 'traffic-chart-status ' + (kind || '');
  messageEl.textContent = message || '';
  trafficRetryAction = retryAction || null;
  retry.hidden = !trafficRetryAction;
  status.hidden = !message && !trafficRetryAction;
}

function clearTrafficPresentation() {
  endTrafficScrub();
  trafficChartState.buckets = [];
  trafficChartState.geometry = null;
  trafficChartState.selectedTimestamp = null;
  const totals = document.getElementById('traffic-totals');
  const detail = document.getElementById('traffic-point-detail');
  const canvas = document.getElementById('trafficChart');
  if (totals) totals.innerHTML = '';
  if (detail) { detail.hidden = true; detail.textContent = ''; }
  if (canvas) {
    canvas.removeAttribute('aria-valuetext');
    canvas.getContext('2d').clearRect(0, 0, canvas.width || 0, canvas.height || 0);
  }
}

async function loadTrafficSites() {
  const requestSequence = ++trafficSiteRequestSequence;
  try {
    const sites = await API.listSites();
    if (Router.current !== 'traffic' || requestSequence !== trafficSiteRequestSequence) return;
    const select = document.getElementById('traffic-site-select');
    if (!select) return;
    if (!Array.isArray(sites) || sites.length === 0) {
      select.innerHTML = '<option value="">暂无站点</option>';
      clearTrafficPresentation();
      setTrafficChartStatus('empty', '暂无站点，请先创建站点。', loadTrafficSites);
      return;
    }
    const previous = select.value;
    select.innerHTML = sites.map(site => `<option value="${site.id}">${esc(site.name)}</option>`).join('');
    if (previous && sites.some(site => String(site.id) === previous)) select.value = previous;
    await loadTrafficChart({ resetSelection: true });
  } catch (error) {
    if (Router.current !== 'traffic' || requestSequence !== trafficSiteRequestSequence) return;
    clearTrafficPresentation();
    setTrafficChartStatus('error', '站点加载失败。', loadTrafficSites);
  }
}

function sanitizeTrafficBuckets(payload) {
  if (!Array.isArray(payload)) return [];
  return payload.reduce((safe, item) => {
    if (!item || !Number.isSafeInteger(Number(item.minute_start_unix))) return safe;
    const bytesIn = Number(item.bytes_in), bytesOut = Number(item.bytes_out), requests = Number(item.requests);
    safe.push({
      minute_start_unix: Number(item.minute_start_unix),
      bytes_in: Number.isFinite(bytesIn) && bytesIn >= 0 ? bytesIn : 0,
      bytes_out: Number.isFinite(bytesOut) && bytesOut >= 0 ? bytesOut : 0,
      requests: Number.isFinite(requests) && requests >= 0 ? requests : 0,
    });
    return safe;
  }, []);
}

async function loadTrafficChart(options) {
  options = options || {};
  const siteSelect = document.getElementById('traffic-site-select');
  const rangeSelect = document.getElementById('traffic-hours-select');
  if (!siteSelect || !rangeSelect) return;
  const siteId = siteSelect.value;
  const minutes = parseInt(rangeSelect.value, 10);
  if (!siteId) { clearTrafficPresentation(); setTrafficChartStatus('empty', '请选择站点。', null); return; }

  const requestId = ++trafficRequestSequence;
  const sameSeries = trafficChartState.siteId === siteId && trafficChartState.minutes === minutes;
  if (options.resetSelection) {
    endTrafficScrub();
    trafficChartState.selectedTimestamp = null;
    updateTrafficPointDetail();
    if (sameSeries && trafficChartState.buckets.length) drawTrafficChart(trafficChartState.buckets);
  }
  if (!sameSeries) clearTrafficPresentation();
  setTrafficChartStatus('loading', sameSeries && trafficChartState.buckets.length ? '正在更新...' : '正在加载流量...', null);
  try {
    const payload = await API.getTrafficTimeline(siteId, minutes);
    if (requestId !== trafficRequestSequence || !trafficChartStillCurrent(siteId, minutes)) return;
    const buckets = sanitizeTrafficBuckets(payload); // copies only the four public aggregate fields
    const currentSelection = !options.resetSelection && sameSeries ? trafficChartState.selectedTimestamp : null;
    trafficChartState.siteId = siteId;
    trafficChartState.minutes = minutes;
    trafficChartState.buckets = buckets;
    trafficChartState.selectedTimestamp = currentSelection !== null && buckets.some(bucket => bucket.minute_start_unix === currentSelection)
      ? currentSelection : null;
    renderTrafficTotals(buckets, minutes);
    drawTrafficChart(buckets);
    updateTrafficPointDetail();
    const active = buckets.some(bucket => bucket.bytes_in || bucket.bytes_out || bucket.requests);
    setTrafficChartStatus(active ? '' : 'empty', active ? '' : '所选时段暂无流量或请求。', null);
  } catch (error) {
    if (requestId !== trafficRequestSequence || !trafficChartStillCurrent(siteId, minutes)) return;
    setTrafficChartStatus('error', '流量加载失败。', () => loadTrafficChart());
  }
}

function trafficChartStillCurrent(siteId, minutes) {
  const site = document.getElementById('traffic-site-select');
  const range = document.getElementById('traffic-hours-select');
  return Router.current === 'traffic' && !!site && !!range && site.value === siteId && parseInt(range.value, 10) === minutes;
}

function trafficRangeLabel(minutes) {
  return ({ 60: '最近 1 小时', 360: '最近 6 小时', 1440: '最近 24 小时', 10080: '最近 7 天' })[minutes]
    || '当前时间范围';
}

function renderTrafficTotals(buckets, minutes) {
  const totals = document.getElementById('traffic-totals');
  if (!totals) return;
  let totalIn = 0, totalOut = 0, requests = 0;
  for (const bucket of buckets) {
    totalIn += bucket.bytes_in;
    totalOut += bucket.bytes_out;
    requests += bucket.requests;
  }
  const range = trafficRangeLabel(minutes);
  totals.innerHTML = `<div class="total-card"><div class="total-label">${range} · 入站总量</div><div class="total-value">${formatBytes(totalIn)}</div></div>
    <div class="total-card"><div class="total-label">${range} · 出站总量</div><div class="total-value">${formatBytes(totalOut)}</div></div>
    <div class="total-card"><div class="total-label">${range} · 请求总数</div><div class="total-value">${requests.toLocaleString()}</div></div>`;
}

function formatTrafficMinute(timestamp) {
  return new Date(timestamp * 1000).toLocaleString([], { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false });
}

function selectedTrafficPointIndex() {
  return trafficChartState.buckets.findIndex(bucket => bucket.minute_start_unix === trafficChartState.selectedTimestamp);
}

function selectTrafficPoint(index) {
  if (index < 0 || index >= trafficChartState.buckets.length) return;
  trafficChartState.selectedTimestamp = trafficChartState.buckets[index].minute_start_unix;
  drawTrafficChart(trafficChartState.buckets);
  updateTrafficPointDetail();
}

function updateTrafficPointDetail() {
  const detail = document.getElementById('traffic-point-detail');
  const canvas = document.getElementById('trafficChart');
  if (!detail) return;
  const index = selectedTrafficPointIndex();
  if (index < 0) {
    detail.hidden = true;
    detail.textContent = '';
    if (canvas) canvas.removeAttribute('aria-valuetext');
    return;
  }
  const bucket = trafficChartState.buckets[index];
  detail.hidden = false;
  detail.innerHTML = `<strong class="traffic-detail-time">${formatTrafficMinute(bucket.minute_start_unix)}</strong>
    <span><i class="legend-dot in" aria-hidden="true"></i>入站 ${formatBytes(bucket.bytes_in)}</span>
    <span><i class="legend-dot out" aria-hidden="true"></i>出站 ${formatBytes(bucket.bytes_out)}</span>
    <span>请求 ${bucket.requests.toLocaleString()}</span>`;
  if (canvas) canvas.setAttribute('aria-valuetext', `${formatTrafficMinute(bucket.minute_start_unix)}，入站 ${formatBytes(bucket.bytes_in)}，出站 ${formatBytes(bucket.bytes_out)}，请求 ${bucket.requests}`);
}

function trafficPointIndexFromPointer(event) {
  const geometry = trafficChartState.geometry;
  const canvas = document.getElementById('trafficChart');
  if (!geometry || !canvas || !geometry.count || !Number.isFinite(event.clientX)) return -1;
  if (geometry.count === 1) return 0;
  const rect = canvas.getBoundingClientRect();
  const chartX = (event.clientX - rect.left) * (rect.width > 0 ? geometry.width / rect.width : 1);
  const raw = Math.round((chartX - geometry.left) / geometry.plotWidth * (geometry.count - 1));
  return Math.max(0, Math.min(geometry.count - 1, raw));
}

function selectTrafficPointFromPointer(event) {
  const index = trafficPointIndexFromPointer(event);
  if (index < 0) return false;
  selectTrafficPoint(index);
  return true;
}

function beginTrafficScrub(event) {
  const canvas = document.getElementById('trafficChart');
  if (!canvas || trafficChartState.scrubPointerId !== null || event.isPrimary === false
      || (typeof event.button === 'number' && event.button !== 0)) return;
  if (!selectTrafficPointFromPointer(event)) return;
  if (typeof event.preventDefault === 'function') event.preventDefault();
  canvas.focus({ preventScroll: true });
  if (typeof canvas.setPointerCapture !== 'function') return;
  canvas.setPointerCapture(event.pointerId);
  trafficChartState.scrubPointerId = event.pointerId;
  canvas.classList.add('is-scrubbing');
}

function continueTrafficScrub(event) {
  const canvas = document.getElementById('trafficChart');
  if (!canvas || trafficChartState.scrubPointerId === null || event.pointerId !== trafficChartState.scrubPointerId) return;
  if (typeof canvas.hasPointerCapture === 'function' && !canvas.hasPointerCapture(event.pointerId)) {
    endTrafficScrub({ type: 'lostpointercapture', pointerId: event.pointerId });
    return;
  }
  if (selectTrafficPointFromPointer(event) && typeof event.preventDefault === 'function') event.preventDefault();
}

function endTrafficScrub(event) {
  const canvas = document.getElementById('trafficChart');
  const pointerId = trafficChartState.scrubPointerId;
  if (pointerId === null) {
    if (canvas) canvas.classList.remove('is-scrubbing');
    return;
  }
  if (event && event.pointerId !== undefined && event.pointerId !== pointerId) return;
  trafficChartState.scrubPointerId = null;
  if (!canvas) return;
  canvas.classList.remove('is-scrubbing');
  const captureWasLost = event && event.type === 'lostpointercapture';
  if (!captureWasLost && typeof canvas.releasePointerCapture === 'function'
      && (typeof canvas.hasPointerCapture !== 'function' || canvas.hasPointerCapture(pointerId))) {
    canvas.releasePointerCapture(pointerId);
  }
}

function navigateTrafficPoint(event) {
  if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(event.key) || !trafficChartState.buckets.length) return;
  event.preventDefault();
  let index = selectedTrafficPointIndex();
  if (index < 0) index = trafficChartState.buckets.length - 1;
  if (event.key === 'ArrowLeft') index = Math.max(0, index - 1);
  if (event.key === 'ArrowRight') index = Math.min(trafficChartState.buckets.length - 1, index + 1);
  if (event.key === 'Home') index = 0;
  if (event.key === 'End') index = trafficChartState.buckets.length - 1;
  selectTrafficPoint(index);
}

function trafficBucketValueAt(buckets, field, index) {
  return buckets[Math.max(0, Math.min(buckets.length - 1, index))][field];
}

function smoothedTrafficValue(buckets, field, index) {
  const last = buckets.length - 1;
  if (index === 0 || index === last) return trafficBucketValueAt(buckets, field, index);
  return (trafficBucketValueAt(buckets, field, index - 2)
    + 4 * trafficBucketValueAt(buckets, field, index - 1)
    + 6 * trafficBucketValueAt(buckets, field, index)
    + 4 * trafficBucketValueAt(buckets, field, index + 1)
    + trafficBucketValueAt(buckets, field, index + 2)) / 16;
}

function trafficCurveTangent(previous, current, next) {
  const incoming = current - previous;
  const outgoing = next - current;
  if (incoming === 0 || outgoing === 0 || Math.sign(incoming) !== Math.sign(outgoing)) return 0;
  return 2 * incoming * outgoing / (incoming + outgoing);
}

function clampTrafficCurveControl(value, start, end) {
  return Math.max(Math.min(start, end), Math.min(Math.max(start, end), value));
}

function strokeTrafficSeries(ctx, buckets, field, color, x, y) {
  if (!buckets.length) return;
  const last = buckets.length - 1;
  let previousX = x(0), previousY = y(smoothedTrafficValue(buckets, field, 0));
  let nextY = last > 0 ? y(smoothedTrafficValue(buckets, field, 1)) : previousY;
  let previousTangent = nextY - previousY;
  ctx.beginPath();
  ctx.moveTo(previousX, previousY);
  for (let index = 1; index < buckets.length; index++) {
    const currentX = x(index), currentY = nextY;
    const followingY = index < last ? y(smoothedTrafficValue(buckets, field, index + 1)) : currentY;
    const currentTangent = index === last
      ? currentY - previousY
      : trafficCurveTangent(previousY, currentY, followingY);
    const controlOffsetX = (currentX - previousX) / 3;
    ctx.bezierCurveTo(
      previousX + controlOffsetX,
      clampTrafficCurveControl(previousY + previousTangent / 3, previousY, currentY),
      currentX - controlOffsetX,
      clampTrafficCurveControl(currentY - currentTangent / 3, previousY, currentY),
      currentX,
      currentY,
    );
    previousX = currentX;
    previousY = currentY;
    nextY = followingY;
    previousTangent = currentTangent;
  }
  ctx.strokeStyle = color;
  ctx.lineWidth = 2;
  ctx.lineCap = 'round';
  ctx.lineJoin = 'round';
  ctx.stroke();
}

function drawTrafficChart(buckets) {
  const canvas = document.getElementById('trafficChart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const renderedWidth = canvas.getBoundingClientRect().width || canvas.parentElement.clientWidth || 800;
  const width = Math.max(280, Math.floor(renderedWidth)), height = 280;
  canvas.width = width * dpr; canvas.height = height * dpr;
  canvas.style.width = width + 'px'; canvas.style.height = height + 'px';
  ctx.scale(dpr, dpr); ctx.clearRect(0, 0, width, height);
  const pad = { top: 20, right: 32, bottom: 44, left: 64 };
  const plotWidth = Math.max(1, width - pad.left - pad.right), plotHeight = height - pad.top - pad.bottom;
  const count = buckets.length;
  trafficChartState.geometry = { left: pad.left, plotWidth, count, width };
  let maximum = 4;
  for (const bucket of buckets) maximum = Math.max(maximum, bucket.bytes_in, bucket.bytes_out);
  maximum *= 1.15;
  const x = index => pad.left + (count <= 1 ? plotWidth / 2 : index / (count - 1) * plotWidth);
  const y = value => pad.top + (1 - value / maximum) * plotHeight;
  ctx.font = '11px -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif';
  for (let row = 0; row <= 4; row++) {
    const yy = pad.top + row / 4 * plotHeight;
    ctx.strokeStyle = 'rgba(255,255,255,.06)'; ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(pad.left, yy); ctx.lineTo(width - pad.right, yy); ctx.stroke();
    ctx.fillStyle = 'rgba(255,255,255,.45)'; ctx.textAlign = 'right';
    ctx.fillText(formatBytes((4 - row) / 4 * maximum), pad.left - 10, yy + 4);
  }
  if (!count) return;
  const labelCount = Math.min(width < 360 ? 2 : width < 640 ? 3 : 5, count);
  for (let label = 0; label < labelCount; label++) {
    const index = labelCount === 1 ? 0 : Math.round(label / (labelCount - 1) * (count - 1));
    ctx.fillStyle = 'rgba(255,255,255,.45)';
    ctx.textAlign = label === 0 ? 'left' : (label === labelCount - 1 ? 'right' : 'center');
    ctx.fillText(formatTrafficMinute(buckets[index].minute_start_unix), x(index), height - 18);
  }
  strokeTrafficSeries(ctx, buckets, 'bytes_out', 'rgb(100,210,255)', x, y);
  strokeTrafficSeries(ctx, buckets, 'bytes_in', 'rgb(10,132,255)', x, y);
  const selected = selectedTrafficPointIndex();
  if (selected >= 0) {
    const selectedX = x(selected);
    ctx.strokeStyle = 'rgba(255,255,255,.45)'; ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(selectedX, pad.top); ctx.lineTo(selectedX, pad.top + plotHeight); ctx.stroke();
    [['bytes_out', 'rgb(100,210,255)'], ['bytes_in', 'rgb(10,132,255)']].forEach(series => {
      ctx.fillStyle = series[1]; ctx.beginPath(); ctx.arc(selectedX, y(smoothedTrafficValue(buckets, series[0], selected)), 4, 0, Math.PI * 2); ctx.fill();
    });
  }
}

function startTrafficRefresh() {
  stopTrafficRefresh();
  trafficRefreshTimer = setInterval(() => { if (Router.current === 'traffic') loadTrafficChart(); }, 15000);
}

function stopTrafficRefresh() {
  trafficRequestSequence++;
  trafficSiteRequestSequence++;
  endTrafficScrub();
  if (trafficRefreshTimer) { clearInterval(trafficRefreshTimer); trafficRefreshTimer = null; }
}

window.addEventListener('resize', () => {
  if (Router.current === 'traffic' && trafficChartState.buckets.length) drawTrafficChart(trafficChartState.buckets);
});
