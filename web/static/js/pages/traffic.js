// Traffic statistics page
function renderTraffic() {
  const page = document.getElementById('page-traffic');
  page.innerHTML = `
    <h1 class="section-title fade-up">流量统计</h1>
    <p class="section-sub fade-up stagger-1">查看各站点流量使用情况</p>
    <div class="controls-row fade-up stagger-1">
      <select class="form-select" id="traffic-site-select">
        <option value="">加载中...</option>
      </select>
      <select class="form-select" id="traffic-hours-select">
        <option value="24">最近 24 小时</option>
        <option value="168">最近 7 天</option>
        <option value="720">最近 30 天</option>
      </select>
    </div>
    <div class="chart-wrap fade-up stagger-2">
      <div class="chart-head">
        <h3>流量趋势</h3>
        <div class="chart-legend">
          <div class="legend-item"><div class="legend-dot in"></div>入站流量</div>
          <div class="legend-item"><div class="legend-dot out"></div>出站流量</div>
        </div>
      </div>
      <canvas id="trafficChart"></canvas>
    </div>
    <div class="traffic-totals" id="traffic-totals"></div>
  `;

  loadTrafficSites();

  document.getElementById('traffic-site-select').onchange = loadTrafficChart;
  document.getElementById('traffic-hours-select').onchange = loadTrafficChart;
}

async function loadTrafficSites() {
  try {
    const sites = await API.listSites();
    const sel = document.getElementById('traffic-site-select');
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

async function loadTrafficChart() {
  const siteId = document.getElementById('traffic-site-select').value;
  const hours = parseInt(document.getElementById('traffic-hours-select').value);
  if (!siteId) return;

  try {
    const logs = await API.getTraffic(siteId, hours);
    const sites = await API.listSites();
    const site = sites.find(s => s.id === parseInt(siteId));

    // Update totals
    const totalIn = logs.reduce((a, l) => a + (l.bytes_in || 0), 0);
    const totalOut = logs.reduce((a, l) => a + (l.bytes_out || 0), 0);

    document.getElementById('traffic-totals').innerHTML = `
      <div class="total-card fade-up stagger-3">
        <div class="total-label">入站流量</div>
        <div class="total-value">${formatBytes(totalIn)}</div>
      </div>
      <div class="total-card fade-up stagger-4">
        <div class="total-label">出站流量</div>
        <div class="total-value">${formatBytes(totalOut)}</div>
      </div>
      <div class="total-card fade-up stagger-5">
        <div class="total-label">累计使用</div>
        <div class="total-value">${formatBytes(site ? site.traffic_used : 0)}</div>
        ${site && site.traffic_quota > 0 ? `<div class="total-delta" style="color:var(--white-38)">额度 ${formatBytes(site.traffic_quota)}</div>` : ''}
      </div>
    `;

    drawTrafficChart(logs, hours);
  } catch (e) {
    console.error('Traffic load error:', e);
  }
}

function drawTrafficChart(logs, hours) {
  const canvas = document.getElementById('trafficChart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.parentElement.clientWidth;
  const h = 280;
  canvas.width = w * dpr;
  canvas.height = h * dpr;
  canvas.style.width = w + 'px';
  canvas.style.height = h + 'px';
  ctx.scale(dpr, dpr);

  const pad = { top: 24, right: 24, bottom: 40, left: 54 };
  const cw = w - pad.left - pad.right;
  const ch = h - pad.top - pad.bottom;

  // Prepare data arrays
  const numPoints = Math.min(hours, 24);
  const inbound = new Array(numPoints).fill(0);
  const outbound = new Array(numPoints).fill(0);

  if (logs.length > 0) {
    // Map logs to chart points
    const now = Date.now();
    logs.forEach(l => {
      const t = new Date(l.recorded_at).getTime();
      const hoursAgo = (now - t) / 3600000;
      const idx = numPoints - 1 - Math.floor(hoursAgo * numPoints / hours);
      if (idx >= 0 && idx < numPoints) {
        inbound[idx] += l.bytes_in / (1024 * 1024); // Convert to MB
        outbound[idx] += l.bytes_out / (1024 * 1024);
      }
    });
  }

  const maxV = Math.max(1, ...inbound, ...outbound) * 1.2;
  const x = i => pad.left + (i / (numPoints - 1 || 1)) * cw;
  const y = v => pad.top + (1 - v / maxV) * ch;

  // Clear
  ctx.clearRect(0, 0, w * dpr, h * dpr);

  // Grid lines
  ctx.strokeStyle = 'rgba(255,255,255,.04)';
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const yy = pad.top + (i / 4) * ch;
    ctx.beginPath(); ctx.moveTo(pad.left, yy); ctx.lineTo(w - pad.right, yy); ctx.stroke();
    ctx.fillStyle = 'rgba(255,255,255,.2)';
    ctx.font = '11px Inter, system-ui';
    ctx.textAlign = 'right';
    const label = ((4 - i) / 4 * maxV).toFixed(0);
    ctx.fillText(label + ' MB', pad.left - 12, yy + 4);
  }

  // Empty state
  if (logs.length === 0) {
    ctx.fillStyle = 'rgba(255,255,255,.2)';
    ctx.font = '14px Inter, system-ui';
    ctx.textAlign = 'center';
    ctx.fillText('暂无流量数据', w / 2, h / 2);
    return;
  }

  // Draw lines
  function smoothLine(data, color, glowColor) {
    ctx.save();
    ctx.beginPath();
    ctx.moveTo(x(0), y(data[0]));
    for (let i = 1; i < data.length; i++) {
      const xc = (x(i - 1) + x(i)) / 2;
      const yc = (y(data[i - 1]) + y(data[i])) / 2;
      ctx.quadraticCurveTo(x(i - 1), y(data[i - 1]), xc, yc);
    }
    ctx.lineTo(x(data.length - 1), y(data[data.length - 1]));

    ctx.shadowColor = glowColor;
    ctx.shadowBlur = 16;
    ctx.strokeStyle = color;
    ctx.lineWidth = 2.5;
    ctx.stroke();
    ctx.shadowBlur = 0;

    // Area fill
    ctx.lineTo(x(data.length - 1), pad.top + ch);
    ctx.lineTo(x(0), pad.top + ch);
    ctx.closePath();
    const grad = ctx.createLinearGradient(0, pad.top, 0, pad.top + ch);
    grad.addColorStop(0, color.replace(')', ',.12)').replace('rgb', 'rgba'));
    grad.addColorStop(1, 'rgba(0,0,0,0)');
    ctx.fillStyle = grad;
    ctx.fill();
    ctx.restore();
  }

  smoothLine(outbound, 'rgb(100,210,255)', 'rgba(100,210,255,.4)');
  smoothLine(inbound, 'rgb(10,132,255)', 'rgba(10,132,255,.4)');
}

window.addEventListener('resize', () => {
  if (Router.current === 'traffic') {
    const canvas = document.getElementById('trafficChart');
    if (canvas) loadTrafficChart();
  }
});
