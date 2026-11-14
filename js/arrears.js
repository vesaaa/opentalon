/* 欠费追缴：联盟停车场欠费数据（演示用随机生成）与本市 / 本省示意地图 */
(function () {
  'use strict';
  const PT = (window.PT = window.PT || {});
  const ri = (a, b) => a + Math.floor(Math.random() * (b - a + 1));
  const pickN = (arr, n) => arr.slice().sort(() => Math.random() - 0.5).slice(0, n);

  // 坐标为近似经纬度，仅用于示意图定位
  const CITY = {
    name: '深圳', home: [113.953, 22.54],
    outline: [[113.76, 22.75], [113.8, 22.6], [113.87, 22.47], [113.95, 22.48], [114.05, 22.5], [114.16, 22.54], [114.3, 22.57], [114.42, 22.6],
      [114.5, 22.47], [114.62, 22.5], [114.6, 22.65], [114.5, 22.72], [114.4, 22.8], [114.25, 22.82], [114.1, 22.78], [114.0, 22.84], [113.9, 22.85], [113.8, 22.8]],
    districts: [['宝安', 113.86, 22.64], ['南山', 113.93, 22.56], ['福田', 114.05, 22.55], ['罗湖', 114.14, 22.57], ['盐田', 114.25, 22.59],
      ['龙华', 114.03, 22.7], ['龙岗', 114.26, 22.73], ['光明', 113.93, 22.77], ['坪山', 114.37, 22.7], ['大鹏', 114.5, 22.58]],
    lots: [['宝安·西乡大道停车场', 113.865, 22.585], ['南山·后海滨路停车场', 113.945, 22.505], ['福田·莲花路停车场', 114.06, 22.555],
      ['罗湖·东门中路停车场', 114.125, 22.548], ['盐田·海景路停车场', 114.245, 22.565], ['龙华·民治大道停车场', 114.035, 22.63],
      ['龙岗·龙翔大道停车场', 114.245, 22.72], ['光明·光明大街停车场', 113.935, 22.755], ['坪山·坪山大道停车场', 114.345, 22.695],
      ['宝安·新安一路停车场', 113.905, 22.565]],
  };
  const PROV = {
    name: '广东',
    outline: [[109.75, 21.65], [109.9, 21.2], [109.75, 20.85], [109.95, 20.3], [110.4, 20.25], [110.55, 20.6], [110.35, 21.0], [110.6, 21.25],
      [111.3, 21.45], [111.9, 21.6], [112.6, 21.7], [113.1, 22.0], [113.55, 22.2], [113.65, 22.6], [113.9, 22.45], [114.3, 22.55], [114.6, 22.6],
      [114.9, 22.75], [115.5, 22.7], [116.2, 22.95], [116.8, 23.35], [117.2, 23.65], [116.9, 24.0], [116.4, 24.3], [116.1, 24.75], [115.75, 24.9],
      [115.4, 24.75], [114.7, 25.3], [114.2, 24.7], [113.9, 25.45], [113.2, 25.5], [112.7, 25.3], [112.2, 24.8], [111.95, 24.3], [111.6, 23.7],
      [111.35, 23.2], [110.85, 22.6], [110.4, 22.2], [109.95, 21.9]],
    cities: [['广州', 113.26, 23.13], ['东莞', 113.75, 23.02], ['佛山', 113.02, 22.95], ['珠海', 113.58, 22.27], ['中山', 113.36, 22.55],
      ['惠州', 114.42, 23.11], ['江门', 112.95, 22.5], ['肇庆', 112.47, 23.1], ['汕头', 116.68, 23.3], ['湛江', 110.36, 21.27],
      ['茂名', 110.92, 21.66], ['韶关', 113.6, 24.81], ['清远', 113.06, 23.7], ['梅州', 116.12, 24.29], ['揭阳', 116.2, 23.6],
      ['汕尾', 115.37, 22.82], ['河源', 114.7, 23.74], ['阳江', 111.98, 21.86], ['云浮', 112.04, 22.92], ['潮州', 116.75, 23.72]],
    home: ['深圳', 114.06, 22.55],
  };
  const day = (n) => { const d = new Date(Date.now() - n * 864e5); return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`; };

  function generate() {
    const city = pickN(CITY.lots, ri(2, 4)).map(([name, lon, lat]) => ({ name, lon, lat, amount: 5 * ri(3, 22), count: 1, date: day(ri(3, 120)), hours: ri(2, 30) }));
    const prov = pickN(PROV.cities, ri(1, 4)).map(([name, lon, lat]) => { const count = ri(1, 3); return { name, lon, lat, count, amount: 5 * ri(4, 30) * count, date: day(ri(5, 200)) }; });
    const sum = (a, k) => a.reduce((s, r) => s + r[k], 0);
    const cityTotal = sum(city, 'amount'), provTotal = sum(prov, 'amount');
    return { city, prov, cityTotal, provTotal, cityCount: city.length, provCount: sum(prov, 'count'), total: cityTotal + provTotal, count: city.length + sum(prov, 'count'), paid: false };
  }

  /* ---------- 示意地图（SVG） ---------- */
  const W = 640, H = 400, PAD = 34;
  function projector(points) {
    let x0 = 1e9, x1 = -1e9, y0 = 1e9, y1 = -1e9;
    for (const [lon, lat] of points) { x0 = Math.min(x0, lon); x1 = Math.max(x1, lon); y0 = Math.min(y0, lat); y1 = Math.max(y1, lat); }
    const c = Math.cos(((y0 + y1) / 2) * Math.PI / 180);
    const k = Math.min((W - PAD * 2) / ((x1 - x0) * c), (H - PAD * 2) / (y1 - y0));
    const ox = (W - (x1 - x0) * c * k) / 2, oy = (H - (y1 - y0) * k) / 2;
    return (lon, lat) => [+(ox + (lon - x0) * c * k).toFixed(1), +(oy + (y1 - lat) * k).toFixed(1)];
  }
  const esc = (s) => String(s).replace(/[&<>"]/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[m]));
  function pin(x, y, amount, label, max) {
    const r = 6 + 9 * Math.sqrt(amount / max), t = `¥${amount}`, bw = t.length * 9 + 14;
    return `<g class="pin"><circle class="pulse" cx="${x}" cy="${y}" r="${r + 5}"/><circle class="dot" cx="${x}" cy="${y}" r="${r}"/>
      <rect class="tagbg" x="${x - bw / 2}" y="${y - r - 25}" width="${bw}" height="19" rx="4"/>
      <text class="tag" x="${x}" y="${y - r - 11}">${t}</text><text class="lot" x="${x}" y="${y + r + 14}">${esc(label)}</text></g>`;
  }
  function mapSVG(data, scope) {
    const M = scope === 'city' ? CITY : PROV;
    const P = projector(M.outline);
    let s = `<svg class="map" viewBox="0 0 ${W} ${H}" role="img" aria-label="${M.name}欠费分布示意图">`;
    for (let x = 40; x < W; x += 40) s += `<line class="grid" x1="${x}" y1="0" x2="${x}" y2="${H}"/>`;
    for (let y = 40; y < H; y += 40) s += `<line class="grid" x1="0" y1="${y}" x2="${W}" y2="${y}"/>`;
    s += `<polygon class="land" points="${M.outline.map(([a, b]) => P(a, b).join(',')).join(' ')}"/>`;
    if (scope === 'city') {
      for (const [n, lon, lat] of CITY.districts) { const [x, y] = P(lon, lat); s += `<text class="place" x="${x}" y="${y}">${n}</text>`; }
      const [hx, hy] = P(CITY.home[0], CITY.home[1]);
      s += `<g class="home"><circle cx="${hx}" cy="${hy}" r="6"/><text x="${hx}" y="${hy + 19}">本停车场</text></g>`;
      const max = Math.max(...data.city.map((r) => r.amount));
      for (const r of data.city) { const [x, y] = P(r.lon, r.lat); s += pin(x, y, r.amount, r.name.split('·')[1], max); }
    } else {
      const owed = new Set(data.prov.map((r) => r.name));
      // 珠三角城市密集：离欠费标记太近的城市名不画，避免和金额标签叠在一起
      const pins = data.prov.map((r) => P(r.lon, r.lat)).concat([P(PROV.home[1], PROV.home[2])]);
      for (const [n, lon, lat] of PROV.cities) {
        if (owed.has(n)) continue;
        const [x, y] = P(lon, lat);
        if (pins.some(([px, py]) => Math.hypot(px - x, py - y) < 36)) continue; s += `<circle class="city" cx="${x}" cy="${y}" r="2.5"/><text class="place" x="${x}" y="${y - 6}">${n}</text>`;
      }
      const max = Math.max(data.cityTotal, ...data.prov.map((r) => r.amount));
      for (const r of data.prov) { const [x, y] = P(r.lon, r.lat); s += pin(x, y, r.amount, `${r.name} · ${r.count} 笔`, max); }
      const [hx, hy] = P(PROV.home[1], PROV.home[2]);
      s += `<g class="pin here">${pin(hx, hy, data.cityTotal, `深圳（本市）· ${data.cityCount} 笔`, max)}</g>`;
    }
    return s + '</svg>';
  }
  function listHTML(data, scope) {
    const rows = scope === 'city'
      ? data.city.map((r) => `<tr><td>${esc(r.name)}</td><td>${r.date}</td><td>${r.hours} 小时</td><td class="num">¥${r.amount}</td></tr>`)
      : [`<tr><td>深圳（本市）</td><td>${data.cityCount} 笔</td><td>—</td><td class="num">¥${data.cityTotal}</td></tr>`]
        .concat(data.prov.map((r) => `<tr><td>${esc(r.name)}</td><td>${r.count} 笔</td><td>最近 ${r.date}</td><td class="num">¥${r.amount}</td></tr>`));
    const head = scope === 'city' ? '<th>停车场</th><th>日期</th><th>停车时长</th><th class="num">欠费</th>' : '<th>城市</th><th>笔数</th><th>备注</th><th class="num">欠费</th>';
    return `<table class="owe-table"><thead><tr>${head}</tr></thead><tbody>${rows.join('')}</tbody></table>`;
  }
  PT.arrears = { generate, mapSVG, listHTML, cityName: CITY.name, provName: PROV.name };
})();
