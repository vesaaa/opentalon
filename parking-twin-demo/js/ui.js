/* 界面层：控制台、统计、告警横幅、闸机详情与异常处置、主循环 */
(function () {
  'use strict';
  const PT = window.PT, sim = PT.sim, T = THREE;
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"]/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[m]));
  const fmtDur = (min) => (min >= 60 ? `${Math.floor(min / 60)} 小时 ${min % 60} 分` : `${min} 分钟`);
  const fmtClock = (ms) => { const s = Math.floor(ms / 1000); return `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`; };

  let speed = 1, paused = false, selected = null, panelSig = '', alertSig = '';

  PT.initScene($('view'));
  sim.init();

  /* ---------- 日志 ---------- */
  const logEl = $('logList');
  sim.onLog = function (msg, kind) {
    const li = document.createElement('li');
    li.className = kind;
    const d = new Date();
    li.innerHTML = `<time>${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}</time>${esc(msg)}`;
    logEl.prepend(li);
    while (logEl.children.length > 30) logEl.lastChild.remove();
  };
  function toast(msg) {
    const t = $('toast');
    t.textContent = msg; t.classList.add('show');
    clearTimeout(toast.tm); toast.tm = setTimeout(() => t.classList.remove('show'), 2600);
  }

  /* ---------- 视角 ---------- */
  function setSeg(key, val) {
    document.querySelectorAll(`.seg[data-key="${key}"] button`).forEach((b) => b.classList.toggle('on', b.dataset.val === val));
  }
  function setFloor(m, move) {
    PT.setFloorMode(m); setSeg('floor', m);
    if (!move) return;
    if (m === 'b1' || m === 'b2') PT.focus({ target: new T.Vector3(0, m === 'b1' ? -5 : -10, 0), r: 135, phi: 0.6 });
    else PT.focus(PT.HOME);
  }
  function focusGate(id) {
    const g = sim.gates[id];
    if (PT.getFloorMode() !== 'all' && PT.getFloorMode() !== 'ground') setFloor('all', false);
    PT.focus({ target: new T.Vector3(g.x, 1, g.stop.z), r: 48, phi: 0.78, theta: -0.55 }, 1.2);
    openPanel(id);
  }

  /* ---------- 控制台 ---------- */
  document.querySelectorAll('.seg').forEach((seg) => seg.addEventListener('click', (e) => {
    const b = e.target.closest('button');
    if (!b) return;
    const key = seg.dataset.key, val = b.dataset.val;
    setSeg(key, val);
    if (key === 'time') PT.env.night = val === 'night';
    else if (key === 'weather') PT.env.weather = val;
    else if (key === 'floor') setFloor(val, true);
    else if (key === 'speed') { paused = val === '0'; if (!paused) speed = +val; }
  }));
  $('resetView').addEventListener('click', () => setFloor('all', true));
  $('ctrlToggle').addEventListener('click', () => {
    const open = $('ctrl').classList.toggle('open');
    $('ctrlToggle').setAttribute('aria-expanded', open);
  });
  $('trigDispute').addEventListener('click', () => toast(sim.trigger('dispute', $('trigGate').value)));
  $('trigStuck').addEventListener('click', () => toast(sim.trigger('stuck', $('trigGate').value)));
  $('autoOn').addEventListener('change', (e) => { sim.auto = e.target.checked; });
  $('autoProb').addEventListener('input', (e) => { sim.autoProb = e.target.value / 100; $('autoProbOut').textContent = e.target.value + '%'; });

  /* ---------- 告警 ---------- */
  sim.onAlert = () => renderAlerts(true);
  function renderAlerts(force) {
    const list = sim.activeAnomalies();
    const sig = list.map((g) => g.id + g.anomaly.type + g.anomaly.car.id).join(',');
    const box = $('alerts');
    if (force || sig !== alertSig) {
      alertSig = sig;
      box.innerHTML = list.map((g) => `<button class="alert" data-gate="${g.id}">
        <span class="alert-ico" aria-hidden="true">!</span>
        <span class="alert-txt"><b>${esc(g.name)} · ${esc(sim.ANOMALY[g.anomaly.type].name)}</b>
        <small>${esc(g.anomaly.car.plate)} · 已阻塞 <i data-t></i> · 排队 <i data-q></i> 辆</small></span>
        <span class="alert-go">定位处理</span></button>`).join('');
    }
    list.forEach((g, i) => {
      const el = box.children[i];
      if (!el) return;
      el.querySelector('[data-t]').textContent = fmtClock(performance.now() - g.anomaly.since);
      el.querySelector('[data-q]').textContent = sim.queueLen(g);
    });
  }
  $('alerts').addEventListener('click', (e) => {
    const b = e.target.closest('.alert');
    if (b) focusGate(b.dataset.gate);
  });

  /* ---------- 闸机详情 ---------- */
  PT.onPick = (id) => { if (id) openPanel(id); };
  function openPanel(id) { selected = id; panelSig = ''; $('panel').hidden = false; renderPanel(); }
  function closePanel() { selected = null; $('panel').hidden = true; }
  const PHASE = { idle: ['空闲', 'idle'], reading: ['识别车牌', 'busy'], paying: ['等待支付', 'busy'], repaying: ['重新缴费', 'busy'], blocked: ['异常阻塞', 'alarm'], open: ['放行中', 'ok'] };

  function renderPanel() {
    if (!selected) return;
    const g = sim.gates[selected], c = g.current, a = g.anomaly, q = sim.queueLen(g);
    const sig = [g.id, g.phase, c && c.id, a && a.type, q, g.stat.count, g.stat.income, c && c.fee, c && c.paid, g.pending].join('|');
    const el = $('panel');
    if (sig !== panelSig) {
      panelSig = sig;
      const old = el.querySelector('#fixAmount'), keep = old ? { v: old.value, f: document.activeElement === old } : null;
      const [pName, pTone] = PHASE[g.phase];
      let h = `<header><div><h2>${esc(g.name)}</h2><span class="chip ${pTone}">${pName}</span></div>
        <button class="x" data-act="close" aria-label="关闭">×</button></header>`;
      if (c) {
        const temp = c.type === 'temp';
        h += `<dl><dt>车牌</dt><dd class="plate">${esc(c.plate)}</dd>
          <dt>类型</dt><dd><span class="tag ${c.type}">${temp ? '临时车' : '月卡车'}</span></dd>`;
        if (g.kind === 'out') {
          h += `<dt>停车时长</dt><dd id="pDur"></dd>`;
          if (temp) h += `<dt>应付金额</dt><dd class="fee">¥${c.fee}</dd><dt>支付状态</dt><dd>${c.paid ? '已支付' : g.phase === 'reading' ? '计费中' : '未支付'}</dd>`;
          else h += `<dt>应付金额</dt><dd>月卡免费</dd>`;
        }
        h += `<dt>后方排队</dt><dd>${q} 辆</dd></dl>`;
      } else {
        h += `<p class="empty">当前无车辆通过。${g.last ? `<br>最近通行：${esc(g.last)}` : ''}</p>`;
      }
      if (g.pending) h += `<p class="note">已预置：下一辆临时车触发「${sim.ANOMALY[g.pending].name}」</p>`;
      if (a && c) {
        h += `<div class="anomaly"><h3>${esc(sim.ANOMALY[a.type].name)}</h3><p>${esc(sim.ANOMALY[a.type].desc(c))}</p>
          <button class="btn danger" data-act="release">直接开闸放行</button>
          <div class="fix"><label for="fixAmount">修改支付金额（元）</label>
          <div class="fix-row"><input id="fixAmount" type="number" min="0" max="999" step="1" inputmode="numeric" value="${Math.max(0, c.fee - 5)}">
          <button class="btn primary" data-act="adjust">确认并重新缴费</button></div></div></div>`;
      }
      h += `<footer>今日通行 <b>${g.stat.count}</b> 辆${g.kind === 'out' ? ` · 收费 <b>¥${g.stat.income}</b>` : ''}</footer>`;
      el.innerHTML = h;
      const inp = el.querySelector('#fixAmount');
      if (inp && keep) { inp.value = keep.v; if (keep.f) inp.focus(); }
    }
    const d = el.querySelector('#pDur');
    if (d && c) d.textContent = fmtDur(sim.parkMinutes(c));
  }
  $('panel').addEventListener('click', (e) => {
    const b = e.target.closest('[data-act]');
    if (!b || !selected) return;
    if (b.dataset.act === 'close') closePanel();
    else if (b.dataset.act === 'release') sim.release(selected);
    else if (b.dataset.act === 'adjust') {
      const v = parseFloat($('fixAmount').value);
      if (isNaN(v) || v < 0) { toast('请输入不小于 0 的金额'); return; }
      sim.adjust(selected, v);
    }
    panelSig = ''; renderPanel(); renderAlerts(true);
  });

  /* ---------- 统计 ---------- */
  function renderStats() {
    $('sCars').textContent = sim.cars.length;
    $('sB1').textContent = sim.freeSlots(1);
    $('sB2').textContent = sim.freeSlots(2);
    $('sIncome').textContent = '¥' + sim.income;
    const n = sim.activeAnomalies().length;
    $('sAlarm').textContent = n;
    $('sAlarm').parentElement.classList.toggle('hot', n > 0);
  }

  /* ---------- 主循环 ---------- */
  let last = performance.now(), uiT = 0;
  function frame(now) {
    const rdt = Math.min(0.1, (now - last) / 1000);
    last = now;
    if (!paused) {
      const sdt = rdt * speed, n = Math.max(1, Math.ceil(sdt / 0.04));
      for (let i = 0; i < n; i++) sim.step(sdt / n);
    }
    sim.sync(rdt, now);
    PT.updateScene(rdt);
    if ((uiT += rdt) > 0.25) { uiT = 0; renderStats(); renderAlerts(false); renderPanel(); }
    requestAnimationFrame(frame);
  }
  sim.onLog('系统启动：2 进 2 出，B1 / B2 共 128 个车位');
  renderStats();
  requestAnimationFrame(frame);
})();
