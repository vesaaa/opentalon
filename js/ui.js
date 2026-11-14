/* 界面层：控制台、统计、告警横幅、闸机详情与异常处置、主循环 */
(function () {
  'use strict';
  const PT = window.PT, sim = PT.sim, T = THREE;
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s).replace(/[&<>"]/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[m]));
  const fmtDur = (min) => (min >= 60 ? `${Math.floor(min / 60)} 小时 ${min % 60} 分` : `${min} 分钟`);
  const fmtClock = (ms) => { const s = Math.floor(ms / 1000); return `${String(Math.floor(s / 60)).padStart(2, '0')}:${String(s % 60).padStart(2, '0')}`; };

  let speed = 1, paused = false, selected = null, selCar = null, modal = null, panelSig = '', alertSig = '';

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

  /* ---------- 画质：记住上次选择；首次按显卡自动判断，帧率太低自动降回标准 ---------- */
  let fpsWatch = null;
  const Q_NAME = ['流畅', '标准', '高'];
  function setQuality(level) { PT.setQuality(level); setSeg('quality', String(level)); }
  (function () {
    let saved = null;
    try { saved = localStorage.getItem('pt-quality'); } catch (err) { /* 忽略 */ }
    if (saved === '0' || saved === '1' || saved === '2') setQuality(+saved);
    else { setQuality(PT.autoQuality()); fpsWatch = { t: 0, n: 0 }; }
  })();

  /* ---------- 控制台 ---------- */
  document.querySelectorAll('.seg').forEach((seg) => seg.addEventListener('click', (e) => {
    const b = e.target.closest('button');
    if (!b) return;
    const key = seg.dataset.key, val = b.dataset.val;
    if (key === 'see') {
      if (val === 'all') ['ground', 'b1', 'b2'].forEach((l) => PT.setSee(l, true));
      else PT.setSee(val, !PT.getSee()[val]);
      const st = PT.getSee();
      seg.querySelectorAll('button').forEach((x) => {
        const on = x.dataset.val === 'all' ? st.ground && st.b1 && st.b2 : st[x.dataset.val];
        x.classList.toggle('on', on); x.setAttribute('aria-pressed', on);
      });
      return;
    }
    setSeg(key, val);
    if (key === 'time') PT.env.night = val === 'night';
    else if (key === 'weather') PT.env.weather = val;
    else if (key === 'floor') setFloor(val, true);
    else if (key === 'quality') { setQuality(+val); fpsWatch = null; try { localStorage.setItem('pt-quality', val); } catch (err) { /* 存不了就算了 */ } }
    else if (key === 'speed') { paused = val === '0'; if (!paused) speed = +val; }
  }));
  $('resetView').addEventListener('click', () => setFloor('all', true));
  $('ctrlToggle').addEventListener('click', () => {
    const open = $('ctrl').classList.toggle('open');
    $('ctrlToggle').setAttribute('aria-expanded', open);
  });
  $('trigDispute').addEventListener('click', () => toast(sim.trigger('dispute', $('trigGate').value)));
  $('trigArrears').addEventListener('click', () => toast(sim.trigger('arrears', $('trigGate').value)));
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
    if (!b) return;
    focusGate(b.dataset.gate);
    const g = sim.gates[b.dataset.gate];
    if (g.anomaly && g.anomaly.type === 'arrears') openModal(g.id, 'sum');
  });

  /* ---------- 闸机详情 ---------- */
  PT.onPick = (id, car) => {
    // 正停在闸机前的车归闸机面板显示，其余车辆显示车辆信息
    if (car && !(car.gate && car.gate.current === car)) openCar(car);
    else if (id) openPanel(id);
    else if (car) openPanel(car.gate.id);
  };
  function openPanel(id) { selected = id; selCar = sim.selCar = null; panelSig = ''; $('panel').hidden = false; renderPanel(); }
  function openCar(c) { selCar = sim.selCar = c; selected = null; $('panel').hidden = false; renderPanel(); }
  function closePanel() { selected = null; selCar = sim.selCar = null; $('panel').hidden = true; }

  /* ---------- 车辆信息（点击车辆） ---------- */
  const CAR_STATE = { arriving: '入场中', parked: '已停放', backing: '倒车出库', leaving: '离场中' };
  function renderCarPanel() {
    const c = selCar;
    if (c.dead) { closePanel(); return; }
    const temp = c.type === 'temp', ci = sim.chargeInfo(c), s = c.slot;
    let st = CAR_STATE[c.state];
    if (c.state === 'arriving' && c.entered) st = '前往车位';
    if (c.state === 'leaving' && c.gate) st = c.chain > 0 ? '出口排队' : '前往出口';
    let h = `<header><div><h2>车辆信息</h2><span class="chip idle">${st}</span></div><button class="x" data-act="close" aria-label="关闭">×</button></header>
      <dl><dt>车牌</dt><dd class="plate">${esc(c.plate)}</dd>
      <dt>类型</dt><dd><span class="tag ${c.type}">${temp ? '临时车' : '月卡车'}</span></dd>
      <dt>车位</dt><dd>${esc(s.name)}${s.charger ? ' · 充电车位' : ''}</dd>
      <dt>停车时长</dt><dd>${c.entered ? fmtDur(sim.parkMinutes(c)) : '尚未入场'}</dd>
      <dt>${temp ? '当前计费' : '费用'}</dt><dd>${temp ? (c.paid ? `已缴 ¥${c.fee}` : c.entered ? `¥${sim.feeNow(c)}` : '—') : '月卡免费'}</dd></dl>`;
    if (ci) {
      const stTxt = ci.ended ? '已结束' : ci.full ? '已充满' : '充电中';
      h += `<div class="charge"><h3>充电信息 <span class="chip ${ci.active ? 'busy' : 'ok'}">${stTxt}</span></h3>
        <div class="soc" role="img" aria-label="当前电量 ${ci.soc}%"><i style="width:${ci.soc}%"></i><b>${ci.soc}%</b></div>
        <dl><dt>充电桩</dt><dd>CP-${esc(s.name)}</dd>
        <dt>功率</dt><dd>${ci.kw} kW · ${ci.kw >= 30 ? '直流快充' : '交流慢充'}</dd>
        <dt>起始电量</dt><dd>${ci.soc0}%</dd>
        <dt>已充电量</dt><dd>${ci.kwh} kWh</dd>
        <dt>充电时长</dt><dd>${fmtDur(ci.minutes)}</dd>
        <dt>充电费</dt><dd>¥${ci.fee}（¥1.2/kWh）</dd></dl></div>`;
    } else {
      h += `<p class="empty">${s.charger ? '该车位有充电桩，本车未充电。' : '该车位没有充电桩。'}</p>`;
    }
    $('panel').innerHTML = h;
  }

  /* ---------- 欠费追缴弹窗：汇总 → 详情地图（本市 / 本省） ---------- */
  function openModal(gateId, view, scope) { modal = { gateId, view, scope: scope || 'city' }; renderModal(); }
  function closeModal() { modal = null; $('modal').hidden = true; }
  function renderModal() {
    const g = sim.gates[modal.gateId], c = g.current, A = PT.arrears;
    if (!g.anomaly || g.anomaly.type !== 'arrears' || !c || !c.arrears) { closeModal(); return; }
    const d = c.arrears;
    let h;
    if (modal.view === 'sum') {
      h = `<header><h2>欠费追缴 · ${esc(g.name)}</h2><button class="x" data-m="close" aria-label="关闭">×</button></header>
        <p class="owe-plate">${esc(c.plate)}</p>
        <div class="owe-total"><span>联盟停车场欠费合计</span><b>¥${d.total}</b><small>共 ${d.count} 笔</small></div>
        <div class="owe-split">
          <div><span>本市（${A.cityName}）</span><b>¥${d.cityTotal}</b><small>${d.cityCount} 笔 · ${d.city.length} 个停车场</small></div>
          <div><span>省内其他城市</span><b>¥${d.provTotal}</b><small>${d.provCount} 笔 · ${d.prov.length} 个城市</small></div>
        </div>
        <p class="owe-note">本次停车费 ¥${c.fee} 尚未缴纳。追缴后应收合计 ¥${c.fee + d.total}。</p>
        <div class="modal-actions"><button class="btn" data-m="map">详情</button>
          <button class="btn primary" data-m="recover">追缴 ¥${c.fee + d.total} 并放行</button>
          <button class="btn danger" data-m="release">直接开闸放行</button></div>`;
    } else {
      const city = modal.scope === 'city';
      h = `<header><h2>${esc(c.plate)} 欠费分布</h2><button class="x" data-m="close" aria-label="关闭">×</button></header>
        <div class="map-bar"><button class="btn" data-m="back">‹ 返回汇总</button>
          <div class="seg"><button data-m="city" class="${city ? 'on' : ''}">本市（${A.cityName}）</button><button data-m="prov" class="${city ? '' : 'on'}">本省（${A.provName}）</button></div>
          <span class="map-sum">${city ? `本市欠费 ¥${d.cityTotal}` : `全省欠费 ¥${d.total}`}</span></div>
        <div class="map-wrap">${A.mapSVG(d, modal.scope)}</div>
        <div class="table-wrap">${A.listHTML(d, modal.scope)}</div>
        <p class="owe-note">示意图，位置为近似；欠费数据为演示用随机生成。</p>`;
    }
    $('modalCard').innerHTML = h;
    $('modalCard').classList.toggle('wide', modal.view === 'map');
    $('modal').hidden = false;
  }
  $('modal').addEventListener('click', (e) => {
    if (e.target === $('modal')) { closeModal(); return; }
    const b = e.target.closest('[data-m]');
    if (!b || !modal) return;
    const m = b.dataset.m, id = modal.gateId;
    if (m === 'close') closeModal();
    else if (m === 'map') openModal(id, 'map', 'city');
    else if (m === 'back') openModal(id, 'sum');
    else if (m === 'city' || m === 'prov') openModal(id, 'map', m);
    else if (m === 'recover' || m === 'release') {
      if (m === 'recover') sim.recover(id); else sim.release(id);
      closeModal(); panelSig = ''; renderPanel(); renderAlerts(true);
    }
  });
  const PHASE = { idle: ['空闲', 'idle'], reading: ['识别车牌', 'busy'], paying: ['等待支付', 'busy'], repaying: ['重新缴费', 'busy'], blocked: ['异常阻塞', 'alarm'], open: ['放行中', 'ok'] };

  function renderPanel() {
    if (selCar) { renderCarPanel(); return; }
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
      if (a && c && a.type === 'arrears') {
        h += `<div class="anomaly"><h3>欠费追缴</h3><p>${esc(sim.ANOMALY.arrears.desc(c))}</p>
          <button class="btn" data-act="owe">查看欠费详情</button>
          <button class="btn primary" data-act="recover">追缴 ¥${c.fee + c.arrears.total} 并放行</button>
          <button class="btn danger" data-act="release">直接开闸放行</button></div>`;
      } else if (a && c) {
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
    if (!b) return;
    if (b.dataset.act === 'close') { closePanel(); return; }
    if (!selected) return;
    if (b.dataset.act === 'owe') { openModal(selected, 'sum'); return; }
    if (b.dataset.act === 'recover') sim.recover(selected);
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
    if (fpsWatch) {
      fpsWatch.t += rdt; fpsWatch.n++;
      if (fpsWatch.t > 5) {
        const lv = PT.getQuality();
        if (fpsWatch.n / fpsWatch.t < 20 && lv > 0) {
          setQuality(lv - 1); toast(`帧率偏低，已自动降为「${Q_NAME[lv - 1]}」画质`);
          fpsWatch = { t: -3, n: 0 };   // 留 3 秒让新档位稳定后再测
        } else fpsWatch = null;
      }
    }
    sim.sync(rdt, now);
    PT.updateScene(rdt);
    if ((uiT += rdt) > 0.25) { uiT = 0; renderStats(); renderAlerts(false); renderPanel(); if (modal && !(sim.gates[modal.gateId].anomaly)) closeModal(); }
    requestAnimationFrame(frame);
  }
  sim.onLog('系统启动：东侧 3 进、西侧 3 出，B1 / B2 共 128 个车位');
  renderStats();
  requestAnimationFrame(frame);
})();
