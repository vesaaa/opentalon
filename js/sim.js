/* 仿真层：行车路线、车辆状态机、闸机收费流程、异常场景 */
(function () {
  'use strict';
  const T = THREE, PT = window.PT, C = PT.C;
  const V = (x, y, z) => new T.Vector3(x, y, z);
  const rand = (a, b) => a + Math.random() * (b - a);
  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));

  const MIN_PER_SEC = 2;      // 仿真 1 秒 = 停车 2 分钟
  const GAP = 5.5;            // 跟车最小中心距
  const ANOMALY = {
    dispute: { name: '费用争议', desc: (c) => `车主对 ¥${c.fee} 的停车费有疑问，拒绝支付，车辆停在出口。` },
    arrears: { name: '欠费追缴', desc: (c) => `系统检测到该车在联盟停车场有 ${c.arrears.count} 笔欠费，合计 ¥${c.arrears.total}，已拦截出场。` },
    stuck: { name: '已缴费未抬杆', desc: (c) => `车主已支付 ¥${c.fee}，但道闸未收到放行指令，车辆无法出场。` },
  };

  const sim = (PT.sim = {
    t: 0, cars: [], gates: {}, income: 0, auto: false, autoProb: 0.15,
    count: { in: 0, out: 0, anomalies: 0 }, onLog: null, onAlert: null, ANOMALY,
  });
  const log = (msg, kind) => sim.onLog && sim.onLog(msg, kind || 'info');

  /* ---------- 路径 ---------- */
  function roundPath(pts, r) {
    const out = [pts[0].clone()];
    for (let i = 1; i < pts.length - 1; i++) {
      const A = pts[i - 1], B = pts[i], Cc = pts[i + 1];
      const ab = A.clone().sub(B), cb = Cc.clone().sub(B);
      const la = ab.length(), lc = cb.length();
      if (la < 1e-3 || lc < 1e-3) continue;
      ab.divideScalar(la); cb.divideScalar(lc);
      if (ab.dot(cb) < -0.9985) { out.push(B.clone()); continue; }
      const t = Math.min(r, la / 2, lc / 2);
      const P1 = B.clone().addScaledVector(ab, t), P2 = B.clone().addScaledVector(cb, t);
      for (let k = 0; k <= 6; k++) {
        const u = k / 6, a = (1 - u) * (1 - u), b = 2 * u * (1 - u), c = u * u;
        out.push(V(a * P1.x + b * B.x + c * P2.x, a * P1.y + b * B.y + c * P2.y, a * P1.z + b * B.z + c * P2.z));
      }
    }
    out.push(pts[pts.length - 1].clone());
    return out;
  }
  function Path(raw) {
    this.pts = roundPath(raw, 2.6);
    this.cum = [0];
    for (let i = 1; i < this.pts.length; i++) this.cum.push(this.cum[i - 1] + this.pts[i].distanceTo(this.pts[i - 1]));
    this.len = this.cum[this.cum.length - 1];
  }
  Path.prototype.at = function (s, pos, tan) {
    const cum = this.cum, n = cum.length;
    s = clamp(s, 0, this.len);
    let lo = 0, hi = n - 1;
    while (hi - lo > 1) { const m = (lo + hi) >> 1; if (cum[m] <= s) lo = m; else hi = m; }
    const a = this.pts[lo], b = this.pts[hi], seg = cum[hi] - cum[lo] || 1;
    pos.lerpVectors(a, b, (s - cum[lo]) / seg);
    if (tan) tan.subVectors(b, a).normalize();
  };
  Path.prototype.locate = function (p) {
    let best = 1e9, bs = 0;
    const ab = V(0, 0, 0), ap = V(0, 0, 0);
    for (let i = 0; i < this.pts.length - 1; i++) {
      const a = this.pts[i];
      ab.subVectors(this.pts[i + 1], a); ap.subVectors(p, a);
      const l2 = ab.lengthSq() || 1, u = clamp(ap.dot(ab) / l2, 0, 1);
      const d = ap.addScaledVector(ab, -u).lengthSq();
      if (d < best) { best = d; bs = this.cum[i] + u * Math.sqrt(l2); }
    }
    return bs;
  };

  // 车库内是一条不交叉的单向蛇形路线：从北侧入库坡道底（东）出发，绕遍东、西两个半区的全部过道，
  // 回到北侧出库坡道底（西）。B2 的车在 B1 中途经东侧坡道下行，绕完 B2 后经西侧坡道回到 B1。
  function loop(level) {
    const a = C.Y1, b = C.Y2;
    if (level === 1) return [V(10, a, -36), V(4, a, -36), V(4, a, -20), V(36, a, -20), V(36, a, 4), V(-36, a, 4), V(-36, a, -20), V(-4, a, -20), V(-4, a, -36), V(-10, a, -36)];
    return [V(10, a, -36), V(4, a, -36), V(4, a, -8), V(8, a, -8), V(26, b, -8), V(36, b, -8), V(36, b, -20), V(4, b, -20), V(4, b, 4), V(36, b, 4),
      V(36, b, 16), V(-36, b, 16), V(-36, b, 4), V(-4, b, 4), V(-4, b, -20), V(-36, b, -20), V(-36, b, -8), V(-26, b, -8), V(-8, a, -8), V(-4, a, -8),
      V(-4, a, -36), V(-10, a, -36)];
  }
  // 地面：入口（楼前右侧）→ 进闸后右转东行 → 沿楼东侧北行 → 北侧西行 → 入库坡道；出库后北侧西行 → 沿楼西侧南行 → 西侧出口
  const surfaceIn = (x) => [V(112, 0, C.ROAD_Z), V(x, 0, C.ROAD_Z), V(x, 0, 38), V(C.RING, 0, 38), V(C.RING, 0, C.NORTH), V(28, 0, C.NORTH)];
  const SPLIT = V(-C.RING, 0, 4);   // 西侧分道口：到这里再选出口车道
  const surfaceOut = [V(-28, 0, C.NORTH), V(-C.RING, 0, C.NORTH), SPLIT];
  const lanes = {};
  const lanePath = (g) => lanes[g.id] || (lanes[g.id] = new Path([SPLIT, V(g.x, 0, 12), V(g.x, 0, C.ROAD_Z), V(-125, 0, C.ROAD_Z)]));
  function slotPaths(slot) {
    if (slot._p) return slot._p;
    const raw = loop(slot.level);
    const ap = V(slot.x, slot.y, slot.aisleZ), sc = V(slot.x, slot.y, slot.z);
    let idx = -1;
    for (let i = 0; i < raw.length - 1; i++) {
      const a = raw[i], b = raw[i + 1];
      if (Math.abs(a.y - slot.y) > 0.01 || Math.abs(b.y - slot.y) > 0.01) continue;
      if (Math.abs(a.distanceTo(ap) + ap.distanceTo(b) - a.distanceTo(b)) < 0.01) { idx = i; break; }
    }
    const u = raw[idx + 1].clone().sub(raw[idx]).normalize();
    const back = ap.clone().addScaledVector(u, -4.5);
    const pre = raw.slice(0, idx + 1).concat([ap, sc]), post = [back].concat(raw.slice(idx + 1));
    const ins = {}, outs = {};
    return (slot._p = {
      u,
      back: new Path([sc, ap, back]),
      entry: (g) => ins[g.id] || (ins[g.id] = new Path(surfaceIn(g.x).concat(pre))),
      exit: () => outs.p || (outs.p = new Path(post.concat(surfaceOut))),
    });
  }
  // 选车道：挑当前车最少的闸口；有预置异常的出口优先让临时车去
  function pickGate(kind, car) {
    const list = Object.values(sim.gates).filter((g) => g.kind === kind);
    if (kind === 'out' && car.type === 'temp') { const p = list.find((g) => g.pending && !g.anomaly); if (p) return p; }
    let best = null, bn = 1e9;
    for (const g of list) {
      const n = sim.cars.filter((c) => c.gate === g).length + Math.random() * 0.5;
      if (n < bn) { bn = n; best = g; }
    }
    return best;
  }

  /* ---------- 闸机 ---------- */
  function makeGate(id, name, kind, x, booth) {
    const g = {
      id, name, kind, x, booth, z: kind === 'in' ? C.IN_Z : C.GATE_Z,
      current: null, phase: 'idle', timer: 0, openAmt: 0, wantOpen: false,
      anomaly: null, pending: null, stat: { count: 0, income: 0 }, last: null, line2: '', line3: '', tone: 'idle',
    };
    g.stop = V(g.x, 0, kind === 'in' ? g.z + 3.6 : g.z - 3.6);
    g.vis = PT.buildGate(g);
    sim.gates[id] = g;
    board(g, '— —', '空闲', 'idle');
    return g;
  }
  const TONE = { idle: '#4cc9ff', busy: '#ffb23e', ok: '#3ddc97', alarm: '#ff4d5e' };
  function board(g, l2, l3, tone) {
    g.line2 = l2; g.line3 = l3; g.tone = tone;
    const b = g.vis.board, x = b.ctx, col = TONE[tone];
    x.clearRect(0, 0, 320, 160);
    x.fillStyle = tone === 'alarm' ? 'rgba(60,6,14,.96)' : 'rgba(5,14,28,.95)';
    x.strokeStyle = col; x.lineWidth = 5;
    x.beginPath(); x.roundRect(4, 4, 312, 152, 16); x.fill(); x.stroke();
    x.textAlign = 'center'; x.textBaseline = 'middle';
    x.fillStyle = col; x.font = '600 26px ' + PT.FONT; x.fillText(g.name, 160, 30);
    x.fillStyle = '#ffffff'; x.font = '700 40px ' + PT.FONT; x.fillText(l2, 160, 80);
    x.fillStyle = col; x.font = '600 30px ' + PT.FONT; x.fillText(l3, 160, 128);
    b.tex.needsUpdate = true;
  }
  function openGate(g, l3) {
    g.wantOpen = true; g.phase = 'open';
    board(g, g.current.plate, l3, 'ok');
  }
  function calcFee(c) {
    const min = (sim.t - c.enterT) * MIN_PER_SEC;
    if (min <= 15) return 0;
    return Math.min(50, 10 + 5 * Math.ceil(Math.max(0, min - 60) / 60));
  }
  sim.parkMinutes = (c) => Math.max(0, Math.round((sim.t - c.enterT) * MIN_PER_SEC));
  const activeAnomalies = () => Object.values(sim.gates).filter((g) => g.anomaly);
  sim.activeAnomalies = activeAnomalies;
  sim.queueLen = (g) => sim.cars.filter((c) => c.gate === g && c !== g.current && c.chain > 0).length;

  function gateArrive(c) {
    const g = c.gate;
    if (g.current || g.phase !== 'idle') return;
    g.current = c; g.phase = 'reading'; g.timer = 0.7;
    board(g, c.plate, '车牌识别中', 'busy');
  }
  function block(g, type) {
    const c = g.current;
    g.phase = 'blocked';
    g.anomaly = { type, since: performance.now(), car: c };
    c.mesh.userData.body.material = PT.alarmMat;
    g.vis.alarm.visible = true;
    sim.count.anomalies++;
    board(g, c.plate, ANOMALY[type].name, 'alarm');
    log(`${g.name} ${c.plate} ${ANOMALY[type].name}，出口被堵`, 'alarm');
    if (sim.onAlert) sim.onAlert(g);
  }
  function clearAnomaly(g) {
    const c = g.current;
    if (c) c.mesh.userData.body.material = c.mesh.userData.baseMat;
    g.anomaly = null; g.vis.alarm.visible = false;
  }
  function addIncome(g, v) { sim.income += v; g.stat.income += v; }

  function updateGate(g, dt) {
    g.openAmt = clamp(g.openAmt + (g.wantOpen ? dt : -dt) / 0.55, 0, 1);
    const c = g.current;
    if (!c) return;
    if (g.phase === 'reading') {
      if ((g.timer -= dt) > 0) return;
      const label = c.type === 'monthly' ? '月卡车' : '临时车';
      if (g.kind === 'in') {
        c.enterT = sim.t; c.entered = true; sim.count.in++; g.stat.count++;
        g.last = `${c.plate} · ${label}`;
        openGate(g, `${label} · 欢迎入场`);
      } else if (c.type === 'monthly') {
        g.last = `${c.plate} · 月卡车`;
        openGate(g, '月卡车 · 一路平安');
      } else {
        c.fee = calcFee(c);
        let plan = g.pending;
        g.pending = null;
        if (!plan && sim.auto && !activeAnomalies().length && Math.random() < sim.autoProb) plan = ['dispute', 'stuck', 'arrears'][(Math.random() * 3) | 0];
        c.plan = plan;
        g.phase = 'paying'; g.timer = plan === 'dispute' || plan === 'arrears' ? 1.1 : rand(2, 3.4);
        board(g, c.plate, `¥${c.fee} 待支付`, 'busy');
      }
    } else if (g.phase === 'paying') {
      if ((g.timer -= dt) > 0) return;
      if (c.plan === 'dispute') { c.plan = null; block(g, 'dispute'); return; }
      if (c.plan === 'arrears') { c.plan = null; c.arrears = PT.arrears.generate(); block(g, 'arrears'); return; }
      c.paid = true; addIncome(g, c.fee);
      if (c.plan === 'stuck') { c.plan = null; block(g, 'stuck'); return; }
      g.last = `${c.plate} · 临时车 ¥${c.fee}`;
      log(`${g.name} ${c.plate} 缴费 ¥${c.fee} 出场`);
      openGate(g, `已缴 ¥${c.fee} · 一路平安`);
    } else if (g.phase === 'repaying') {
      if ((g.timer -= dt) > 0) return;
      if (!c.paid) { c.paid = true; addIncome(g, c.fee); }
      g.last = `${c.plate} · 临时车 ¥${c.fee}（${c.arrears && c.arrears.paid ? '含追缴' : '改价'}）`;
      log(`${g.name} ${c.plate} 按 ¥${c.fee} 缴费成功，自动放行`, 'ok');
      openGate(g, `已缴 ¥${c.fee} · 一路平安`);
    }
  }
  function gatePassed(c) {
    const g = c.gate;
    if (g.kind === 'out') { sim.count.out++; g.stat.count++; }
    g.wantOpen = false; g.current = null; g.phase = 'idle';
    board(g, '— —', '空闲', 'idle');
    c.stopS = null; c.gate = null;
  }

  /* ---------- 异常处置（界面调用） ---------- */
  sim.release = function (id) {
    const g = sim.gates[id], c = g.current;
    if (!g.anomaly || !c) return;
    log(`${g.name} ${c.plate} 人工开闸放行${c.paid ? '' : `（免收 ¥${c.fee}）`}`, 'ok');
    g.last = `${c.plate} · 临时车 人工放行`;
    clearAnomaly(g);
    openGate(g, '人工放行');
  };
  sim.adjust = function (id, amount) {
    const g = sim.gates[id], c = g.current;
    if (!g.anomaly || !c) return;
    amount = Math.max(0, Math.round(amount));
    log(`${g.name} ${c.plate} 金额由 ¥${c.fee} 改为 ¥${amount}，重新发起缴费`, 'ok');
    if (c.paid) addIncome(g, amount - c.fee);
    c.fee = amount;
    clearAnomaly(g);
    g.phase = 'repaying'; g.timer = 2;
    board(g, c.plate, `¥${amount} 重新缴费`, 'busy');
  };
  // 欠费追缴：把联盟停车场欠费连同本次停车费一并收取后放行
  sim.recover = function (id) {
    const g = sim.gates[id], c = g.current;
    if (!g.anomaly || !c || !c.arrears) return;
    log(`${g.name} ${c.plate} 追缴欠费 ¥${c.arrears.total}，连同本次 ¥${c.fee} 一并缴纳`, 'ok');
    c.fee += c.arrears.total; c.arrears.paid = true;
    clearAnomaly(g);
    g.phase = 'repaying'; g.timer = 2.2;
    board(g, c.plate, `¥${c.fee} 追缴中`, 'busy');
  };
  sim.trigger = function (type, target) {
    let outs = [sim.gates.O1, sim.gates.O2, sim.gates.O3];
    if (sim.gates[target]) outs = [sim.gates[target]];
    outs = outs.filter((g) => !g.anomaly && !g.pending);
    if (!outs.length) return '所选出口已有异常或已在等待触发';
    const paying = outs.find((g) => g.phase === 'paying' && g.current && !g.current.plan && !g.current.paid);
    if (paying) {
      paying.current.plan = type;
      if (type !== 'stuck') paying.timer = Math.min(paying.timer, 0.5);
      return `${paying.name}：当前临时车即将触发「${ANOMALY[type].name}」`;
    }
    const g = outs[(Math.random() * outs.length) | 0];
    g.pending = type;
    const coming = sim.cars.some((c) => c.type === 'temp' && (c.state === 'backing' || (c.state === 'leaving' && (c.stage === 1 || c.gate === g))));
    if (!coming) {
      const parked = sim.cars.filter((c) => c.type === 'temp' && c.state === 'parked').sort((a, b) => a.timer - b.timer)[0];
      if (parked) parked.timer = 0;
    }
    return `${g.name}：下一辆出场的临时车将触发「${ANOMALY[type].name}」`;
  };

  /* ---------- 车辆 ---------- */
  let carId = 0;
  const CH = 'ABCDEFGHJKLMNPQRSTUVWXYZ0123456789';
  function plate() {
    let s = '粤B·';
    for (let i = 0; i < 5; i++) s += CH[(Math.random() * (i === 0 ? 24 : CH.length)) | 0];
    return s;
  }
  function newCar(type, slot) {
    const c = {
      id: ++carId, plate: plate(), type, side: slot.side, slot, state: '', path: null, s: 0, v: 0,
      pos: V(0, 0, 0), dir: V(0, 0, 1), tan: V(0, 0, 1), mesh: PT.makeCarMesh(type),
      stopS: null, cleared: false, gate: null, timer: 0, enterT: sim.t, fee: 0, paid: false, plan: null,
      chain: 0, blockT: 0, ghost: 0, reverse: false, charge: null, entered: false,
    };
    slot.car = c; c.mesh.userData.car = c;
    PT.groups.cars.add(c.mesh);
    sim.cars.push(c);
    return c;
  }
  function setPath(c, path, gate) {
    c.path = path; c.s = 0; c.v = 0; c.gate = gate || null; c.cleared = false;
    c.stopS = gate ? path.locate(gate.stop) : null;
    path.at(0, c.pos, c.tan);
  }
  /* ---------- 充电 ---------- */
  const KW = [7, 7, 11, 40];
  function startCharge(c, t0) {
    c.charge = { kw: KW[(Math.random() * KW.length) | 0], cap: 60, soc0: Math.round(rand(12, 65)), t0, t1: null, lit: 'on' };
    PT.setChargerLight(c.slot, 'on');
  }
  function stopCharge(c) {
    if (c.charge && c.charge.t1 == null) c.charge.t1 = sim.t;
    PT.setChargerLight(c.slot, 'idle');
  }
  sim.chargeInfo = function (c) {
    const g = c.charge;
    if (!g) return null;
    const hrs = Math.max(0, ((g.t1 == null ? sim.t : g.t1) - g.t0) * MIN_PER_SEC / 60);
    const need = g.cap * (100 - g.soc0) / 100, kwh = Math.min(g.kw * hrs, need), full = kwh >= need - 1e-6;
    return {
      kw: g.kw, soc: Math.round(g.soc0 + (kwh / g.cap) * 100), soc0: g.soc0, kwh: kwh.toFixed(1), fee: (kwh * 1.2).toFixed(1),
      full, active: g.t1 == null && !full, ended: g.t1 != null, minutes: Math.round(Math.min(hrs, need / g.kw) * 60),
    };
  };
  function placeParked(c, t0) {
    const s = c.slot;
    c.state = 'parked'; c.v = 0; c.chain = 0; c.reverse = false;
    c.pos.set(s.x, s.y, s.z); c.dir.set(0, 0, Math.sign(s.z - s.aisleZ));
    PT.setSlotLight(s, true, c.type === 'temp');
    if (s.charger && Math.random() < 0.6) startCharge(c, t0 == null ? sim.t : t0);
  }
  function trySpawn() {
    for (const o of sim.cars) if (o.state === 'arriving' && o.pos.x > 96) return;
    if (sim.cars.filter((c) => c.state === 'arriving' && c.stopS != null).length >= 5) return;
    const free = PT.SLOTS.filter((s) => !s.car);
    if (!free.length) return;
    const slot = free[(Math.random() * free.length) | 0];
    const c = newCar(Math.random() < 0.6 ? 'monthly' : 'temp', slot);
    c.state = 'arriving';
    const gate = pickGate('in', c);
    setPath(c, slotPaths(slot).entry(gate), gate);
    c.dir.copy(c.tan); c.v = 7;
  }
  // 倒车出库前检查过道：车尾会摆向上游，所以上游方向要留出更长的空档
  function aisleClear(c, up) {
    const s = c.slot, u = slotPaths(s).u;
    for (const o of sim.cars) {
      if (o === c || o.state === 'parked' || Math.abs(o.pos.y - s.y) > 2) continue;
      if (o.state === 'backing' && o.slot.aisleZ === s.aisleZ && Math.abs(o.slot.x - s.x) < 9) return false;
      const dx = o.pos.x - s.x, dz = o.pos.z - s.aisleZ;
      const along = dx * u.x + dz * u.z, perp = Math.abs(dx * u.z - dz * u.x);
      if (perp < 3.6 && along > -up && along < 4.5) return false;
    }
    return true;
  }
  function removeCar(c) {
    PT.groups.cars.remove(c.mesh);
    sim.cars.splice(sim.cars.indexOf(c), 1);
  }

  // B2 回到 B1 后沿 x=-4 北行，在 z=-20 与 B1 西区过道的车流汇合：匝道来车让行，过道车不受其影响
  function inStub(c) {
    return Math.abs(c.pos.y - C.Y1) < 0.8 && Math.abs(c.pos.x + 4) < 1.2 && c.pos.z > -17.5 && c.pos.z < -6;
  }
  function mergeBlocked(c) {
    if (c.pos.z > -11) return false;            // 还没到路口，继续往前开
    for (const o of sim.cars) {
      if (o === c || o.state === 'parked' || Math.abs(o.pos.y - C.Y1) > 0.8) continue;
      if (Math.abs(o.pos.z + 20) < 2.2 && o.pos.x > -15 && o.pos.x < -2.5) return true;
      if (Math.abs(o.pos.x + 4) < 1.4 && o.pos.z < -18 && o.pos.z > -25) return true;
    }
    return false;
  }
  const dv = V(0, 0, 0);
  function updateCar(c, dt) {
    if (c.state === 'parked') {
      c.timer -= dt;
      if (c.timer <= 0 && aisleClear(c, 20)) { stopCharge(c); c.state = 'backing'; c.reverse = true; setPath(c, slotPaths(c.slot).back, null); }
      return;
    }
    const p = c.path;
    c.stub = inStub(c);
    let vmax = c.reverse ? 2 : c.pos.y < -0.3 ? 5.2 : 8.5;
    if (c.state !== 'leaving') vmax = Math.min(vmax, Math.sqrt(2 * 2.2 * Math.max(0, p.len - c.s)) + 0.35);
    let holding = false;
    if (c.stopS != null) {
      if (!c.cleared) {
        const d = c.stopS - c.s;
        if (d < 0.3) {
          vmax = 0; holding = true;
          gateArrive(c);
          if (c.gate.current === c && c.gate.wantOpen && c.gate.openAmt > 0.9) c.cleared = true;
        } else vmax = Math.min(vmax, Math.sqrt(2 * 3.2 * d));
      } else if (c.s > c.stopS + 7.6) gatePassed(c);
    }
    // 前车检测
    let lead = null, lf = 1e9;
    if (c.reverse) {
      // 倒车出库：刚起步时让过道来车先行，进入过道后由后车避让
      if (c.s < 0.8 && !aisleClear(c, 15)) vmax = 0;
    } else if (c.ghost > 0) c.ghost -= dt;
    else {
      for (const o of sim.cars) {
        if (o === c || o.state === 'parked' || (o.stub && !c.stub)) continue;
        dv.subVectors(o.pos, c.pos);
        if (Math.abs(dv.y) > 2.2) continue;
        const f = dv.dot(c.tan);
        if (f < 0.3 || f > 10 || f >= lf) continue;
        const lat2 = dv.lengthSq() - f * f;
        if (lat2 > 2.25 && !(lat2 < 9 && f < 4.2)) continue;
        lead = o; lf = f;
      }
    }
    // 进闸后要右转并入东行车道：让行已经在这条车道上、从左侧车道开过来的车
    if (c.state === 'arriving' && c.cleared && c.pos.y > -0.5 && c.pos.z > 39.8 && c.pos.z < 44.5 && c.tan.z < -0.9) {
      for (const o of sim.cars) {
        if (o !== c && o.state === 'arriving' && Math.abs(o.pos.z - 38) < 2 && o.pos.x > c.pos.x - 9 && o.pos.x < c.pos.x + 2.5) { vmax = 0; break; }
      }
    }
    const stubHold = c.stub && mergeBlocked(c);
    if (stubHold) vmax = 0;
    // 出闸后汇入市政道路：让行正在驶来的车辆
    if (c.state === 'leaving' && !c.gate && c.pos.z > 43 && c.pos.z < 47.5 && c.tan.z > 0.9) {
      for (const o of sim.cars) {
        if (o === c) continue;
        if (o.v > 1 && Math.abs(o.pos.z - C.ROAD_Z) < 2.5 && o.pos.x > c.pos.x - 3 && o.pos.x < c.pos.x + 16) { vmax = 0; break; }
        // 相邻出口车道同时出闸：让内侧（上游）车道的车先汇入
        if (o.state === 'leaving' && o.stage === 2 && !o.gate && o.pos.x > c.pos.x + 2 && o.pos.x < c.pos.x + 10 && o.pos.z > c.pos.z - 1 && o.pos.z < 50) { vmax = 0; break; }
      }
    }
    if (lead) { const gap = lead.reverse ? GAP + 3.5 : GAP; vmax = Math.min(vmax, lf < gap ? 0 : (lf - gap) * 1.7); }
    c.chain = holding || stubHold ? 1 : lead && lf < GAP + 1.5 && lead.chain > 0 && lead.chain < 80 ? lead.chain + 1 : 0;
    if (lead && vmax < 0.2 && !c.chain) {
      if ((c.blockT += dt) > 6) { c.ghost = 2.5; c.blockT = 0; }
    } else c.blockT = 0;

    c.v += clamp(vmax - c.v, -9 * dt, 3.2 * dt);
    if (c.v < 0) c.v = 0;
    c.s += c.v * dt;
    p.at(c.s, c.pos, c.tan);

    if (c.s >= p.len - 0.03) {
      if (c.state === 'arriving') { c.timer = rand(50, 200); placeParked(c); }
      else if (c.state === 'backing') {
        c.slot.car = null; PT.setSlotLight(c.slot, false);
        c.state = 'leaving'; c.reverse = false; c.stage = 1;
        setPath(c, slotPaths(c.slot).exit(), null);
      } else if (c.stage === 1) {
        // 开到西侧分道口才选出口车道：挑排队最少的，不会都挤到被堵的那条
        const v = c.v, gate = pickGate('out', c);
        c.stage = 2; setPath(c, lanePath(gate), gate); c.v = v;
      } else c.dead = true;
    }
  }

  /* ---------- 装饰：对向车道过境车 ---------- */
  const decor = [];
  function initDecor() {
    for (let i = 0; i < 5; i++) {
      const m = PT.makeCarMesh('decor');
      m.position.set(-140 + i * 58 + rand(-8, 8), 0, 56); m.rotation.y = Math.PI / 2;
      PT.groups.surface.add(m);
      decor.push({ m, v: rand(8, 11) });
    }
  }

  /* ---------- 对外接口 ---------- */
  let spawnT = 1, chargeT = 1;
  sim.init = function () {
    C.IN.forEach((x, i) => makeGate('I' + (i + 1), '入口 ' + (i + 1), 'in', x, i === 2));
    C.OUT.forEach((x, i) => makeGate('O' + (i + 1), '出口 ' + (i + 1), 'out', x, i === 2));
    for (const lv of [1, 2]) PT.addFlowLine(new Path(surfaceIn(C.RING).concat(loop(lv), surfaceOut, [V(-C.RING, 0, C.ROAD_Z), V(-125, 0, C.ROAD_Z)])).pts, lv);
    const pool = PT.SLOTS.slice().sort(() => Math.random() - 0.5).slice(0, 56);
    for (const s of pool) {
      const c = newCar(Math.random() < 0.6 ? 'monthly' : 'temp', s);
      c.enterT = -rand(20, 230); c.timer = rand(3, 150); c.entered = true;
      placeParked(c, c.enterT);
    }
    initDecor();
  };
  sim.step = function (dt) {
    sim.t += dt;
    if ((spawnT -= dt) <= 0) { trySpawn(); spawnT = rand(1.8, 3.6); }
    for (const id in sim.gates) updateGate(sim.gates[id], dt);
    for (let i = sim.cars.length - 1; i >= 0; i--) {
      const c = sim.cars[i];
      updateCar(c, dt);
      if (c.dead) removeCar(c);
    }
    if ((chargeT -= dt) <= 0) {
      chargeT = 1;
      for (const c of sim.cars) {
        if (c.state === 'parked' && c.charge && c.charge.lit === 'on' && sim.chargeInfo(c).full) { c.charge.lit = 'full'; PT.setChargerLight(c.slot, 'full'); }
      }
    }
    for (const d of decor) { d.m.position.x += d.v * dt; if (d.m.position.x > 150) d.m.position.x = -150; }
  };
  const look = V(0, 0, 0);
  sim.sync = function (rdt, now) {
    const k = Math.min(1, rdt * 9);
    for (const c of sim.cars) {
      if (c.state !== 'parked') {
        look.copy(c.tan); if (c.reverse) look.negate();
        c.dir.lerp(look, k).normalize();
      }
      c.mesh.position.copy(c.pos);
      look.copy(c.pos).add(c.dir);
      c.mesh.lookAt(look);
      c.mesh.visible = PT.carVisible(c.pos.y);
    }
    const sc = sim.selCar, ring = PT.selRing;
    ring.visible = !!sc && !sc.dead && sc.mesh.visible;
    if (ring.visible) { ring.position.set(sc.pos.x, sc.pos.y + 0.16, sc.pos.z); ring.scale.setScalar(1 + 0.06 * Math.sin(now * 0.006)); }
    for (const id in sim.gates) {
      const g = sim.gates[id], v = g.vis;
      v.pivot.rotation.z = v.dirX * g.openAmt * 1.45;
      const blink = Math.sin(now * 0.012) > 0;
      v.lamp.material.color.setHex(g.anomaly ? (blink ? 0xff2d44 : 0x44080e) : g.openAmt > 0.5 ? 0x3ddc97 : 0xff4d5e);
      if (g.anomaly) {
        const ph = (now * 0.0012) % 1;
        v.ring.scale.setScalar(0.7 + ph * 0.9); v.ring.material.opacity = 0.95 * (1 - ph);
        v.beam.material.opacity = 0.1 + 0.08 * Math.sin(now * 0.008);
      }
    }
  };
  sim.feeNow = calcFee;
  sim.selCar = null;
  sim.freeSlots = (level) => PT.SLOTS.filter((s) => s.level === level && !s.car).length;
})();
