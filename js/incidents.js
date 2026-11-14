/* 场内事件：火情、设备故障（入口道闸）、行人摔倒、充电桩故障——现场效果、对车流的影响、处置流程 */
(function () {
  'use strict';
  const T = THREE, PT = window.PT, sim = PT.sim, X = sim._;
  const V = (x, y, z) => new T.Vector3(x, y, z);
  const pick = (a) => a[(Math.random() * a.length) | 0];
  const lv = (l) => (l === 1 ? 'B1' : 'B2');
  const TYPES = (sim.INCIDENT = {
    fire: { name: '火情', icon: '火', color: '#ff3b30' },
    device: { name: '设备故障', icon: '设', color: '#ff9f0a' },
    person: { name: '行人摔倒', icon: '人', color: '#ff9f0a' },
    charger: { name: '充电桩故障', icon: '桩', color: '#d946ef' },
  });
  sim.incidents = [];
  let seq = 0;

  /* ---------- 现场标记：地面脉冲圈 + 悬浮图标 ---------- */
  function marker(inc, r) {
    const t = TYPES[inc.type], g = new T.Group();
    g.position.copy(inc.pos);
    const ring = new T.Mesh(new T.RingGeometry(r, r + 0.45, 40),
      new T.MeshBasicMaterial({ color: t.color, transparent: true, opacity: 0.9, side: T.DoubleSide, depthWrite: false, blending: T.AdditiveBlending }));
    ring.rotation.x = -Math.PI / 2; ring.position.y = 0.1; ring.renderOrder = 8; g.add(ring);
    const ic = PT.textSprite(96, 96, 2.4), x = ic.ctx;
    x.fillStyle = t.color; x.beginPath(); x.arc(48, 48, 44, 0, 7); x.fill();
    x.strokeStyle = '#fff'; x.lineWidth = 6; x.stroke();
    x.fillStyle = '#fff'; x.font = '700 52px ' + PT.FONT; x.textAlign = 'center'; x.textBaseline = 'middle'; x.fillText(t.icon, 48, 51);
    ic.tex.needsUpdate = true; ic.sp.position.y = 3.6; g.add(ic.sp);
    inc.ring = ring;
    (inc.level === 1 ? PT.groups.b1 : inc.level === 2 ? PT.groups.b2 : PT.groups.surface).add(g);
    return g;
  }
  const smokeTex = (() => {
    const c = PT.textSprite(64, 64, 1), r = c.ctx.createRadialGradient(32, 32, 0, 32, 32, 32);
    r.addColorStop(0, 'rgba(255,255,255,.9)'); r.addColorStop(1, 'rgba(255,255,255,0)');
    c.ctx.fillStyle = r; c.ctx.fillRect(0, 0, 64, 64); c.tex.needsUpdate = true;
    return c.tex;
  })();
  function fireFx(inc) {
    inc.flames = []; inc.smoke = [];
    for (let i = 0; i < 5; i++) {
      const f = new T.Mesh(new T.ConeGeometry(0.45 + Math.random() * 0.35, 1.5 + Math.random() * 1.1, 7),
        new T.MeshBasicMaterial({ color: i % 2 ? 0xffd21a : 0xff6a1a, transparent: true, opacity: 0.85, blending: T.AdditiveBlending, depthWrite: false }));
      f.position.set((Math.random() - 0.5) * 1.3, 1.9, (Math.random() - 0.5) * 2.6); f.userData.h = f.position.y; f.renderOrder = 8;
      inc.obj.add(f); inc.flames.push(f);
    }
    for (let i = 0; i < 7; i++) {
      const s = new T.Sprite(new T.SpriteMaterial({ map: smokeTex, color: 0x2a2a2e, transparent: true, opacity: 0.5, depthWrite: false }));
      s.userData.ph = i / 7; s.renderOrder = 9; inc.obj.add(s); inc.smoke.push(s);
    }
  }
  function personFx(inc) {
    const mk = (w, h, d, c, x, y, z) => { const m = new T.Mesh(new T.BoxGeometry(w, h, d), new T.MeshStandardMaterial({ color: c, roughness: 0.8 })); m.position.set(x, y, z); return m; };
    const body = new T.Group();
    body.add(mk(0.5, 0.24, 0.7, 0x3b82f6, 0, 0.14, 0.1), mk(0.42, 0.2, 0.85, 0x1f2937, 0, 0.12, -0.7));
    const head = new T.Mesh(new T.SphereGeometry(0.17, 10, 8), new T.MeshStandardMaterial({ color: 0xf1c9a5 })); head.position.set(0, 0.17, 0.62); body.add(head);
    body.rotation.y = Math.random() * 6; inc.obj.add(body);
    // 处置时到场的安保人员
    const helper = new T.Group();
    helper.add(mk(0.5, 0.95, 0.32, 0xd9f31f, 0, 1.15, 0), mk(0.44, 0.7, 0.3, 0x1f2937, 0, 0.35, 0));
    const h2 = new T.Mesh(new T.SphereGeometry(0.17, 10, 8), new T.MeshStandardMaterial({ color: 0xf1c9a5 })); h2.position.y = 1.8; helper.add(h2);
    helper.position.set(1.1, 0, 0.3); helper.visible = false; inc.obj.add(helper); inc.helper = helper;
  }

  /* ---------- 触发 ---------- */
  sim.triggerIncident = function (type) {
    const inc = { id: ++seq, type, name: TYPES[type].name, since: performance.now(), state: 'active', timer: 0, total: 0, level: 0 };
    if (type === 'fire') {
      if (sim.incidents.some((i) => i.type === 'fire')) return '已有一处火情正在处置';
      const car = pick(sim.cars.filter((c) => c.state === 'parked' && c.timer > 15));
      if (!car) return '场内暂无停放车辆';
      const s = car.slot;
      Object.assign(inc, { level: s.level, pos: V(s.x, s.y, s.z), car, where: `${s.name} 车位`,
        desc: `${s.name} 车位的车辆 ${car.plate} 起火冒烟。${lv(s.level)} 层已暂停安排新车入位，周边车辆减速通行。`,
        actions: [{ id: 'a', label: '启动喷淋灭火', t: 6, primary: true }, { id: 'b', label: '通知消防到场处置', t: 12 }] });
      car.timer = 1e6; sim.closed[s.level] = true;
      inc.hazard = { kind: 'slow', pos: inc.pos, r: 13 };
      inc.obj = marker(inc, 3.2); fireFx(inc);
    } else if (type === 'person') {
      let p = null, s = null;
      for (let k = 0; k < 30 && !p; k++) {
        s = pick(PT.SLOTS);
        const q = V(s.x + (Math.random() - 0.5) * 1.6, s.y, s.aisleZ);
        if (!sim.cars.some((c) => c.state !== 'parked' && Math.abs(c.pos.y - q.y) < 2 && c.pos.distanceTo(q) < 11)) p = q;
      }
      if (!p) return '过道车辆较多，稍后再试';
      Object.assign(inc, { level: s.level, pos: p, where: `${lv(s.level)} ${s.side === 'W' ? '西' : '东'}区过道（${s.name} 旁）`,
        desc: `有行人在 ${s.name} 车位旁的过道上摔倒，无法自行起身。后方车辆已在其前方停车等待。`,
        actions: [{ id: 'a', label: '派安保人员救助', t: 5, primary: true }, { id: 'b', label: '呼叫 120 并封闭通道', t: 10 }] });
      inc.hazard = { kind: 'stop', pos: p };
      inc.obj = marker(inc, 1.8); personFx(inc);
    } else if (type === 'device') {
      const g = pick(Object.values(sim.gates).filter((x) => x.kind === 'in' && !x.fault));
      if (!g) return '所有入口道闸都已故障';
      g.fault = true; g.vis.alarm.visible = true;
      if (!g.current) X.board(g, '— —', '设备故障', 'alarm');
      Object.assign(inc, { gate: g, pos: V(g.x, 0, g.z), where: g.name,
        desc: `${g.name} 道闸控制器无响应，无法抬杆。该车道已停止放行，新到车辆改走其他入口。`,
        actions: [{ id: 'a', label: '远程重启设备', t: 4, primary: true }, { id: 'b', label: '改为人工值守放行', t: 2 }] });
      inc.obj = marker(inc, 2.4);
    } else {
      const all = PT.SLOTS.filter((s) => s.charger && !s.fault);
      const busy = all.filter((s) => s.car && s.car.charge && s.car.charge.t1 == null && s.car.state === 'parked');
      const s = pick(busy.length ? busy : all);
      if (!s) return '所有充电桩都已故障';
      const d = Math.sign(s.z - s.aisleZ), car = s.car && s.car.state === 'parked' ? s.car : null;
      if (car && car.charge && car.charge.t1 == null) { inc.soc = sim.chargeInfo(car).soc; X.endCharge(car); }
      s.fault = true; X.blinkSlots.delete(s);
      Object.assign(inc, { slot: s, level: s.level, pos: V(s.x, s.y, s.z + d * 2.95), where: `CP-${s.name}`,
        desc: `充电桩 CP-${s.name} 通讯中断并报过流保护${car && car.ev ? `，车辆 ${car.plate} 的充电已中止` : ''}。`,
        actions: [{ id: 'a', label: '远程重启充电桩', t: 4, primary: true }, { id: 'b', label: '停用并派单维修', t: 8 }] });
      inc.obj = marker(inc, 1.3);
    }
    if (inc.hazard) sim.hazards.push(inc.hazard);
    sim.incidents.push(inc);
    sim.count.incidents = (sim.count.incidents || 0) + 1;
    X.log(`${inc.name}：${inc.where}`, 'alarm');
    if (sim.onAlert) sim.onAlert();
    return `已触发「${inc.name}」：${inc.where}`;
  };

  /* ---------- 处置 ---------- */
  sim.handleIncident = function (id, actionId) {
    const inc = sim.incidents.find((i) => i.id === id);
    if (!inc || inc.state !== 'active') return;
    const a = inc.actions.find((x) => x.id === actionId);
    inc.state = 'handling'; inc.action = a; inc.timer = inc.total = a.t;
    if (inc.helper) inc.helper.visible = true;
    X.log(`${inc.name}（${inc.where}）：${a.label}`, 'ok');
    if (sim.onAlert) sim.onAlert();
  };
  function resolve(inc) {
    if (inc.type === 'fire') { sim.closed[inc.level] = false; if (!inc.car.dead) inc.car.timer = X.rand(30, 80); }
    else if (inc.type === 'device') {
      const g = inc.gate; g.fault = false; g.vis.alarm.visible = !!g.anomaly;
      if (!g.current) X.board(g, '— —', '空闲', 'idle');
    } else if (inc.type === 'charger') {
      const s = inc.slot, car = s.car && s.car.state === 'parked' ? s.car : null;
      s.fault = false;
      if (!car) PT.setChargerLight(s, 'free');
      else if (car.ev && inc.soc != null && inc.soc < 100) X.startCharge(car, sim.t, inc.soc);   // 恢复后接着充
      else { PT.setChargerLight(s, 'occupied'); if (!car.ev) X.blinkSlots.add(s); }
    }
    const k = sim.hazards.indexOf(inc.hazard); if (k >= 0) sim.hazards.splice(k, 1);
    if (inc.obj.parent) inc.obj.parent.remove(inc.obj);
    sim.incidents.splice(sim.incidents.indexOf(inc), 1);
    X.log(`${inc.name}（${inc.where}）已处置完毕，恢复正常`, 'ok');
    if (sim.onAlert) sim.onAlert();
  }

  /* ---------- 每步 / 每帧 ---------- */
  let autoT = 40;
  sim.incStep = function (dt) {
    for (const inc of sim.incidents.slice()) if (inc.state === 'handling' && (inc.timer -= dt) <= 0) resolve(inc);
    // Auto 模式：没有进行中的事件时，隔一段时间随机发生一起
    if (sim.auto && !sim.incidents.length && (autoT -= dt) <= 0) { autoT = X.rand(50, 100); sim.triggerIncident(pick(Object.keys(TYPES))); }
  };
  let faultOn = true;
  sim.incSync = function (now) {
    const ph = (now * 0.0011) % 1, on = Math.sin(now * 0.012) > 0;
    for (const inc of sim.incidents) {
      inc.ring.scale.setScalar(0.75 + ph * 0.8); inc.ring.material.opacity = 0.95 * (1 - ph);
      if (inc.type === 'fire') {
        const k = inc.state === 'handling' ? Math.max(0.05, inc.timer / inc.total) : 1;   // 灭火过程中火势逐渐减小
        inc.flames.forEach((f, i) => {
          const s = k * (0.8 + 0.35 * Math.sin(now * 0.02 + i * 1.7));
          f.scale.set(k * (0.9 + 0.2 * Math.sin(now * 0.013 + i)), s, k); f.position.y = f.userData.h + s * 0.4;
        });
        inc.smoke.forEach((s) => {
          const u = (s.userData.ph + now * 0.00025) % 1;
          s.position.set(Math.sin(u * 9 + s.userData.ph * 20) * 0.8, 2.2 + u * 2.3, Math.cos(u * 7) * 0.9);
          s.scale.setScalar(1.6 + u * 3.2); s.material.opacity = 0.5 * (1 - u) * (0.4 + 0.6 * k);
        });
      }
    }
    if (on !== faultOn) { faultOn = on; for (const inc of sim.incidents) if (inc.slot) PT.setChargerLight(inc.slot, on ? 'fault' : 'dim'); }
  };
})();
