/* 场景层：渲染器、相机控制、昼夜与天气、静态建筑/车库/道路、闸机与车辆模型 */
(function () {
  'use strict';
  const T = THREE;
  const PT = (window.PT = window.PT || {});
  const C = (PT.C = {
    Y1: -5, Y2: -10,          // B1 / B2 楼面标高
    GATE_Z: 40,               // 道闸所在 z
    ROAD_Z: 52,               // 市政道路（西行车道）z
    XE: { W: -36, E: 40 },    // 入口车道 x
    XX: { W: -40, E: 36 },    // 出口车道 x
  });
  const lerp = (a, b, k) => a + (b - a) * k;
  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));

  /* ---------- 车位定义（每侧每层 4 排 × 8 个） ---------- */
  PT.SLOTS = [];
  (function () {
    const rows = [{ z: 9.5, a: 4 }, { z: -1.5, a: 4 }, { z: -14.5, a: -20 }, { z: -25.5, a: -20 }];
    for (const side of ['W', 'E']) for (const level of [1, 2]) for (const r of rows) for (let k = 0; k < 8; k++) {
      PT.SLOTS.push({
        id: PT.SLOTS.length, side, level,
        x: (side === 'W' ? -1 : 1) * (9.4 + 2.8 * k),
        y: level === 1 ? C.Y1 : C.Y2, z: r.z, aisleZ: r.a, car: null,
      });
    }
  })();

  let renderer, scene, camera, canvas;
  let gSurface, gB1, gB2, gCars;
  let hemi, sun, groundMat, winMat, glowMat, poolMat, starMat, beamMat, rain, snow;
  const hitBoxes = [];
  let floorMode = 'all';

  const orbit = (PT.orbit = { target: new T.Vector3(0, -3, 10), r: 185, theta: 0.62, phi: 0.98, tween: null });
  PT.HOME = { target: new T.Vector3(0, -3, 10), r: 185, theta: 0.62, phi: 0.98 };
  const env = (PT.env = { night: false, weather: 'clear', n: 0, wr: 0, ws: 0, wf: 0 });

  /* ---------- 小工具 ---------- */
  function box(w, h, d, mat, x, y, z, parent) {
    const m = new T.Mesh(new T.BoxGeometry(w, h, d), mat);
    m.position.set(x, y, z);
    parent.add(m);
    return m;
  }
  function edges(mesh, color, opacity) {
    const e = new T.LineSegments(new T.EdgesGeometry(mesh.geometry),
      new T.LineBasicMaterial({ color, transparent: true, opacity }));
    mesh.add(e);
    return e;
  }
  function quad(a, b, c, d, mat, parent, lineColor) {
    const g = new T.BufferGeometry();
    g.setAttribute('position', new T.Float32BufferAttribute([...a, ...b, ...c, ...a, ...c, ...d], 3));
    g.computeVertexNormals();
    const m = new T.Mesh(g, mat);
    parent.add(m);
    if (lineColor != null) {
      const lg = new T.BufferGeometry();
      lg.setAttribute('position', new T.Float32BufferAttribute([...a, ...b, ...c, ...d], 3));
      parent.add(new T.LineLoop(lg, new T.LineBasicMaterial({ color: lineColor, transparent: true, opacity: 0.8 })));
    }
    return m;
  }
  function lineSegs(arr, color, opacity, parent) {
    const g = new T.BufferGeometry();
    g.setAttribute('position', new T.Float32BufferAttribute(arr, 3));
    const l = new T.LineSegments(g, new T.LineBasicMaterial({ color, transparent: true, opacity }));
    parent.add(l);
    return l;
  }
  function canvasTex(w, h, draw) {
    const cv = document.createElement('canvas');
    cv.width = w; cv.height = h;
    const ctx = cv.getContext('2d');
    if (draw) draw(ctx, w, h);
    const tex = new T.CanvasTexture(cv);
    tex.colorSpace = T.SRGBColorSpace;
    return { cv, ctx, tex };
  }
  PT.FONT = '"PingFang SC","Microsoft YaHei","Noto Sans CJK SC","Noto Sans SC",sans-serif';
  function textSprite(w, h, worldW) {
    const c = canvasTex(w, h);
    const sp = new T.Sprite(new T.SpriteMaterial({ map: c.tex, transparent: true, depthWrite: false }));
    sp.scale.set(worldW, (worldW * h) / w, 1);
    c.sp = sp;
    return c;
  }
  PT.textSprite = textSprite;

  const glowTex = canvasTex(64, 64, (g) => {
    const r = g.createRadialGradient(32, 32, 0, 32, 32, 32);
    r.addColorStop(0, 'rgba(255,255,255,1)'); r.addColorStop(0.35, 'rgba(255,255,255,.45)'); r.addColorStop(1, 'rgba(255,255,255,0)');
    g.fillStyle = r; g.fillRect(0, 0, 64, 64);
  }).tex;
  const beamTex = canvasTex(32, 128, (g) => {
    const r = g.createLinearGradient(0, 0, 0, 128);
    r.addColorStop(0, 'rgba(255,255,255,.9)'); r.addColorStop(1, 'rgba(255,255,255,0)');
    g.fillStyle = r; g.fillRect(0, 0, 32, 128);
  }).tex;

  /* ---------- 初始化 ---------- */
  PT.initScene = function (cv) {
    canvas = cv;
    renderer = new T.WebGLRenderer({ canvas, antialias: true });
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
    scene = PT.scene = new T.Scene();
    scene.background = new T.Color(0x3d5f86);
    scene.fog = new T.FogExp2(0x3d5f86, 0.0011);
    camera = PT.camera = new T.PerspectiveCamera(40, 1, 1, 1500);

    hemi = new T.HemisphereLight(0xcfe4ff, 0x0b1a30, 1.5);
    sun = new T.DirectionalLight(0xfff1dc, 2.6);
    sun.position.set(80, 140, 90);
    scene.add(hemi, sun);

    gSurface = new T.Group(); gB1 = new T.Group(); gB2 = new T.Group(); gCars = new T.Group();
    scene.add(gB2, gB1, gSurface, gCars);
    PT.groups = { surface: gSurface, b1: gB1, b2: gB2, cars: gCars };

    buildGround();
    buildBuilding();
    buildLevel(C.Y1, gB1, 1, 'B1');
    buildLevel(C.Y2, gB2, 2, 'B2');
    buildRamps();
    buildLampsAndCity();
    buildWeather();
    initCarAssets();
    bindInput();
    resize();
    if (window.ResizeObserver) new ResizeObserver(resize).observe(canvas.parentElement);
    window.addEventListener('resize', resize);
    applyCamera();
  };

  function resize() {
    const w = canvas.parentElement.clientWidth || 800, h = canvas.parentElement.clientHeight || 600;
    renderer.setSize(w, h, false);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
  }

  /* ---------- 地面、道路 ---------- */
  function buildGround() {
    groundMat = new T.MeshStandardMaterial({ color: 0x15304f, transparent: true, opacity: 0.5, depthWrite: false, roughness: 0.9 });
    const g = new T.Mesh(new T.PlaneGeometry(300, 300), groundMat);
    g.rotation.x = -Math.PI / 2; g.renderOrder = 3;
    gSurface.add(g);
    const grid = new T.GridHelper(300, 60, 0x3b86d6, 0x215089);
    grid.material.transparent = true; grid.material.opacity = 0.32; grid.position.y = 0.02;
    gSurface.add(grid);

    const roadMat = new T.MeshStandardMaterial({ color: 0x0a1626, transparent: true, opacity: 0.85, depthWrite: false, roughness: 0.8 });
    const road = new T.Mesh(new T.PlaneGeometry(300, 12), roadMat);
    road.rotation.x = -Math.PI / 2; road.position.set(0, 0.03, 54); road.renderOrder = 4;
    gSurface.add(road);
    for (const sx of [-38, 38]) {
      const d = new T.Mesh(new T.PlaneGeometry(8.6, 18), roadMat);
      d.rotation.x = -Math.PI / 2; d.position.set(sx, 0.03, 39); d.renderOrder = 4;
      gSurface.add(d);
    }
    const ln = [];
    for (let x = -148; x < 148; x += 8) ln.push(x, 0.06, 54, x + 4, 0.06, 54);
    lineSegs(ln, 0xffd166, 0.7, gSurface);
    lineSegs([-150, 0.06, 48, 150, 0.06, 48, -150, 0.06, 60, 150, 0.06, 60], 0x4cc9ff, 0.55, gSurface);
    // 园区红线
    lineSegs([-62, 0.06, -42, 62, 0.06, -42, 62, 0.06, -42, 62, 0.06, 48, -62, 0.06, 48, -62, 0.06, -42], 0x4cc9ff, 0.5, gSurface);
    // 车道分隔线与停止线
    const dl = [];
    for (const sx of [-38, 38]) dl.push(sx, 0.06, 30, sx, 0.06, 48);
    for (const k of ['W', 'E']) {
      dl.push(C.XE[k] - 1.8, 0.06, C.GATE_Z + 1.2, C.XE[k] + 1.8, 0.06, C.GATE_Z + 1.2);
      dl.push(C.XX[k] - 1.8, 0.06, C.GATE_Z - 1.2, C.XX[k] + 1.8, 0.06, C.GATE_Z - 1.2);
    }
    lineSegs(dl, 0xffffff, 0.6, gSurface);
  }

  /* ---------- 办公楼 ---------- */
  function buildBuilding() {
    const base = canvasTex(512, 512, (g, w, h) => {
      g.fillStyle = '#12294a'; g.fillRect(0, 0, w, h);
      for (let r = 0; r < 14; r++) for (let c = 0; c < 16; c++) {
        g.fillStyle = (r + c) % 5 === 0 ? '#2d5d94' : '#234a7a';
        g.fillRect(c * 32 + 4, r * (h / 14) + 7, 24, h / 14 - 14);
      }
    });
    const emis = canvasTex(512, 512, (g, w, h) => {
      g.fillStyle = '#000'; g.fillRect(0, 0, w, h);
      for (let r = 0; r < 14; r++) for (let c = 0; c < 16; c++) {
        if (Math.random() < 0.42) {
          g.fillStyle = Math.random() < 0.7 ? '#ffd58a' : '#9fd8ff';
          g.fillRect(c * 32 + 4, r * (h / 14) + 7, 24, h / 14 - 14);
        }
      }
    });
    winMat = new T.MeshStandardMaterial({
      color: 0xffffff, map: base.tex, emissive: 0xffffff, emissiveMap: emis.tex, emissiveIntensity: 0,
      transparent: true, opacity: 0.8, roughness: 0.35, metalness: 0.35,
    });
    const capMat = new T.MeshStandardMaterial({ color: 0x1a3a62, transparent: true, opacity: 0.85, roughness: 0.6 });
    const podMat = new T.MeshStandardMaterial({ color: 0x1c426e, transparent: true, opacity: 0.72, roughness: 0.5 });
    const pod = box(60, 7, 38, podMat, 0, 3.5, -9, gSurface); pod.renderOrder = 5;
    edges(pod, 0x6fd3ff, 0.9);
    const tower = box(46, 56, 28, [winMat, winMat, capMat, capMat, winMat, winMat], 0, 35, -10, gSurface);
    tower.renderOrder = 6;
    edges(tower, 0x6fd3ff, 0.95);
    const fl = [];
    for (let y = 11; y < 63; y += 4) {
      fl.push(-23, y, 4, 23, y, 4, 23, y, 4, 23, y, -24, 23, y, -24, -23, y, -24, -23, y, -24, -23, y, 4);
    }
    lineSegs(fl, 0x4cc9ff, 0.22, gSurface);
    const roof = box(14, 4, 9, capMat, 6, 65, -12, gSurface); edges(roof, 0x6fd3ff, 0.8);
    lineSegs([-12, 63, -16, -12, 76, -16], 0xff5d6c, 0.9, gSurface);
    const name = textSprite(512, 96, 30);
    name.ctx.font = '700 54px ' + PT.FONT; name.ctx.textAlign = 'center'; name.ctx.textBaseline = 'middle';
    name.ctx.fillStyle = '#bfe6ff'; name.ctx.fillText('A 座 · 办公楼', 256, 50); name.tex.needsUpdate = true;
    name.sp.position.set(0, 82, -10); gSurface.add(name.sp);
  }

  /* ---------- 地下楼层 ---------- */
  function buildLevel(y, grp, level, name) {
    const fm = new T.MeshStandardMaterial({ color: 0x0f2743, transparent: true, opacity: 0.62, depthWrite: false, roughness: 0.85 });
    const f = new T.Mesh(new T.PlaneGeometry(96, 66), fm);
    f.rotation.x = -Math.PI / 2; f.position.set(0, y, 1); f.renderOrder = level === 1 ? 2 : 1;
    grp.add(f);
    const shell = new T.LineSegments(new T.EdgesGeometry(new T.BoxGeometry(96, 4.6, 66)),
      new T.LineBasicMaterial({ color: 0x4cc9ff, transparent: true, opacity: 0.6 }));
    shell.position.set(0, y + 2.3, 1);
    grp.add(shell);

    // 车位线 + 占用指示灯
    const sl = [];
    const slots = PT.SLOTS.filter((s) => s.level === level);
    const lights = new T.InstancedMesh(new T.BoxGeometry(1.4, 0.08, 0.35), new T.MeshBasicMaterial(), slots.length);
    const m4 = new T.Matrix4(), free = new T.Color(0x3ddc97);
    slots.forEach((s, i) => {
      const x0 = s.x - 1.3, x1 = s.x + 1.3, zb = s.z + Math.sign(s.z - s.aisleZ) * 2.5, zf = s.z - Math.sign(s.z - s.aisleZ) * 2.5;
      sl.push(x0, y + 0.04, zf, x0, y + 0.04, zb, x1, y + 0.04, zf, x1, y + 0.04, zb, x0, y + 0.04, zb, x1, y + 0.04, zb);
      m4.makeTranslation(s.x, y + 0.06, zf);
      lights.setMatrixAt(i, m4); lights.setColorAt(i, free);
      s.light = lights; s.lightIdx = i;
    });
    lights.instanceColor.needsUpdate = true;
    grp.add(lights);
    lineSegs(sl, 0x3aa0ff, 0.5, grp);

    // 立柱
    const colMat = new T.MeshStandardMaterial({ color: 0x2a5d94, transparent: true, opacity: 0.55 });
    const cols = new T.InstancedMesh(new T.BoxGeometry(0.6, 4.6, 0.6), colMat, 40);
    let n = 0;
    for (const sx of [-1, 1]) for (let k = 0; k < 5; k++) for (const z of [7, 1, -17, -23]) {
      m4.makeTranslation(sx * (8 + 5.6 * k), y + 2.3, z); cols.setMatrixAt(n++, m4);
    }
    grp.add(cols);

    // 电梯核心筒
    const core = box(4, 4.6, 16, new T.MeshStandardMaterial({ color: 0x1b4472, transparent: true, opacity: 0.75 }), 0, y + 2.3, -8, grp);
    edges(core, 0x7fe0ff, 0.9);

    const lb = textSprite(128, 64, 9);
    lb.ctx.font = '700 48px ' + PT.FONT; lb.ctx.textAlign = 'center'; lb.ctx.textBaseline = 'middle';
    lb.ctx.fillStyle = '#7fe0ff'; lb.ctx.fillText(name, 64, 34); lb.tex.needsUpdate = true;
    lb.sp.position.set(-53, y + 2.5, 34); grp.add(lb.sp);
  }
  PT.setSlotLight = function (slot, occupied, temp) {
    slot.light.setColorAt(slot.lightIdx, new T.Color(occupied ? (temp ? 0xffb23e : 0x4c8dff) : 0x3ddc97));
    slot.light.instanceColor.needsUpdate = true;
  };

  function buildRamps() {
    const rm = new T.MeshStandardMaterial({ color: 0x1f6fb5, transparent: true, opacity: 0.45, side: T.DoubleSide, depthWrite: false });
    for (const sx of [-1, 1]) {
      // 地面 → B1
      quad([sx * 34, 0, 30], [sx * 42, 0, 30], [sx * 42, C.Y1, 12], [sx * 34, C.Y1, 12], rm, gB1, 0x7fe0ff);
      // B1 → B2
      quad([sx * 8, C.Y1, -12], [sx * 8, C.Y1, -4], [sx * 26, C.Y2, -4], [sx * 26, C.Y2, -12], rm, gB2, 0x7fe0ff);
    }
  }
  PT.addFlowLine = function (pts, level) {
    const g = new T.BufferGeometry().setFromPoints(pts.map((p) => new T.Vector3(p.x, p.y + 0.07, p.z)));
    (level === 1 ? gB1 : gB2).add(new T.Line(g, new T.LineBasicMaterial({ color: level === 1 ? 0x4cc9ff : 0x9d8cff, transparent: true, opacity: 0.28 })));
  };

  /* ---------- 路灯、周边体块、星空 ---------- */
  function buildLampsAndCity() {
    glowMat = new T.SpriteMaterial({ map: glowTex, color: 0xffe2a6, transparent: true, opacity: 0, blending: T.AdditiveBlending, depthWrite: false });
    poolMat = new T.MeshBasicMaterial({ map: glowTex, color: 0xffd58a, transparent: true, opacity: 0, blending: T.AdditiveBlending, depthWrite: false });
    const poleMat = new T.MeshStandardMaterial({ color: 0x5a7fa8 });
    const poolGeo = new T.PlaneGeometry(22, 22); poolGeo.rotateX(-Math.PI / 2);
    for (let x = -130; x <= 130; x += 20) {
      box(0.25, 7, 0.25, poleMat, x, 3.5, 47, gSurface);
      const s = new T.Sprite(glowMat); s.scale.set(5, 5, 1); s.position.set(x, 7.2, 47); gSurface.add(s);
      const p = new T.Mesh(poolGeo, poolMat); p.position.set(x, 0.09, 50); gSurface.add(p);
    }
    const bm = new T.MeshStandardMaterial({ color: 0x10243f, transparent: true, opacity: 0.55, roughness: 0.9 });
    [[-100, 22, -20, 36, 44], [-104, 14, -78, 44, 40], [100, 30, -30, 34, 50], [98, 12, 14, 30, 24], [-30, 18, -90, 50, 30],
      [40, 26, -92, 44, 30], [-70, 16, 92, 60, 30], [10, 22, 96, 50, 34], [84, 14, 90, 46, 28], [-98, 10, 22, 30, 26]]
      .forEach(([x, h, z, w, d]) => { const b = box(w, h, d, bm, x, h / 2, z, gSurface); edges(b, 0x4cc9ff, 0.28); });

    const sp = [];
    for (let i = 0; i < 700; i++) {
      const a = Math.random() * Math.PI * 2, e = Math.random() * 1.3 + 0.08;
      sp.push(900 * Math.cos(e) * Math.cos(a), 900 * Math.sin(e), 900 * Math.cos(e) * Math.sin(a));
    }
    const sg = new T.BufferGeometry(); sg.setAttribute('position', new T.Float32BufferAttribute(sp, 3));
    starMat = new T.PointsMaterial({ color: 0xffffff, size: 1.6, sizeAttenuation: false, transparent: true, opacity: 0, fog: false, depthWrite: false });
    scene.add(new T.Points(sg, starMat));
  }

  /* ---------- 雨 / 雪 ---------- */
  function buildWeather() {
    const NR = 5000, rp = new Float32Array(NR * 6);
    for (let i = 0; i < NR; i++) {
      const x = (Math.random() - 0.5) * 280, y = Math.random() * 110 - 12, z = (Math.random() - 0.5) * 240;
      rp.set([x, y, z, x + 0.35, y - 3.4, z], i * 6);
    }
    const rg = new T.BufferGeometry(); rg.setAttribute('position', new T.BufferAttribute(rp, 3));
    rain = new T.LineSegments(rg, new T.LineBasicMaterial({ color: 0xa9cdff, transparent: true, opacity: 0, depthWrite: false }));
    rain.frustumCulled = false; rain.visible = false; scene.add(rain);

    const NS = 4000, spos = new Float32Array(NS * 3);
    for (let i = 0; i < NS; i++) spos.set([(Math.random() - 0.5) * 280, Math.random() * 110 - 12, (Math.random() - 0.5) * 240], i * 3);
    const sg = new T.BufferGeometry(); sg.setAttribute('position', new T.BufferAttribute(spos, 3));
    snow = new T.Points(sg, new T.PointsMaterial({ map: glowTex, color: 0xffffff, size: 1.5, transparent: true, opacity: 0, depthWrite: false }));
    snow.frustumCulled = false; snow.visible = false; scene.add(snow);
  }
  function updateWeather(dt, t) {
    if (env.wr > 0.01) {
      rain.visible = true; rain.material.opacity = 0.75 * env.wr;
      const a = rain.geometry.attributes.position.array, d = 85 * dt;
      for (let i = 1; i < a.length; i += 6) {
        a[i] -= d; a[i + 3] -= d;
        if (a[i + 3] < -12) { a[i] += 110; a[i + 3] += 110; }
      }
      rain.geometry.attributes.position.needsUpdate = true;
    } else rain.visible = false;
    if (env.ws > 0.01) {
      snow.visible = true; snow.material.opacity = 0.9 * env.ws;
      const a = snow.geometry.attributes.position.array;
      for (let i = 0; i < a.length; i += 3) {
        a[i + 1] -= 7 * dt; a[i] += Math.sin(t * 0.8 + i) * 1.2 * dt;
        if (a[i + 1] < -12) a[i + 1] += 110;
      }
      snow.geometry.attributes.position.needsUpdate = true;
    } else snow.visible = false;
  }

  const cDay = new T.Color(0x3d5f86), cNight = new T.Color(0x040a16), cGD = new T.Color(0x8c9aa9), cGN = new T.Color(0x131b28);
  const cSunD = new T.Color(0xfff1dc), cSunN = new T.Color(0x86a4ff), tA = new T.Color(), tB = new T.Color();
  function updateEnv(dt) {
    const k = Math.min(1, dt * 2.2), w = env.weather;
    env.n += ((env.night ? 1 : 0) - env.n) * k;
    env.wr += ((w === 'rain' ? 1 : 0) - env.wr) * k;
    env.ws += ((w === 'snow' ? 1 : 0) - env.ws) * k;
    env.wf += ((w === 'fog' ? 1 : 0) - env.wf) * k;
    const ov = Math.max(env.wr * 0.7, env.ws * 0.8, env.wf);
    tA.copy(cDay).lerp(cNight, env.n); tB.copy(cGD).lerp(cGN, env.n); tA.lerp(tB, ov * 0.85);
    scene.background.copy(tA); scene.fog.color.copy(tA);
    scene.fog.density = 0.0011 + 0.0026 * env.wr + 0.0034 * env.ws + 0.0115 * env.wf;
    hemi.intensity = lerp(1.5, 0.62, env.n) * (1 - 0.2 * ov);
    sun.intensity = lerp(2.6, 0.5, env.n) * (1 - 0.6 * ov);
    sun.color.copy(cSunD).lerp(cSunN, env.n);
    winMat.emissiveIntensity = env.n * 1.5;
    glowMat.opacity = env.n * 0.95; poolMat.opacity = env.n * 0.3;
    starMat.opacity = env.n * (1 - ov) * 0.9;
    beamMat.opacity = env.n * 0.5; beamMat.visible = env.n > 0.03;
  }

  /* ---------- 楼层显示 ---------- */
  PT.setFloorMode = function (m) {
    floorMode = m;
    gSurface.visible = m === 'all' || m === 'ground';
    gB1.visible = m === 'all' || m === 'b1';
    gB2.visible = m === 'all' || m === 'b2';
    groundMat.opacity = m === 'ground' ? 0.96 : 0.5;
  };
  PT.getFloorMode = () => floorMode;
  PT.carVisible = function (y) {
    if (floorMode === 'all') return true;
    const lv = y > -2.5 ? 'ground' : y > -7.5 ? 'b1' : 'b2';
    return lv === floorMode;
  };

  /* ---------- 车辆模型 ---------- */
  const carGeo = {}, carMat = {};
  function initCarAssets() {
    carGeo.body = new T.BoxGeometry(1.8, 0.62, 4.4);
    carGeo.cab = new T.BoxGeometry(1.6, 0.55, 2.3);
    carGeo.lamp = new T.BoxGeometry(1.5, 0.14, 0.08);
    carGeo.beam = new T.PlaneGeometry(2.8, 9); carGeo.beam.rotateX(-Math.PI / 2); carGeo.beam.translate(0, -0.42, 6.8);
    const mk = (c) => new T.MeshStandardMaterial({ color: c, emissive: c, emissiveIntensity: 0.28, roughness: 0.4, metalness: 0.3 });
    carMat.monthly = [0x2fb8ff, 0x4f8dff, 0x38d6e8].map(mk);
    carMat.temp = [0xffb02e, 0xff8a3d, 0xffd24a].map(mk);
    carMat.decor = [mk(0x6f86a6)];
    carMat.alarm = PT.alarmMat = new T.MeshStandardMaterial({ color: 0xff2d44, emissive: 0xff2d44, emissiveIntensity: 1 });
    carMat.cab = new T.MeshStandardMaterial({ color: 0x0b1930, roughness: 0.2, metalness: 0.6 });
    carMat.front = new T.MeshBasicMaterial({ color: 0xfff3c4 });
    carMat.rear = new T.MeshBasicMaterial({ color: 0xff3344 });
    beamMat = new T.MeshBasicMaterial({ map: beamTex, color: 0xfff0c0, transparent: true, opacity: 0, blending: T.AdditiveBlending, depthWrite: false });
  }
  PT.makeCarMesh = function (type) {
    const g = new T.Group(), set = carMat[type];
    const body = new T.Mesh(carGeo.body, set[(Math.random() * set.length) | 0]); body.position.y = 0.52;
    const cab = new T.Mesh(carGeo.cab, carMat.cab); cab.position.set(0, 1.06, -0.25);
    const f = new T.Mesh(carGeo.lamp, carMat.front); f.position.set(0, 0.56, 2.21);
    const r = new T.Mesh(carGeo.lamp, carMat.rear); r.position.set(0, 0.56, -2.21);
    const beam = new T.Mesh(carGeo.beam, beamMat); beam.position.y = 0.5;
    g.add(body, cab, f, r, beam);
    g.userData.body = body; g.userData.baseMat = body.material;
    return g;
  };

  /* ---------- 闸机模型 ---------- */
  PT.buildGate = function (gate) {
    const ix = gate.side === 'W' ? -38 : 38, z = C.GATE_Z;
    const dirX = gate.x > ix ? 1 : -1;
    const postMat = new T.MeshStandardMaterial({ color: 0x2c6cab, emissive: 0x143a66, emissiveIntensity: 0.6 });
    if (gate.kind === 'in') {
      const booth = box(1.5, 2.8, 2.6, new T.MeshStandardMaterial({ color: 0x1d4b7d, transparent: true, opacity: 0.9 }), ix, 1.4, z + 0.2, gSurface);
      edges(booth, 0x7fe0ff, 0.95);
    }
    const postX = gate.x - dirX * 1.75;
    box(0.5, 1.3, 0.5, postMat, postX, 0.65, z, gSurface);
    const pivot = new T.Group(); pivot.position.set(postX, 1.15, z); gSurface.add(pivot);
    const arm = new T.Mesh(new T.BoxGeometry(3.5, 0.16, 0.16), new T.MeshBasicMaterial({ color: 0xffe14d }));
    arm.position.x = dirX * 1.75; pivot.add(arm);
    const lamp = new T.Mesh(new T.SphereGeometry(0.22, 12, 8), new T.MeshBasicMaterial({ color: 0xff4d5e }));
    lamp.position.set(postX, 1.55, z); gSurface.add(lamp);

    const board = textSprite(320, 160, 5.6);
    board.sp.position.set(gate.x + dirX * 1.6, 5.4, gate.kind === 'in' ? z - 3 : z + 4.5); gSurface.add(board.sp);

    const stopZ = gate.kind === 'in' ? z + 3.6 : z - 3.6;
    const alarm = new T.Group(); alarm.position.set(gate.x, 0, stopZ); alarm.visible = false; gSurface.add(alarm);
    const ring = new T.Mesh(new T.RingGeometry(3.4, 4.1, 48),
      new T.MeshBasicMaterial({ color: 0xff3048, transparent: true, opacity: 0.9, side: T.DoubleSide, depthWrite: false, blending: T.AdditiveBlending }));
    ring.rotation.x = -Math.PI / 2; ring.position.y = 0.12; alarm.add(ring);
    const beam = new T.Mesh(new T.CylinderGeometry(3.2, 3.2, 16, 32, 1, true),
      new T.MeshBasicMaterial({ color: 0xff3048, transparent: true, opacity: 0.14, side: T.DoubleSide, depthWrite: false, blending: T.AdditiveBlending }));
    beam.position.y = 8; alarm.add(beam);

    const hit = new T.Mesh(new T.BoxGeometry(4.4, 9, 9), new T.MeshBasicMaterial({ transparent: true, opacity: 0, depthWrite: false }));
    hit.position.set(gate.x, 4, z); hit.userData.gate = gate.id; gSurface.add(hit); hitBoxes.push(hit);

    return { pivot, dirX, lamp, board, alarm, ring, beam };
  };

  /* ---------- 相机控制（拖拽旋转 / 平移 / 缩放） ---------- */
  function applyCamera() {
    const sp = Math.sin(orbit.phi), cp = Math.cos(orbit.phi);
    camera.position.set(orbit.target.x + orbit.r * sp * Math.sin(orbit.theta), orbit.target.y + orbit.r * cp,
      orbit.target.z + orbit.r * sp * Math.cos(orbit.theta));
    camera.lookAt(orbit.target);
  }
  function limit() {
    orbit.phi = clamp(orbit.phi, 0.1, 1.5);
    orbit.r = clamp(orbit.r, 22, 460);
    orbit.target.x = clamp(orbit.target.x, -130, 130);
    orbit.target.z = clamp(orbit.target.z, -110, 110);
  }
  function pan(dx, dy) {
    const k = (2 * orbit.r * Math.tan((camera.fov * Math.PI) / 360)) / canvas.clientHeight;
    const ct = Math.cos(orbit.theta), st = Math.sin(orbit.theta);
    orbit.target.x += (-ct * dx - st * dy) * k;
    orbit.target.z += (st * dx - ct * dy) * k;
  }
  PT.focus = function (o, dur) {
    let d = (o.theta != null ? o.theta : orbit.theta) - orbit.theta;
    d = Math.atan2(Math.sin(d), Math.cos(d));
    orbit.tween = {
      k: 0, dur: dur || 1.1,
      f: { t: orbit.target.clone(), r: orbit.r, th: orbit.theta, ph: orbit.phi },
      to: { t: (o.target || orbit.target).clone(), r: o.r != null ? o.r : orbit.r, th: orbit.theta + d, ph: o.phi != null ? o.phi : orbit.phi },
    };
  };
  function bindInput() {
    const ptrs = new Map();
    let down = null, pinch = 0, mid = null;
    const ray = new T.Raycaster(), ndc = new T.Vector2();
    PT.pick = function (cx, cy) {
      if (!gSurface.visible) return null;
      const r = canvas.getBoundingClientRect();
      ndc.set(((cx - r.left) / r.width) * 2 - 1, -((cy - r.top) / r.height) * 2 + 1);
      ray.setFromCamera(ndc, camera);
      const h = ray.intersectObjects(hitBoxes, false);
      return h.length ? h[0].object.userData.gate : null;
    };
    const two = () => {
      const [a, b] = [...ptrs.values()];
      return { d: Math.hypot(a.x - b.x, a.y - b.y), x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 };
    };
    canvas.addEventListener('pointerdown', (e) => {
      canvas.setPointerCapture(e.pointerId);
      ptrs.set(e.pointerId, { x: e.clientX, y: e.clientY });
      if (ptrs.size === 1) down = { x: e.clientX, y: e.clientY, t: performance.now(), moved: false, pan: e.button === 2 || e.shiftKey };
      else if (ptrs.size === 2) { if (down) down.moved = true; const t = two(); pinch = t.d; mid = t; }
    });
    canvas.addEventListener('pointermove', (e) => {
      const p = ptrs.get(e.pointerId);
      if (!p) { canvas.style.cursor = PT.pick(e.clientX, e.clientY) ? 'pointer' : 'grab'; return; }
      const dx = e.clientX - p.x, dy = e.clientY - p.y;
      p.x = e.clientX; p.y = e.clientY;
      if (ptrs.size === 1 && down) {
        if (Math.hypot(e.clientX - down.x, e.clientY - down.y) > 4) down.moved = true;
        if (!down.moved) return;
        orbit.tween = null;
        if (down.pan) pan(dx, dy); else { orbit.theta -= dx * 0.005; orbit.phi -= dy * 0.005; }
      } else if (ptrs.size === 2) {
        orbit.tween = null;
        const t = two();
        if (pinch > 0) orbit.r *= pinch / Math.max(1, t.d);
        pan(t.x - mid.x, t.y - mid.y);
        pinch = t.d; mid = t;
      }
      limit();
    });
    const up = (e) => {
      if (!ptrs.has(e.pointerId)) return;
      ptrs.delete(e.pointerId);
      if (ptrs.size === 0 && down && !down.moved && performance.now() - down.t < 500 && e.type === 'pointerup') {
        if (PT.onPick) PT.onPick(PT.pick(e.clientX, e.clientY));
      }
      if (ptrs.size === 0) down = null;
    };
    canvas.addEventListener('pointerup', up);
    canvas.addEventListener('pointercancel', up);
    canvas.addEventListener('contextmenu', (e) => e.preventDefault());
    canvas.addEventListener('wheel', (e) => {
      e.preventDefault();
      orbit.tween = null;
      orbit.r *= Math.exp((e.deltaMode === 1 ? e.deltaY * 30 : e.deltaY) * 0.0012);
      limit();
    }, { passive: false });
  }

  /* ---------- 每帧 ---------- */
  let clock = 0;
  PT.updateScene = function (dt) {
    clock += dt;
    const tw = orbit.tween;
    if (tw) {
      tw.k = Math.min(1, tw.k + dt / tw.dur);
      const e = tw.k < 0.5 ? 4 * tw.k * tw.k * tw.k : 1 - Math.pow(-2 * tw.k + 2, 3) / 2;
      orbit.target.lerpVectors(tw.f.t, tw.to.t, e);
      orbit.r = lerp(tw.f.r, tw.to.r, e); orbit.theta = lerp(tw.f.th, tw.to.th, e); orbit.phi = lerp(tw.f.ph, tw.to.ph, e);
      if (tw.k >= 1) orbit.tween = null;
    }
    updateEnv(dt);
    updateWeather(dt, clock);
    PT.alarmMat.emissiveIntensity = 0.6 + 0.6 * Math.sin(clock * 8);
    applyCamera();
    renderer.render(scene, camera);
  };
})();
