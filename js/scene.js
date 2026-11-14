/* 场景层：渲染器、相机控制、昼夜与天气、静态建筑/车库/道路、闸机与车辆模型 */
(function () {
  'use strict';
  const T = THREE;
  const PT = (window.PT = window.PT || {});
  const C = (PT.C = {
    Y1: -5, Y2: -10,          // B1 / B2 楼面标高
    GATE_Z: 40,               // 道闸所在 z
    ROAD_Z: 52,               // 市政道路（西行车道）z
    IN: [15, 19, 23], IN_Z: 42, // 三条入口车道 x 与道闸 z：在楼前右侧草坪的南边，进闸后先右转
    OUT: [-38, -42, -46],     // 西侧三条出口车道 x
    RING: 42, NORTH: -36,     // 绕楼单向环路：东侧北行 → 北侧西行 → 西侧南行
  });
  const lerp = (a, b, k) => a + (b - a) * k;
  const clamp = (v, a, b) => Math.max(a, Math.min(b, v));

  /* ---------- 车位定义（每侧每层 4 排 × 8 个） ---------- */
  PT.SLOTS = [];
  (function () {
    const rows = [{ z: 9.5, a: 4 }, { z: -1.5, a: 4 }, { z: -14.5, a: -20 }, { z: -25.5, a: -20 }];
    for (const side of ['W', 'E']) for (const level of [1, 2]) for (const r of rows) for (let k = 0; k < 8; k++) {
      const no = rows.indexOf(r) * 8 + k + 1;
      PT.SLOTS.push({
        name: `${level === 1 ? 'B1' : 'B2'}-${side === 'W' ? '西' : '东'}${String(no).padStart(2, '0')}`,
        charger: r.z === -25.5 || r.z === 9.5,   // 背靠墙的两排车位装充电桩
        id: PT.SLOTS.length, side, level,
        x: (side === 'W' ? -1 : 1) * (9.4 + 2.8 * k),
        y: level === 1 ? C.Y1 : C.Y2, z: r.z, aisleZ: r.a, car: null,
      });
    }
  })();

  let renderer, scene, camera, canvas;
  let gSurface, gB1, gB2, gCars;
  const winMats = [];
  let hemi, sun, groundMat, roadMat, lawnMat, cityMat, glowMat, poolMat, starMat, beamMat, rain, snow;
  const hitBoxes = [];
  let floorMode = 'all';
  const floorMats = {}, see = { ground: false, b1: true, b2: true };
  // 高画质相关：阴影、天空环境反射、色调映射、凹凸贴图
  let skyDome = null, rampStub = null, qLevel = 1;
  let hq = false, pmrem, envRT = null, envDirty = false, skyGeo, skyScene, sunSprite, skyKey = '';
  const bumpList = [], carPaint = [];

  const orbit = (PT.orbit = { target: new T.Vector3(0, -3, 10), r: 185, theta: 0.62, phi: 0.98, tween: null });
  PT.HOME = { target: new T.Vector3(0, -3, 10), r: 185, theta: 0.62, phi: 0.98 };
  const env = (PT.env = { night: false, weather: 'clear', n: 0, wr: 0, ws: 0, wf: 0 });

  /* ---------- 小工具 ---------- */
  function box(w, h, d, mat, x, y, z, parent) {
    const m = new T.Mesh(new T.BoxGeometry(w, h, d), mat);
    m.position.set(x, y, z);
    if (parent === gSurface) { m.castShadow = true; m.receiveShadow = true; }
    parent.add(m);
    return m;
  }
  function edges(mesh, color, opacity) {
    const e = new T.LineSegments(new T.EdgesGeometry(mesh.geometry),
      new T.LineBasicMaterial({ color, transparent: true, opacity }));
    e.renderOrder = 8;
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
    // 地表的线要在地面之后绘制，否则会在地面上留下能看穿到地库的细缝
    if (parent === gSurface) l.renderOrder = 8;
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
    sp.renderOrder = 50;
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
    renderer.setPixelRatio(1);
    renderer.shadowMap.enabled = true; renderer.shadowMap.type = T.PCFSoftShadowMap;
    pmrem = new T.PMREMGenerator(renderer);
    scene = PT.scene = new T.Scene();
    scene.background = new T.Color(0x3d5f86);
    scene.fog = new T.FogExp2(0x3d5f86, 0.0011);
    camera = PT.camera = new T.PerspectiveCamera(40, 1, 1, 1500);

    hemi = new T.HemisphereLight(0xcfe4ff, 0x0b1a30, 1.5);
    sun = new T.DirectionalLight(0xfff1dc, 2.6);
    sun.position.set(110, 140, 50);
    const sc = sun.shadow.camera;
    sc.left = -115; sc.right = 115; sc.top = 115; sc.bottom = -115; sc.near = 20; sc.far = 420;
    sun.shadow.mapSize.set(2048, 2048); sun.shadow.bias = -0.0004; sun.shadow.normalBias = 0.6;
    scene.add(hemi, sun);
    buildSky();

    gSurface = new T.Group(); gB1 = new T.Group(); gB2 = new T.Group(); gCars = new T.Group();
    scene.add(gB2, gB1, gSurface, gCars);
    PT.groups = { surface: gSurface, b1: gB1, b2: gB2, cars: gCars };

    buildTextures();
    buildGround();
    buildBuilding();
    buildShop();
    buildLevel(C.Y1, gB1, 1, 'B1');
    buildLevel(C.Y2, gB2, 2, 'B2');
    buildRamps();
    buildRampStub();
    PT.setSee('ground', false);
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

  /* ---------- 天空：渐变天穹 + 太阳/月亮；高画质时同时作为环境反射源 ---------- */
  function buildSky() {
    skyGeo = new T.SphereGeometry(1000, 32, 16);
    skyGeo.setAttribute('color', new T.BufferAttribute(new Float32Array(skyGeo.attributes.position.count * 3), 3));
    const mat = new T.MeshBasicMaterial({ vertexColors: true, side: T.BackSide, fog: false, depthWrite: false });
    const dome = (skyDome = new T.Mesh(skyGeo, mat)); dome.renderOrder = -10; scene.add(dome);
    skyScene = new T.Scene(); skyScene.add(new T.Mesh(skyGeo, mat));
    sunSprite = new T.Sprite(new T.SpriteMaterial({ map: glowTex, transparent: true, blending: T.AdditiveBlending, fog: false, depthWrite: false }));
    sunSprite.position.copy(sun.position).normalize().multiplyScalar(900); sunSprite.renderOrder = -5;
    scene.add(sunSprite);
  }
  const sTop = new T.Color(), sHor = new T.Color(), sGnd = new T.Color(), sTmp = new T.Color();
  function paintSky() {
    const pos = skyGeo.attributes.position, col = skyGeo.attributes.color;
    for (let i = 0; i < pos.count; i++) {
      const h = pos.getY(i) / 1000;
      if (h >= 0) sTmp.copy(sHor).lerp(sTop, Math.sqrt(h)); else sTmp.copy(sHor).lerp(sGnd, Math.min(1, -h * 5));
      col.setXYZ(i, sTmp.r, sTmp.g, sTmp.b);
    }
    col.needsUpdate = true;
  }
  function refreshEnvMap() {
    const rt = pmrem.fromScene(skyScene, 0.03, 1, 2000);
    if (envRT) envRT.dispose();
    envRT = rt; scene.environment = rt.texture;
  }
  PT.autoQuality = function () {
    try {
      const gl = renderer.getContext(), e = gl.getExtension('WEBGL_debug_renderer_info');
      return /swiftshader|llvmpipe|software|basic render/i.test(e ? gl.getParameter(e.UNMASKED_RENDERER_WEBGL) : '') ? 0 : 2;
    } catch (err) { return 1; }
  };
  // 画质三档：0 流畅（降低渲染分辨率，给没有显卡加速的电脑用）/ 1 标准 / 2 高（阴影、反射、色调映射、凹凸）
  PT.getQuality = () => qLevel;
  PT.setQuality = function (level) {
    qLevel = level;
    const on = (hq = level === 2);
    sun.castShadow = on;
    renderer.toneMapping = on ? T.ACESFilmicToneMapping : T.NoToneMapping;
    renderer.toneMappingExposure = on ? 1.2 : 1;
    renderer.setPixelRatio(level === 2 ? Math.min(window.devicePixelRatio || 1, 2) : level === 1 ? 1 : 0.5);
    resize();
    applyVisibility();
    if (on) envDirty = true; else scene.environment = null;
    for (const m of winMats) { m.metalness = on ? 0.75 : 0.2; m.roughness = on ? 0.12 : 0.22; }
    for (const m of carPaint) { m.metalness = on ? 0.6 : 0.3; m.roughness = on ? 0.28 : 0.4; }
    for (const [m, t, k] of bumpList) { m.bumpMap = on ? t : null; m.bumpScale = k; m.needsUpdate = true; }
  };

  /* ---------- 程序化贴图：全部用 canvas 现画，不加载图片资源 ---------- */
  function tile(tex) {
    tex.wrapS = tex.wrapT = T.RepeatWrapping;
    tex.anisotropy = renderer.capabilities.getMaxAnisotropy();
    return tex;
  }
  function speckle(g, w, h, n, rgb, spread, alpha) {
    for (let i = 0; i < n; i++) {
      const k = (Math.random() - 0.5) * spread;
      g.fillStyle = `rgba(${(rgb[0] + k) | 0},${(rgb[1] + k) | 0},${(rgb[2] + k) | 0},${alpha})`;
      g.fillRect(Math.random() * w, Math.random() * h, 1 + Math.random() * 2.5, 1 + Math.random() * 2.5);
    }
  }
  const TEX = {};
  function buildTextures() {
    TEX.asphalt = tile(canvasTex(256, 256, (g, w, h) => {
      g.fillStyle = '#2c3037'; g.fillRect(0, 0, w, h); speckle(g, w, h, 6000, [70, 74, 80], 90, 0.5);
    }).tex);
    TEX.paving = tile(canvasTex(256, 256, (g, w, h) => {
      g.fillStyle = '#7f8993'; g.fillRect(0, 0, w, h); speckle(g, w, h, 3500, [128, 137, 147], 70, 0.4);
      for (let r = 0; r < 4; r++) for (let c = -1; c < 4; c++) {
        const x = c * 64 + (r % 2) * 32, y = r * 64;
        g.fillStyle = `rgba(255,255,255,${Math.random() * 0.07})`; g.fillRect(x, y, 64, 64);
        g.strokeStyle = 'rgba(38,46,56,.75)'; g.lineWidth = 2; g.strokeRect(x, y, 64, 64);
      }
    }).tex);
    TEX.grass = tile(canvasTex(256, 256, (g, w, h) => {
      g.fillStyle = '#3d6a3a'; g.fillRect(0, 0, w, h);
      for (let i = 0; i < 7000; i++) {
        const k = Math.random();
        g.fillStyle = `rgba(${(30 + k * 50) | 0},${(80 + k * 90) | 0},${(30 + k * 40) | 0},.55)`;
        g.fillRect(Math.random() * w, Math.random() * h, 1.5, 2 + Math.random() * 3);
      }
    }).tex);
    TEX.concrete = tile(canvasTex(256, 256, (g, w, h) => {
      g.fillStyle = '#6a737d'; g.fillRect(0, 0, w, h); speckle(g, w, h, 5000, [106, 115, 125], 60, 0.4);
      g.strokeStyle = 'rgba(30,36,44,.5)'; g.lineWidth = 2; g.strokeRect(0, 0, w, h);
    }).tex);
    // 周边楼：8 开间 × 8 层的可平铺立面
    const cityDraw = (lit) => (g, w, h) => {
      g.fillStyle = lit ? '#000' : '#8c949d'; g.fillRect(0, 0, w, h);
      if (!lit) speckle(g, w, h, 2500, [140, 148, 157], 50, 0.35);
      for (let r = 0; r < 8; r++) for (let c = 0; c < 8; c++) {
        if (lit) { if (Math.random() > 0.3) continue; g.fillStyle = Math.random() < 0.75 ? '#ffd58a' : '#bfe2ff'; }
        else { const k = 0.7 + Math.random() * 0.3; g.fillStyle = `rgb(${(52 * k) | 0},${(78 * k) | 0},${(108 * k) | 0})`; }
        g.fillRect(c * 32 + 5, r * 32 + 7, 22, 18);
      }
    };
    TEX.city = tile(canvasTex(256, 256, cityDraw(false)).tex);
    TEX.cityLit = tile(canvasTex(256, 256, cityDraw(true)).tex);
    // 裙楼：上部石材挂板，下部玻璃店面
    TEX.podium = tile(canvasTex(512, 256, (g, w, h) => {
      g.fillStyle = '#b0aa9c'; g.fillRect(0, 0, w, h); speckle(g, w, h, 5000, [176, 170, 156], 50, 0.4);
      g.strokeStyle = 'rgba(70,66,58,.6)'; g.lineWidth = 2;
      for (let x = 0; x <= w; x += 64) { g.beginPath(); g.moveTo(x, 0); g.lineTo(x, 96); g.stroke(); }
      g.beginPath(); g.moveTo(0, 48); g.lineTo(w, 48); g.stroke();
      const gl = g.createLinearGradient(0, 100, 0, h);
      gl.addColorStop(0, '#3f6488'); gl.addColorStop(1, '#16283c');
      g.fillStyle = gl; g.fillRect(0, 100, w, h - 100);
      g.fillStyle = '#d5dae0';
      for (let x = 0; x <= w; x += 64) g.fillRect(x - 2, 100, 4, h - 100);
      g.fillRect(0, 96, w, 8); g.fillRect(0, 170, w, 3);
      g.fillStyle = '#4a4f57'; g.fillRect(0, h - 10, w, 10);
    }).tex);
  }
  // 按真实尺寸缩放 UV，让同一张可平铺贴图在不同大小的面上密度一致
  function planeUV(geo, su, sv) {
    const uv = geo.attributes.uv;
    for (let i = 0; i < uv.count; i++) uv.setXY(i, uv.getX(i) * su, uv.getY(i) * sv);
  }
  function boxUV(geo, w, h, d, uSide, vSide, uTop) {
    const uv = geo.attributes.uv;
    const sc = [[d / uSide, h / vSide], [d / uSide, h / vSide], [w / uTop, d / uTop], [w / uTop, d / uTop], [w / uSide, h / vSide], [w / uSide, h / vSide]];
    for (let f = 0; f < 6; f++) for (let k = 0; k < 4; k++) {
      const i = f * 4 + k; uv.setXY(i, uv.getX(i) * sc[f][0], uv.getY(i) * sc[f][1]);
    }
  }
  function flat(w, d, mat, x, y, z, unit, order) {
    const geo = new T.PlaneGeometry(w, d); planeUV(geo, w / unit, d / unit);
    const m = new T.Mesh(geo, mat);
    m.receiveShadow = true;
    m.rotation.x = -Math.PI / 2; m.position.set(x, y, z); m.renderOrder = order;
    gSurface.add(m);
    return m;
  }

  /* ---------- 地面、道路、绿化 ---------- */
  function buildGround() {
    groundMat = new T.MeshStandardMaterial({ map: TEX.paving, transparent: true, opacity: 0.5, depthWrite: false, roughness: 0.95 });
    // 地面在两侧坡道上方留出洞口，地面不透视时车辆仍能看着驶入地库
    const shape = new T.Shape([new T.Vector2(-150, -150), new T.Vector2(150, -150), new T.Vector2(150, 150), new T.Vector2(-150, 150)]);
    for (const sx of [-1, 1]) {
      const a = sx * 10.4, b = sx * 28;   // 北侧：东边是入库坡道（约 1 点钟方向），西边是出库坡道
      shape.holes.push(new T.Path([new T.Vector2(a, 33.5), new T.Vector2(b, 33.5), new T.Vector2(b, 38.5), new T.Vector2(a, 38.5)]));
    }
    const gg = new T.ShapeGeometry(shape); planeUV(gg, 1 / 6, 1 / 6);
    const ground = new T.Mesh(gg, groundMat);
    ground.rotation.x = -Math.PI / 2; ground.renderOrder = 3; ground.receiveShadow = true; gSurface.add(ground);
    bumpList.push([groundMat, TEX.paving, 3]);
    const grid = new T.GridHelper(300, 60, 0x3b86d6, 0x215089);
    grid.material.transparent = true; grid.material.opacity = 0.12; grid.position.y = 0.02; grid.renderOrder = 8;
    gSurface.add(grid);

    roadMat = new T.MeshStandardMaterial({ map: TEX.asphalt, transparent: true, opacity: 1, depthWrite: false, roughness: 0.9 });
    bumpList.push([roadMat, TEX.asphalt, 2]);
    flat(300, 12, roadMat, 0, 0.03, 54, 8, 4);
    flat(13, 44, roadMat, -42, 0.03, 26, 8, 4);               // 西侧出口广场（三车道）
    flat(5, 42.5, roadMat, -42, 0.03, -17.25, 8, 4);          // 西侧环路
    flat(13, 12.5, roadMat, 19, 0.03, 41.75, 8, 4);           // 入口广场（三车道，草坪南侧）
    flat(19, 5, roadMat, 35, 0.03, 38, 8, 4);                 // 进闸后右转的东行车道
    flat(5, 79, roadMat, 42, 0.03, 1, 8, 4);                  // 东侧环路（北行）
    for (const sx of [-1, 1]) flat(16.5, 5, roadMat, sx * 36.25, 0.03, C.NORTH, 8, 4); // 北侧环路（坡道口两端）
    flat(20, 5, roadMat, 0, 0.03, C.NORTH, 8, 4);

    // 草坪与树
    lawnMat = new T.MeshStandardMaterial({ map: TEX.grass, transparent: true, opacity: 0.6, depthWrite: false, roughness: 1 });
    const lawns = [[-56, 3, 8, 86], [56, 3, 8, 86], [-34.5, -14, 6.5, 34], [34.5, -14, 6.5, 34], [-19, 32, 22, 22], [19, 27.5, 22, 13]];
    const trunkM = new T.MeshStandardMaterial({ color: 0x6b4a2f, roughness: 1 });
    const leafM = new T.MeshStandardMaterial({ color: 0x3f8a45, roughness: 0.9, flatShading: true });
    const spots = [];
    for (const [x, z, w, d] of lawns) {
      flat(w, d, lawnMat, x, 0.035, z, 8, 4);
      const n = Math.max(3, Math.round((w * d) / 150));
      for (let i = 0; i < n; i++) spots.push([x + (Math.random() - 0.5) * (w - 5), z + (Math.random() - 0.5) * (d - 5), 0.8 + Math.random() * 0.5]);
    }
    const trunks = new T.InstancedMesh(new T.CylinderGeometry(0.22, 0.3, 2.4, 6), trunkM, spots.length);
    const crowns = new T.InstancedMesh(new T.IcosahedronGeometry(2.1, 0), leafM, spots.length);
    const m4 = new T.Matrix4(), q = new T.Quaternion(), v = new T.Vector3(), sc = new T.Vector3();
    spots.forEach(([x, z, k], i) => {
      m4.compose(v.set(x, 1.2 * k, z), q, sc.set(k, k, k)); trunks.setMatrixAt(i, m4);
      q.setFromAxisAngle(T.Object3D.DEFAULT_UP, Math.random() * 6);
      m4.compose(v.set(x, 3.6 * k, z), q, sc.set(k, k * 1.15, k)); crowns.setMatrixAt(i, m4);
      q.identity();
    });
    trunks.castShadow = crowns.castShadow = true;
    gSurface.add(trunks, crowns);

    const ln = [];
    for (let x = -148; x < 148; x += 8) ln.push(x, 0.06, 54, x + 4, 0.06, 54);
    lineSegs(ln, 0xffd166, 0.8, gSurface);
    lineSegs([-150, 0.06, 48, 150, 0.06, 48, -150, 0.06, 60, 150, 0.06, 60], 0xe8eef5, 0.6, gSurface);
    // 园区红线
    lineSegs([-62, 0.06, -42, 62, 0.06, -42, 62, 0.06, -42, 62, 0.06, 48, -62, 0.06, 48, -62, 0.06, -42], 0x4cc9ff, 0.5, gSurface);
    // 车道分隔线与停止线
    const dl = [];
    for (const x of [36, 40, 44, 48]) dl.push(-x, 0.06, 16, -x, 0.06, 48);
    for (const x of [13, 17, 21, 25]) dl.push(x, 0.06, 40.5, x, 0.06, 48);
    for (const x of C.IN) dl.push(x - 1.8, 0.06, C.IN_Z + 1.2, x + 1.8, 0.06, C.IN_Z + 1.2);
    for (const x of C.OUT) dl.push(x - 1.8, 0.06, C.GATE_Z - 1.2, x + 1.8, 0.06, C.GATE_Z - 1.2);
    lineSegs(dl, 0xffffff, 0.7, gSurface);
  }

  /* ---------- 办公楼 ---------- */
  // 整面玻璃幕墙：每层上沿是层间板，下面是带竖梃的玻璃；夜间随机亮灯
  function facade(cols, rows, W, H) {
    const cw = W / cols, rh = H / rows, lit = [];
    const map = canvasTex(W, H, (g) => {
      g.fillStyle = '#aeb8c2'; g.fillRect(0, 0, W, H);
      for (let r = 0; r < rows; r++) {
        g.fillStyle = '#33465c'; g.fillRect(0, r * rh, W, rh * 0.2);
        for (let c = 0; c < cols; c++) {
          const t = r / rows, k = 0.78 + Math.random() * 0.22;
          const x = c * cw + 2, y = r * rh + rh * 0.22, w = cw - 4, h = rh * 0.78 - 2;
          g.fillStyle = `rgb(${((112 - 58 * t) * k) | 0},${((162 - 66 * t) * k) | 0},${((208 - 62 * t) * k) | 0})`;
          g.fillRect(x, y, w, h);
          g.fillStyle = 'rgba(255,255,255,.10)'; g.fillRect(x, y, w * 0.35, h);
          if (Math.random() < 0.14) { g.fillStyle = 'rgba(232,236,240,.4)'; g.fillRect(x, y, w, h * (0.3 + Math.random() * 0.4)); }
          lit.push(Math.random() < 0.4 ? (Math.random() < 0.72 ? '#ffd58a' : '#bfe2ff') : null);
        }
      }
    }).tex;
    const emis = canvasTex(W, H, (g) => {
      g.fillStyle = '#000'; g.fillRect(0, 0, W, H);
      lit.forEach((col, i) => {
        if (!col) return;
        const r = (i / cols) | 0, c = i % cols;
        g.fillStyle = col; g.fillRect(c * cw + 2, r * rh + rh * 0.22, cw - 4, rh * 0.78 - 2);
      });
    }).tex;
    map.anisotropy = emis.anisotropy = renderer.capabilities.getMaxAnisotropy();
    const m = new T.MeshStandardMaterial({ map, emissive: 0xffffff, emissiveMap: emis, emissiveIntensity: 0, transparent: true, opacity: 0.93, roughness: 0.22, metalness: 0.2 });
    winMats.push(m);
    return m;
  }
  function buildBuilding() {
    const roofMat = new T.MeshStandardMaterial({ map: TEX.concrete, roughness: 0.9 });
    const podMat = new T.MeshStandardMaterial({ map: TEX.podium, transparent: true, opacity: 0.95, roughness: 0.6 });
    const pod = box(60, 7, 38, [podMat, podMat, roofMat, roofMat, podMat, podMat], 0, 3.5, -9, gSurface); pod.renderOrder = 5;
    boxUV(pod.geometry, 60, 7, 38, 20, 7, 8);
    bumpList.push([podMat, TEX.podium, 2]);
    edges(pod, 0x9fdcff, 0.45);
    const wide = facade(23, 14, 1024, 1024), narrow = facade(14, 14, 512, 1024);
    const tower = box(46, 56, 28, [narrow, narrow, roofMat, roofMat, wide, wide], 0, 35, -10, gSurface);
    tower.renderOrder = 6;
    edges(tower, 0x9fdcff, 0.5);
    const roof = box(14, 4, 9, roofMat, 6, 65, -12, gSurface); edges(roof, 0x9fdcff, 0.4);
    lineSegs([-12, 63, -16, -12, 76, -16], 0xff5d6c, 0.9, gSurface);
    const name = textSprite(512, 96, 30);
    name.ctx.font = '700 54px ' + PT.FONT; name.ctx.textAlign = 'center'; name.ctx.textBaseline = 'middle';
    name.ctx.fillStyle = '#bfe6ff'; name.ctx.fillText('A 座 · 办公楼', 256, 50); name.tex.needsUpdate = true;
    name.sp.position.set(0, 82, -10); gSurface.add(name.sp);
  }

  /* ---------- 地下楼层 ---------- */
  function buildLevel(y, grp, level, name) {
    const fm = new T.MeshStandardMaterial({ map: TEX.concrete, color: 0x9db4d2, transparent: true, opacity: 0.62, depthWrite: false, roughness: 0.85 });
    const fg = new T.PlaneGeometry(96, 74); planeUV(fg, 12, 9.25);
    const f = new T.Mesh(fg, fm);
    f.rotation.x = -Math.PI / 2; f.position.set(0, y, -3); f.renderOrder = level === 1 ? 2 : 1;
    floorMats[level === 1 ? 'b1' : 'b2'] = fm;
    grp.add(f);
    const shell = new T.LineSegments(new T.EdgesGeometry(new T.BoxGeometry(96, 4.6, 74)),
      new T.LineBasicMaterial({ color: 0x4cc9ff, transparent: true, opacity: 0.6 }));
    shell.position.set(0, y + 2.3, -3);
    grp.add(shell);

    // 车位线 + 占用指示灯
    const sl = [], slEv = [];   // 普通车位线 / 充电车位线（绿色）
    const slots = PT.SLOTS.filter((s) => s.level === level);
    const lights = new T.InstancedMesh(new T.BoxGeometry(1.4, 0.08, 0.35), new T.MeshBasicMaterial(), slots.length);
    const m4 = new T.Matrix4(), free = new T.Color(0x3ddc97);
    slots.forEach((s, i) => {
      const x0 = s.x - 1.3, x1 = s.x + 1.3, zb = s.z + Math.sign(s.z - s.aisleZ) * 2.5, zf = s.z - Math.sign(s.z - s.aisleZ) * 2.5;
      (s.charger ? slEv : sl).push(x0, y + 0.04, zf, x0, y + 0.04, zb, x1, y + 0.04, zf, x1, y + 0.04, zb, x0, y + 0.04, zb, x1, y + 0.04, zb);
      m4.makeTranslation(s.x, y + 0.06, zf);
      lights.setMatrixAt(i, m4); lights.setColorAt(i, free);
      s.light = lights; s.lightIdx = i;
    });
    lights.instanceColor.needsUpdate = true;
    grp.add(lights);
    lineSegs(sl, 0xe6ecf2, 0.75, grp);
    lineSegs(slEv, 0x35d07f, 0.95, grp);

    // 立柱
    const colMat = new T.MeshStandardMaterial({ color: 0x2a5d94, transparent: true, opacity: 0.55 });
    const cols = new T.InstancedMesh(new T.BoxGeometry(0.6, 4.6, 0.6), colMat, 40);
    let n = 0;
    for (const sx of [-1, 1]) for (let k = 0; k < 5; k++) for (const z of [7, 1, -17, -23]) {
      m4.makeTranslation(sx * (8 + 5.6 * k), y + 2.3, z); cols.setMatrixAt(n++, m4);
    }
    grp.add(cols);

    // 电梯核心筒
    // 充电桩：背靠墙的两排车位，每个车位一台，指示灯颜色表示 空闲 / 充电中 / 已充满
    const ch = slots.filter((s) => s.charger);
    const wallMat = new T.MeshStandardMaterial({ map: TEX.concrete, color: 0xb8c4d2, transparent: true, opacity: 0.82 });
    for (const sx of [-1, 1]) for (const wz of [-28.78, 12.78]) box(24, 3.2, 0.3, wallMat, sx * 19.2, y + 1.6, wz, grp);
    const cBody = new T.InstancedMesh(new T.BoxGeometry(0.5, 1.5, 0.32), new T.MeshStandardMaterial({ color: 0xe6edf5, roughness: 0.5 }), ch.length);
    const cLight = new T.InstancedMesh(new T.BoxGeometry(0.36, 0.55, 0.08), new T.MeshBasicMaterial(), ch.length);
    // 桩顶状态灯：绿 = 空闲无车，红 = 充电中，黄 = 有车未充电
    const cLamp = new T.InstancedMesh(new T.SphereGeometry(0.3, 12, 8), new T.MeshBasicMaterial(), ch.length);
    ch.forEach((s, i) => {
      const d = Math.sign(s.z - s.aisleZ), hz = s.z + d * 2.95;
      m4.makeTranslation(s.x, y + 0.75, hz); cBody.setMatrixAt(i, m4);
      m4.makeTranslation(s.x, y + 1.05, hz - d * 0.18); cLight.setMatrixAt(i, m4); cLight.setColorAt(i, CH_COL.free);
      m4.makeTranslation(s.x, y + 1.78, hz); cLamp.setMatrixAt(i, m4); cLamp.setColorAt(i, CH_COL.free);
      s.cLight = cLight; s.cLamp = cLamp; s.cIdx = i;
    });
    cLight.instanceColor.needsUpdate = cLamp.instanceColor.needsUpdate = true;
    grp.add(cBody, cLight, cLamp);

    const core = box(4, 4.6, 16, new T.MeshStandardMaterial({ color: 0x1b4472, transparent: true, opacity: 0.75 }), 0, y + 2.3, -8, grp);
    edges(core, 0x7fe0ff, 0.9);

    const lb = textSprite(128, 64, 9);
    lb.ctx.font = '700 48px ' + PT.FONT; lb.ctx.textAlign = 'center'; lb.ctx.textBaseline = 'middle';
    lb.ctx.fillStyle = '#7fe0ff'; lb.ctx.fillText(name, 64, 34); lb.tex.needsUpdate = true;
    lb.sp.position.set(-53, y + 2.5, 34); grp.add(lb.sp);
  }
  const CH_COL = { free: new T.Color(0x2ee66b), charging: new T.Color(0xff2d3d), occupied: new T.Color(0xffc21a), dim: new T.Color(0x4a3906), fault: new T.Color(0xe23cff) };
  PT.setChargerLight = function (slot, state) {
    if (!slot.cLight) return;
    for (const m of [slot.cLight, slot.cLamp]) { m.setColorAt(slot.cIdx, CH_COL[state]); m.instanceColor.needsUpdate = true; }
  };
  PT.setSlotLight = function (slot, occupied, temp) {
    slot.light.setColorAt(slot.lightIdx, new T.Color(occupied ? (temp ? 0xffb23e : 0x4c8dff) : 0x3ddc97));
    slot.light.instanceColor.needsUpdate = true;
  };

  function buildRamps() {
    const rm = new T.MeshStandardMaterial({ color: 0x56626f, transparent: true, opacity: 0.88, side: T.DoubleSide, depthWrite: false });
    for (const sx of [-1, 1]) {
      // 地面 ↔ B1：北侧环路上，东边入库、西边出库
      quad([sx * 28, 0, -38.5], [sx * 28, 0, -33.5], [sx * 10, C.Y1, -33.5], [sx * 10, C.Y1, -38.5], rm, gB1, 0x7fe0ff);
      // B1 ↔ B2：东边下行、西边上行
      quad([sx * 8, C.Y1, -10.5], [sx * 8, C.Y1, -5.5], [sx * 26, C.Y2, -5.5], [sx * 26, C.Y2, -10.5], rm, gB2, 0x7fe0ff);
    }
  }
  // 流畅档不画地库时，用一块深色斜面填住坡道洞口，避免洞里露出天空色
  function buildRampStub() {
    rampStub = new T.Group(); rampStub.visible = false; gSurface.add(rampStub);
    const m = new T.MeshBasicMaterial({ color: 0x20262e, side: T.DoubleSide });
    for (const sx of [-1, 1]) {
      const x0 = sx * 28, x1 = sx * 10.4;
      quad([x0, 0, -38.5], [x0, 0, -33.5], [x1, C.Y1, -33.5], [x1, C.Y1, -38.5], m, rampStub);
      // 坡道坑的两侧墙和尽头墙
      for (const z of [-38.5, -33.5]) quad([x0, 0, z], [x1, 0, z], [x1, C.Y1, z], [x1, C.Y1, z], m, rampStub);
      quad([x1, 0, -38.5], [x1, 0, -33.5], [x1, C.Y1, -33.5], [x1, C.Y1, -38.5], m, rampStub);
    }
  }
  /* ---------- 出入口之间的小餐厅 ---------- */
  function buildShop() {
    const wall = canvasTex(256, 128, (g, w, h) => {
      g.fillStyle = '#f4efe6'; g.fillRect(0, 0, w, h);
      g.fillStyle = '#c8102e'; g.fillRect(0, 0, w, 24);
      for (let x = 0; x < w; x += 16) { g.fillStyle = (x / 16) % 2 ? '#c8102e' : '#ffffff'; g.fillRect(x, 24, 16, 12); }
      g.fillStyle = '#27445f'; for (let x = 12; x < w; x += 64) g.fillRect(x, 52, 40, 60);
      g.fillStyle = 'rgba(255,255,255,.18)'; for (let x = 12; x < w; x += 64) g.fillRect(x, 52, 14, 60);
      g.fillStyle = '#8a8f96'; g.fillRect(0, h - 8, w, 8);
    }).tex;
    tile(wall);
    const wm = new T.MeshStandardMaterial({ map: wall, roughness: 0.7 });
    const red = new T.MeshStandardMaterial({ color: 0xc8102e, roughness: 0.6 });
    const body = box(12, 4, 8, [wm, wm, red, red, wm, wm], 0, 2, 34, gSurface);
    boxUV(body.geometry, 12, 4, 8, 12, 4, 12);
    box(13.2, 0.5, 9.2, red, 0, 4.25, 34, gSurface);
    const sign = textSprite(384, 128, 9);
    const x = sign.ctx;
    x.fillStyle = '#c8102e'; x.beginPath(); x.roundRect(4, 4, 376, 120, 18); x.fill();
    x.strokeStyle = '#fff'; x.lineWidth = 5; x.stroke();
    x.fillStyle = '#fff'; x.textAlign = 'center'; x.textBaseline = 'middle';
    x.font = '700 62px ' + PT.FONT; x.fillText('肯德基 KFC', 192, 66);
    sign.tex.needsUpdate = true;
    sign.sp.position.set(0, 7, 34); gSurface.add(sign.sp);
  }
  /* ---------- 路灯、周边体块、星空 ---------- */
  function buildLampsAndCity() {
    glowMat = new T.SpriteMaterial({ map: glowTex, color: 0xffe2a6, transparent: true, opacity: 0, blending: T.AdditiveBlending, depthWrite: false });
    poolMat = new T.MeshBasicMaterial({ map: glowTex, color: 0xffd58a, transparent: true, opacity: 0, blending: T.AdditiveBlending, depthWrite: false });
    const poleMat = new T.MeshStandardMaterial({ color: 0x5a7fa8 });
    const poolGeo = new T.PlaneGeometry(22, 22); poolGeo.rotateX(-Math.PI / 2);
    for (let x = -130; x <= 130; x += 20) {
      box(0.25, 7, 0.25, poleMat, x, 3.5, 47, gSurface);
      const s = new T.Sprite(glowMat); s.scale.set(5, 5, 1); s.position.set(x, 7.2, 47); s.renderOrder = 8; gSurface.add(s);
      const p = new T.Mesh(poolGeo, poolMat); p.position.set(x, 0.09, 50); p.renderOrder = 8; gSurface.add(p);
    }
    cityMat = [0xffffff, 0xe2d6c6, 0xc6d6e8].map((c) => new T.MeshStandardMaterial({ map: TEX.city, color: c, emissive: 0xffffff, emissiveMap: TEX.cityLit, emissiveIntensity: 0, roughness: 0.85 }));
    for (const m of cityMat) bumpList.push([m, TEX.city, 2]);
    const cityRoof = new T.MeshStandardMaterial({ map: TEX.concrete, roughness: 0.95 });
    [[-100, 22, -20, 36, 44], [-104, 14, -78, 44, 40], [100, 30, -30, 34, 50], [98, 12, 14, 30, 24], [-30, 18, -90, 50, 30],
      [40, 26, -92, 44, 30], [-70, 16, 92, 60, 30], [10, 22, 96, 50, 34], [84, 14, 90, 46, 28], [-98, 10, 22, 30, 26]]
      .forEach(([x, h, z, w, d], i) => {
        const sm = cityMat[i % 3];
        const b = box(w, h, d, [sm, sm, cityRoof, cityRoof, sm, sm], x, h / 2, z, gSurface);
        boxUV(b.geometry, w, h, d, 32, 32, 10);
      });

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
    rain.renderOrder = 60; rain.frustumCulled = false; rain.visible = false; scene.add(rain);

    const NS = 4000, spos = new Float32Array(NS * 3);
    for (let i = 0; i < NS; i++) spos.set([(Math.random() - 0.5) * 280, Math.random() * 110 - 12, (Math.random() - 0.5) * 240], i * 3);
    const sg = new T.BufferGeometry(); sg.setAttribute('position', new T.BufferAttribute(spos, 3));
    snow = new T.Points(sg, new T.PointsMaterial({ map: glowTex, color: 0xffffff, size: 1.5, transparent: true, opacity: 0, depthWrite: false }));
    snow.renderOrder = 60; snow.frustumCulled = false; snow.visible = false; scene.add(snow);
  }
  // 单看 B1 / B2 时在室内，天气不起作用；雨雪也只落到地面，不会穿进地库
  const indoors = () => floorMode === 'b1' || floorMode === 'b2';
  function updateWeather(dt, t) {
    const out = !indoors();
    if (out && env.wr > 0.01) {
      rain.visible = true; rain.material.opacity = 0.75 * env.wr;
      const a = rain.geometry.attributes.position.array, d = 85 * dt;
      for (let i = 1; i < a.length; i += 6) {
        a[i] -= d; a[i + 3] -= d;
        if (a[i + 3] < 0) { a[i] += 98; a[i + 3] += 98; }
      }
      rain.geometry.attributes.position.needsUpdate = true;
    } else rain.visible = false;
    if (out && env.ws > 0.01) {
      snow.visible = true; snow.material.opacity = 0.9 * env.ws;
      const a = snow.geometry.attributes.position.array;
      for (let i = 0; i < a.length; i += 3) {
        a[i + 1] -= 7 * dt; a[i] += Math.sin(t * 0.8 + i) * 1.2 * dt;
        if (a[i + 1] < 0) a[i + 1] += 98;
      }
      snow.geometry.attributes.position.needsUpdate = true;
    } else snow.visible = false;
  }

  const cGD = new T.Color(0x8c9aa9), cGN = new T.Color(0x131b28), cMoon = new T.Color(0xcfd8ff);
  const cTopD = new T.Color(0x3a7bd0), cTopN = new T.Color(0x02050d), cHorD = new T.Color(0xa9c9ea), cHorN = new T.Color(0x0e1a31);
  const cGndD = new T.Color(0x6c747e), cGndN = new T.Color(0x05080f);
  const cSunD = new T.Color(0xfff1dc), cSunN = new T.Color(0x86a4ff), tA = new T.Color(), tB = new T.Color();
  function updateEnv(dt) {
    const k = Math.min(1, dt * 2.2), w = env.weather;
    env.n += ((env.night ? 1 : 0) - env.n) * k;
    env.wr += ((w === 'rain' ? 1 : 0) - env.wr) * k;
    env.ws += ((w === 'snow' ? 1 : 0) - env.ws) * k;
    env.wf += ((w === 'fog' ? 1 : 0) - env.wf) * k;
    const ov = indoors() ? 0 : Math.max(env.wr * 0.7, env.ws * 0.8, env.wf);   // 室内不受阴天压暗
    tB.copy(cGD).lerp(cGN, env.n);
    sTop.copy(cTopD).lerp(cTopN, env.n).lerp(tB, ov * 0.85);
    sHor.copy(cHorD).lerp(cHorN, env.n).lerp(tB, ov * 0.85);
    sGnd.copy(cGndD).lerp(cGndN, env.n);
    scene.background.copy(sHor); scene.fog.color.copy(sHor);
    const key = Math.round(env.n * 40) + '|' + Math.round(ov * 40);
    if (key !== skyKey) { skyKey = key; paintSky(); envDirty = true; }
    if (hq && envDirty) { refreshEnvMap(); envDirty = false; }
    sunSprite.material.opacity = (1 - ov) * 0.95;
    sunSprite.material.color.copy(cSunD).lerp(cMoon, env.n);
    sunSprite.scale.setScalar(lerp(190, 70, env.n));
    scene.fog.density = 0.0011 + (indoors() ? 0 : 0.0026 * env.wr + 0.0034 * env.ws + 0.0115 * env.wf);
    hemi.intensity = lerp(1.5, 0.62, env.n) * (1 - 0.2 * ov) * (hq ? 0.6 : 1);
    sun.intensity = lerp(2.6, 0.5, env.n) * (1 - 0.6 * ov);
    // 雨天路面变湿：降低粗糙度，高画质下会反射天空
    roadMat.roughness = lerp(0.9, 0.25, env.wr); groundMat.roughness = lerp(0.95, 0.45, env.wr);
    sun.color.copy(cSunD).lerp(cSunN, env.n);
    for (const m of winMats) m.emissiveIntensity = env.n * 1.5;
    for (const m of cityMat) m.emissiveIntensity = env.n * 1.1;
    glowMat.opacity = env.n * 0.95; poolMat.opacity = env.n * 0.3;
    starMat.opacity = env.n * (1 - ov) * 0.9;
    beamMat.opacity = env.n * 0.5; beamMat.visible = env.n > 0.03;
  }

  /* ---------- 楼层显示 ---------- */
  // 流畅档下，被不透明楼板完全挡住的楼层干脆不画，省掉大量像素填充
  const hiddenBy = (lv) => qLevel === 0 && floorMode === 'all' && (!see.ground || (lv === 'b2' && !see.b1));
  function applyVisibility() {
    const m = floorMode;
    gSurface.visible = m === 'all' || m === 'ground';
    gB1.visible = (m === 'all' || m === 'b1') && !hiddenBy('b1');
    gB2.visible = (m === 'all' || m === 'b2') && !hiddenBy('b2');
    if (skyDome) skyDome.visible = qLevel > 0;
    if (rampStub) rampStub.visible = hiddenBy('b1');
  }
  PT.setFloorMode = function (m) { floorMode = m; applyVisibility(); };
  // 逐层透视开关：关闭后该层楼板变为不透明，遮住下方楼层
  PT.setSee = function (layer, on) {
    see[layer] = on;
    groundMat.opacity = see.ground ? 0.5 : 1;
    lawnMat.opacity = see.ground ? 0.6 : 1;
    floorMats.b1.opacity = see.b1 ? 0.62 : 1;
    floorMats.b2.opacity = see.b2 ? 0.62 : 1;
    // 不透视的楼板写入深度，彻底挡住下方的车辆、线条和灯光
    groundMat.depthWrite = !see.ground; floorMats.b1.depthWrite = !see.b1; floorMats.b2.depthWrite = !see.b2;
    applyVisibility();
  };
  PT.getSee = () => see;
  PT.getFloorMode = () => floorMode;
  PT.carVisible = function (y) {
    const lv = y > -2.5 ? 'ground' : y > -7.5 ? 'b1' : 'b2';
    if (floorMode !== 'all') return lv === floorMode;
    return lv === 'ground' || !hiddenBy(lv);
  };

  /* ---------- 车辆模型（程序生成：侧面轮廓拉伸的车身 + 车窗 + 车轮 + 灯具 + 车牌 + 车顶标记） ---------- */
  // prof：侧面轮廓（u 沿车长，前为正；v 为高度）。g：车窗带 [后窗底u, 后窗底v, 后窗顶u, 车顶v, 前窗顶u, 前窗底u, 前窗底v]
  const MODELS = (PT.CAR_MODELS = [
    { name: '轿车', L: 4.6, W: 1.8, r: 0.33, hl: 0.68, tl: 0.72, roofZ: -0.35,
      prof: [[-2.3, 0.3], [-2.3, 0.85], [-1.7, 0.95], [-1.1, 1.42], [0.35, 1.42], [1.15, 0.95], [2.2, 0.82], [2.3, 0.6], [2.3, 0.3]], g: [-1.7, 0.95, -1.1, 1.42, 0.35, 1.15, 0.95] },
    { name: 'SUV', L: 4.7, W: 1.9, r: 0.37, hl: 0.84, tl: 0.92, roofZ: -0.85,
      prof: [[-2.35, 0.38], [-2.35, 1.05], [-2.2, 1.7], [0.45, 1.7], [1.25, 1.1], [2.25, 1.0], [2.35, 0.72], [2.35, 0.38]], g: [-2.35, 1.05, -2.2, 1.7, 0.45, 1.25, 1.1] },
    { name: '两厢车', L: 4.0, W: 1.75, r: 0.31, hl: 0.68, tl: 0.75, roofZ: -0.75,
      prof: [[-2, 0.3], [-2, 0.9], [-1.75, 1.46], [0.25, 1.46], [1.0, 0.93], [1.9, 0.82], [2, 0.6], [2, 0.3]], g: [-2, 0.9, -1.75, 1.46, 0.25, 1.0, 0.93] },
    { name: 'MPV', L: 4.9, W: 1.9, r: 0.35, hl: 0.8, tl: 0.96, roofZ: -0.6,
      prof: [[-2.45, 0.36], [-2.45, 1.15], [-2.35, 1.82], [1.15, 1.82], [2.0, 1.12], [2.4, 0.98], [2.45, 0.62], [2.45, 0.36]], g: [-2.45, 1.15, -2.35, 1.82, 1.15, 2.0, 1.12] },
  ]);
  const PAINTS = [0xf1f1ee, 0xc7ccd1, 0x1c1e22, 0x6c7178, 0xb0202b, 0x1f4fa3, 0x2f5d50, 0xcbb994, 0x7c8ea3, 0x8a2f3c];
  PT.CAR_PAINTS = PAINTS.length;
  const carGeo = {}, carMat = {};
  function mergeGeos(list) {
    const pos = [], nor = [], uv = [];
    for (const g0 of list) {
      const g = g0.index ? g0.toNonIndexed() : g0;
      pos.push(...g.attributes.position.array); nor.push(...g.attributes.normal.array); uv.push(...g.attributes.uv.array);
    }
    const out = new T.BufferGeometry();
    out.setAttribute('position', new T.Float32BufferAttribute(pos, 3));
    out.setAttribute('normal', new T.Float32BufferAttribute(nor, 3));
    out.setAttribute('uv', new T.Float32BufferAttribute(uv, 2));
    return out;
  }
  const boxes = (list) => mergeGeos(list.map(([w, h, d, x, y, z]) => new T.BoxGeometry(w, h, d).translate(x, y, z)));
  function extrude(pts, width) {
    const g = new T.ExtrudeGeometry(new T.Shape(pts.map((p) => new T.Vector2(p[0], p[1]))), { depth: width, bevelEnabled: false });
    g.translate(0, 0, -width / 2); g.rotateY(-Math.PI / 2);   // 车长沿 z，车头朝 +z
    return g;
  }
  function initCarAssets() {
    for (const m of MODELS) {
      const [ub, vb, ur, vr, uf, uw, vb2] = m.g, f = m.L / 2, hx = m.W / 2 - 0.32, sx = m.W / 2 - 0.06;
      m.roofY = vr;
      m.body = extrude(m.prof, m.W);
      m.glassS = extrude([[ub + 0.14, vb + 0.05], [ur + 0.1, vr - 0.07], [uf - 0.1, vr - 0.07], [uw - 0.16, vb2 + 0.05]], m.W + 0.03);   // 侧窗
      m.glassF = extrude([[ub - 0.04, vb + 0.02], [ur - 0.04, vr - 0.02], [uf + 0.04, vr - 0.02], [uw + 0.04, vb2 + 0.02]], m.W - 0.22); // 前后挡风
      m.wheel = new T.CylinderGeometry(m.r, m.r, 0.24, 16).rotateZ(Math.PI / 2);
      m.head = boxes([[0.42, 0.15, 0.1, hx, m.hl, f - 0.03], [0.42, 0.15, 0.1, -hx, m.hl, f - 0.03]]);
      m.tail = boxes([[0.4, 0.15, 0.1, hx, m.tl, -f + 0.03], [0.4, 0.15, 0.1, -hx, m.tl, -f + 0.03]]);
      m.rev = boxes([[0.22, 0.08, 0.08, 0.5, m.tl - 0.18, -f + 0.03]]);
      m.sigL = boxes([[0.14, 0.12, 0.12, sx, m.hl, f - 0.05], [0.14, 0.12, 0.12, sx, m.tl, -f + 0.05]]);
      m.sigR = boxes([[0.14, 0.12, 0.12, -sx, m.hl, f - 0.05], [0.14, 0.12, 0.12, -sx, m.tl, -f + 0.05]]);
      m.plate = mergeGeos([new T.PlaneGeometry(0.62, 0.2).translate(0, 0.46, f + 0.012), new T.PlaneGeometry(0.62, 0.2).rotateY(Math.PI).translate(0, 0.5, -f - 0.012)]);
      // 流畅档用的简化车身
      m.simple = boxes([[m.W, 0.62, m.L, 0, 0.6, 0], [m.W - 0.2, 0.5, m.L * 0.52, 0, 1.15, -0.25]]);
    }
    carGeo.beam = new T.PlaneGeometry(2.8, 9); carGeo.beam.rotateX(-Math.PI / 2); carGeo.beam.translate(0, 0.08, 4.5);
    carGeo.blob = new T.PlaneGeometry(3.4, 6.4); carGeo.blob.rotateX(-Math.PI / 2);
    carGeo.mark = new T.PlaneGeometry(0.85, 0.85); carGeo.mark.rotateX(-Math.PI / 2); carGeo.mark.rotateY(Math.PI);   // 字头朝车头，从上往下看是正的
    carMat.paint = PAINTS.map((c) => new T.MeshStandardMaterial({ color: c, roughness: 0.4, metalness: 0.3 }));
    carPaint.push(...carMat.paint);
    carMat.glass = new T.MeshStandardMaterial({ color: 0x0b141f, roughness: 0.08, metalness: 0.7 });
    const hub = canvasTex(64, 64, (g) => {
      g.fillStyle = '#15171a'; g.fillRect(0, 0, 64, 64);
      g.fillStyle = '#b9c0c8'; g.beginPath(); g.arc(32, 32, 19, 0, 7); g.fill();
      g.strokeStyle = '#3a4048'; g.lineWidth = 4;
      for (let i = 0; i < 5; i++) { const a = (i * Math.PI * 2) / 5; g.beginPath(); g.moveTo(32, 32); g.lineTo(32 + 19 * Math.cos(a), 32 + 19 * Math.sin(a)); g.stroke(); }
      g.fillStyle = '#2a2f36'; g.beginPath(); g.arc(32, 32, 5, 0, 7); g.fill();
    }).tex;
    const tire = new T.MeshStandardMaterial({ color: 0x15171a, roughness: 0.95 }), rim = new T.MeshStandardMaterial({ map: hub, roughness: 0.5 });
    carMat.wheel = [tire, rim, rim];
    carMat.front = new T.MeshBasicMaterial({ color: 0xfff3c4 });
    carMat.white = new T.MeshBasicMaterial({ color: 0xffffff });
    carMat.amber = new T.MeshBasicMaterial({ color: 0xffa51f });
    carMat.alarm = PT.alarmMat = new T.MeshStandardMaterial({ color: 0xff2d44, emissive: 0xff2d44, emissiveIntensity: 1 });
    carMat.blob = new T.MeshBasicMaterial({ map: glowTex, color: 0x000000, transparent: true, opacity: 0.55, depthWrite: false });
    // 车顶标记：蓝底「月」= 月卡车，橙底「临」= 临时车
    const mark = (bg, ch) => new T.MeshBasicMaterial({ transparent: true, map: canvasTex(64, 64, (g) => {
      g.fillStyle = bg; g.beginPath(); g.arc(32, 32, 29, 0, 7); g.fill();
      g.strokeStyle = '#fff'; g.lineWidth = 4; g.stroke();
      g.fillStyle = '#fff'; g.font = '700 36px ' + PT.FONT; g.textAlign = 'center'; g.textBaseline = 'middle'; g.fillText(ch, 32, 34);
    }).tex });
    carMat.mark = { monthly: mark('#1f6fff', '月'), temp: mark('#ff7a1a', '临') };
    // 选中车辆的高亮圈
    const ring = (PT.selRing = new T.Mesh(new T.RingGeometry(2.9, 3.4, 48), new T.MeshBasicMaterial({ color: 0x7fe0ff, transparent: true, opacity: 0.95, side: T.DoubleSide, depthWrite: false })));
    ring.rotation.x = -Math.PI / 2; ring.renderOrder = 9; ring.visible = false; scene.add(ring);
    beamMat = new T.MeshBasicMaterial({ map: beamTex, color: 0xfff0c0, transparent: true, opacity: 0, blending: T.AdditiveBlending, depthWrite: false });
  }
  // 车牌贴图：绿牌（渐变绿底黑字）= 新能源，蓝牌（蓝底白字）= 燃油车
  function plateTex(look) {
    return canvasTex(128, 40, (g) => {
      if (look.ev) { const gr = g.createLinearGradient(0, 0, 128, 0); gr.addColorStop(0, '#f2faf2'); gr.addColorStop(1, '#35b35a'); g.fillStyle = gr; }
      else g.fillStyle = '#1447b8';
      g.fillRect(0, 0, 128, 40);
      g.strokeStyle = look.ev ? '#10331c' : '#fff'; g.lineWidth = 2; g.strokeRect(2, 2, 124, 36);
      g.fillStyle = look.ev ? '#0c1410' : '#fff'; g.font = `700 ${look.ev ? 21 : 23}px ` + PT.FONT; g.textAlign = 'center'; g.textBaseline = 'middle';
      g.fillText(look.plate, 64, 21);
    }).tex;
  }
  // look：{ type: 'monthly' | 'temp' | 'decor', model, color, ev, plate }
  PT.makeCarMesh = function (look) {
    const g = new T.Group(), m = MODELS[look.model], paint = carMat.paint[look.color], u = g.userData;
    const add = (geo, mat) => { const x = new T.Mesh(geo, mat); g.add(x); return x; };
    const simple = qLevel === 0;
    const body = add(simple ? m.simple : m.body, paint);
    body.castShadow = true; body.receiveShadow = true;
    u.body = body; u.baseMat = paint; u.model = m;
    u.tailMat = new T.MeshBasicMaterial({ color: 0x5e0c14 });
    add(m.head, carMat.front); add(m.tail, u.tailMat);
    if (!simple) {
      add(m.glassS, carMat.glass); add(m.glassF, carMat.glass);
      u.wheels = [];
      for (const [sx, sz] of [[1, 1], [-1, 1], [1, -1], [-1, -1]]) {   // 前两个是前轮，可转向
        const w = add(m.wheel, carMat.wheel);
        w.position.set(sx * (m.W / 2 - 0.1), m.r, sz * (m.L / 2 - 0.82)); w.rotation.order = 'YXZ';
        u.wheels.push(w);
      }
      u.rev = add(m.rev, carMat.white); u.sigL = add(m.sigL, carMat.amber); u.sigR = add(m.sigR, carMat.amber);
      u.rev.visible = u.sigL.visible = u.sigR.visible = false;
      const tex = plateTex(look);
      tex.anisotropy = renderer.capabilities.getMaxAnisotropy();
      u.plateMat = new T.MeshBasicMaterial({ map: tex });
      add(m.plate, u.plateMat);
    }
    if (carMat.mark[look.type]) { const mk = add(carGeo.mark, carMat.mark[look.type]); mk.position.set(0, (simple ? 1.4 : m.roofY) + 0.03, m.roofZ); mk.renderOrder = 7; }
    const beam = add(carGeo.beam, beamMat); beam.position.z = m.L / 2; beam.renderOrder = 8;
    // 车底柔和暗斑：没有实时阴影时也有贴地感
    const blob = add(carGeo.blob, carMat.blob); blob.position.y = 0.05; blob.scale.set(m.W / 1.8, 1, m.L / 4.4); blob.renderOrder = 8;
    beam.userData.noPick = blob.userData.noPick = true;
    u.dispose = () => { u.tailMat.dispose(); if (u.plateMat) { u.plateMat.map.dispose(); u.plateMat.dispose(); } };
    return g;
  };
  // 充电线：从充电桩到车头侧面的一条下垂曲线
  const cableMat = new T.LineBasicMaterial({ color: 0x9ff3ff });
  PT.addCable = function (slot, carLen) {
    const d = Math.sign(slot.z - slot.aisleZ);
    const a = new T.Vector3(slot.x, slot.y + 1.05, slot.z + d * 2.75), b = new T.Vector3(slot.x + 0.75, slot.y + 0.8, slot.z + d * (carLen / 2 - 0.9));
    const mid = a.clone().add(b).multiplyScalar(0.5); mid.y = slot.y + 0.15; mid.x += 0.5;
    const line = new T.Line(new T.BufferGeometry().setFromPoints(new T.QuadraticBezierCurve3(a, mid, b).getPoints(12)), cableMat);
    (slot.level === 1 ? gB1 : gB2).add(line);
    return line;
  };
  PT.removeCable = function (line) { if (line.parent) line.parent.remove(line); line.geometry.dispose(); };

  /* ---------- 闸机模型 ---------- */
  PT.buildGate = function (gate) {
    const z = gate.z, dirX = 1;
    const postMat = new T.MeshStandardMaterial({ color: 0x2c6cab, emissive: 0x143a66, emissiveIntensity: 0.6 });
    if (gate.booth) {
      const booth = box(1.5, 2.8, 2.6, new T.MeshStandardMaterial({ color: 0x1d4b7d, transparent: true, opacity: 0.9 }), gate.x + (gate.x > 0 ? 3.3 : -3.6), 1.4, z + 0.2, gSurface);
      edges(booth, 0x7fe0ff, 0.95);
    }
    const postX = gate.x - dirX * 1.75;
    box(0.5, 1.3, 0.5, postMat, postX, 0.65, z, gSurface);
    const pivot = new T.Group(); pivot.position.set(postX, 1.15, z); gSurface.add(pivot);
    const arm = new T.Mesh(new T.BoxGeometry(3.5, 0.16, 0.16), new T.MeshBasicMaterial({ color: 0xffe14d }));
    arm.position.x = dirX * 1.75; pivot.add(arm);
    const lamp = new T.Mesh(new T.SphereGeometry(0.22, 12, 8), new T.MeshBasicMaterial({ color: 0xff4d5e }));
    lamp.position.set(postX, 1.55, z); gSurface.add(lamp);

    const board = textSprite(320, 160, 3.7);
    // 信息牌始终画在最上层，不被路面、告警光柱、岗亭等半透明物体盖住
    board.sp.material.depthTest = false; board.sp.renderOrder = 999;
    board.sp.position.set(gate.x, 5.2, gate.kind === 'in' ? z - 3 : z + 4.5); gSurface.add(board.sp);

    const stopZ = gate.kind === 'in' ? z + 3.6 : z - 3.6;
    const alarm = new T.Group(); alarm.position.set(gate.x, 0, stopZ); alarm.visible = false; gSurface.add(alarm);
    const ring = new T.Mesh(new T.RingGeometry(3.4, 4.1, 48),
      new T.MeshBasicMaterial({ color: 0xff3048, transparent: true, opacity: 0.9, side: T.DoubleSide, depthWrite: false, blending: T.AdditiveBlending }));
    ring.rotation.x = -Math.PI / 2; ring.position.y = 0.12; ring.renderOrder = 8; alarm.add(ring);
    const beam = new T.Mesh(new T.CylinderGeometry(3.2, 3.2, 16, 32, 1, true),
      new T.MeshBasicMaterial({ color: 0xff3048, transparent: true, opacity: 0.14, side: T.DoubleSide, depthWrite: false, blending: T.AdditiveBlending }));
    beam.position.y = 8; beam.renderOrder = 8; alarm.add(beam);

    const hit = new T.Mesh(new T.BoxGeometry(3.8, 9, 9), new T.MeshBasicMaterial({ transparent: true, opacity: 0, depthWrite: false }));
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
    // 点选车辆：被不透明楼板挡住的地库车辆不可选
    PT.pickCar = function (cx, cy) {
      const r = canvas.getBoundingClientRect();
      ndc.set(((cx - r.left) / r.width) * 2 - 1, -((cy - r.top) / r.height) * 2 + 1);
      ray.setFromCamera(ndc, camera);
      for (const h of ray.intersectObjects(gCars.children, true)) {
        const grp = h.object.parent, c = grp.userData.car;
        if (h.object.userData.noPick || !c || !grp.visible) continue;
        const y = grp.position.y;
        if (floorMode === 'all' && ((y < -2.5 && !see.ground) || (y < -7.5 && !see.b1))) continue;
        return c;
      }
      return null;
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
      if (!p) { canvas.style.cursor = PT.pick(e.clientX, e.clientY) || PT.pickCar(e.clientX, e.clientY) ? 'pointer' : 'grab'; return; }
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
        if (PT.onPick) PT.onPick(PT.pick(e.clientX, e.clientY), PT.pickCar(e.clientX, e.clientY));
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
