/* 地面标线：车道边线、导向箭头、坡道口文字、让行线、车位编号、充电车位标识（B1 / B2 与地面环路） */
(function () {
  'use strict';
  const T = THREE, PT = window.PT, C = PT.C;

  // 把很多贴地小矩形合并成一个网格。f 是朝向（xz 平面单位向量，贴图的"上"指向 f），w 横向宽度，l 纵向长度
  function Quads() { this.pos = []; this.uv = []; }
  Quads.prototype.add = function (cx, y, cz, fx, fz, w, l, u0, v0, u1, v1) {
    const rx = -fz, rz = fx, hw = w / 2, hl = l / 2;   // r 是从上往下看、f 朝上时的"右"
    const A = [cx - rx * hw - fx * hl, cz - rz * hw - fz * hl], B = [cx + rx * hw - fx * hl, cz + rz * hw - fz * hl];
    const D = [cx - rx * hw + fx * hl, cz - rz * hw + fz * hl], E = [cx + rx * hw + fx * hl, cz + rz * hw + fz * hl];
    this.pos.push(A[0], y, A[1], B[0], y, B[1], E[0], y, E[1], A[0], y, A[1], E[0], y, E[1], D[0], y, D[1]);
    this.uv.push(u0, v0, u1, v0, u1, v1, u0, v0, u1, v1, u0, v1);
  };
  Quads.prototype.strip = function (ax, az, bx, bz, y, w) {   // 从 a 到 b 的一条实线
    const dx = bx - ax, dz = bz - az, l = Math.hypot(dx, dz);
    if (l > 0.01) this.add((ax + bx) / 2, y, (az + bz) / 2, dx / l, dz / l, w, l, 0, 0, 1, 1);
  };
  Quads.prototype.mesh = function (mat, parent, order) {
    if (!this.pos.length) return null;
    const g = new T.BufferGeometry();
    g.setAttribute('position', new T.Float32BufferAttribute(this.pos, 3));
    g.setAttribute('uv', new T.Float32BufferAttribute(this.uv, 2));
    g.computeVertexNormals();
    const m = new T.Mesh(g, mat);
    m.renderOrder = order; parent.add(m);
    return m;
  };
  function tex(w, h, draw) {
    const cv = document.createElement('canvas'); cv.width = w; cv.height = h;
    draw(cv.getContext('2d'), w, h);
    const t = new T.CanvasTexture(cv); t.colorSpace = T.SRGBColorSpace; t.anisotropy = 8;
    return t;
  }
  const decal = (map) => new T.MeshBasicMaterial({ map, transparent: true, depthWrite: false });

  PT.buildMarkings = function () {
    const R = PT.sim._.routes, WHITE = '#f3f6f9';
    const straight = decal(tex(64, 160, (g) => {
      g.fillStyle = WHITE; g.fillRect(24, 62, 16, 98);
      g.beginPath(); g.moveTo(32, 0); g.lineTo(62, 70); g.lineTo(2, 70); g.closePath(); g.fill();
    }));
    const turn = decal(tex(128, 160, (g) => {            // 右转箭头；左转时把贴图左右镜像
      g.strokeStyle = WHITE; g.lineWidth = 16; g.lineCap = 'butt';
      g.beginPath(); g.moveTo(36, 160); g.lineTo(36, 78); g.quadraticCurveTo(36, 44, 72, 44); g.lineTo(84, 44); g.stroke();
      g.fillStyle = WHITE; g.beginPath(); g.moveTo(126, 44); g.lineTo(80, 10); g.lineTo(80, 78); g.closePath(); g.fill();
    }));
    const lineMat = new T.MeshBasicMaterial({ color: 0xeef2f6 });

    // 沿一条折线画：直行箭头、转弯箭头、两侧车道边线（坡道段不画）
    function alongRoute(pts, y, grp, order, edges) {
      const lines = new Quads(), arrS = new Quads(), arrT = new Quads();
      for (let i = 0; i < pts.length - 1; i++) {
        const a = pts[i], b = pts[i + 1];
        if (Math.abs(a.y - y) > 0.01 || Math.abs(b.y - y) > 0.01) continue;
        const len = Math.hypot(b.x - a.x, b.z - a.z);
        if (len < 4) continue;
        const fx = (b.x - a.x) / len, fz = (b.z - a.z) / len, rx = -fz, rz = fx;
        // 下一段是否在同一层拐弯
        let side = 0;
        const n = pts[i + 2];
        if (n && Math.abs(n.y - y) < 0.01) {
          const l2 = Math.hypot(n.x - b.x, n.z - b.z), d = ((n.x - b.x) * rx + (n.z - b.z) * rz) / (l2 || 1);
          if (Math.abs(d) > 0.5) side = d > 0 ? 1 : -1;
        }
        const hasTurn = side !== 0 && len >= 9;
        const end = len - (hasTurn ? 8 : 3.5);
        for (let s = Math.min(5, len / 2); s <= end; s += 9) arrS.add(a.x + fx * s, y + 0.05, a.z + fz * s, fx, fz, 0.9, 2.6, 0, 0, 1, 1);
        if (hasTurn) arrT.add(b.x - fx * 4.4, y + 0.05, b.z - fz * 4.4, fx, fz, 1.9, 2.6, side > 0 ? 0 : 1, 0, side > 0 ? 1 : 0, 1);
        if (edges && len > 7) for (const k of [-1.75, 1.75]) {
          lines.strip(a.x + fx * 2.8 + rx * k, a.z + fz * 2.8 + rz * k, b.x - fx * 2.8 + rx * k, b.z - fz * 2.8 + rz * k, y + 0.045, 0.14);
        }
      }
      lines.mesh(lineMat, grp, 0); arrS.mesh(straight, grp, order); arrT.mesh(turn, grp, order);
    }
    // 地面文字（坡道口、让行）
    function floorText(text, grp, order, x, y, z, fx, fz, w, l) {
      const q = new Quads(); q.add(x, y + 0.05, z, fx, fz, w, l, 0, 0, 1, 1);
      q.mesh(decal(tex(256, Math.round((256 * l) / w), (g, W, H) => {
        g.fillStyle = WHITE; g.textAlign = 'center'; g.textBaseline = 'middle';
        g.font = `700 ${Math.round(H * 0.72)}px ` + PT.FONT; g.fillText(text, W / 2, H / 2 + 2);
      })), grp, order);
    }

    // 车位编号图集：8 列 × 16 行，每格一个编号
    const atlas = decal(tex(1024, 1024, (g) => {
      g.fillStyle = WHITE; g.textAlign = 'center'; g.textBaseline = 'middle'; g.font = '700 44px ' + PT.FONT;
      PT.SLOTS.forEach((s, i) => g.fillText(s.name.split('-')[1], (i % 8) * 128 + 64, ((i / 8) | 0) * 64 + 34));
    }));
    const evMat = decal(tex(96, 96, (g) => {
      g.fillStyle = '#1fa25a'; g.beginPath(); g.roundRect(4, 4, 88, 88, 14); g.fill();
      g.fillStyle = '#fff'; g.beginPath();
      g.moveTo(54, 10); g.lineTo(26, 52); g.lineTo(44, 52); g.lineTo(38, 86); g.lineTo(70, 40); g.lineTo(50, 40); g.closePath(); g.fill();
    }));

    for (const level of [1, 2]) {
      const y = level === 1 ? C.Y1 : C.Y2, grp = level === 1 ? PT.groups.b1 : PT.groups.b2;
      const order = level === 1 ? 2.5 : 1.5;   // 画在本层楼板之后、上一层楼板之前
      alongRoute(R.loop(level), y, grp, order, true);
      const nums = new Quads(), ev = new Quads();
      PT.SLOTS.forEach((s, i) => {
        if (s.level !== level) return;
        const d = Math.sign(s.z - s.aisleZ), c = i % 8, r = (i / 8) | 0;
        nums.add(s.x, y + 0.05, s.z - d * 3.2, 0, d, 1.7, 0.85, c / 8, 1 - (r + 1) / 16, (c + 1) / 8, 1 - r / 16);
        if (s.charger) ev.add(s.x, y + 0.05, s.z + d * 1.2, 0, d, 1.3, 1.3, 0, 0, 1, 1);
      });
      nums.mesh(atlas, grp, order); ev.mesh(evMat, grp, order);
    }
    // B1 上属于"去 B2 / 从 B2 回来"的两小段车道（不在 B1 自己的环线里）
    const P = (x, z) => ({ x, y: C.Y1, z });
    alongRoute([P(4, -20), P(4, -8), P(8, -8)], C.Y1, PT.groups.b1, 2.5, true);
    alongRoute([P(-4, -8), P(-4, -20)], C.Y1, PT.groups.b1, 2.5, true);
    // 坡道口与让行标识
    const b1 = PT.groups.b1, b2 = PT.groups.b2;
    floorText('B2', b1, 2.5, 4, C.Y1, -14.5, 0, 1, 2.2, 1.2);            // B1：前方左转下 B2
    floorText('出口', b1, 2.5, -4, C.Y1, -28, 0, -1, 2.4, 1.2);          // B1：北行去出库坡道
    floorText('B1 出口', b2, 1.5, -31.5, C.Y2, -8, 1, 0, 2.6, 0.95);     // B2：上坡回 B1
    floorText('让', b1, 2.5, -4, C.Y1, -12.2, 0, -1, 1.3, 1.3);
    const yl = new Quads();
    for (const x of [-5.3, -4.4, -3.5, -2.6]) yl.strip(x - 0.3, -14.4, x + 0.3, -14.4, C.Y1 + 0.045, 0.35);
    yl.mesh(lineMat, b1, 0);

    // 地面环路：只画导向箭头，在地面之后绘制
    const s = PT.groups.surface, V = (x, z) => ({ x, y: 0.07, z });
    alongRoute([V(21, 38), V(C.RING, 38), V(C.RING, C.NORTH), V(29, C.NORTH)], 0.07, s, 8, false);
    alongRoute([V(-29, C.NORTH), V(-C.RING, C.NORTH), V(-C.RING, 6)], 0.07, s, 8, false);
  };
})();
