// Panel de reproducción. El servidor lleva el reloj (SSE); aquí solo se pinta.
(() => {
  "use strict";
  const cfg = JSON.parse(document.getElementById("cfg").textContent);
  const tl = cfg.timeline;
  const $ = (id) => document.getElementById(id);
  const MAX_LISTED = 60;

  const state = { t: cfg.t, speed: cfg.speed, playing: false, source: null, total: 0 };

  // ---------- formato ----------
  // Igual que el servidor: «12 345,6» (espacio para los miles, coma decimal).
  const fmtNum = (x, d = 0) =>
    x == null
      ? "—"
      : x
          .toLocaleString("es-ES", { minimumFractionDigits: d, maximumFractionDigits: d, useGrouping: "always" })
          .replace(/\./g, " ");
  const fmtPct = (x) => (x == null ? "—" : `${fmtNum(100 * x, 1)} %`);
  const clock = (t) => {
    const d = new Date((t + cfg.utc_offset) * 1000);
    return d.toISOString().slice(11, 19);
  };

  // ---------- gráfico (SVG propio) ----------
  const W = 1000, H = 250, M = { l: 52, r: 10, t: 30, b: 42 };
  const PW = W - M.l - M.r, PH = H - M.t - M.b;
  const n = tl.flows_per_second.length;
  const yMax = Math.max(1, ...tl.flows_per_second);
  const x = (t) => M.l + ((t - tl.start) / (tl.end - tl.start)) * PW;
  const xb = (i) => x(tl.start + i * tl.bin_seconds);
  const y = (v) => M.t + PH - (v / yMax) * PH;
  const svg = $("chart");
  const NS = "http://www.w3.org/2000/svg";
  const el = (name, attrs = {}, parent = svg) => {
    const node = document.createElementNS(NS, name);
    for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
    parent.appendChild(node);
    return node;
  };

  function drawChart() {
    const defs = el("defs");
    const clip = el("clipPath", { id: "revealed" }, defs);
    const clipRect = el("rect", { x: 0, y: 0, width: x(state.t), height: H }, clip);

    // rejilla y eje Y
    const grid = el("g", { class: "grid" });
    const axis = el("g", { class: "axis" });
    for (let k = 0; k <= 4; k++) {
      const v = (yMax * k) / 4;
      el("line", { x1: M.l, x2: W - M.r, y1: y(v), y2: y(v) }, grid);
      el("text", { x: M.l - 6, y: y(v) + 4, "text-anchor": "end" }, axis).textContent = fmtNum(v);
    }
    // eje X: una marca cada 15 minutos (hora local)
    const step = 900;
    for (let t = Math.ceil((tl.start + cfg.utc_offset) / step) * step - cfg.utc_offset; t <= tl.end; t += step) {
      el("text", { x: x(t), y: H - 10, "text-anchor": "middle" }, axis).textContent = clock(t).slice(0, 5);
    }

    // zonas de ataque real, con su nombre (no solo color)
    const zones = el("g", { class: "zone" });
    for (const z of tl.zones) {
      const w = Math.max(2, x(z.end) - x(z.start));
      el("rect", { x: x(z.start), y: M.t, width: w, height: PH }, zones);
      if (w > 30) {
        el("text", { x: x(z.start) + 4, y: M.t + 14 }, zones).textContent = cfg.families[z.family] || z.family;
      }
    }

    // área de flujos/s: atenuada entera y brillante hasta el cursor
    let d = `M${xb(0)},${y(0)}`;
    tl.flows_per_second.forEach((v, i) => { d += `L${xb(i)},${y(v)}L${xb(i + 1)},${y(v)}`; });
    d += `L${xb(n)},${y(0)}Z`;
    el("path", { d, class: "area-dim" });
    el("path", { d, class: "area-live", "clip-path": "url(#revealed)" });

    // marcas de alertas: modelo arriba (triángulos), reglas abajo (cuadrados)
    const marks = el("g", { "clip-path": "url(#revealed)" });
    let dm = "", dr = "";
    tl.model_alerts.forEach((c, i) => {
      if (c > 0) { const cx = xb(i + 0.5); dm += `M${cx - 3},${M.t - 16}L${cx + 3},${M.t - 16}L${cx},${M.t - 9}Z`; }
    });
    tl.rules_alerts.forEach((c, i) => {
      if (c > 0) { const cx = xb(i + 0.5); dr += `M${cx - 2.5},${M.t + PH + 6}h5v5h-5Z`; }
    });
    el("path", { d: dm, class: "mark-model" }, marks);
    el("path", { d: dr, class: "mark-rules" }, marks);
    el("text", { x: 4, y: M.t - 9, class: "row-label" }).textContent = "modelo";
    el("text", { x: 4, y: M.t + PH + 12, class: "row-label" }).textContent = "reglas";

    const cursor = el("line", { class: "cursor", y1: M.t - 20, y2: M.t + PH + 14 });
    const hover = el("line", { class: "hover", y1: M.t, y2: M.t + PH, visibility: "hidden" });
    return { clipRect, cursor, hover };
  }
  const chart = drawChart();

  function renderCursor() {
    const cx = x(state.t);
    chart.clipRect.setAttribute("width", cx);
    chart.cursor.setAttribute("x1", cx);
    chart.cursor.setAttribute("x2", cx);
  }

  // tooltip: intervalo bajo el ratón
  const tooltip = $("tooltip");
  svg.addEventListener("pointermove", (ev) => {
    const r = svg.getBoundingClientRect();
    const sx = ((ev.clientX - r.left) / r.width) * W;
    const i = Math.floor(((sx - M.l) / PW) * n);
    if (i < 0 || i >= n) { tooltip.hidden = true; chart.hover.setAttribute("visibility", "hidden"); return; }
    const t = tl.start + i * tl.bin_seconds;
    const zone = tl.zones.filter((z) => z.start <= t && t < z.end).map((z) => cfg.families[z.family]);
    tooltip.innerHTML =
      `<b>${clock(t)}</b><br>${fmtNum(tl.flows_per_second[i], 1)} flujos/s` +
      `<br>Ataque real: ${zone.length ? zone.join(", ") : "ninguno"}` +
      `<br>Alertas del modelo: ${fmtNum(tl.model_alerts[i])} · reglas: ${fmtNum(tl.rules_alerts[i])}`;
    tooltip.hidden = false;
    const px = ev.clientX - r.left;
    tooltip.style.left = `${Math.min(px + 12, r.width - 200)}px`;
    tooltip.style.top = "8px";
    chart.hover.setAttribute("x1", xb(i + 0.5));
    chart.hover.setAttribute("x2", xb(i + 0.5));
    chart.hover.setAttribute("visibility", "visible");
  });
  svg.addEventListener("pointerleave", () => { tooltip.hidden = true; chart.hover.setAttribute("visibility", "hidden"); });

  // ---------- marcador ----------
  function renderScore(s) {
    $("s-model-recall").textContent = fmtPct(s.model.recall);
    $("s-model-detected").textContent = `${fmtNum(s.model.detected)} de ${fmtNum(s.attacks)} flujos de ataque`;
    $("s-model-fa").textContent = fmtNum(s.model.false_alarms_per_hour, 1);
    $("s-model-fp").textContent = `${fmtNum(s.model.false_alarms)} flujos normales marcados`;
    $("s-rules-recall").textContent = fmtPct(s.rules.recall);
    $("s-rules-fa").textContent = `detectados · ${fmtNum(s.rules.false_alarms_per_hour, 1)} falsas alarmas/h`;
    $("s-flows").textContent = fmtNum(s.flows);
    $("s-attacks").textContent = `${fmtNum(s.attacks)} de ataque · ${fmtNum(s.hours * 60, 0)} min de tráfico`;
  }

  // ---------- lista de alertas ----------
  const list = $("alerts");
  const announce = $("announce");
  let lastAnnounce = 0;
  function addItems(items, isNew) {
    for (const item of items) {
      const tmp = document.createElement("template");
      tmp.innerHTML = item.html.trim();
      const li = tmp.content.firstElementChild;
      if (isNew) li.classList.add("new");
      list.prepend(li);
      if (window.htmx) htmx.process(li);
    }
    while (list.children.length > MAX_LISTED) list.lastElementChild.remove();
  }
  function setTotal(total) { state.total = total; $("alert-total").textContent = fmtNum(total); }

  function applyReset(p) {
    state.t = p.t;
    list.replaceChildren();
    addItems(p.items, false);
    setTotal(p.total);
    renderScore(p.score);
    renderClock(p.clock);
  }
  function applyTick(p) {
    state.t = p.t;
    if (p.new.length) {
      addItems(p.new, true);
      setTotal(state.total + p.new.length);
      const now = performance.now();
      if (now - lastAnnounce > 3000) {
        announce.textContent = `${p.new.length} alerta${p.new.length > 1 ? "s" : ""} nueva${p.new.length > 1 ? "s" : ""}`;
        lastAnnounce = now;
      }
    }
    for (const u of p.updates) {
      const span = document.getElementById(`n-${u.id}`);
      if (span) span.textContent = fmtNum(u.n);
    }
    renderScore(p.score);
    renderClock(p.clock);
  }

  // ---------- reloj y barra ----------
  const seek = $("seek");
  seek.min = Math.floor(tl.start); seek.max = Math.ceil(tl.end); seek.value = state.t;
  function renderClock(text) {
    $("clock").textContent = text || clock(state.t);
    seek.value = state.t;
    seek.setAttribute("aria-valuetext", text || clock(state.t));
    renderCursor();
  }

  // ---------- reproducción (SSE) ----------
  const playBtn = $("play");
  function setPlaying(on) {
    state.playing = on;
    playBtn.setAttribute("aria-pressed", on);
    playBtn.setAttribute("aria-label", on ? "Pausar" : "Reproducir");
    playBtn.querySelector(".icon").textContent = on ? "❚❚" : "▶";
    playBtn.querySelector(".label").textContent = on ? "Pausar" : "Reproducir";
    $("live").hidden = !on;
  }
  function connect() {
    if (state.source) state.source.close();
    const url = `/stream?dia=${cfg.day}&t=${state.t}&velocidad=${state.speed}`;
    const es = new EventSource(url);
    es.addEventListener("reset", (e) => applyReset(JSON.parse(e.data)));
    es.addEventListener("tick", (e) => applyTick(JSON.parse(e.data)));
    es.addEventListener("end", () => { stop(); });
    es.onerror = () => { if (es.readyState === EventSource.CLOSED) stop(); };
    state.source = es;
  }
  function play() {
    if (state.t >= tl.end - 1) state.t = tl.start;  // al final, vuelve a empezar
    setPlaying(true);
    connect();
  }
  function stop() {
    if (state.source) { state.source.close(); state.source = null; }
    setPlaying(false);
  }
  async function snapshot() {
    const r = await fetch(`/api/estado?dia=${cfg.day}&t=${state.t}`);
    applyReset(await r.json());
  }

  playBtn.addEventListener("click", () => (state.playing ? stop() : play()));
  document.querySelectorAll(".btn-speed").forEach((b) =>
    b.addEventListener("click", () => {
      state.speed = Number(b.dataset.speed);
      document.querySelectorAll(".btn-speed").forEach((o) => o.setAttribute("aria-checked", o === b));
      if (state.playing) connect();
    })
  );
  seek.addEventListener("input", () => { state.t = Number(seek.value); renderClock(); });
  seek.addEventListener("change", () => { state.t = Number(seek.value); state.playing ? connect() : snapshot(); });
  document.addEventListener("keydown", (ev) => {
    const tag = ev.target.tagName;
    if (ev.code === "Space" && !["INPUT", "BUTTON", "A", "TEXTAREA"].includes(tag)) {
      ev.preventDefault();
      state.playing ? stop() : play();
    }
  });

  // al pulsar una alerta, la explicación recibe el foco (teclado y lectores de pantalla)
  document.body.addEventListener("htmx:afterSwap", (ev) => {
    if (ev.detail.target.id === "detail") ev.detail.target.focus();
  });

  // ---------- pestañas ----------
  const tabs = [...document.querySelectorAll('[role="tab"]')];
  tabs.forEach((tab) =>
    tab.addEventListener("click", () => {
      tabs.forEach((t) => {
        const on = t === tab;
        t.setAttribute("aria-selected", on);
        document.getElementById(t.getAttribute("aria-controls")).hidden = !on;
      });
    })
  );

  // ---------- arranque ----------
  applyReset(cfg.initial);
  if (cfg.autoplay) play();
})();
