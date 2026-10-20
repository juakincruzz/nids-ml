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

  // ---------- gráfico (SVG propio, en píxeles reales: el texto no se deforma) ----------
  const M = { l: 46, r: 8, t: 46, b: 46 };
  const n = tl.flows_per_second.length;
  const yMax = niceMax(Math.max(1, ...tl.flows_per_second));
  const svg = $("chart");
  const seek = $("seek");
  const NS = "http://www.w3.org/2000/svg";
  let W = 0, H = 0, PW = 0, PH = 0;
  const x = (t) => M.l + ((t - tl.start) / (tl.end - tl.start)) * PW;
  const xb = (i) => x(tl.start + i * tl.bin_seconds);
  const y = (v) => M.t + PH - (v / yMax) * PH;
  const el = (name, attrs = {}, parent = svg) => {
    const node = document.createElementNS(NS, name);
    for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, v);
    parent.appendChild(node);
    return node;
  };

  function niceMax(v) {
    const p = 10 ** Math.floor(Math.log10(v));
    return [1, 2, 2.5, 5, 10].map((m) => m * p).find((m) => m >= v);
  }

  let chart = null;
  function drawChart() {
    W = svg.clientWidth; H = svg.clientHeight;
    if (!W) return;  // pestaña oculta: se dibuja al mostrarla
    PW = W - M.l - M.r; PH = H - M.t - M.b;
    svg.replaceChildren();
    svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    seek.style.paddingLeft = `${M.l - 8}px`;
    seek.style.paddingRight = `${M.r - 8}px`;

    const defs = el("defs");
    const clip = el("clipPath", { id: "revealed" }, defs);
    const clipRect = el("rect", { x: 0, y: 0, width: 0, height: H }, clip);

    // zonas de ataque real, con su nombre (no solo color)
    const zones = el("g", { class: "zone" });
    for (const z of tl.zones) {
      const w = Math.max(2, x(z.end) - x(z.start));
      el("rect", { x: x(z.start), y: M.t, width: w, height: PH }, zones);
      el("rect", { x: x(z.start), y: M.t, width: w, height: 2, class: "zone-edge" }, zones);
      const name = cfg.families[z.family] || z.family;
      if (w > name.length * 7 + 8) {
        el("text", { x: x(z.start) + 6, y: M.t + 18 }, zones).textContent = name;
      }
    }

    // rejilla y eje Y: tres líneas bastan
    const grid = el("g", { class: "grid" });
    const axis = el("g", { class: "axis" });
    for (let k = 1; k <= 2; k++) {
      const v = (yMax * k) / 2;
      el("line", { x1: M.l, x2: W - M.r, y1: y(v), y2: y(v) }, grid);
      el("text", { x: M.l - 10, y: y(v) + 4, "text-anchor": "end" }, axis).textContent = fmtNum(v);
    }
    el("text", { x: M.l - 10, y: y(0) + 4, "text-anchor": "end" }, axis).textContent = "0";
    // eje X: marcas cada 15 min (o 30 si no caben), hora local
    const step = PW / ((tl.end - tl.start) / 900) < 56 ? 1800 : 900;
    for (let t = Math.ceil((tl.start + cfg.utc_offset) / step) * step - cfg.utc_offset; t <= tl.end; t += step) {
      el("text", { x: x(t), y: M.t + PH + 34, "text-anchor": "middle" }, axis).textContent = clock(t).slice(0, 5);
    }

    // área de flujos/s: tenue entera y marcada hasta el cursor
    let d = `M${xb(0)},${y(0)}`;
    tl.flows_per_second.forEach((v, i) => { d += `L${xb(i)},${y(v)}L${xb(i + 1)},${y(v)}`; });
    d += `L${xb(n)},${y(0)}Z`;
    el("path", { d, class: "area-dim" });
    el("path", { d, class: "area-live", "clip-path": "url(#revealed)" });
    el("line", { x1: M.l, x2: W - M.r, y1: y(0), y2: y(0), class: "baseline" });

    // marcas de alertas: modelo arriba (triángulos), reglas abajo (cuadrados)
    const marks = el("g", { "clip-path": "url(#revealed)" });
    let dm = "", dr = "";
    const top = M.t - 20, bottom = M.t + PH + 8;
    tl.model_alerts.forEach((c, i) => {
      if (c > 0) { const cx = xb(i + 0.5); dm += `M${cx - 4},${top}L${cx + 4},${top}L${cx},${top + 7}Z`; }
    });
    tl.rules_alerts.forEach((c, i) => {
      if (c > 0) { const cx = xb(i + 0.5); dr += `M${cx - 3},${bottom}h6v6h-6Z`; }
    });
    el("path", { d: dm, class: "mark-model" }, marks);
    el("path", { d: dr, class: "mark-rules" }, marks);
    el("text", { x: M.l - 10, y: top + 7, class: "row-label", "text-anchor": "end" }).textContent = "modelo";
    el("text", { x: M.l - 10, y: bottom + 7, class: "row-label", "text-anchor": "end" }).textContent = "reglas";

    const hover = el("line", { class: "hover", y1: M.t, y2: M.t + PH, visibility: "hidden" });
    const cursor = el("line", { class: "cursor", y1: top - 6, y2: M.t + PH });
    const head = el("circle", { class: "cursor-head", cy: top - 6, r: 3.5 });
    chart = { clipRect, cursor, head, hover };
    renderCursor();
  }

  function renderCursor() {
    if (!chart) return;
    const cx = x(state.t);
    chart.clipRect.setAttribute("width", cx);
    chart.cursor.setAttribute("x1", cx);
    chart.cursor.setAttribute("x2", cx);
    chart.head.setAttribute("cx", cx);
  }

  new ResizeObserver(() => { if (svg.clientWidth !== W || svg.clientHeight !== H) drawChart(); }).observe(svg);

  // tooltip: intervalo bajo el ratón
  const tooltip = $("tooltip");
  const hideTooltip = () => { tooltip.hidden = true; chart.hover.setAttribute("visibility", "hidden"); };
  svg.addEventListener("pointermove", (ev) => {
    const r = svg.getBoundingClientRect();
    const px = ev.clientX - r.left;
    const i = Math.floor(((px - M.l) / PW) * n);
    if (i < 0 || i >= n) return hideTooltip();
    const t = tl.start + i * tl.bin_seconds;
    const zone = tl.zones.filter((z) => z.start <= t && t < z.end).map((z) => cfg.families[z.family]);
    tooltip.innerHTML =
      `<b>${clock(t)}</b>${fmtNum(tl.flows_per_second[i], 1)} flujos por segundo` +
      `<br>Ataque real: <span class="t-attack">${zone.length ? zone.join(", ") : "ninguno"}</span>` +
      `<br>Alertas: ${fmtNum(tl.model_alerts[i])} del modelo, ${fmtNum(tl.rules_alerts[i])} de las reglas`;
    tooltip.hidden = false;
    const tw = tooltip.offsetWidth;
    tooltip.style.left = `${px + 14 + tw > r.width ? px - 14 - tw : px + 14}px`;
    chart.hover.setAttribute("x1", xb(i + 0.5));
    chart.hover.setAttribute("x2", xb(i + 0.5));
    chart.hover.setAttribute("visibility", "visible");
  });
  svg.addEventListener("pointerleave", hideTooltip);

  // ---------- marcador ----------
  function renderScore(s) {
    $("s-model-recall").textContent = fmtPct(s.model.recall);
    $("s-model-detected").textContent = `${fmtNum(s.model.detected)} de ${fmtNum(s.attacks)} flujos de ataque`;
    $("s-model-fa").textContent = fmtNum(s.model.false_alarms_per_hour, 1);
    $("s-model-fp").textContent = `${fmtNum(s.model.false_alarms)} flujos normales marcados como ataque`;
    $("s-rules-recall").textContent = fmtPct(s.rules.recall);
    $("s-rules-fa").textContent = `con ${fmtNum(s.rules.false_alarms_per_hour, 1)} falsas alarmas por hora`;
    $("s-flows").textContent = fmtNum(s.flows);
    $("s-attacks").textContent = `${fmtNum(s.attacks)} de ataque en ${fmtNum(s.hours * 60, 0)} min de tráfico`;
  }

  // ---------- lista de alertas ----------
  const list = $("alerts");
  const announce = $("announce");
  let lastAnnounce = 0;
  let selectedId = null;
  function addItems(items, isNew) {
    for (const item of items) {
      const tmp = document.createElement("template");
      tmp.innerHTML = item.html.trim();
      const li = tmp.content.firstElementChild;
      if (isNew) li.classList.add("new");
      if (li.dataset.id === selectedId) li.classList.add("selected");
      list.prepend(li);
      if (window.htmx) htmx.process(li);
    }
    while (list.children.length > MAX_LISTED) list.lastElementChild.remove();
    $("alerts-empty").hidden = list.children.length > 0;
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
      if (!span) continue;
      span.textContent = fmtNum(u.n);
      span.parentElement.querySelector(".pl").textContent = u.n === 1 ? "" : "s";
    }
    renderScore(p.score);
    renderClock(p.clock);
  }

  // ---------- reloj y barra ----------
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
    playBtn.querySelector(".i-play").toggleAttribute("hidden", on);
    playBtn.querySelector(".i-pause").toggleAttribute("hidden", !on);
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

  // ---------- explicación: sustituye a la lista hasta que se vuelve ----------
  const feed = $("feed");
  const detail = $("detail");
  function closeDetail() {
    if (feed.dataset.detail !== "open") return;
    delete feed.dataset.detail;
    detail.replaceChildren();
    const li = list.querySelector(`[data-id="${selectedId}"]`);
    list.querySelectorAll(".selected").forEach((o) => o.classList.remove("selected"));
    selectedId = null;
    if (li) li.querySelector("button").focus({ preventScroll: true });
  }
  list.addEventListener("click", (ev) => {
    const li = ev.target.closest(".alert-item");
    if (!li) return;
    list.querySelectorAll(".selected").forEach((o) => o.classList.remove("selected"));
    li.classList.add("selected");
    selectedId = li.dataset.id;
  });
  detail.addEventListener("click", (ev) => { if (ev.target.closest("[data-close-detail]")) closeDetail(); });
  // al abrir una alerta, la explicación recibe el foco (teclado y lectores de pantalla) sin mover la página
  document.body.addEventListener("htmx:afterSwap", (ev) => {
    if (ev.detail.target.id !== "detail") return;
    feed.dataset.detail = "open";
    detail.scrollTop = 0;
    detail.focus({ preventScroll: true });
    // en una sola columna la explicación queda debajo del gráfico: se lleva a la vista
    if (getComputedStyle(feed).position !== "sticky") feed.scrollIntoView({ block: "start" });
  });

  document.addEventListener("keydown", (ev) => {
    const tag = ev.target.tagName;
    if (ev.code === "Space" && !["INPUT", "BUTTON", "A", "TEXTAREA"].includes(tag)) {
      ev.preventDefault();
      state.playing ? stop() : play();
    } else if (ev.key === "Escape") {
      closeDetail();
    }
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
      if (tab.id === "tab-live") drawChart();  // el SVG no tenía tamaño mientras estaba oculto
    })
  );

  // ---------- arranque ----------
  drawChart();
  applyReset(cfg.initial);
  if (cfg.autoplay) play();
})();
