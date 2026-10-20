"use strict";
// The web view, drawn as threads: programs on this PC down the left,
// the services and organizations they talk to down the right, one thread
// per connection. Rows read left to right and the list just grows longer
// as more programs appear, so it stays readable at any size. Destinations
// are ordered by the rows of the programs that use them, which keeps
// threads from crossing more than they have to. Plain SVG, no libraries.
// Every name is set with textContent, never markup, so a hostile program
// name can't inject anything.
//
//   const web = OrbWeb.create(svg, onSelect, { maxRows })
//   web.update({ nodes, links, empty })   same model the dashboard builds
//   web.select(id); web.selected          the selected node, or null
// maxRows (optional) shows only the most important programs, for the
// small view on Home; web.hidden says how many were left out.
window.OrbWeb = (() => {
  const NS = "http://www.w3.org/2000/svg";
  // Drawn at the box's real width, so text stays 15px however wide the
  // window is; redrawn when the box resizes.
  const PILL_H = 32;
  const ROW = 44;
  const LX = 0;
  const RANK = { bad: 0, warn: 1, held: 2, ok: 3, neutral: 4 };
  const STATUS_WORD = { ok: "approved", warn: "not approved yet", bad: "needs action", held: "suspended by you", neutral: "other program" };

  function el(tag, attrs, text) {
    const n = document.createElementNS(NS, tag);
    for (const [k, v] of Object.entries(attrs || {})) n.setAttribute(k, v);
    if (text != null) n.textContent = text;
    return n;
  }
  const clip = (s, max) => (s.length > max ? s.slice(0, max - 1) + "…" : s);
  const rowY = (i) => 4 + i * ROW + PILL_H / 2;

  function create(svg, onSelect, opts = {}) {
    let model = { nodes: [], links: [] };
    let selected = null;
    let hidden = 0;
    let linkEls = [];
    const layer = el("g");
    svg.append(layer);
    let W = 760, PILL_W = 236, RX = W - PILL_W, MAX_CHARS = 24;
    let lastW = 0;
    if (window.ResizeObserver) {
      new ResizeObserver(() => {
        const w = Math.round(svg.clientWidth);
        if (w && Math.abs(w - lastW) > 2) draw();
      }).observe(svg);
    }

    function select(id) {
      selected = id;
      draw();
      onSelect && onSelect(model.nodes.find((x) => x.id === id) || null);
    }

    // Fade every thread that doesn't touch id (null: show all).
    function highlight(id) {
      for (const { node, from, to } of linkEls) {
        node.classList.toggle("dim", !!id && from !== id && to !== id);
        node.classList.toggle("lit", !!id && (from === id || to === id));
      }
    }

    function pill(n, x, y, cls) {
      const g = el("g", {
        class: cls + (n.id === selected ? " selected" : ""),
        tabindex: "0", role: "button", "data-id": n.id,
      });
      g.append(el("rect", { class: "pill", x, y: y - PILL_H / 2, width: PILL_W, height: PILL_H, rx: PILL_H / 2 }));
      return g;
    }

    function wire(g, n) {
      g.addEventListener("click", (e) => { e.stopPropagation(); select(n.id); });
      g.addEventListener("keydown", (e) => {
        if (e.key === "Enter" || e.key === " ") { e.preventDefault(); select(n.id); }
      });
      g.addEventListener("mouseenter", () => highlight(n.id));
      g.addEventListener("mouseleave", () => highlight(selected));
      g.addEventListener("focus", () => highlight(n.id));
      g.addEventListener("blur", () => highlight(selected));
    }

    function draw() {
      // Redrawing every few seconds must not steal keyboard focus.
      const focused = layer.contains(document.activeElement) ? document.activeElement.getAttribute("data-id") : null;
      layer.replaceChildren();
      linkEls = [];
      lastW = Math.round(svg.clientWidth);
      W = Math.max(320, lastW || 760);
      PILL_W = Math.min(260, Math.round(W * 0.38));
      RX = W - PILL_W;
      MAX_CHARS = Math.max(8, Math.floor((PILL_W - 50) / 8.2));

      let programs = model.nodes.filter((n) => n.kind !== "service");
      const traffic = (n) => (n.traffic ? n.traffic.conns || 0 : 0);
      programs.sort((a, b) => (RANK[a.status] ?? 5) - (RANK[b.status] ?? 5) ||
        traffic(b) - traffic(a) || a.label.localeCompare(b.label));
      hidden = 0;
      if (opts.maxRows && programs.length > opts.maxRows) {
        hidden = programs.length - opts.maxRows;
        programs = programs.slice(0, opts.maxRows);
      }
      const row = new Map(programs.map((n, i) => [n.id, i]));
      const nodeById = new Map(model.nodes.map((n) => [n.id, n]));
      const links = model.links.filter((l) => row.has(l.from) && nodeById.has(l.to));

      // Destinations, each placed near the average row of its programs.
      const dest = new Map();
      for (const l of links) {
        if (!dest.has(l.to)) dest.set(l.to, []);
        dest.get(l.to).push(row.get(l.from));
      }
      const order = [...dest].map(([id, rows]) => ({
        id, ai: id.startsWith("svc:"), at: rows.reduce((s, r) => s + r, 0) / rows.length,
      })).sort((a, b) => a.at - b.at || (b.ai - a.ai) || a.id.localeCompare(b.id));
      const drow = new Map(order.map((d, i) => [d.id, i]));

      const rows = Math.max(programs.length, order.length, 1);
      const h = rows * ROW + 8;
      svg.setAttribute("viewBox", `0 0 ${W} ${h}`);
      svg.setAttribute("height", String(h));

      if (!programs.length) {
        layer.append(el("text", { class: "empty-text", x: W / 2, y: h / 2 + 5, "text-anchor": "middle" }, model.empty || "Nothing to show"));
        return;
      }

      // Threads first, so pills sit on top. Ordinary traffic underneath.
      const threads = el("g", { class: "threads-layer" });
      const drawn = links.map((l) => {
        const n = nodeById.get(l.from);
        let cls = l.status === "new" ? "new" : l.status === "bad" ? "bad"
          : ({ ok: "ok", warn: "warn", bad: "bad", held: "held" })[n.status] || "idle";
        if (!l.to.startsWith("svc:") && cls !== "new" && cls !== "bad") cls = "idle";
        return { l, cls };
      }).sort((a, b) => (a.cls === "idle" ? 0 : 1) - (b.cls === "idle" ? 0 : 1));
      for (const { l, cls } of drawn) {
        const y1 = rowY(row.get(l.from)), y2 = rowY(drow.get(l.to));
        const x1 = LX + PILL_W, x2 = RX, mx = (x1 + x2) / 2;
        const p = el("path", { class: "thread " + cls, d: `M${x1} ${y1} C${mx} ${y1}, ${mx} ${y2}, ${x2} ${y2}` });
        threads.append(p);
        linkEls.push({ node: p, from: l.from, to: l.to });
      }
      layer.append(threads);

      // Programs.
      programs.forEach((n, i) => {
        const y = rowY(i);
        const status = n.status in RANK ? n.status : "neutral";
        const g = pill(n, LX, y, `node ${status}`);
        g.setAttribute("aria-label", `${n.label}, ${STATUS_WORD[status] || status}`);
        g.append(el("circle", { class: "dot", cx: LX + 20, cy: y, r: 6 }));
        g.append(el("text", { class: "label", x: LX + 36, y: y + 5 }, clip(n.label, MAX_CHARS)));
        g.append(el("title", {}, `${n.label}: ${STATUS_WORD[status] || status}`));
        wire(g, n);
        layer.append(g);
      });

      // Destinations.
      for (const d of order) {
        const n = nodeById.get(d.id);
        const y = rowY(drow.get(d.id));
        const users = links.filter((l) => l.to === d.id).map((l) => nodeById.get(l.from).status);
        const cls = !d.ai ? "org" : users.includes("bad") ? "bad" : users.includes("warn") ? "warn" : "ai";
        const g = pill(n, RX, y, `dest ${cls}`);
        g.setAttribute("aria-label", `${n.label}, ${d.ai ? "AI service" : "organization"}`);
        if (d.ai) {
          g.append(el("rect", { class: "diamond", x: RX + PILL_W - 26, y: y - 6, width: 12, height: 12,
            transform: `rotate(45 ${RX + PILL_W - 20} ${y})` }));
        }
        g.append(el("text", { class: "label", x: RX + 18, y: y + 5 }, clip(n.label, MAX_CHARS)));
        g.append(el("title", {}, n.label));
        wire(g, n);
        layer.append(g);
      }

      highlight(selected);
      if (focused) {
        const again = [...layer.querySelectorAll("[data-id]")].find((g) => g.getAttribute("data-id") === focused);
        if (again) again.focus();
      }
    }

    svg.addEventListener("click", () => {
      if (selected) { selected = null; draw(); onSelect && onSelect(null); }
    });

    return {
      update(next) {
        model = next || { nodes: [], links: [] };
        if (selected && !model.nodes.some((n) => n.id === selected)) {
          selected = null;
          onSelect && onSelect(null);
        }
        draw();
      },
      select(id) { select(id); },
      get selected() { return model.nodes.find((n) => n.id === selected) || null; },
      get hidden() { return hidden; },
    };
  }

  return { create };
})();
