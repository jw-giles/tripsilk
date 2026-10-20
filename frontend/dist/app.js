(() => {
"use strict";
// Tripsilk dashboard. All text from the backend (process paths, file names,
// threat names) is inserted with textContent, never innerHTML: a security
// tool must not be injectable through a hostile file name.

const api = () => window.go.main.App;
const $ = (id) => document.getElementById(id);

function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") n.className = v;
    else if (k === "onclick") n.addEventListener("click", v);
    else if (k === "dataset") Object.assign(n.dataset, v);
    else n.setAttribute(k, v);
  }
  for (const kid of kids) if (kid != null) n.append(kid);
  return n;
}

const baseName = (p) => (p || "").split(/[\\/]/).pop() || p;

function ago(iso) {
  const t = new Date(iso);
  if (isNaN(t) || t.getFullYear() < 2000) return "never";
  const s = Math.round((Date.now() - t) / 1000);
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return t.toLocaleDateString();
}

let toastTimer;
function toast(msg, isErr = false) {
  const t = $("toast");
  t.textContent = msg;
  t.className = "toast" + (isErr ? " err" : "");
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => (t.hidden = true), isErr ? 7000 : 3500);
}

// Run a backend action, report the result, refresh the view.
// CANCEL: an action returns this when the user backed out, so no success
// toast is shown for something that didn't happen.
const CANCEL = Symbol("cancel");
// Actions that only log while Practice mode is on.
const PRACTICE_ONLY = new Set(["Suspended", "Internet blocked", "Program ended", "Internet disconnected"]);
let practice = false;

async function act(fn, okMsg) {
  try {
    const r = await fn();
    if (r === CANCEL) return;
    if (okMsg) toast(practice && PRACTICE_ONLY.has(okMsg) ? "Practice mode: logged, not done" : okMsg);
  } catch (e) {
    toast(String(e && e.message ? e.message : e), true);
  }
  refresh();
}

// ---- Wall ----

const WALL = {
  protected: ["You're protected", "Defender is healthy, your trip lines are set, and every program using AI is one you approved."],
  attention: ["Something needs a look", null],
  danger: ["Act now: something touched your web", "A trip line was touched or an AI app ran a dangerous command. Check the red alerts in Activity, suspend anything you don't recognize, then run a full scan."],
  loading: ["Checking your PC…", ""],
};

function renderWall(s) {
  const [title, detail] = WALL[s.overall] || WALL.loading;
  $("wall").dataset.state = s.overall;
  $("wall-title").textContent = title;
  let d = detail;
  if (d == null) {
    const reasons = [];
    if (s.unhandled) reasons.push(`${s.unhandled} alert${s.unhandled > 1 ? "s" : ""} to review`);
    if ((s.defenderIssues || []).length) reasons.push(s.defenderIssues[0]);
    if (!(s.bait || []).length) reasons.push("You haven't set any trip lines yet");
    const unknown = (s.flows || []).filter((f) => !f.local && !(s.allowed || []).includes((f.image || "").toLowerCase()));
    if (unknown.length) reasons.push(`${unknown.length} program${unknown.length > 1 ? "s" : ""} you haven't approved ${unknown.length > 1 ? "are" : "is"} using AI`);
    d = reasons.join(". ") + ".";
  }
  $("wall-detail").textContent = d;
  const busy = !!s.scanning;
  $("btn-quick").disabled = busy;
  $("btn-full").disabled = busy;
  $("btn-quick").textContent = s.scanning === "QuickScan" ? "Scanning…" : s.scanning === "FullScan" ? "Full scan running…" : "Scan now";
  $("btn-full").textContent = s.scanning === "FullScan" ? "Full scan running…" : "Run full scan";
  $("btn-ack").hidden = !s.unhandled;
  $("btn-disconnect").hidden = !!s.disconnected;
  $("btn-reconnect").hidden = !s.disconnected;
  practice = !!s.dryRun;
  $("dryrun-banner").hidden = !s.dryRun;
  $("chk-dryrun").checked = !!s.dryRun;
  $("chk-contain").checked = !!s.autoContain;
  $("chk-read").checked = !!s.readAuditing;
  $("chk-toasts").checked = !!s.toasts;
  const sm = s.sysmon || {};
  $("sysmon-status").textContent = sm.installed
    ? `Sysmon: reading its log, ${Number(sm.events || 0).toLocaleString()} events saved to the journal so far.${sm.error ? " Last problem: " + sm.error : ""}`
    : "Sysmon: not installed. It's optional; if you install it, Tripsilk reads its log within 10 minutes.";
  const ev = s.eventLog || {};
  $("chk-evlog").checked = !!ev.on;
  $("evlog-status").hidden = !ev.on;
  $("evlog-status").textContent = !ev.on ? "" : !ev.open
    ? "Not copying: the event source couldn't be opened. Turn this off and on again."
    : ev.errors ? `Copying, but ${ev.errors} alerts couldn't be written (last: ${ev.lastError}).`
    : "Copying. Event IDs: 1001 trip line, 1002 ransomware shield, 1003 agent, 1004 burst, 1005 internet lock, 1006 control channel, 1007 AI connection.";
  $("chk-signin").checked = !!s.startAtSignIn;
  // A dev build can turn the task off but not on (see the note).
  $("chk-signin").disabled = !s.installed && !s.startAtSignIn;
  $("signin-note").hidden = !!s.installed;
  renderSensor(s.sensor || {});
  renderPractice(s);
  const u = s.usage || {};
  const pct = (x) => (Number(x || 0) < 0.1 ? "under 0.1" : Number(x).toFixed(1)) + "%";
  $("usage-status").textContent = u.measured
    ? `Processor: ${pct(u.cpuPercent)} of this PC right now (highest so far ${pct(u.peakPercent)}). Memory: ${Math.round(u.memoryMB || 0)} MB. Disk: ${(u.diskMB || 0).toFixed(1)} MB for settings, history and the journal.`
    : "Measuring…";
}

// The week-of-practice record next to the freeze switch: what automatic
// containment would have frozen while it was off.
function renderPractice(s) {
  const week = Date.now() - 7 * 864e5;
  const recent = (s.wouldFreeze || []).filter((w) => new Date(w.time).getTime() > week);
  const p = $("practice-record");
  if (s.autoContain && !s.dryRun) { p.textContent = ""; return; }
  if (!recent.length) {
    p.textContent = "Last 7 days: nothing would have been frozen.";
    return;
  }
  const names = [...new Set(recent.map((w) => baseName(w.image)))];
  p.textContent = `Last 7 days: ${recent.length} time${recent.length > 1 ? "s" : ""} Tripsilk would have frozen something: ${names.join(", ")}. ` +
    "If any of these were your own programs doing normal work, leave this off for now.";
}

function renderSensor(sn) {
  const fmtN = (n) => Number(n || 0).toLocaleString();
  let t;
  if (sn.running) {
    t = `On. Windows hands Tripsilk every program start, connection and DNS lookup as it happens (about every ${sn.flushMs || 1000} ms). ${fmtN(sn.events)} events so far`;
    const lost = Number(sn.dropped || 0) + Number(sn.lost || 0);
    t += lost ? `, ${fmtN(lost)} missed while the PC was busy.` : ", none missed.";
    t += sn.ownTraffic
      ? ` Tripsilk's own network traffic: ${fmtN(sn.ownTraffic)} (last: ${sn.ownLast}).`
      : " Tripsilk's own network traffic: none.";
  } else if (sn.error) {
    t = `Off: ${sn.error}. Tripsilk checks every 2 to 5 seconds instead, which can miss a program that starts and exits in between.`;
  } else {
    t = "Starting…";
  }
  $("sensor-status").textContent = t;
  const j = sn.journal || {};
  if (j.dir) {
    const mb = (Number(j.bytes || 0) / 1048576).toFixed(1);
    $("journal-status").textContent = `Event journal: ${j.dir} (${mb} MB in ${j.files || 0} file${j.files === 1 ? "" : "s"}, one JSON line per event, admins only, capped at 256 MB).` +
      (j.errors ? ` ${fmtN(j.errors)} lines couldn't be written: ${j.lastError || "unknown error"}.` : "");
  } else {
    $("journal-status").textContent = sn.journalError ? `Event journal off: ${sn.journalError}.` : "";
  }
}

// ---- Alerts ----

const ACTION_LABEL = { allow: "Allow", addservice: "Add to its rule", allowchild: "Allow for this app", allowchannel: "Allow for this app", allowdest: "Add to its list", suspend: "Suspend", block: "Block internet", fullscan: "Run full scan", terminate: "End program", scan: "Scan it", disconnect: "Disconnect internet", resume: "Resume", resumeall: "Resume all" };
const ACTION_DONE = { allow: "Allowed", addservice: "Rule updated", allowchild: "Allowed for this app", allowchannel: "Allowed for this app", allowdest: "Added to its list", suspend: "Suspended", block: "Internet blocked", fullscan: "Full scan started", terminate: "Program ended", scan: "Scanning", disconnect: "Internet disconnected", resume: "Resumed", resumeall: "Resumed, internet restored" };

function runAlertAction(a, kind) {
  const calls = {
    allow: () => api().Allow(a.process),
    allowchild: () => api().AllowChild(a.process, a.child),
    allowchannel: () => api().AllowChannel(a.process, a.channel),
    allowdest: () => api().AllowDest(a.process, a.dest),
    addservice: () => api().AllowService(a.process, a.service),
    suspend: () => api().Suspend(a.pid, a.process),
    block: () => api().Block(a.process),
    fullscan: () => api().FullScan(),
    scan: () => api().ScanProgram(a.process),
    resume: () => api().Resume(a.pid),
    resumeall: () => api().ResumeAll(a.pid),
    disconnect: () => api().Disconnect(),
    terminate: () => {
      if (!confirm(`End ${baseName(a.process)}? This stops it immediately. Only do this if you're sure it's harmful.`)) return Promise.resolve(CANCEL);
      return api().Terminate(a.pid, a.process);
    },
  };
  act(calls[kind], ACTION_DONE[kind]);
}

function alertItem(a, fresh) {
  const noProc = { fullscan: 1, disconnect: 1 };
  let actions = (a.actions || []).filter((k) => ACTION_LABEL[k] && (noProc[k] || (a.process && (k !== "allowchild" || a.child) && (k !== "allowchannel" || a.channel) && (k !== "allowdest" || a.dest) && (k !== "addservice" || a.service))));
  // The recommended action goes first and stands out.
  if (a.do && actions.includes(a.do)) actions = [a.do, ...actions.filter((k) => k !== a.do)];
  const danger = (k) => k === "suspend" || k === "terminate";
  const cls = (k) => {
    if (a.do) return "btn small" + (k === a.do ? (danger(k) ? " danger" : " primary") : " ghost");
    return "btn small" + (danger(k) ? " danger" : (k.startsWith("allow") || k === "addservice" || k === "scan" || k === "resume" || k === "resumeall" || k === "disconnect") ? " ghost" : "");
  };
  const plain = !!a.summary;
  return el("li", { class: "alert" + (fresh ? " fresh" : ""), dataset: { sev: a.severity } },
    el("div", { class: "a-head" },
      el("span", { class: "a-title" }, a.title),
      el("time", { class: "a-time", datetime: a.time, title: new Date(a.time).toLocaleString() }, ago(a.time))),
    plain ? el("p", { class: "a-detail" }, a.summary) : (a.detail ? el("p", { class: "a-detail" }, a.detail) : null),
    plain && a.why ? el("p", { class: "a-why" }, a.why) : null,
    evidenceBlock(a, plain),
    actions.length
      ? el("div", { class: "a-actions" }, ...actions.map((k) =>
          el("button", { class: cls(k), onclick: () => runAlertAction(a, k) }, ACTION_LABEL[k])))
      : null);
}

// evidenceBlock is the hard detail under "Show evidence": what a
// specialist checks before trusting the alert.
function evidenceBlock(a, plain) {
  const ev = a.evidence || {};
  const showDetail = plain && a.detail;
  if (!a.process && !ev.destination && !showDetail) return null;
  const rows = [];
  const row = (k, v) => rows.push(el("dt", {}, k), el("dd", {}, v));
  if (a.pid) row("Process ID", String(a.pid));
  if (a.process) row("Program", a.process);
  const sum = el("dd", { class: "mono" }, ev.sha256 || (ev.hashNote ? `not yet (${ev.hashNote})` : "not available"));
  if (a.process) rows.push(el("dt", {}, "SHA-256"), sum);
  if ((ev.chain || []).length > 1) row("Started by", ev.chain.slice(1).map((c) => `${baseName(c.image) || "?"} (${c.pid})`).join(" ← "));
  if (ev.destination) row("Destination", ev.destination);
  const check = a.process ? el("button", { class: "btn small ghost", onclick: () => checkProgram(a, sum) }, "Check this program on VirusTotal") : null;
  return el("details", { class: "a-evidence" },
    el("summary", {}, "Show evidence"),
    showDetail ? el("p", { class: "a-tech" }, a.detail) : null,
    rows.length ? el("dl", {}, ...rows) : null,
    check ? el("p", { class: "hint" }, check, " Opens VirusTotal in your browser with the file's fingerprint only. Tripsilk itself sends nothing.") : null);
}

function checkProgram(a, sumCell) {
  const have = (a.evidence || {}).sha256;
  const go = (sha) => api().OpenURL("https://www.virustotal.com/gui/file/" + sha);
  if (have) return act(() => go(have), "Opened in your browser");
  act(() => api().FileHash(a.process).then((sha) => {
    sumCell.textContent = sha;
    a.evidence = Object.assign({}, a.evidence, { sha256: sha });
    return go(sha);
  }), "Opened in your browser");
}

// announce reads important new alerts aloud to screen-reader users; the
// list itself updates silently.
function announce(a) {
  if (a.severity !== "high" && a.severity !== "critical") return;
  const r = $("announcer");
  r.textContent = "";
  setTimeout(() => { r.textContent = `${a.severity === "critical" ? "Critical alert" : "Alert"}: ${a.title}. ${a.summary || ""}`; }, 50);
}

let alerts = [];
function renderAlerts(freshId) {
  $("alerts").replaceChildren(...alerts.slice(0, 200).map((a) => alertItem(a, a.id === freshId)));
  $("alerts-empty").hidden = alerts.length > 0;
  $("home-alerts").replaceChildren(...alerts.slice(0, 4).map((a) => alertItem(a, a.id === freshId)));
  $("home-alerts-empty").hidden = alerts.length > 0;
}

// ---- Side panels ----

function renderFlows(s) {
  const allowed = new Set((s.allowed || []).map((p) => p.toLowerCase()));
  const flows = s.flows || [];
  $("flows").replaceChildren(...flows.map((f) => {
    const ok = allowed.has((f.image || "").toLowerCase());
    return el("li", {},
      el("div", { class: "r-main" },
        el("div", { class: "r-name" }, f.image ? baseName(f.image) : `PID ${f.pid}`, " ",
          el("span", { class: "tag " + (ok || f.local ? "ok" : "warn") }, ok ? "allowed" : f.local ? "local model" : "not approved")),
        el("div", { class: "r-sub" }, f.local ? `${f.provider}, running on this PC` : `${f.provider}, ${f.remote}` +
          ((s.serviceRules || {})[(f.image || "").toLowerCase()] ? `. Locked to ${(s.serviceRules[(f.image || "").toLowerCase()]).join(", ")}` : ""))),
      el("div", { class: "r-btns" },
        !ok && f.image ? el("button", { class: "btn small ghost", onclick: () => act(() => api().Allow(f.image), "Allowed") }, "Allow") : null,
        ok && !f.local && f.image && !(s.serviceRules || {})[(f.image || "").toLowerCase()]
          ? el("button", { class: "btn small ghost", title: "Allow only the AI services it uses now; anything else raises an alert", onclick: () => act(() => api().LockToCurrent(f.image), "Locked to current services") }, "Lock")
          : null,
        f.image ? el("button", { class: "btn small danger", onclick: () => act(() => api().Suspend(f.pid, f.image), "Suspended") }, "Suspend") : null));
  }));
  $("flows-empty").hidden = flows.length > 0;
  $("net-error").hidden = !s.netError;
  $("net-error").textContent = s.netError ? "Can't read network activity: " + s.netError : "";

  const al = s.allowed || [];
  $("allowed-wrap").hidden = al.length === 0;
  $("allowed-count").textContent = al.length;
  $("allowed").replaceChildren(...al.map((p) =>
    el("li", {}, el("span", { class: "r-sub" }, p),
      el("button", { class: "btn small ghost", onclick: () => act(() => api().Disallow(p), "Removed") }, "Remove"))));
}

function renderBait(s) {
  const bait = s.bait || [];
  $("bait").replaceChildren(...bait.map((b) =>
    el("li", {},
      el("div", { class: "r-main" },
        el("div", { class: "r-name" }, baseName(b.path)),
        el("div", { class: "r-sub" }, b.path)),
      el("button", { class: "btn small ghost", onclick: () => act(() => api().RemoveBait(b.path), "Trip line removed") }, "Remove"))));
  if (!bait.length) $("bait").replaceChildren(el("li", { class: "empty" }, "No trip lines set."));
}

function renderDefender(s) {
  const d = s.defender || {};
  const facts = $("defender");
  if (!d.available) {
    facts.replaceChildren(el("dt", {}, "Status"), el("dd", { class: "bad" }, d.error || "Unavailable"));
  } else {
    const row = (k, v, bad) => [el("dt", {}, k), el("dd", bad ? { class: "bad" } : {}, v)];
    facts.replaceChildren(
      ...row("Real-time protection", d.realTimeProtection ? "On" : "Off", !d.realTimeProtection),
      ...row("Tamper protection", d.tamperProtected ? "On" : "Off", !d.tamperProtected),
      ...row("Definitions", `${d.signatureVersion} (${d.signatureAgeDays} day${d.signatureAgeDays === 1 ? "" : "s"} old)`, d.signatureAgeDays > 3),
      ...row("Last quick scan", ago(d.lastQuickScan)),
      ...row("Last full scan", ago(d.lastFullScan)));
  }
  $("def-issues").replaceChildren(...(d.available ? s.defenderIssues || [] : []).map((i) => el("li", {}, i)));
  const cfa = s.folderProtection;
  $("chk-cfa").checked = cfa === "on";
  $("chk-cfa").disabled = !d.available || cfa === "unknown" || cfa === "";
  $("cfa-note").textContent = cfa === "audit"
    ? "Windows folder protection is in audit mode: it logs but doesn't block. Turn the switch on to block."
    : cfa === "on" ? "On. Unapproved programs can't change your Documents, Pictures and other folders."
    : "Off. This is the strongest block against ransomware, and it's built into Windows.";

  const th = s.threats || [];
  $("threats-wrap").hidden = th.length === 0;
  $("threat-count").textContent = th.length;
  $("threats").replaceChildren(...th.map((t) =>
    el("li", {}, el("div", { class: "r-main" },
      el("div", { class: "r-name" }, t.name),
      el("div", { class: "r-sub" }, `${t.severity}, ${t.action}, ${ago(t.detected)}`)))));
}

function renderHeld(s) {
  const sus = Object.entries(s.suspended || {});
  const rules = s.blockedRules || [];
  $("held-section").hidden = !sus.length && !rules.length;
  $("held").replaceChildren(
    ...sus.map(([pid, img]) => el("li", {},
      el("div", { class: "r-main" }, el("div", { class: "r-name" }, baseName(img)), el("div", { class: "r-sub" }, `Suspended, PID ${pid}`)),
      el("button", { class: "btn small ghost", onclick: () => act(() => api().Resume(Number(pid)), "Resumed") }, "Resume"))),
    ...rules.map((r) => {
      const img = r.replace(/^(Tripsilk|aWall) block: /, "");
      return el("li", {},
        el("div", { class: "r-main" }, el("div", { class: "r-name" }, baseName(img)), el("div", { class: "r-sub" }, "Internet blocked")),
        el("button", { class: "btn small ghost", onclick: () => act(() => api().Unblock(r), "Internet access restored") }, "Unblock"));
    }));
}

function renderAgents(s) {
  $("agent-section").hidden = !s.agentGuard;
  const agents = s.agents || [];
  $("agents").replaceChildren(...agents.map((g) =>
    el("li", {},
      el("div", { class: "r-main" },
        el("div", { class: "r-name" }, g.image ? baseName(g.image) : `PID ${g.pid}`),
        el("div", { class: "r-sub" }, g.descendants
          ? `Watching ${g.descendants} program${g.descendants > 1 ? "s" : ""} it started`
          : "Watching what it starts")),
      g.image ? el("button", { class: "btn small danger", onclick: () => act(() => api().Suspend(g.pid, g.image), "Suspended") }, "Suspend") : null)));
  $("agents-empty").hidden = agents.length > 0;

  const approvals = Object.entries(s.childAllow || {}).flatMap(([agent, kids]) => kids.map((k) => [agent, k]));
  $("approvals-wrap").hidden = approvals.length === 0;
  $("approval-count").textContent = approvals.length;
  $("approvals").replaceChildren(...approvals.map(([agent, kid]) =>
    el("li", {}, el("span", { class: "r-sub" }, `${baseName(agent)} may start ${kid}`),
      el("button", { class: "btn small ghost", onclick: () => act(() => api().RemoveChildAllow(agent, kid), "Approval removed") }, "Remove"))));

  const found = (s.agentConfigs || []).filter((c) => c.found);
  $("configs").replaceChildren(...found.map((c) =>
    el("li", {}, el("div", { class: "r-main" },
      el("div", { class: "r-name" }, c.product),
      el("div", { class: "r-sub" }, c.error ? c.error : `${c.servers} tool${c.servers === 1 ? "" : "s"} (MCP servers), ${c.path}`)))));
  if (!found.length) $("configs").replaceChildren(el("li", { class: "empty" }, "No AI app tool lists found on this PC."));
  const bad = s.startupUnreadable || [];
  $("startup-line").textContent = `${s.startupCount} startup entries on record. New ones raise an alert.` +
    (bad.length ? ` Can't read: ${bad.join(", ")}.` : "");
}

// ---- Rule cards ----
// One card per AI app, from what already exists: approval to use AI, its
// service lock, programs it may start, channels it may reach. The "never"
// list is what alerts whatever the approvals say.

const NEVER = [
  "Run hidden (encoded) PowerShell, add Defender exclusions, delete backups or clear logs: always a critical alert",
  "Touch a trip line: critical alert, and frozen if automatic freezing is on",
  "Add a startup entry or a new AI tool (MCP server): alert",
];

// First-time destinations: what a per-app internet allowlist would learn
// from. Shown, never alerted on.
function firstsList(list, learning) {
  if (learning) return el("div", { class: "hint" }, "Still learning what's normal on this PC (first 3 days).");
  if (!list || !list.length) return el("div", { class: "hint" }, "Nowhere new.");
  const shown = list.slice(0, 8);
  return el("ul", { class: "card-list" },
    ...shown.map((f) => el("li", {}, f.org, " ", el("span", { class: "hint" }, ago(f.time)))),
    list.length > shown.length ? el("li", { class: "hint" }, `and ${list.length - shown.length} more`) : null);
}

// internetCard: the agent's internet lock. Unlocked, it shows what
// Tripsilk has learned and offers to lock to it; locked, the list itself.
function internetCard(img, allow, used) {
  if (allow) {
    return el("div", {},
      el("p", { class: "hint" }, allow.length
        ? `Locked to ${allow.length === 1 ? "1 place" : allow.length + " places"}. Anywhere else freezes it (in practice, it's recorded). `
        : "Locked to nothing: any connection freezes it. ",
        el("button", { class: "link", onclick: () => act(() => api().UnlockDests(img), "Internet lock removed") }, "Remove lock")),
      allow.length ? el("ul", { class: "card-list" }, ...allow.map((d) => el("li", {}, d, " ",
        el("button", { class: "link", onclick: () => act(() => api().RemoveDest(img, d), "Removed from its list") }, "remove")))) : null);
  }
  if (!used.length) return el("div", { class: "hint" }, "Anywhere. Places it reaches are learned here, so you can lock it to them.");
  const shown = used.slice(0, 12);
  return el("div", {},
    el("p", { class: "hint" }, `Anywhere. Learned so far: ${shown.join(", ")}${used.length > shown.length ? ` and ${used.length - shown.length} more` : ""}. `,
      el("button", { class: "link", onclick: () => act(() => api().LockDests(img), "Internet locked") },
        `Lock to these ${used.length === 1 ? "1 place" : used.length + " places"}`)));
}

// renderSaid: Claude Code's log against the shells it started.
function renderSaid(r) {
  if (!r) return;
  const n = (x) => Number(x || 0).toLocaleString();
  let body;
  if (r.status === "no-logs") body = [el("p", {}, "No Claude Code sessions in the last day.")];
  else if (r.status === "cant-compare") body = [el("p", {}, "Can't compare. ", r.why || "")];
  else {
    const un = r.unexplained || [];
    body = [el("p", {}, `In the last day, Claude Code's logs asked for ${n(r.said)} shell commands. Tripsilk saw it start ${n(r.seen)} shells and matched ${n(r.matched)} of them to a command. `,
      un.length ? `${n(un.length)} matched nothing it said:` : "Every shell it started matches a command in its log.")];
    if (un.length) body.push(
      el("ul", { class: "card-list" }, ...un.map((u) => el("li", {},
        el("span", { class: "hint" }, `${ago(u.time)}, ${baseName(u.image)}: `),
        el("code", { class: "mono-path" }, (u.cmdLine || "(no command line)").slice(0, 240))))),
      el("p", { class: "hint" }, "Some may be Claude Code's own housekeeping. One you don't recognize, especially one that downloads or runs something, is worth suspending Claude Code over."));
  }
  body.push(el("p", { class: "hint" }, `Checked ${ago(r.at)}.`));
  $("said").replaceChildren(...body);
}

// renderWeek: the weekly summary on Home, in plain sentences.
function renderWeek(r) {
  if (!r) return;
  const n = (x) => Number(x || 0).toLocaleString();
  const plural = (x, one, many) => `${n(x)} ${x === 1 ? one : many}`;
  const al = r.alerts || {};
  const total = Object.values(al).reduce((a, b) => a + b, 0);
  const since = new Date(r.from);
  const fullWeek = Date.now() - since.getTime() > 6.9 * 864e5;
  const when = fullWeek ? "In the last 7 days" : `Since ${since.toLocaleDateString(undefined, { weekday: "long", month: "short", day: "numeric" })}`;
  const sev = ["critical", "high", "medium", "low"].filter((k) => al[k]).map((k) => `${n(al[k])} ${k}`).join(", ");
  const lines = [
    el("p", {}, `${when}, Tripsilk recorded ${plural(r.events, "event", "events")}, including ${plural(r.starts, "program start", "program starts")}. `,
      total ? `${plural(total, "alert", "alerts")} (${sev}).` : "No alerts."),
  ];
  const stopped = (r.stopped || []).reduce((a, b) => a + b.count, 0);
  lines.push(el("p", {}, stopped
    ? `Tripsilk stopped programs itself ${plural(stopped, "time", "times")}.`
    : "Tripsilk didn't freeze or suspend anything itself.",
    r.practice ? ` In practice mode it would have frozen something ${plural(r.practice, "time", "times")}: check those in Settings before turning on automatic freezing.` : ""));
  const apps = (r.aiApps || []).map(baseName);
  if (apps.length) lines.push(el("p", {}, `AI apps that raised alerts: ${apps.join(", ")}.`));
  const top = r.top || [];
  if (top.length) lines.push(el("h3", { class: "sub-h" }, "Most frequent"),
    el("ul", { class: "card-list" }, ...top.map((t) => el("li", {}, t.title, " ",
      el("span", { class: "hint" }, `${t.count > 1 ? `${n(t.count)} times, ` : ""}last ${ago(t.last)}`)))));
  if (r.partial) lines.push(el("p", { class: "hint" }, "Part of the journal couldn't be read, so these numbers may be low."));
  $("week").replaceChildren(...lines);
}

function renderRuleCards(s) {
  const apps = new Map();
  const add = (img) => { if (img) { const k = img.toLowerCase(); if (!apps.has(k)) apps.set(k, img); } };
  (s.allowed || []).forEach(add);
  Object.keys(s.serviceRules || {}).forEach(add);
  Object.keys(s.childAllow || {}).forEach(add);
  Object.keys(s.channelAllow || {}).forEach(add);
  Object.keys(s.destAllow || {}).forEach(add);
  (s.agents || []).forEach((g) => add(g.image));
  $("cards-section").hidden = apps.size === 0;
  const live = new Map();
  for (const f of s.flows || []) if (!f.local && f.image) {
    const k = f.image.toLowerCase();
    if (!live.has(k)) live.set(k, new Set());
    live.get(k).add(f.provider);
  }
  const names = s.channelNames || {};
  $("rule-cards").replaceChildren(...[...apps.entries()].sort((a, b) => baseName(a[1]).localeCompare(baseName(b[1]))).map(([k, img]) => {
    const rule = (s.serviceRules || {})[k];
    const kids = (s.childAllow || {})[k] || [];
    const chans = (s.channelAllow || {})[k] || [];
    const approved = (s.allowed || []).some((x) => x.toLowerCase() === k);
    const services = rule
      ? el("div", {}, `Only ${rule.join(", ")}. `,
          el("button", { class: "link", onclick: () => act(() => api().ClearServiceRule(img), "Rule removed") }, "Remove lock"))
      : el("div", {}, approved ? "Any AI service (not locked). " : "Not approved to use AI yet. ",
          live.has(k) ? el("button", { class: "link", onclick: () => act(() => api().LockToCurrent(img), "Locked") }, `Lock to ${[...live.get(k)].join(", ")}`) : null);
    const starts = kids.length
      ? el("ul", { class: "card-list" }, ...kids.map((c) => el("li", {}, c, " ",
          el("button", { class: "link", onclick: () => act(() => api().RemoveChildAllow(img, c), "Approval removed") }, "remove"))))
      : el("div", { class: "hint" }, "Nothing approved: shells and tools it starts are listed as they happen.");
    const net = internetCard(img, (s.destAllow || {})[k], (s.destUsed || {})[k] || []);
    const reach = chans.length
      ? el("ul", { class: "card-list" }, ...chans.map((c) => el("li", {}, names[c] || c, " ",
          el("button", { class: "link", onclick: () => act(() => api().RemoveChannelAllow(img, c), "Approval removed") }, "remove"))))
      : el("div", { class: "hint" }, "None: bot services, paste sites and tunnels alert.");
    return el("article", { class: "rule-card" },
      el("h3", {}, baseName(img)),
      el("p", { class: "hint mono-path" }, img),
      el("h4", {}, "AI services"), services,
      el("h4", {}, "May start without alerts"), starts,
      el("h4", {}, "Internet"), net,
      el("h4", {}, "May reach chat bots, paste sites and tunnels"), reach,
      el("h4", {}, "Reached for the first time (last 7 days)"), firstsList((s.firstDests || {})[k], s.learning),
      el("h4", {}, "Never, whatever is approved"),
      el("ul", { class: "card-list never" }, ...NEVER.map((n) => el("li", {}, n))));
  }));
}

// ---- Constellation ----

const CATS = [
  { id: "ai", label: "AI" }, { id: "browser", label: "Browsers" }, { id: "game", label: "Games" },
  { id: "chat", label: "Chat & calls" }, { id: "cloud", label: "Cloud sync" }, { id: "dev", label: "Developer" },
  { id: "system", label: "System" }, { id: "other", label: "Other" },
];
const CAT_LABEL = Object.fromEntries(CATS.map((c) => [c.id, c.label]));
const CAT_ONE = { ai: "AI app", browser: "Browser", game: "Game", chat: "Chat app", cloud: "Cloud sync app",
  dev: "Developer tool", system: "Windows component", other: "Program" };
let filters = new Set(["ai", "browser", "game", "chat", "cloud", "dev", "system", "other"]);
try {
  const saved = JSON.parse(localStorage.getItem("tripsilk.filters") || "null");
  if (Array.isArray(saved)) filters = new Set(saved.filter((x) => CAT_LABEL[x]));
} catch { /* storage unavailable: keep the default */ }
function saveFilters() {
  try { localStorage.setItem("tripsilk.filters", JSON.stringify([...filters])); } catch { /* ignore */ }
}

let sphere = null;
let homeWeb = null;
const ALL_CATS = new Set(CATS.map((c) => c.id));

function constellationModel(s, cats = filters) {
  const lower = (x) => (x || "").toLowerCase();
  const allowed = new Set((s.allowed || []).map(lower));
  const flagged = new Set((s.flagged || []).map(lower));
  const rules = new Map(Object.entries(s.serviceRules || {}));
  const broken = new Set((s.violations || []).map((v) => v.image + "|" + v.service));
  const heldPid = new Map(Object.entries(s.suspended || {}).map(([pid, img]) => [lower(img), Number(pid)]));
  const apps = new Map();
  const services = new Map();
  const app = (image, pid, local) => {
    const key = image ? lower(image) : `pid:${pid}`;
    if (!apps.has(key)) {
      apps.set(key, { id: "app:" + key, kind: local ? "local" : "app", label: image ? baseName(image) : `PID ${pid}`,
        image, pid, providers: new Set(), moons: 0 });
    }
    return apps.get(key);
  };
  const showAI = cats.has("ai");
  for (const f of showAI ? s.flows || [] : []) {
    const a = app(f.image, f.pid, f.local);
    if (!f.local) {
      a.providers.add(f.provider);
      services.set(f.provider, (services.get(f.provider) || []).concat(a.label));
    }
  }
  if (showAI) {
    for (const g of s.agents || []) app(g.image, g.pid, false).moons = g.descendants || 0;
    for (const [img, pid] of heldPid) app(img, pid, false);
  }

  const nodes = [];
  const links = [];
  for (const [key, a] of apps) {
    if (heldPid.has(key)) { a.status = "held"; a.pid = heldPid.get(key); }
    else if (flagged.has(key)) a.status = "bad";
    else if (a.kind === "local" || allowed.has(key)) a.status = "ok";
    else a.status = "warn";
    a.approved = a.kind === "local" || allowed.has(key);
    a.rule = rules.get(key) || null;
    a.locked = !!a.rule;
    a.violations = [...a.providers].filter((p) => broken.has(key + "|" + p));
    if (a.violations.length && a.status === "ok") a.status = "warn";
    nodes.push(a);
    for (const p of a.providers) {
      links.push({ from: a.id, to: "svc:" + p, status: broken.has(key + "|" + p) ? "bad" : undefined });
    }
  }
  const svcNodes = new Map();
  for (const [label, users] of services) {
    const n = { id: "svc:" + label, kind: "service", label, status: "ok", users, count: 0, hosts: new Set() };
    svcNodes.set(n.id, n);
    nodes.push(n);
  }

  // ---- All traffic, by type ----
  const traffic = (s.traffic || []).filter((t) => cats.has(t.category));
  const visible = new Set(traffic.map((t) => t.key));
  const appIds = new Set(nodes.filter((n) => n.kind !== "service").map((n) => n.id));
  let trafficApps = 0;
  for (const t of traffic) {
    const id = "app:" + t.key;
    let n = nodes.find((x) => x.id === id);
    if (!n) {
      const sat = t.mothership && visible.has(t.mothership);
      n = { id, kind: sat ? "sat" : "app", parent: sat ? "app:" + t.mothership : undefined,
        label: t.label, image: t.image, pid: t.pids[0], providers: new Set(), moons: 0,
        status: heldPid.has(t.key) ? "held" : flagged.has(t.key) ? "bad" : "neutral" };
      if (n.status === "held") n.pid = heldPid.get(t.key);
      nodes.push(n);
      appIds.add(id);
      trafficApps++;
    }
    n.category = t.category;
    n.traffic = t;
    n.mothershipLabel = t.mothership ? baseName(t.mothership) : "";
    for (const l of t.links) {
      // AI links are already drawn by the AI view when it is on.
      if (l.ai && showAI && n.providers.has(l.org)) continue;
      const oid = (l.ai ? "svc:" : "org:") + l.org;
      let o = svcNodes.get(oid);
      if (!o) {
        o = { id: oid, kind: "service", label: l.org, status: l.ai ? "ok" : "idle", users: [], count: 0, hosts: new Set() };
        svcNodes.set(oid, o);
        nodes.push(o);
      }
      o.count += l.count;
      if (!o.users.includes(t.label)) o.users.push(t.label);
      l.hosts.forEach((h) => o.hosts.add(h));
      links.push({ from: id, to: oid, count: l.count, status: l.new ? "new" : undefined });
    }
  }
  let empty = "Nothing to show. Pick a type above.";
  if (cats.size === 1 && showAI) empty = "No AI activity right now";
  else if (cats.size) empty = "No traffic of these types right now";
  return { nodes, links, empty, apps: appIds.size, services: svcNodes.size, trafficApps };
}

function describeStar(n) {
  const list = (xs) => xs.length > 1 ? xs.slice(0, -1).join(", ") + " and " + xs[xs.length - 1] : xs[0] || "";
  const talks = n.providers ? list([...n.providers]) : "";
  const moons = n.moons ? ` It has started ${n.moons} program${n.moons > 1 ? "s" : ""} Tripsilk is watching.` : "";
  if (n.kind === "service") {
    const what = n.status === "ok" ? "AI service" : "Organization";
    return `${what} used by ${list(n.users || [])}.`;
  }
  if (n.traffic && n.status === "neutral") {
    const kind = CAT_ONE[n.category] || "Program";
    const by = n.kind === "sat" && n.mothershipLabel ? `, launched by ${n.mothershipLabel}` : "";
    return `${kind}${by}. ${n.traffic.conns} connection${n.traffic.conns === 1 ? "" : "s"} right now.`;
  }
  if (n.status === "held") return "Suspended by you. It's frozen until you resume it.";
  if (n.status === "bad") return "This app has an alert that needs action. Check What's happening below, and suspend it if you didn't expect this." + moons;
  if (n.kind === "local") return "An AI model running on this PC. It doesn't send anything over the internet by itself." + moons;
  if (n.violations && n.violations.length) {
    return `Locked to ${list(n.rule)}, but it's also talking to ${list(n.violations)}. Add it to the rule if that's expected; otherwise suspend it.` + moons;
  }
  if (n.status === "warn") return `You haven't approved this app.${talks ? ` It's talking to ${talks}.` : ""} Allow it if you use it with AI on purpose.` + moons;
  const lock = n.rule ? ` Locked to ${list(n.rule)}: anything else raises an alert.` : "";
  return `Approved. Talking to ${talks || "nothing right now"}.` + lock + moons;
}

const STATUS_TEXT = { ok: "Approved", warn: "Not approved", bad: "Needs action", held: "Suspended", idle: "Idle" };

function renderStarDetail(n) {
  const box = $("obs-detail");
  box.hidden = !n;
  if (!n) return;
  $("obs-name").textContent = n.label;
  const chip = $("obs-chip");
  const outside = n.violations && n.violations.length && n.status === "warn" && n.approved;
  chip.textContent = n.kind === "service" ? (n.status === "ok" ? "AI service" : "Organization")
    : outside ? "Outside its rule" : n.status === "neutral" ? (CAT_ONE[n.category] || "Program") : STATUS_TEXT[n.status];
  chip.className = "chip " + (n.kind === "service" || n.status === "neutral" ? "idle" : n.status);
  $("obs-text").textContent = describeStar(n);
  const rows = [];
  if (n.kind === "service" && n.hosts && n.hosts.size) {
    rows.push(el("li", {}, [...n.hosts].slice(0, 8).join(", ") + (n.hosts.size > 8 ? ", …" : "")));
  } else if (n.traffic) {
    for (const l of n.traffic.links.slice(0, 6)) {
      rows.push(el("li", {}, el("strong", {}, `${l.org}${l.count > 1 ? " \u00d7" + l.count : ""}`),
        l.new ? el("span", { class: "chip new" }, "New") : null,
        " ", l.hosts.slice(0, 4).join(", ")));
    }
  }
  $("obs-links").replaceChildren(...rows);
  $("obs-links").hidden = rows.length === 0;
  const isApp = n.kind !== "service" && n.image;
  $("obs-allow").hidden = !(isApp && n.status === "warn" && !n.approved);
  $("obs-suspend").hidden = !(isApp && n.pid && n.status !== "held");
  $("obs-resume").hidden = !(isApp && n.pid && n.status === "held");
  const canLock = isApp && n.kind === "app" && n.status !== "held" && n.status !== "neutral";
  $("obs-lock").hidden = !(canLock && !n.locked && n.providers && n.providers.size);
  $("obs-unlock").hidden = !(isApp && n.locked);
  $("obs-addsvc").hidden = !(isApp && n.violations && n.violations.length);
  $("obs-addsvc").textContent = n.violations && n.violations.length ? `Add ${n.violations[0]} to rule` : "Add to rule";
  $("obs-lock").onclick = () => act(() => api().LockToCurrent(n.image), "Locked to current services");
  $("obs-unlock").onclick = () => act(() => api().ClearServiceRule(n.image), "Rule removed");
  $("obs-addsvc").onclick = () => act(() => api().AllowService(n.image, n.violations[0]), "Rule updated");
  $("obs-allow").onclick = () => act(() => api().Allow(n.image), "Allowed");
  $("obs-suspend").onclick = () => act(() => api().Suspend(n.pid, n.image), "Suspended");
  $("obs-resume").onclick = () => act(() => api().Resume(n.pid), "Resumed");
}

function renderConstellation(s) {
  if (homeWeb) {
    homeWeb.update(constellationModel(s, ALL_CATS));
    const more = homeWeb.hidden;
    $("home-web-more").textContent = more ? `${more} more program${more === 1 ? "" : "s"} with quieter traffic. Show all to see them.` : "";
  }
  if (!sphere) return;
  const m = constellationModel(s);
  sphere.update(m);
  const review = m.nodes.filter((n) => n.status === "bad" || n.status === "warn").length;
  const onlyAI = filters.size === 1 && filters.has("ai");
  $("obs-counts").textContent =
    `${m.apps} program${m.apps === 1 ? "" : "s"}, ${m.services} ${onlyAI ? "AI service" : "destination"}${m.services === 1 ? "" : "s"}` +
    (review ? `, ${review} to review` : "");
  renderChips(s);
  $("obs-learning").textContent = s.learning
    ? `Learning what's normal for this PC until ${new Date(s.learningEnds).toLocaleDateString()}. After that, first-time connections glow.`
    : "First-time connections glow for a day.";
  $("sphere").setAttribute("aria-label",
    `Map of ${m.apps} apps on this PC and the ${m.services} AI services they connect to. ` +
    (review ? `${review} need review; details are in the lists below.` : "Nothing needs review."));
  renderStarDetail(sphere.selected);
}

function renderChips(s) {
  const counts = {};
  for (const t of s.traffic || []) counts[t.category] = (counts[t.category] || 0) + 1;
  counts.ai = Math.max(counts.ai || 0, new Set((s.flows || []).map((f) => f.image)).size);
  $("chips").replaceChildren(...CATS.map((c) =>
    el("button", { class: "chip-btn", "aria-pressed": filters.has(c.id) ? "true" : "false",
      onclick: () => {
        filters.has(c.id) ? filters.delete(c.id) : filters.add(c.id);
        saveFilters();
        refresh();
      } }, c.label, counts[c.id] ? el("span", { class: "chip-count" }, String(counts[c.id])) : null)));
}

function renderTiles(s) {
  const allowed = new Set((s.allowed || []).map((p) => p.toLowerCase()));
  const apps = new Map();
  for (const f of s.flows || []) apps.set((f.image || `pid:${f.pid}`).toLowerCase(), f);
  const unapproved = [...apps.values()].filter((f) => !f.local && !allowed.has((f.image || "").toLowerCase())).length;
  $("tile-ai").textContent = String(apps.size);
  $("tile-ai-sub").textContent = !apps.size ? "None right now" : unapproved ? `${unapproved} not approved yet` : "All approved";
  $("tile-ai").closest(".tile").dataset.state = unapproved ? "warn" : "ok";

  const bait = (s.bait || []).length;
  $("tile-bait").textContent = String(bait);
  $("tile-bait-sub").textContent = bait ? "Untouched" : "Add one so you'll know";
  $("tile-bait").closest(".tile").dataset.state = bait ? "ok" : "warn";

  const d = s.defender || {};
  const healthy = d.available && d.realTimeProtection;
  $("tile-def").textContent = !d.available ? "Unavailable" : healthy ? "On" : "Off";
  $("tile-def-sub").textContent = !d.available ? (d.error || "Can't read Defender")
    : (s.defenderIssues || []).length ? s.defenderIssues[0]
    : `Definitions ${d.signatureAgeDays === 0 ? "up to date" : d.signatureAgeDays + " day" + (d.signatureAgeDays === 1 ? "" : "s") + " old"}`;
  $("tile-def").closest(".tile").dataset.state = !healthy ? "bad" : (s.defenderIssues || []).length ? "warn" : "ok";

  const n = s.unhandled || 0;
  $("nav-alerts").hidden = !n;
  $("nav-alerts").textContent = String(n);
}

function renderListeners(s) {
  const ls = (s.listeners || []).filter((l) => l.exposed);
  const local = (s.listeners || []).length - ls.length;
  const byImg = new Map();
  for (const l of ls) {
    const k = l.image || `PID ${l.pid}`;
    if (!byImg.has(k)) byImg.set(k, new Set());
    byImg.get(k).add(l.port);
  }
  $("listeners").replaceChildren(...[...byImg].sort((a, b) => a[0].localeCompare(b[0])).map(([img, ports]) =>
    el("li", {}, el("div", { class: "r-main" },
      el("div", { class: "r-name" }, baseName(img)),
      el("div", { class: "r-sub" }, `Port${ports.size > 1 ? "s" : ""} ${[...ports].sort((a, b) => a - b).join(", ")}`)))));
  $("listeners-empty").hidden = byImg.size > 0;
  $("listeners-local").textContent = local > 0
    ? `${local} more only reachable from this PC itself.` : "";
}

// The eight eyes: what Tripsilk is watching, and what to do about one that's off.
function renderEyes(s) {
  const d = s.defender || {};
  const eyes = [
    ["AI traffic", !s.netError, "Can't read network activity right now."],
    ["Agent watch", !!s.agentGuard, "Not available on this PC."],
    ["Trip lines", (s.bait || []).length > 0, "Add a trip line file under Trip lines."],
    ["Ransomware shield", !!s.shieldOn, "Couldn't watch your folders."],
    ["Microsoft Defender", !!d.available && !(s.defenderIssues || []).length, "See Microsoft Defender below."],
    ["Open ports", !s.trafficError, "Can't read which programs accept connections."],
    ["Folder protection", s.folderProtection === "on", "Turn on Windows folder protection under Microsoft Defender."],
    ["Installed copy", !!s.installed, "Install Tripsilk so other programs can't replace it."],
  ];
  const open = eyes.filter((e) => e[1]).length;
  $("eyes").replaceChildren(...eyes.map(([name, on], i) =>
    el("span", { class: "eye" + (i >= 4 ? " rear" : "") + (on ? "" : " off"), title: name + (on ? "" : " (off)") })));
  $("eyes-label").textContent = `${open} of 8 eyes open`;
  $("eyes-list").replaceChildren(...eyes.map(([name, on, fix]) =>
    el("li", {}, el("span", { class: "eye" + (on ? "" : " off") }),
      el("span", {}, name + (on ? "" : " is off"), on ? null : el("span", { class: "why" }, fix)))));
}

function renderCoverage(s) {
  $("cov-yes").replaceChildren(...(s.coverage || []).map((c) => el("li", {}, c)));
  $("cov-no").replaceChildren(...(s.notCovered || []).map((c) => el("li", {}, c)));
}

// ---- Refresh loop ----

let refreshing = false;
async function refresh() {
  if (refreshing) return;
  refreshing = true;
  try {
    const s = await api().Snapshot();
    renderWall(s);
    renderFlows(s);
    renderBait(s);
    renderDefender(s);
    renderHeld(s);
    renderAgents(s);
    renderRuleCards(s);
    renderWeek(s.recap);
    renderSaid(s.saidDid);
    renderConstellation(s);
    renderListeners(s);
    renderCoverage(s);
    renderEyes(s);
    renderTiles(s);
    maybeSetup(s);
  } catch (e) {
    $("wall").dataset.state = "danger";
    $("wall-title").textContent = "Tripsilk couldn't start";
    $("wall-detail").textContent = String(e && e.message ? e.message : e);
  } finally {
    refreshing = false;
  }
}

// ---- First-run setup ----
// Three screens: approve the AI apps you use, create a trip line, turn on
// Windows folder protection. Shown until finished or skipped.

let setup = null; // { step, snap, picked:Set }

// While setup is open, everything behind it is inert: no focus, no clicks,
// hidden from screen readers.
function setBehindInert(on) {
  for (const n of document.body.children) {
    if (n.id !== "setup" && n.id !== "toast" && n.id !== "announcer") n.inert = on;
  }
}

function closeSetup() {
  $("setup").hidden = true;
  setBehindInert(false);
  setup = null;
}

function maybeSetup(s) {
  if (s.setupDone) { if (setup) closeSetup(); else $("setup").hidden = true; return; }
  if (!setup) {
    if (document.getElementById("splash")) return; // after the opening animation
    setup = { step: 0, picked: new Map(), shown: -1, busy: false }; // picked: key -> image
    $("setup").hidden = false;
    setBehindInert(true);
  }
  setup.snap = s;
  renderSetup();
}

function aiApps(s) {
  const seen = new Map();
  for (const f of s.flows || []) {
    if (f.local || !f.image) continue;
    const k = f.image.toLowerCase();
    if (!seen.has(k)) seen.set(k, { image: f.image, services: new Set() });
    seen.get(k).services.add(f.provider);
  }
  return [...seen.values()];
}

function renderSetup() {
  if (!setup) return;
  const s = setup.snap;
  const body = $("setup-body");
  const next = $("setup-next");
  next.disabled = setup.busy;
  // The 4-second refresh re-renders the step; don't rebuild it under the
  // user while they're on one of its controls, or keyboard focus is lost.
  if (setup.shown === setup.step && body.contains(document.activeElement)) return;
  $("setup-step").textContent = setup.step < 3 ? `Step ${setup.step + 1} of 3` : "All set";
  if (setup.step === 0) {
    $("setup-h").textContent = "Approve the AI apps you use";
    const allowed = new Set((s.allowed || []).map((x) => x.toLowerCase()));
    const apps = aiApps(s);
    if (!apps.length) {
      body.replaceChildren(el("p", {}, "No program is using an AI service right now. That's fine: when one does, Tripsilk will ask you about it."));
    } else {
      body.replaceChildren(
        el("p", {}, "These programs are talking to AI services right now. Tick the ones you use on purpose. Anything you don't tick will be flagged so you can check it."),
        el("ul", { class: "setup-list" }, ...apps.map((a) => {
          const k = a.image.toLowerCase();
          const box = el("input", { type: "checkbox" });
          box.checked = allowed.has(k) || setup.picked.has(k);
          box.disabled = allowed.has(k);
          box.onchange = () => box.checked ? setup.picked.set(k, a.image) : setup.picked.delete(k);
          return el("li", {}, el("label", { class: "toggle" }, box,
            el("span", {}, el("b", {}, baseName(a.image)), " uses ", [...a.services].join(", "),
              allowed.has(k) ? " (already approved)" : "", el("br"), el("small", { class: "hint" }, a.image))));
        })));
    }
    next.textContent = "Next";
  } else if (setup.step === 1) {
    $("setup-h").textContent = "Set a trip line";
    const bait = s.bait || [];
    body.replaceChildren(
      el("p", {}, "A trip line is a file nothing on this PC has any reason to touch. If a program opens or changes it, Tripsilk raises the alarm. It's the most reliable way to catch something going through your files."),
      bait.length
        ? el("p", { class: "setup-done" }, `You already have ${bait.length} trip line${bait.length > 1 ? "s" : ""}: ${bait.map((b) => b.path).join(", ")}.`)
        : el("p", {}, el("button", { class: "btn", onclick: () => act(() => api().CreateTripline().then((p) => toast("Trip line created: " + p))) }, "Create a trip line for me"),
            " Tripsilk makes a small text file that looks like old paperwork."));
    next.textContent = "Next";
  } else if (setup.step === 2) {
    $("setup-h").textContent = "Turn on Windows folder protection";
    const on = s.folderProtection === "on";
    body.replaceChildren(
      el("p", {}, "Windows can stop unknown programs from changing your Documents, Pictures and Desktop. It's the strongest block against ransomware, and it's built into Windows."),
      on ? el("p", { class: "setup-done" }, "It's on.")
         : el("p", {}, el("button", { class: "btn", onclick: () => act(() => api().SetFolderProtection(true), "Folder protection on") }, "Turn it on"),
             " Windows may then ask before letting a new app save into those folders. You can allow apps in Windows Security."));
    next.textContent = "Next";
  } else {
    $("setup-h").textContent = "You're set up";
    body.replaceChildren(
      el("p", {}, s.dryRun
        ? "Tripsilk starts in practice mode: for the first few days it records what it would freeze or block without doing it, so you can see what it flags on a normal day. Turn practice mode off in Settings when you're happy."
        : "Tripsilk is watching. Alerts appear on Home and under Activity, with what happened, why it matters and what to do."),
      s.installed && !s.startAtSignIn
        ? el("p", {}, el("button", { class: "btn", onclick: () => act(() => api().SetStartAtSignIn(true), "Tripsilk will start when you sign in") }, "Start Tripsilk when I sign in"),
            " Recommended: otherwise protection stops at the next restart until you open Tripsilk again.")
        : s.startAtSignIn ? el("p", { class: "setup-done" }, "Tripsilk starts when you sign in.") : null,
      el("p", { class: "hint" }, "Closing the window keeps Tripsilk running in the background."));
    next.textContent = "Open Tripsilk";
  }
  // A new step: move focus to its heading so keyboard and screen-reader
  // users start at the top of it. Re-renders of the same step keep focus.
  if (setup.shown !== setup.step) {
    setup.shown = setup.step;
    $("setup-h").focus();
  }
}

async function setupNext() {
  if (!setup || setup.busy) return;
  if (setup.step === 0 && setup.picked.size) {
    setup.busy = true;
    next_busy(true);
    // Approve what was ticked, even if its connection has closed since.
    for (const image of setup.picked.values()) {
      try { await api().Allow(image); } catch (e) { toast(String(e && e.message ? e.message : e), true); }
    }
    setup.picked.clear();
    setup.busy = false;
    next_busy(false);
  }
  if (setup.step >= 3) return finishSetup();
  setup.step++;
  renderSetup();
  refresh();
}

function next_busy(b) { $("setup-next").disabled = b; }

function finishSetup() {
  // Close only once it's saved; otherwise the next refresh would reopen it.
  Promise.resolve(api().FinishSetup()).then(closeSetup, (e) => toast(String(e && e.message ? e.message : e), true));
}

// ---- Pages ----

function showPage(name) {
  for (const p of document.querySelectorAll("main.page")) p.hidden = p.dataset.page !== name;
  for (const b of document.querySelectorAll(".nav-btn")) {
    if (b.dataset.page === name) b.setAttribute("aria-current", "page");
    else b.removeAttribute("aria-current");
  }
  window.scrollTo(0, 0);
}

// The opening animation removes itself when it finishes; a click skips it.
function splash() {
  const sp = $("splash");
  if (!sp) return;
  const done = () => sp.remove();
  sp.addEventListener("click", () => { sp.classList.add("skip"); setTimeout(done, 250); });
  sp.addEventListener("animationend", (e) => { if (e.animationName === "ts-fade") done(); });
  setTimeout(done, 4000); // in case animations are off entirely
}

function wire() {
  for (const b of document.querySelectorAll(".nav-btn")) b.addEventListener("click", () => showPage(b.dataset.page));
  for (const b of document.querySelectorAll("[data-go]")) b.addEventListener("click", () => showPage(b.dataset.go));
  // The eyes popover closes when you click anywhere else.
  document.addEventListener("click", (e) => {
    const w = $("eyes-wrap");
    if (w.open && !w.contains(e.target)) w.open = false;
  });
  $("week-update").onclick = () => act(() => api().RefreshRecap(), "Summary updated");
  $("btn-quick").onclick = () => act(() => api().QuickScan(), "Quick scan started");
  $("btn-full").onclick = () => act(() => api().FullScan(), "Full scan started. This can take an hour or more.");
  $("btn-report").onclick = () => act(() => api().CopyReport(),
    "Report copied. Paste it into Claude or another AI and ask what to do.");
  $("btn-ack").onclick = () => act(() => api().Acknowledge(), "Marked as handled");
  $("btn-defs").onclick = () => act(() => api().UpdateDefinitions(), "Definitions updated");
  $("chk-cfa").onchange = (e) => act(() => api().SetFolderProtection(e.target.checked),
    e.target.checked ? "Folder protection on" : "Folder protection off");
  $("btn-disconnect").onclick = () => {
    if (confirm("Block every program from the internet, including Defender updates? Tripsilk's dashboard keeps working. Use this if you think you're being hacked right now.")) act(() => api().Disconnect(), "Internet disconnected");
  };
  $("btn-reconnect").onclick = () => act(() => api().Reconnect(), "Internet restored");
  $("btn-add-bait").onclick = () => act(async () => {
    const p = await api().AddBait();
    if (p) toast("Trip line set on " + baseName(p));
  });
  $("chk-read").onchange = (e) => act(() => api().SetReadDetection(e.target.checked),
    e.target.checked ? "Read detection on" : "Read detection off");
  $("chk-dryrun").onchange = (e) => act(() => api().SetDryRun(e.target.checked),
    e.target.checked ? "Practice mode on" : "Practice mode off");
  $("chk-toasts").onchange = (e) => act(() => api().SetToasts(e.target.checked),
    e.target.checked ? "Notifications on" : "Notifications off");
  $("chk-evlog").onchange = (e) => act(() => api().SetEventLog(e.target.checked),
    e.target.checked ? "Copying alerts to the Event Log" : "Stopped copying to the Event Log");
  $("chk-signin").onchange = (e) => act(() => api().SetStartAtSignIn(e.target.checked),
    e.target.checked ? "Tripsilk will start when you sign in" : "Tripsilk won't start at sign-in");
  $("btn-quit").onclick = () => api().Quit();
  $("btn-dryrun-off").onclick = () => act(() => api().SetDryRun(false), "Practice mode off");
  $("setup-next").onclick = setupNext;
  $("chk-contain").onchange = (e) => act(() => api().SetAutoContain(e.target.checked),
    e.target.checked ? "Automatic containment on" : "Automatic containment off");
  $("setup-skip").onclick = finishSetup;
}

async function boot() {
  splash();
  wire();
  if (window.OrbWeb) {
    sphere = window.OrbWeb.create($("sphere"), renderStarDetail);
    // Clicking a program on Home opens it on the Programs page.
    homeWeb = window.OrbWeb.create($("home-web"), async (n) => {
      if (!n) return;
      homeWeb.select(null);
      showPage("programs");
      // Make sure the Programs filters aren't hiding it.
      const cat = n.kind === "service" ? null : n.category || "ai";
      if (cat && !filters.has(cat)) {
        filters.add(cat);
        saveFilters();
        await refresh();
      }
      sphere.select(n.id);
    }, { maxRows: 7 });
  }
  try { alerts = (await api().Alerts()) || []; } catch { alerts = []; }
  renderAlerts();
  window.runtime.EventsOn("alert", (a) => {
    alerts.unshift(a);
    renderAlerts(a.id);
    announce(a);
    refresh();
  });
  refresh();
  setInterval(refresh, 4000);
  setInterval(() => renderAlerts(), 60000); // keep "x min ago" current
}

// Wails injects window.go/window.runtime before scripts run; wait if not.
if (window.go && window.runtime) boot();
else window.addEventListener("load", boot);
})();
