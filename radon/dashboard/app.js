// R.A.D.O.N. dashboard
const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const SEVERITY_COLORS = {
  critical: "#f43f5e", high: "#f97316", medium: "#eab308", low: "#22c55e", info: "#3b82f6",
};
const SERVICE_LABELS = {
  iam: "IAM", gcs: "Cloud Storage", compute: "Compute Engine", cloud_run: "Cloud Run",
};

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

function titleCase(s) {
  return String(s).split("_").map((w) => w.charAt(0).toUpperCase() + w.slice(1)).join(" ");
}

function cap(s) {
  return String(s).charAt(0).toUpperCase() + String(s).slice(1);
}

// ---------- theme ----------
let currentTheme = localStorage.getItem("radon-theme") || "dark";

function applyTheme(theme) {
  const resolved = theme === "system"
    ? (window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark")
    : theme;
  document.documentElement.setAttribute("data-theme", resolved);
}

function setTheme(theme) {
  currentTheme = theme;
  localStorage.setItem("radon-theme", theme);
  applyTheme(theme);
}

applyTheme(currentTheme);
window.matchMedia("(prefers-color-scheme: light)").addEventListener("change", () => {
  if (currentTheme === "system") applyTheme("system");
});

// ---------- sidebar collapse ----------
const sidebar = $("#sidebar");
if (localStorage.getItem("radon-sidebar") === "collapsed") sidebar.classList.add("collapsed");
$("#collapse-btn").addEventListener("click", () => {
  sidebar.classList.toggle("collapsed");
  localStorage.setItem("radon-sidebar", sidebar.classList.contains("collapsed") ? "collapsed" : "expanded");
});

async function json(url, opts) {
  const resp = await fetch(url, opts);
  if (!resp.ok) throw new Error(`${resp.status} ${url}`);
  return resp.json();
}

function scoreColor(score) {
  if (score < 40) return "var(--critical)";
  if (score < 70) return "var(--medium)";
  return "var(--low)";
}

// ---------- tab switching ----------
function switchTab(name) {
  $$(".nav-item").forEach((b) => b.classList.toggle("active", b.dataset.tab === name));
  $$(".tab").forEach((t) => {
    const active = t.id === `tab-${name}`;
    t.hidden = !active;
    t.classList.toggle("active", active);
  });
  ({ overview: renderOverview, findings: renderFindings, chat: renderChat, trends: renderTrends, scan: renderScan, settings: renderSettings }[name])();
}

$$(".nav-item").forEach((b) => b.addEventListener("click", () => switchTab(b.dataset.tab)));

// ---------- dashboard ----------
let miniChart = null;
let summaryCache = null;

async function renderOverview() {
  const el = $("#tab-overview");
  let score = null;
  try { score = await json("/score"); } catch { /* no scan yet */ }

  const counts = score
    ? [["critical", score.critical], ["high", score.high], ["medium", score.medium], ["low", score.low]]
    : [];

  el.innerHTML = `
    <h2 class="tab-title">Security Dashboard</h2>
    <p class="tab-desc">Security posture of the most recent scan.</p>
    <div class="dashboard-grid">
      <div class="dashboard-left">
        <div class="panel score-card">
          <div class="score-value" style="color:${score ? scoreColor(score.score) : "var(--muted)"}">
            ${score ? score.score : "—"}<span class="score-suffix">%</span>
          </div>
          <div class="score-label">Security score</div>
          <div class="counts">
            ${counts.map(([k, v]) => `<div class="count-row ${k}" data-sev="${k}"><span class="count-label">${k}</span><span class="count-num">${v}</span></div>`).join("")}
          </div>
        </div>
        <div class="panel scan-box">
          <div class="scan-box-title">Run a fresh scan</div>
          <div class="scan-box-sub">Re-audit the project</div>
        </div>
      </div>
      <div class="dashboard-right">
        <div class="panel mini-chart-panel">
          <h3>Security History</h3>
          <div class="chart-box mini"><canvas id="chart-mini"></canvas></div>
        </div>
        <div class="panel narrative">
          <h3>Risk narrative</h3>
          <p id="narrative-text">Loading…</p>
        </div>
      </div>
    </div>`;

  el.querySelectorAll(".count-row").forEach((row) => row.addEventListener("click", () => {
    severityFilter = row.dataset.sev;
    switchTab("findings");
  }));
  el.querySelector(".mini-chart-panel").addEventListener("click", () => switchTab("trends"));
  el.querySelector(".scan-box").addEventListener("click", () => switchTab("scan"));

  if (summaryCache) {
    const p = el.querySelector("#narrative-text");
    if (p) p.textContent = summaryCache;
  } else {
    json("/summary").then((s) => {
      summaryCache = s.summary;
      const p = el.querySelector("#narrative-text");
      if (p) p.textContent = s.summary;
    }).catch(() => { const p = el.querySelector("#narrative-text"); if (p) p.textContent = "No scan yet — run one from the Scan tab."; });
  }

  json("/score/history").then((h) => {
    if (h.length && el.querySelector("#chart-mini")) drawScoreChart(h);
  }).catch(() => {});
}

function drawScoreChart(history) {
  if (miniChart) miniChart.destroy();
  const labels = history.map((_, i) => `#${i + 1}`);
  miniChart = new Chart($("#chart-mini"), {
    type: "line",
    data: {
      labels,
      datasets: [{
        label: "Score",
        data: history.map((p) => p.score),
        borderColor: "#38bdf8",
        backgroundColor: "rgba(56, 189, 248, 0.12)",
        fill: true, tension: 0, pointRadius: 3, borderWidth: 2,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: "#5b6a80" }, grid: { color: "rgba(148, 163, 184, 0.06)" } },
        y: { min: 0, max: 100, ticks: { color: "#5b6a80" }, grid: { color: "rgba(148, 163, 184, 0.06)" } },
      },
    },
  });
}

// ---------- findings ----------
let cachedReports = [];
let severityFilter = "all";

async function renderFindings() {
  const el = $("#tab-findings");
  try { cachedReports = await json("/reports"); } catch { cachedReports = []; }

  el.innerHTML = `
    <h2 class="tab-title">Findings</h2>
    <p class="tab-desc">Grouped by service. Click a finding to expand it, relabel with +, or Fix to discuss it with the AI.</p>
    <div class="findings-toolbar">
      ${["all", ...SEVERITIES].map((s) => {
        const n = s === "all" ? cachedReports.length : cachedReports.filter((r) => r.finding.severity === s).length;
        return `<button class="filter-chip ${s === severityFilter ? "active" : ""}" data-sev="${s}">${s}<span class="chip-count">${n}</span></button>`;
      }).join("")}
    </div>
    <div class="service-groups"></div>`;

  el.querySelectorAll(".filter-chip").forEach((b) => b.addEventListener("click", () => {
    severityFilter = b.dataset.sev;
    renderFindings();
  }));
  renderServiceGroups(el.querySelector(".service-groups"));
}

function renderServiceGroups(container) {
  const filtered = severityFilter === "all"
    ? cachedReports
    : cachedReports.filter((r) => r.finding.severity === severityFilter);

  const groups = {};
  for (const r of filtered) (groups[r.finding.service] ||= []).push(r);
  const order = Object.keys(groups).sort((a, b) =>
    (SERVICE_LABELS[a] || a).localeCompare(SERVICE_LABELS[b] || b));

  container.innerHTML = order.map((svc) => {
    const reports = groups[svc].slice().sort((a, b) => {
      if (a.status === "ignored" && b.status !== "ignored") return 1;
      if (b.status === "ignored" && a.status !== "ignored") return -1;
      return SEVERITIES.indexOf(a.finding.severity) - SEVERITIES.indexOf(b.finding.severity);
    });
    return `
      <div class="service-group open">
        <div class="service-head">
          <span class="service-caret">▶</span>
          <span class="service-name">${esc(SERVICE_LABELS[svc] || svc)}</span>
          <span class="service-count">${reports.length} finding${reports.length === 1 ? "" : "s"}</span>
        </div>
        <div class="finding-list">${reports.map(findingCard).join("")}</div>
      </div>`;
  }).join("") || `<div class="empty"><div class="empty-big">No findings</div><div class="empty-sub">Run a scan to see results.</div></div>`;

  container.onclick = (e) => {
    const menuBtn = e.target.closest(".menu button");
    if (menuBtn) { setStatus(menuBtn.closest(".finding").dataset.id, menuBtn.dataset.status); return; }
    const fixBtn = e.target.closest(".fix-btn");
    if (fixBtn) {
      const c = fixBtn.closest(".finding").dataset;
      askAboutFinding({ rule: c.rule, resource: c.resource, severity: c.severity, detail: c.detail });
      return;
    }
    const statusBtn = e.target.closest(".status-btn");
    if (statusBtn) { statusBtn.closest(".status-menu").classList.toggle("open"); return; }
    const head = e.target.closest(".service-head");
    if (head) { head.closest(".service-group").classList.toggle("open"); return; }
    const finding = e.target.closest(".finding");
    if (finding) { finding.classList.toggle("open"); return; }
  };
}

function findingCard(r) {
  const f = r.finding, a = r.assessment;
  return `
    <div class="finding ${f.severity} ${r.status === "ignored" ? "ignored" : ""}"
         data-id="${esc(f.id)}" data-rule="${esc(f.rule)}" data-resource="${esc(f.resource)}"
         data-detail="${esc(f.detail)}" data-severity="${esc(f.severity)}">
      <div class="finding-row">
        <span class="finding-caret">▸</span>
        <span class="badge ${f.severity}">${f.severity}</span>
        <span class="rule">${esc(titleCase(f.rule))}</span>
        <span class="resource">${esc(f.resource)}</span>
        <div class="status-menu">
          <button class="status-btn">${esc(r.status)}</button>
          <div class="menu">
            <button data-status="unresolved">Unresolved</button>
            <button data-status="resolved">Resolved</button>
            <button data-status="ignored">Ignored</button>
          </div>
        </div>
        <button class="fix-btn">Fix</button>
      </div>
      <div class="finding-detail">${esc(cap(f.detail))}</div>
      <div class="finding-assess">
        <div class="a-label">What's wrong</div>
        <div class="a-text">${esc(a.explanation)}</div>
        <div class="a-label">How to fix</div>
        <div class="a-text">${esc(a.remediation)}</div>
      </div>
    </div>`;
}

async function setStatus(fid, status) {
  await json(`/reports/status?finding_id=${encodeURIComponent(fid)}&status=${status}`, { method: "POST" });
  renderFindings();
}

// ---------- chat ----------
let chatMessages = [];
let chatStyle = localStorage.getItem("radon-chat-style") || "normal";
let userName = localStorage.getItem("radon-user-name") || "admin";
let chatContext = localStorage.getItem("radon-context") || "";
let systemPrompt = localStorage.getItem("radon-system-prompt") || "";
let chatBusy = false;

const SEND_ICON = `<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 2L11 13"/><path d="M22 2l-7 20-4-9-9-4 20-7z"/></svg>`;
const STOP_ICON = `<svg width="13" height="13" viewBox="0 0 24 24" fill="currentColor"><rect x="6" y="6" width="12" height="12" rx="2"/></svg>`;

function renderChat() {
  const el = $("#tab-chat");
  if (el.dataset.built) return;
  el.dataset.built = "1";
  el.innerHTML = `
    <h2 class="tab-title">AI Chat</h2>
    <p class="tab-desc">Ask about a finding or how to remediate your posture. Click Fix on any finding to jump here with its context.</p>
    <div class="chat-wrap">
      <div class="chat-log" id="chat-log"></div>
      <div class="chat-input-row">
        <textarea class="chat-input" id="chat-input" rows="2" placeholder="Ask about a finding or how to fix something…"></textarea>
        <button class="chat-send" id="chat-send" title="Send">${SEND_ICON}</button>
      </div>
    </div>`;
  $("#chat-send").addEventListener("click", sendChat);
  $("#chat-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendChat(); }
  });
  appendChat("assistant", "Ask me anything about your project's security posture. Click **Fix** on any finding to bring its context here.");
}

function setChatBusy(busy) {
  chatBusy = busy;
  const btn = $("#chat-send");
  btn.innerHTML = busy ? STOP_ICON : SEND_ICON;
  btn.disabled = busy;
  $("#chat-input").disabled = busy;
}

async function sendChat() {
  const input = $("#chat-input");
  const text = input.value.trim();
  if (!text || chatBusy) return;
  input.value = "";
  await sendChatText(text);
}

async function sendChatText(text) {
  if (chatBusy) return;
  appendChat("user", text);
  chatMessages.push({ role: "user", content: text });
  setChatBusy(true);
  const thinking = appendThinking();
  try {
    const reply = await json("/chat", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ messages: chatMessages, style: chatStyle, user_name: userName, context: chatContext, system_prompt: systemPrompt }),
    });
    thinking.remove();
    chatMessages.push({ role: "assistant", content: reply.reply });
    appendChat("assistant", reply.reply);
  } catch {
    thinking.remove();
    appendChat("assistant", "Something went wrong — try again.");
  } finally {
    setChatBusy(false);
  }
}

function appendThinking() {
  const log = $("#chat-log");
  const div = document.createElement("div");
  div.className = "msg assistant";
  div.innerHTML = `<span class="msg-role">R.A.D.O.N.</span><span class="thinking-dots"><i></i><i></i><i></i></span>`;
  log.appendChild(div);
  log.scrollTop = log.scrollHeight;
  return div;
}

function appendChat(role, text) {
  const log = $("#chat-log");
  const div = document.createElement("div");
  div.className = `msg ${role}`;
  if (role === "assistant") {
    div.innerHTML = `<span class="msg-role">R.A.D.O.N.</span><div class="msg-body">${renderMarkdown(text)}</div>`;
  } else {
    div.textContent = text;
  }
  log.appendChild(div);
  log.scrollTop = log.scrollHeight;
}

function renderMarkdown(text) {
  let s = String(text).replace(/\r\n?/g, "\n");
  s = esc(s);
  s = s.replace(/```(\w*)\n?([\s\S]*?)```/g, "<pre><code>$2</code></pre>");
  s = s.replace(/`([^`\n]+)`/g, "<code>$1</code>");
  s = s.replace(/~~([^~]+)~~/g, "<del>$1</del>");
  s = s.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  s = s.replace(/__([^_]+)__/g, "<strong>$1</strong>");
  s = s.replace(/(^|[^*])\*([^*\n]+)\*/g, "$1<em>$2</em>");
  s = s.replace(/(^|[^_])_([^_\n]+)_/g, "$1<em>$2</em>");
  s = s.replace(/\[([^\]]+)\]\(([^)\s]+)\)/g, '<a href="$2" target="_blank" rel="noopener">$1</a>');
  s = s.replace(/^### (.+)$/gm, "<h4>$1</h4>");
  s = s.replace(/^## (.+)$/gm, "<h3>$1</h3>");
  s = s.replace(/^# (.+)$/gm, "<h2>$1</h2>");
  s = s.replace(/^(\s*)[-*] (.+)$/gm, "$1• $2");
  s = s.replace(/^(\s*)\d+\. (.+)$/gm, "$1• $2");
  s = s.replace(/\n{2,}/g, "\n");
  s = s.replace(/\n/g, "<br>");
  return s;
}

async function askAboutFinding(f) {
  switchTab("chat");
  await sendChatText(
    `How do I fix this finding?\n\nRule: ${titleCase(f.rule)}\nResource: ${f.resource}\nSeverity: ${f.severity}\nDetail: ${f.detail}`);
}

// ---------- trends ----------
const TREND_SEVERITIES = ["critical", "high", "medium", "low"];
let trendToggles = { critical: true, high: true, medium: true, low: true };
let trendChart = null;

async function renderTrends() {
  const el = $("#tab-trends");
  const history = await json("/score/history").catch(() => []);

  el.innerHTML = `
    <h2 class="tab-title">Security Trends</h2>
    <p class="tab-desc">Finding counts across successive scans. Toggle a severity to show or hide its line.</p>
    <div class="panel chart-panel">
      <h3>Findings by severity</h3>
      <div class="chart-box"><canvas id="chart-trend"></canvas></div>
    </div>
    <div class="trend-toolbar">
      ${TREND_SEVERITIES.map((s) =>
        `<button class="trend-toggle ${trendToggles[s] ? "active" : ""}" data-trend="${s}"><span class="tdot ${s}"></span>${s}</button>`).join("")}
    </div>`;

  el.querySelectorAll("[data-trend]").forEach((b) => b.addEventListener("click", () => {
    trendToggles[b.dataset.trend] = !trendToggles[b.dataset.trend];
    renderTrends();
  }));

  if (history.length) {
    drawTrendChart(history);
  } else {
    el.querySelector(".chart-panel").innerHTML =
      `<div class="empty"><div class="empty-big">No scans yet</div><div class="empty-sub">Run a scan from the Scan tab to build up a trend.</div></div>`;
  }
}

function drawTrendChart(history) {
  if (trendChart) trendChart.destroy();
  const labels = history.map((_, i) => `#${i + 1}`);
  const datasets = TREND_SEVERITIES
    .filter((s) => trendToggles[s])
    .map((s) => ({
      label: s,
      data: history.map((p) => p[s]),
      borderColor: SEVERITY_COLORS[s],
      backgroundColor: hexToRgba(SEVERITY_COLORS[s], 0.1),
      fill: true, tension: 0, pointRadius: 2.5, borderWidth: 2,
    }));
  trendChart = new Chart($("#chart-trend"), {
    type: "line",
    data: { labels, datasets },
    options: chartOptions(null, null),
  });
}

function chartOptions(min, max) {
  return {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: { backgroundColor: "#171b25", borderColor: "#2e3749", borderWidth: 1, titleColor: "#e2e8f0", bodyColor: "#8494ab" },
    },
    scales: {
      x: { ticks: { color: "#5b6a80" }, grid: { color: "rgba(148, 163, 184, 0.06)" } },
      y: { min, max, ticks: { color: "#5b6a80", precision: 0 }, grid: { color: "rgba(148, 163, 184, 0.06)" } },
    },
  };
}

function hexToRgba(hex, a) {
  const r = parseInt(hex.slice(1, 3), 16), g = parseInt(hex.slice(3, 5), 16), b = parseInt(hex.slice(5, 7), 16);
  return `rgba(${r}, ${g}, ${b}, ${a})`;
}

// ---------- scan ----------
function renderScan() {
  const el = $("#tab-scan");
  el.innerHTML = `
    <h2 class="tab-title">Security Scan</h2>
    <p class="tab-desc">Run a scan against the configured GCP project and stream its progress.</p>
    <div class="scan-layout">
      <div class="scan-actions"><button class="scan-btn" id="scan-btn">Run scan</button></div>
      <div class="terminal" id="terminal"><div class="term-line"><span class="prompt">$</span> ready — click "Run scan"</div></div>
      <div class="scan-result" id="scan-result"></div>
    </div>`;
  $("#scan-btn").addEventListener("click", runScan);
}

function runScan() {
  const btn = $("#scan-btn");
  btn.disabled = true;
  btn.textContent = "Scanning…";
  const terminal = $("#terminal");
  terminal.innerHTML = "";
  termQueue.length = 0;
  termRevealing = false;

  const es = new EventSource("/scan/stream");
  es.onmessage = (e) => {
    const data = JSON.parse(e.data);
    if (data.line) appendTerm(terminal, data.line, data.level);
    else if (data.done) {
      appendTerm(terminal, `Scan complete. Security score: ${data.score.score}% (${data.score.critical + data.score.high + data.score.medium + data.score.low + data.score.info} findings)`, "done");
      es.close(); btn.disabled = false; btn.textContent = "Run scan";
      summaryCache = null;
      showScanResult(data.score);
    } else if (data.error) {
      appendTerm(terminal, `ERROR: ${data.error}`, "error");
      es.close(); btn.disabled = false; btn.textContent = "Run scan";
    }
  };
  es.onerror = () => { es.close(); btn.disabled = false; btn.textContent = "Run scan"; };
}

const termQueue = [];
let termRevealing = false;

function appendTerm(terminal, text, level = "info") {
  termQueue.push({ text, level });
  if (!termRevealing) revealTerm(terminal);
}

function revealTerm(terminal) {
  if (!termQueue.length) { termRevealing = false; return; }
  termRevealing = true;
  const { text, level } = termQueue.shift();
  const cls = { info: "info", ok: "ok", fail: "fail", done: "done", error: "fail" }[level] || "info";
  const div = document.createElement("div");
  div.className = `term-line ${cls}`;
  div.innerHTML = `<span class="prompt">$</span> ${esc(text)}`;
  terminal.appendChild(div);
  terminal.scrollTop = terminal.scrollHeight;
  setTimeout(() => revealTerm(terminal), 10);
}

function showScanResult(score) {
  const el = $("#scan-result");
  el.classList.add("show");
  el.innerHTML = `
    <div class="panel">
      <div class="mono" style="font-size:2rem;font-weight:700;color:${scoreColor(score.score)}">${score.score}% <span style="color:var(--muted);font-size:0.85rem;font-weight:400">security score</span></div>
      <p style="color:var(--muted);margin:0.5rem 0 0">
        ${score.critical} critical · ${score.high} high · ${score.medium} medium · ${score.low} low · ${score.info} info
      </p>
    </div>`;
}

// ---------- settings ----------
async function renderSettings() {
  const el = $("#tab-settings");
  let cfg = null;
  try { cfg = await json("/config"); } catch { /* no config */ }

  el.innerHTML = `
    <h2 class="tab-title">Settings</h2>
    <p class="tab-desc">Appearance, data, and model configuration.</p>
    <div class="settings-sections">
      <div class="panel settings-section">
        <h3>Appearance</h3>
        <div class="seg-group">
          ${["dark", "light", "system"].map((t) => `<button class="seg ${currentTheme === t ? "active" : ""}" data-theme="${t}">${t}</button>`).join("")}
        </div>
      </div>
      <div class="panel settings-section">
        <h3>Model style</h3>
        <div class="seg-group">
          ${["concise", "normal", "socratic", "informal"].map((s) => `<button class="seg ${chatStyle === s ? "active" : ""}" data-style="${s}">${s}</button>`).join("")}
        </div>
      </div>
      <div class="panel settings-section">
        <h3>AI personalization</h3>
        <div class="field">
          <label class="field-label" for="set-name">What the AI calls you</label>
          <input class="field-input" id="set-name" type="text" value="${esc(userName)}" placeholder="admin">
        </div>
        <div class="field">
          <label class="field-label" for="set-context">Project context</label>
          <textarea class="field-input" id="set-context" rows="2" placeholder="This project runs on Google Cloud Platform (GCP).">${esc(chatContext)}</textarea>
        </div>
        <div class="field">
          <label class="field-label" for="set-system">System prompt</label>
          <textarea class="field-input" id="set-system" rows="3" placeholder="Always provide actionable remediation steps. Ask the user for more information when needed.">${esc(systemPrompt)}</textarea>
        </div>
      </div>
      <div class="panel settings-section">
        <h3>Data</h3>
        <div class="seg-group">
          <button class="seg" id="btn-sample">Populate sample data</button>
          <button class="seg danger" id="btn-reset">Delete all data</button>
        </div>
      </div>
      <div class="panel settings-section">
        <h3>Project</h3>
        <div class="settings-list">
          ${settingRow("Project ID", cfg ? cfg.project_id : "—")}
          ${settingRow("Scanner endpoint", cfg ? cfg.endpoint : "—")}
          ${settingRow("LLM status", cfg && cfg.llm_live ? "Connected" : "Disconnected (mock)")}
          ${settingRow("Version", cfg ? cfg.version : "—")}
          ${settingRow("License", "Apache 2.0")}
        </div>
      </div>
    </div>`;

  el.querySelectorAll("[data-theme]").forEach((b) => b.addEventListener("click", () => {
    setTheme(b.dataset.theme);
    renderSettings();
  }));
  el.querySelectorAll("[data-style]").forEach((b) => b.addEventListener("click", () => {
    chatStyle = b.dataset.style;
    localStorage.setItem("radon-chat-style", chatStyle);
    renderSettings();
  }));
  el.querySelector("#set-name").addEventListener("input", (e) => { userName = e.target.value.trim(); localStorage.setItem("radon-user-name", userName); });
  el.querySelector("#set-context").addEventListener("input", (e) => { chatContext = e.target.value; localStorage.setItem("radon-context", chatContext); });
  el.querySelector("#set-system").addEventListener("input", (e) => { systemPrompt = e.target.value; localStorage.setItem("radon-system-prompt", systemPrompt); });
  el.querySelector("#btn-sample").addEventListener("click", async () => {
    await json("/seed", { method: "POST" });
    summaryCache = null;
    switchTab("overview");
  });
  el.querySelector("#btn-reset").addEventListener("click", async () => {
    await json("/reset", { method: "POST" });
    summaryCache = null;
    switchTab("overview");
  });
}

function settingRow(label, value) {
  return `<div class="setting-row"><span class="setting-label">${esc(label)}</span><span class="setting-value">${esc(value)}</span></div>`;
}

// boot
switchTab("overview");
