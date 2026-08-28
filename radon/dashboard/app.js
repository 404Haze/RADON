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
  ({ overview: renderOverview, findings: renderFindings, chat: renderChat, trends: renderTrends, scan: renderScan }[name])();
}

$$(".nav-item").forEach((b) => b.addEventListener("click", () => switchTab(b.dataset.tab)));

// ---------- overview ----------
async function renderOverview() {
  const el = $("#tab-overview");
  let score = null, summary = null;
  try { score = await json("/score"); } catch { /* no scan yet */ }
  try { summary = await json("/summary"); } catch { /* no scan yet */ }

  const counts = score
    ? [["critical", score.critical], ["high", score.high], ["medium", score.medium], ["low", score.low], ["info", score.info]]
    : [];

  el.innerHTML = `
    <h2 class="tab-title">Overview</h2>
    <p class="tab-desc">Security posture of the most recent scan.</p>
    <div class="overview-grid">
      <div class="panel score-card">
        <div class="score-value" style="color:${score ? scoreColor(score.score) : "var(--muted)"}">
          ${score ? score.score : "—"}<span class="score-suffix">%</span>
        </div>
        <div class="score-label">Security score</div>
        <div class="counts">
          ${counts.map(([k, v]) => `<div class="count-row ${k}"><span class="count-label">${k}</span><span class="count-num">${v}</span></div>`).join("")}
        </div>
      </div>
      <div class="panel narrative">
        <h3>Risk narrative</h3>
        <p>${esc(summary ? summary.summary : "No scan yet — run one from the Scan tab.")}</p>
      </div>
    </div>`;
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

  container.querySelectorAll(".service-head").forEach((h) =>
    h.addEventListener("click", () => h.parentElement.classList.toggle("open")));
  container.querySelectorAll(".finding-row").forEach((row) =>
    row.addEventListener("click", (e) => {
      if (e.target.closest("button")) return;
      row.closest(".finding").classList.toggle("open");
    }));
  container.querySelectorAll(".status-btn").forEach((b) =>
    b.addEventListener("click", (e) => {
      e.stopPropagation();
      b.parentElement.classList.toggle("open");
    }));
  container.querySelectorAll(".menu button").forEach((b) =>
    b.addEventListener("click", (e) => {
      e.stopPropagation();
      setStatus(b.closest(".finding").dataset.id, b.dataset.status);
    }));
  container.querySelectorAll(".fix-btn").forEach((b) =>
    b.addEventListener("click", (e) => {
      e.stopPropagation();
      const c = b.closest(".finding").dataset;
      askAboutFinding({ rule: c.rule, resource: c.resource, severity: c.severity, detail: c.detail });
    }));
}

function findingCard(r) {
  const f = r.finding, a = r.assessment;
  return `
    <div class="finding ${f.severity} ${r.status === "ignored" ? "ignored" : ""}"
         data-id="${esc(f.id)}" data-rule="${esc(f.rule)}" data-resource="${esc(f.resource)}"
         data-detail="${esc(f.detail)}" data-severity="${esc(f.severity)}">
      <div class="finding-row">
        <span class="badge ${f.severity}">${f.severity}</span>
        <span class="rule">${esc(f.rule)}</span>
        <span class="resource">${esc(f.resource)}</span>
        <span class="spacer"></span>
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
      <div class="finding-detail">${esc(f.detail)}</div>
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
const CHAT_SYSTEM = "You are R.A.D.O.N.'s remediation assistant. Help the user understand and fix cloud security findings in their GCP project. Be concise, concrete, and specific to the finding or resource they mention.";
let chatMessages = [{ role: "system", content: CHAT_SYSTEM }];

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
        <button class="chat-send" id="chat-send">Send</button>
      </div>
      <div class="chat-hint">No live model loaded — responses are mocked. Set RADON_LLM_ENDPOINT for real triage.</div>
    </div>`;
  $("#chat-send").addEventListener("click", sendChat);
  $("#chat-input").addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); sendChat(); }
  });
  appendChat("assistant", "Ask me anything about your project's security posture. Click Fix on any finding to bring its context here.");
}

async function sendChat() {
  const input = $("#chat-input");
  const text = input.value.trim();
  if (!text) return;
  input.value = "";
  await sendChatText(text);
}

async function sendChatText(text) {
  appendChat("user", text);
  chatMessages.push({ role: "user", content: text });
  const reply = await json("/chat", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ messages: chatMessages }),
  });
  chatMessages.push({ role: "assistant", content: reply.reply });
  appendChat("assistant", reply.reply);
}

function appendChat(role, text) {
  const log = $("#chat-log");
  const div = document.createElement("div");
  div.className = `msg ${role}`;
  if (role === "assistant") {
    div.innerHTML = `<span class="msg-role">R.A.D.O.N.</span>${esc(text)}`;
  } else {
    div.textContent = text;
  }
  log.appendChild(div);
  log.scrollTop = log.scrollHeight;
}

async function askAboutFinding(f) {
  switchTab("chat");
  await sendChatText(
    `How do I fix this finding?\n\nRule: ${f.rule}\nResource: ${f.resource}\nSeverity: ${f.severity}\nDetail: ${f.detail}`);
}

// ---------- trends ----------
let trendCharts = [];

async function renderTrends() {
  const el = $("#tab-trends");
  const history = await json("/score/history").catch(() => []);

  el.innerHTML = `
    <h2 class="tab-title">Trends</h2>
    <p class="tab-desc">Posture and finding counts across successive scans.</p>
    <div class="chart-grid">
      <div class="panel chart-panel">
        <h3>Security score</h3>
        <div class="chart-box"><canvas id="chart-score"></canvas></div>
      </div>
      <div class="panel chart-panel">
        <h3>Findings by severity</h3>
        <div class="chart-box"><canvas id="chart-severity"></canvas></div>
      </div>
    </div>`;

  trendCharts.forEach((c) => c.destroy());
  trendCharts = [];
  const labels = history.map((_, i) => `#${i + 1}`);

  if (history.length) {
    trendCharts.push(new Chart($("#chart-score"), {
      type: "line",
      data: {
        labels,
        datasets: [{
          label: "Score",
          data: history.map((p) => p.score),
          borderColor: "#38bdf8",
          backgroundColor: "rgba(56, 189, 248, 0.12)",
          fill: true, tension: 0.35, pointRadius: 3, borderWidth: 2,
        }],
      },
      options: chartOptions(0, 100),
    }));

    trendCharts.push(new Chart($("#chart-severity"), {
      type: "line",
      data: {
        labels,
        datasets: SEVERITIES.map((s) => ({
          label: s,
          data: history.map((p) => p[s]),
          borderColor: SEVERITY_COLORS[s],
          backgroundColor: hexToRgba(SEVERITY_COLORS[s], 0.1),
          fill: true, tension: 0.35, pointRadius: 2.5, borderWidth: 2,
        })),
      },
      options: chartOptions(null, null),
    }));
  } else {
    el.querySelector(".chart-grid").innerHTML =
      `<div class="empty"><div class="empty-big">No scans yet</div><div class="empty-sub">Run a scan from the Scan tab to build up a trend.</div></div>`;
  }
}

function chartOptions(min, max) {
  return {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { labels: { color: "#8494ab", boxWidth: 12, boxHeight: 12 } },
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
    <h2 class="tab-title">Scan</h2>
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

  const es = new EventSource("/scan/stream");
  es.onmessage = (e) => {
    const data = JSON.parse(e.data);
    if (data.line) appendTerm(terminal, data.line);
    else if (data.done) {
      appendTerm(terminal, `Scan complete — score ${data.score.score}% (${data.score.critical + data.score.high + data.score.medium + data.score.low + data.score.info} findings)`, "done");
      es.close(); btn.disabled = false; btn.textContent = "Run scan";
      showScanResult(data.score);
    } else if (data.error) {
      appendTerm(terminal, `ERROR: ${data.error}`, "error");
      es.close(); btn.disabled = false; btn.textContent = "Run scan";
    }
  };
  es.onerror = () => { es.close(); btn.disabled = false; btn.textContent = "Run scan"; };
}

function appendTerm(terminal, text, cls = "ok") {
  const div = document.createElement("div");
  div.className = `term-line ${cls}`;
  div.innerHTML = `<span class="prompt">$</span> ${esc(text)}`;
  terminal.appendChild(div);
  terminal.scrollTop = terminal.scrollHeight;
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

// boot
switchTab("overview");
