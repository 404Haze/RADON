// R.A.D.O.N. dashboard
const $ = (sel) => document.querySelector(sel);

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

let activeFilter = "all";

async function json(url, opts) {
  const resp = await fetch(url, opts);
  if (!resp.ok) throw new Error(`${resp.status} ${url}`);
  return resp.json();
}

async function runScan() {
  const btn = $("#scan-btn");
  btn.disabled = true;
  btn.textContent = "Scanning…";
  try {
    await json("/scan", { method: "POST" });
    await refresh();
  } catch (err) {
    console.error(err);
  } finally {
    btn.disabled = false;
    btn.textContent = "Run scan";
  }
}

function renderCounts(s) {
  const items = [
    ["critical", s.critical], ["high", s.high], ["medium", s.medium],
    ["low", s.low], ["info", s.info],
  ];
  $("#counts").innerHTML = items
    .map(([k, v]) => `<div class="count ${k}"><span>${v}</span><span>${k}</span></div>`)
    .join("");
}

async function loadScore() {
  try {
    const s = await json("/score");
    $("#score-value").textContent = s.score;
    renderCounts(s);
  } catch {
    $("#score-value").textContent = "—";
    $("#counts").innerHTML = "";
  }
}

function drawTrend(history) {
  const svg = $("#trend-chart");
  if (!history.length) return;
  const w = 420, h = 130, pad = 24;
  svg.setAttribute("viewBox", `0 0 ${w} ${h}`);
  const n = history.length;
  const x = (i) => (n === 1 ? pad : pad + (i * (w - 2 * pad)) / (n - 1));
  const y = (p) => h - pad - (p.score / 100) * (h - 2 * pad);
  const pts = history.map((p, i) => [x(i), y(p)]);
  const line = pts.map((p) => p.map((v) => v.toFixed(1)).join(",")).join(" ");
  svg.innerHTML =
    `<line x1="${pad}" y1="${h - pad}" x2="${w - pad}" y2="${h - pad}" stroke="#2a3040"/>` +
    `<polyline points="${line}" fill="none" stroke="#4da3ff" stroke-width="2"/>` +
    pts.map(([cx, cy]) => `<circle cx="${cx}" cy="${cy}" r="3.5" fill="#4da3ff"/>`).join("") +
    `<text x="${pad}" y="${h - 6}" fill="#8b93a5" font-size="10">${history.length} scan${history.length === 1 ? "" : "s"}</text>`;
}

async function loadHistory() {
  try {
    drawTrend(await json("/score/history"));
  } catch { /* no scans yet */ }
}

function reportCard(r) {
  const f = r.finding, a = r.assessment;
  const fixed = r.status === "remediated";
  return `
    <article class="finding ${f.severity}${fixed ? " fixed" : ""}">
      <div class="finding-head">
        <span class="badge ${f.severity}">${f.severity}</span>
        <span class="rule">${esc(f.rule)}</span>
        <span class="resource">${esc(f.resource)}</span>
        <span class="service">${esc(f.service)}</span>
        <button class="remediate" data-id="${esc(f.id)}" ${fixed ? "disabled" : ""}>${fixed ? "Fixed" : "Mark fixed"}</button>
      </div>
      <div class="detail">${esc(f.detail)}</div>
      <details>
        <summary>AI assessment</summary>
        <div class="assessment">
          <p class="explanation">${esc(a.explanation)}</p>
          <p class="remediation">${esc(a.remediation)}</p>
        </div>
      </details>
    </article>`;
}

function renderReports(reports) {
  const el = $("#findings");
  el.innerHTML = reports.length
    ? reports.map(reportCard).join("")
    : '<p class="empty">No findings. Run a scan to get started.</p>';
  el.querySelectorAll(".remediate").forEach((btn) =>
    btn.addEventListener("click", () => remediate(btn.dataset.id)));
}

async function loadReports() {
  const reports = await json("/reports");
  const filtered = activeFilter === "all"
    ? reports
    : reports.filter((r) => r.finding.severity === activeFilter);
  renderReports(filtered);
}

async function remediate(id) {
  await json(`/reports/status?finding_id=${encodeURIComponent(id)}&status=remediated`, { method: "POST" });
  await loadReports();
}

function renderFilters() {
  const sevs = ["all", "critical", "high", "medium", "low", "info"];
  $("#filters").innerHTML = sevs
    .map((s) => `<button class="filter${s === activeFilter ? " active" : ""}" data-sev="${s}">${s}</button>`)
    .join("");
  $("#filters").querySelectorAll(".filter").forEach((btn) =>
    btn.addEventListener("click", () => {
      activeFilter = btn.dataset.sev;
      renderFilters();
      loadReports();
    }));
}

async function refresh() {
  await Promise.all([loadScore(), loadHistory(), loadReports()]);
}

$("#scan-btn").addEventListener("click", runScan);
renderFilters();
refresh();
