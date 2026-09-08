(function () {
  var D = window.RADON_DEMO;
  if (!D) return;

  function ok(obj) {
    return new Response(JSON.stringify(obj), { status: 200, headers: { "Content-Type": "application/json" } });
  }
  function noop() { return ok({}); }

  window.fetch = function (url) {
    var u = String(url);
    if (u === "/score") return Promise.resolve(ok(D.score));
    if (u === "/summary") return Promise.resolve(ok({ summary: D.summary }));
    if (u === "/score/history") return Promise.resolve(ok(D.history));
    if (u === "/reports") return Promise.resolve(ok(D.reports));
    if (u.indexOf("/reports/status") === 0) return Promise.resolve(noop());
    if (u === "/chat") return Promise.resolve(ok({ reply: D.demo_reply }));
    if (u === "/settings") return Promise.resolve(ok(D.settings));
    if (u === "/models") return Promise.resolve(ok(D.models));
    if (u === "/components") return Promise.resolve(ok(D.components));
    if (u === "/seed" || u === "/reset" || u === "/scan") return Promise.resolve(ok(D.score));
    if (u.indexOf("/components/") === 0 || u.indexOf("/models/") === 0) return Promise.resolve(noop());
    return Promise.resolve(noop());
  };

  window.EventSource = function () {
    var es = { onmessage: null, onerror: null, _timer: null };
    var i = 0;
    es.close = function () { if (es._timer) clearInterval(es._timer); };
    es._timer = setInterval(function () {
      if (!es.onmessage) return;
      if (i < D.scan_lines.length) {
        var ln = D.scan_lines[i++];
        es.onmessage({ data: JSON.stringify({ line: ln[0], level: ln[1] }) });
      } else {
        es.onmessage({ data: JSON.stringify({ done: true, score: D.score }) });
        es.close();
      }
    }, 35);
    return es;
  };

  // ---- demo banner: fixed pill, rounded, centered, follows on scroll ----
  (function () {
    var style = document.createElement("style");
    style.textContent =
      ".demo-banner{position:fixed;top:14px;left:50%;transform:translateX(-50%);" +
      "display:flex;align-items:center;gap:8px;padding:6px 15px;border-radius:999px;" +
      "border:1px solid var(--border);background:rgba(18,21,29,0.88);" +
      "color:var(--muted);font-size:12.5px;z-index:100;box-shadow:0 2px 14px rgba(0,0,0,0.4);}" +
      ".demo-banner .dot{width:7px;height:7px;border-radius:50%;" +
      "background:var(--accent);box-shadow:0 0 8px var(--accent);flex-shrink:0;}";
    document.head.appendChild(style);

    var bar = document.createElement("div");
    bar.className = "demo-banner";
    var dot = document.createElement("span");
    dot.className = "dot";
    var txt = document.createElement("span");
    txt.textContent = D.banner;
    bar.appendChild(dot);
    bar.appendChild(txt);

    document.body.appendChild(bar);
  })();

  // ---- chat pre-fill (two exchanges) + export no-op ----
  window.addEventListener("DOMContentLoaded", function () {
    var orig = window.renderChat;
    if (typeof orig === "function") {
      var done = false;
      window.renderChat = function () {
        orig();
        if (done) return;
        done = true;
        var log = document.getElementById("chat-log");
        if (!log) return;
        log.innerHTML = "";
        chatMessages.length = 0;
        (D.chat_history || []).forEach(function (m) {
          appendChat(m.role, m.content);
          chatMessages.push({ role: m.role, content: m.content });
        });
      };
    }

    window.exportFindings = function () {
      if (typeof showToast === "function") showToast("Export unavailable in this demo");
    };
  });
})();
