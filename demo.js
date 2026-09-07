(function () {
  var D = window.RADON_DEMO;
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
})();
