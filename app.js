(function(){
"use strict";
var $ = function(id){ return document.getElementById(id); };
var esc = function(s){ return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;"); };
var reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
var sleep = function(ms){ return reduce ? Promise.resolve() : new Promise(function(r){ setTimeout(r, ms); }); };
var SEV = ["critical","high","medium","low","info"];
var COL = { critical:"var(--crit)", high:"var(--high)", medium:"var(--med)", low:"var(--low)", info:"var(--info)" };
var WEIGHTS = { critical:10, high:7, medium:4, low:1, info:0 };

/* ---- risk score: same math as core/risk.py ---- */
function rawScore(c){ return SEV.reduce(function(a, s){ return a + WEIGHTS[s] * (c[s] || 0); }, 0); }
function curveScore(c){
  var raw = rawScore(c);
  if (raw <= 50) return raw;
  return Math.min(100, Math.round(50 + 50 * (1 - Math.exp(-(raw - 50) / 100))));
}

/* ---- hero: the real web scan ---- */
(function(){
  var s = window.SCANS[0], sm = s.summary;
  $("hsId").textContent = s.id;
  $("hsScore").textContent = sm.risk_score;
  $("hsTarget").textContent = s.target;
  $("hsDur").textContent = s.duration + " s, " + sm.web_checks + " checks";
  var max = Math.max.apply(null, SEV.map(function(k){ return sm.severity_counts[k] || 0; })) || 1;
  $("hsBars").innerHTML = SEV.map(function(k){
    var n = sm.severity_counts[k] || 0;
    return '<div class="bar"><span>' + k + '</span><div class="t"><i style="width:' + (n/max*100) + '%;background:' + COL[k] + '"></i></div><span class="n">' + n + '</span></div>';
  }).join("");
  $("hsNote").textContent = "Real scan of a local test page. All " + sm.total_findings + " findings are missing security headers and cookie flags.";
})();

/* ---- 01 authorize: same logic as core/target_guard.py ---- */
var RANGES = ["0.0.0.0/8","100.64.0.0/10","169.254.0.0/16","198.18.0.0/15","198.51.100.0/24","203.0.113.0/24","224.0.0.0/4","240.0.0.0/4"];
var LOOP = ["127.0.0.0/8","::1/128"];
var DNS = {
  "app.example.com": ["192.0.2.10"],
  "metadata.internal.test": ["169.254.169.254"],
  "docs.example.net": ["203.0.113.7"],
  "cdn.example.org": ["192.0.2.80","169.254.10.5"],
  "localhost": ["127.0.0.1","::1"],
  "2130706433": ["127.0.0.1"]
};
var EXAMPLES = ["metadata.internal.test","docs.example.net","app.example.com","cdn.example.org","http://localhost:8080/admin","2130706433","169.254.169.254","[::1]:8443","::ffff:169.254.169.254"];

function isV4(s){ var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s); return !!m && m.slice(1).every(function(x){ return +x <= 255; }); }
function isV6(s){ return s.indexOf(":") !== -1 && /^[0-9a-f:.]+$/i.test(s); }
function v4int(s){ return s.split(".").reduce(function(a, x){ return (a * 256 + (+x)); }, 0); }
function inCidr4(addr, cidr){
  var p = cidr.split("/"), bits = +p[1];
  var size = Math.pow(2, 32 - bits), base = Math.floor(v4int(p[0]) / size) * size, a = v4int(addr);
  return a >= base && a < base + size;
}
function extractHost(t){
  t = t.trim(); if (!t) return "";
  var b = (t[0] === "[" && t[t.length-1] === "]") ? t.slice(1, -1) : t;
  if (isV4(b) || isV6(b)) return b.toLowerCase();
  b = t.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").split(/[\/?#]/)[0];
  var at = b.lastIndexOf("@"); if (at >= 0) b = b.slice(at + 1);
  if (b[0] === "["){ var e = b.indexOf("]"); return e > 0 ? b.slice(1, e).toLowerCase() : ""; }
  return b.replace(/:\d*$/, "").replace(/\.$/, "").toLowerCase();
}
function blockedBy(addr, ranges){
  var a = addr.toLowerCase(), m = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(a);
  var v4 = m ? m[1] : (isV4(a) ? a : null);
  for (var i = 0; i < ranges.length; i++){
    var r = ranges[i];
    if (r.indexOf(":") !== -1){ if (r === "::1/128" && (a === "::1" || a === "0:0:0:0:0:0:0:1")) return r; }
    else if (v4 && inCidr4(v4, r)) return r;
  }
  return null;
}

var tgt = $("tgt"), loop = $("loop"), trace = $("trace"), verdict = $("verdict"), chipBox = $("tgtChips");
EXAMPLES.forEach(function(ex){
  var b = document.createElement("button");
  b.type = "button"; b.className = "chip"; b.textContent = ex; b.setAttribute("aria-pressed", "false");
  b.addEventListener("click", function(){ tgt.value = ex; check(); });
  chipBox.appendChild(b);
});
function row(cls, ic, tx, sub){
  return '<li class="' + cls + '"><span class="ic" aria-hidden="true">' + ic + '</span><span class="tx">' + tx + (sub ? '<small>' + sub + '</small>' : '') + '</span></li>';
}
function check(){
  var raw = tgt.value, host = extractHost(raw), ranges = RANGES.concat(loop.checked ? LOOP : []);
  Array.prototype.forEach.call(chipBox.children, function(c){ c.setAttribute("aria-pressed", c.textContent === raw ? "true" : "false"); });
  if (!host){ trace.innerHTML = ""; verdict.innerHTML = '<p class="muted">Type a target, or pick an example.</p>'; return; }
  var rows = [], literal = isV4(host) || isV6(host), addrs, via = "";
  rows.push(row("ok", "1", "Host: <code>" + esc(host) + "</code>", host !== raw.trim() ? "extracted from " + esc(raw.trim()) : ""));
  if (literal){ addrs = [host]; rows.push(row("ok", "2", "Already an address, nothing to resolve")); }
  else {
    addrs = DNS[host] || [];
    via = host + " resolves to ";
    rows.push(addrs.length ? row("ok", "2", "Resolves to " + addrs.map(function(a){ return "<code>" + esc(a) + "</code>"; }).join(", "), "sample DNS table") :
                             row("nt", "2", "Not in this demo&rsquo;s sample DNS table", "The real tool would ask your OS resolver. A name that does not resolve is not blocked, and the scan fails on its own."));
  }
  var hit = null;
  addrs.forEach(function(a){
    var r = blockedBy(a, ranges);
    if (r && !hit) hit = { a: a, r: r };
    rows.push(r ? row("no", "&#10005;", "<code>" + esc(a) + "</code> is inside <code>" + r + "</code>") : row("ok", "&#10003;", "<code>" + esc(a) + "</code> is not in any blocked range"));
  });
  trace.innerHTML = rows.join("");
  if (hit){
    verdict.innerHTML = '<div class="v-block stop"><h3>Refused before any traffic</h3><p>' + esc(via) + '<code>' + esc(hit.a) + '</code>, inside blocked range <code>' + hit.r + '</code>. Recorded in the audit trail as <code>blocked_range_denied</code> with this reason.</p></div>';
  } else {
    verdict.innerHTML = '<div class="v-block go"><h3>Not blocked</h3><p>VulnForge now asks: <b>Do you have authorization to scan this target? (yes/no)</b></p><div class="v-act"><button class="btn sm primary" id="yes" type="button">yes</button><button class="btn sm" id="no" type="button">no</button></div></div>';
    $("yes").addEventListener("click", function(){ verdict.innerHTML = '<div class="v-block go"><h3>Authorization confirmed</h3><p>The confirmation is logged, then the scan starts. You are saying you own this system or have written permission to test it.</p></div>'; });
    $("no").addEventListener("click", function(){ verdict.innerHTML = '<div class="v-block stop"><h3>Scan aborted</h3><p>No authorization confirmed. The decline is logged and nothing is sent to the target.</p></div>'; });
  }
}
tgt.addEventListener("input", check); loop.addEventListener("change", check); check();

/* ---- scan selection shared by 02 and 03 ---- */
var cur = 0, runToken = 0;
var seg = $("scanSeg");
window.SCANS.forEach(function(s, i){
  var b = document.createElement("button");
  b.type = "button"; b.setAttribute("role", "tab"); b.textContent = s.label;
  b.addEventListener("click", function(){ pickScan(i); });
  seg.appendChild(b);
});

/* ---- 02 scan replay ---- */
function lines(s){
  var sm = s.summary, sc = sm.severity_counts, isPort = s.ports.length > 0;
  var mods = isPort ? "port" : "web";
  var cve = s.findings.filter(function(f){ return f.src === "cve_matcher"; }).length;
  var L = [];
  L.push(["$ python vulnforge.py " + s.target + " -s " + mods + (isPort ? " -p 8899" : ""), ""]);
  L.push(["Authorization confirmed (a throwaway server on this machine).", "t-d"]);
  L.push(["", ""]);
  L.push(["Scan ID   " + s.id, ""]);
  L.push(["Target    " + s.target, ""]);
  L.push(["Modules   " + mods, ""]);
  L.push(["", ""]);
  if (isPort){
    L.push(["&#9656; port scan    nmap -sV, found " + s.ports.map(function(p){ return p.port + " " + p.service + " (" + p.product + " " + p.version + ")"; }).join(", "), "t-ok"]);
    L.push(["&#9656; cve match    " + cve + " matches against that version", "t-ok"]);
  } else {
    L.push(["&#9656; web scan     " + sm.web_checks + " checks run", "t-ok"]);
  }
  L.push(["&#9656; filter       " + sm.total_findings + " kept, " + (sm.hidden_low_confidence || 0) + " hidden below min_confidence", "t-ok"]);
  L.push(["", ""]);
  L.push(["Findings   <span class=\"t-c\">critical " + sc.critical + "</span> &middot; <span class=\"t-h\">high " + sc.high + "</span> &middot; <span class=\"t-m\">medium " + sc.medium + "</span> &middot; <span class=\"t-l\">low " + sc.low + "</span>", ""]);
  L.push(["Risk       <b>" + sm.risk_score + "/100</b>   in " + s.duration + " s", ""]);
  L.push(["Reports    JSON, HTML  &rarr;  reports/" + s.id + ".*", "t-d"]);
  return L;
}
var term = $("termBody"), runBtn = $("runBtn"), skipBtn = $("skipBtn"), skipping = false;
function showAll(){ term.innerHTML = lines(window.SCANS[cur]).map(function(l){ return '<span class="' + l[1] + '">' + l[0] + '</span>'; }).join("\n"); }
async function replay(){
  var my = ++runToken; skipping = false; runBtn.hidden = true; skipBtn.hidden = false;
  var L = lines(window.SCANS[cur]), out = [];
  term.innerHTML = "";
  for (var i = 0; i < L.length; i++){
    out.push('<span class="' + L[i][1] + '">' + L[i][0] + '</span>');
    term.innerHTML = out.join("\n") + '<span class="caret"></span>';
    if (!skipping) await sleep(L[i][0] === "" ? 120 : (i < 6 ? 260 : 520));
    if (my !== runToken) return;
  }
  term.innerHTML = out.join("\n");
  runBtn.hidden = false; skipBtn.hidden = true; runBtn.textContent = "Replay again";
}
runBtn.addEventListener("click", replay);
skipBtn.addEventListener("click", function(){ skipping = true; });

/* ---- 03 findings explorer ---- */
var sevFilter = "all", query = "", sel = 0;
function visible(){
  var s = window.SCANS[cur], q = query.trim().toLowerCase();
  return s.findings.filter(function(f){
    return (sevFilter === "all" || f.sev === sevFilter) && (!q || (f.title + " " + f.desc + " " + (f.cve || "")).toLowerCase().indexOf(q) !== -1);
  });
}
function renderChips(){
  var s = window.SCANS[cur], c = s.summary.severity_counts, box = $("sevChips");
  var items = [["all", "All " + s.findings.length]].concat(SEV.filter(function(k){ return c[k]; }).map(function(k){ return [k, k + " " + c[k]]; }));
  if (!items.some(function(x){ return x[0] === sevFilter; })) sevFilter = "all";
  box.innerHTML = "";
  items.forEach(function(it){
    var b = document.createElement("button");
    b.type = "button"; b.className = "chip"; b.textContent = it[1]; b.setAttribute("aria-pressed", it[0] === sevFilter ? "true" : "false");
    b.addEventListener("click", function(){ sevFilter = it[0]; sel = 0; renderChips(); renderList(); });
    box.appendChild(b);
  });
}
function renderList(){
  var list = visible(), ul = $("flist");
  ul.innerHTML = "";
  if (!list.length){ ul.innerHTML = '<li class="empty">No findings match.</li>'; $("fdetail").innerHTML = '<p class="empty">Nothing to show.</p>'; return; }
  if (sel >= list.length) sel = 0;
  list.forEach(function(f, i){
    var li = document.createElement("li"), b = document.createElement("button");
    b.type = "button"; b.className = "fi"; b.setAttribute("aria-selected", i === sel ? "true" : "false");
    b.innerHTML = '<i style="background:' + COL[f.sev] + '"></i><span>' + esc(f.title) + '</span>';
    b.addEventListener("click", function(){ sel = i; renderList(); });
    li.appendChild(b); ul.appendChild(li);
  });
  detail(list[sel]);
}
function detail(f){
  var g = window.GUIDES[f.g] || { tools: [], steps: [] };
  var pills = '<span class="pill sev" style="background:' + COL[f.sev] + '">' + f.sev + '</span><span class="pill">confidence: ' + f.conf + '</span><span class="pill">' + esc(f.src) + '</span>' + (f.cat ? '<span class="pill">' + esc(f.cat) + '</span>' : '');
  var h = '<div class="f-top">' + pills + '</div><h3>' + esc(f.title) + '</h3>';
  if (f.desc) h += '<p>' + esc(f.desc) + '</p>';
  if (f.ev) h += '<p class="k mono">Evidence</p><div class="ev">' + esc(f.ev) + '</div>';
  if (f.fix) h += '<p class="k mono">Fix</p><p>' + esc(f.fix) + '</p>';
  h += '<p class="k mono">How to verify it yourself</p>';
  if (g.tools.length) h += '<div class="tools">' + g.tools.map(function(t){ return '<span class="pill">' + esc(t) + '</span>'; }).join("") + '</div>';
  h += '<ol style="margin-top:10px">' + g.steps.map(function(s){ return '<li>' + esc(s) + '</li>'; }).join("") + '</ol>';
  $("fdetail").innerHTML = h;
  $("fdetail").scrollTop = 0;
}
$("q").addEventListener("input", function(e){ query = e.target.value; sel = 0; renderList(); });

function pickScan(i){
  cur = i; runToken++; skipping = false; sel = 0; sevFilter = "all"; query = ""; $("q").value = "";
  Array.prototype.forEach.call(seg.children, function(b, j){ b.setAttribute("aria-selected", j === i ? "true" : "false"); b.tabIndex = j === i ? 0 : -1; });
  var s = window.SCANS[i];
  $("scanBlurb").textContent = s.blurb;
  $("termTitle").textContent = "vulnforge: " + s.id;
  runBtn.hidden = false; skipBtn.hidden = true; runBtn.textContent = "Replay scan";
  term.innerHTML = '<span class="t-d">Press &ldquo;Replay scan&rdquo; to watch this scan run.</span>';
  renderChips(); renderList();
}
pickScan(0);

/* ---- 04 score calculator ---- */
var state = { critical: 0, high: 0, medium: 5, low: 5 };
var PRESETS = [
  ["Web scan: 5 medium, 5 low", { critical:0, high:0, medium:5, low:5 }],
  ["One critical", { critical:1, high:0, medium:0, low:0 }],
  ["15 highs", { critical:0, high:15, medium:0, low:0 }],
  ["Port + CVE scan: 21 critical, 48 high", { critical:21, high:48, medium:0, low:0 }]
];
var presetBox = $("presets"), sliderBox = $("sliders");
PRESETS.forEach(function(p){
  var b = document.createElement("button");
  b.type = "button"; b.className = "chip"; b.textContent = p[0];
  b.addEventListener("click", function(){ SEV.slice(0, 4).forEach(function(k){ state[k] = p[1][k]; }); syncSliders(); update(); });
  presetBox.appendChild(b);
});
SEV.slice(0, 4).forEach(function(k){
  var d = document.createElement("div"); d.className = "sl";
  d.innerHTML = '<label for="s-' + k + '">' + k + '</label><input id="s-' + k + '" type="range" min="0" max="80" value="' + state[k] + '"><output for="s-' + k + '" id="o-' + k + '">' + state[k] + '</output>';
  d.querySelector("input").addEventListener("input", function(e){ state[k] = +e.target.value; $("o-" + k).textContent = state[k]; update(); });
  sliderBox.appendChild(d);
});
function syncSliders(){ SEV.slice(0, 4).forEach(function(k){ $("s-" + k).value = state[k]; $("o-" + k).textContent = state[k]; }); }
function update(){
  var raw = rawScore(state), old = Math.min(100, raw), now = curveScore(state);
  $("gOld").style.width = old + "%"; $("gNew").style.width = now + "%";
  $("vOld").textContent = old; $("vNew").textContent = now;
  var ci = now >= 40 ? "CI would exit with status 1 (score 40 or more)." : "CI would exit with status 0 (score under 40).";
  var note;
  if (raw <= 50) note = "Raw sum " + raw + ". At or below 50 the old and new scores are identical. " + ci;
  else if (old === 100) note = "Raw sum " + raw + ". The old cap would read 100 no matter how bad it got; the curve reads " + now + " and keeps moving as findings are added. " + ci;
  else note = "Raw sum " + raw + ". Above 50 the curve compresses the score (" + old + " becomes " + now + ") so the top of the scale stays usable. " + ci;
  $("gNote").textContent = note;
}
update();
})();
