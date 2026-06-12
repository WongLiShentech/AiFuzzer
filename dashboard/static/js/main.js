// aifuzz dashboard front-end.
//  ANALYZE (product): a batch scanner fed by uploads (many), a Git repo, or the
//    library. Each contract gets its own VULNERABLE/CLEAN report with the code
//    that caused it and the exploit sequence. Mode toggle: Random | AI-guided(M3).
//  EVALUATION (benchmark): labeled suite (verdict vs ground truth) + random-vs-AI.
// No AI yet -- random fuzzing only; M3's AI-guided mode reuses the same endpoints.

const results = document.getElementById("results");
const evalResults = document.getElementById("eval-results");
const benchResults = document.getElementById("benchmark-results");
const caseModal = document.getElementById("case-modal");
const caseModalBody = document.getElementById("case-modal-body");

let currentMode = "random";
let uploadedFiles = [];   // [{name, source}]

const TYPE_DESC = {
  "reentrancy": "Funds drained by re-entering before the contract updates its balances.",
  "access-control": "Privileged functions callable by accounts that were never authorised.",
  "ordering-attacks": "Outcome depends on transaction ordering — front-running / TOD.",
  "oracle-manipulation": "Pricing logic that trusts a manipulable on-chain price source.",
  "none": "Clean control — a correct contract that should report no vulnerabilities.",
};

function esc(s) {
  return String(s).replace(/[&<>"]/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
}
function errorPanel(target, msg) { target.innerHTML = `<div class="error-panel">${esc(msg)}</div>`; }
function severityClass(sev) { return { high: "sev-high", medium: "sev-medium", low: "sev-low" }[sev] || "sev-low"; }

// ---------- report fragments ----------
function codeBlock(title, src) {
  if (!src) return "";
  return `<details class="code-panel"><summary>${esc(title)}
    <span class="code-path">${esc(src.path)}</span></summary>
    <pre><code>${esc(src.code)}</code></pre></details>`;
}
function vulnCodeBlock(vc) {
  if (!vc) return "";
  const rows = vc.rows.map((r) =>
    `<div class="codeline ${r.vuln ? "vuln" : ""}"><span class="ln">${r.n}</span><span class="ct">${esc(r.code)}</span></div>`).join("");
  return `<div class="vuln-code"><h4>Code that caused it
    <span class="code-path">${esc(vc.path)} · line${vc.lines.length > 1 ? "s" : ""} ${vc.lines.join(", ")}</span></h4>
    <div class="codeview">${rows}</div></div>`;
}
function findingCard(f, sources) {
  const sc = severityClass(f.severity);
  const seq = (f.sequence && f.sequence.length)
    ? `<div class="seq"><h4>Proof of exploit — triggering transaction sequence</h4>
         <ol>${f.sequence.map((s) => `<li>${esc(s)}</li>`).join("")}</ol></div>` : "";
  const code = sources
    ? `<div class="code-wrap">${codeBlock("Full vulnerable contract", sources.target)}
         ${codeBlock("Test harness (attacker + oracle)", sources.harness)}</div>` : "";
  return `<div class="finding ${sc}">
    <div class="finding-top"><span class="badge sev ${sc}">${esc(f.severity)}</span>
      <span class="finding-title">${esc(f.title)}</span></div>
    <div class="finding-desc">${esc(f.description)}</div>
    <div class="kv"><span>rule: ${esc(f.rule_id)}</span><span>engine: ${esc(f.engine)}</span>
      <span>contract: ${esc(f.contract)}</span><span>line: ${f.line === null ? "—" : esc(f.line)}</span></div>
    ${seq}${code}</div>`;
}

// ---------- per-contract result body ----------
function reportBody(e) {
  if (e.status === "skipped")
    return `<div class="skip-panel"><strong>Skipped.</strong> ${esc(e.reason || "could not analyze")}
      <div class="skip-note">Its shape wasn't one the templates recognise, or it needs external deps to
      compile — generating a harness for it is the M3 AI step.</div></div>`;
  if (e.status === "pending")
    return `<div class="note-panel">${esc(e.reason || "AI-guided fuzzing (M3) is not implemented yet.")}</div>`;
  if (e.status === "clean")
    return `<div class="clean-panel"><div class="big">No vulnerabilities found</div>
      <div class="sub">Resisted the tested attacks. Fuzzing samples behaviour — not a proof of safety.</div></div>`;
  // vulnerable
  const r = e.report;
  return vulnCodeBlock(e.vulnerable_code) + r.findings.map((f) => findingCard(f, e.sources)).join("");
}

function statusBadge(s) {
  const map = { vulnerable: ["st-vuln", "VULNERABLE"], clean: ["st-clean", "CLEAN"],
                skipped: ["st-skip", "SKIPPED"], pending: ["st-pending", "PENDING"] };
  const [cls, label] = map[s] || ["st-skip", s.toUpperCase()];
  return `<span class="status-badge ${cls}">${label}</span>`;
}

function renderResults(entries, opts = {}) {
  const vulnN = entries.filter((e) => e.status === "vulnerable").length;
  const meta = opts.meta ? `<span class="results-meta">${esc(opts.meta)}</span>` : "";
  const head = `<div class="results-head">
    <h2>Scan results <span class="results-count">${entries.length} contract${entries.length === 1 ? "" : "s"} · ${vulnN} vulnerable</span></h2>${meta}</div>`;
  const items = entries.map((e, i) => `
    <details class="result-item" ${entries.length === 1 ? "open" : ""}>
      <summary>${statusBadge(e.status)}<span class="result-name">${esc(e.name)}</span></summary>
      <div class="result-body">${reportBody(e)}</div>
    </details>`).join("");
  const spinner = opts.busy
    ? `<div class="result-item busy"><div class="spinner sm"></div> Analyzing ${esc(opts.busy)}…</div>` : "";
  results.innerHTML = head + spinner + items;
  results.scrollIntoView({ behavior: "smooth", block: "start" });
}

// ---------- normalizers ----------
function fromAnalyze(data, name) {
  if (data.pending) return { name, status: "pending", reason: data.error };
  if (!data.ok) return { name, status: "skipped", reason: data.error };
  return { name: data.name || name, status: data.verdict, report: data.report,
           sources: data.sources, vulnerable_code: data.vulnerable_code };
}
function fromFuzz(data, name) {
  if (data.pending) return { name, status: "pending", reason: data.error };
  if (!data.ok) return { name, status: "skipped", reason: data.error };
  return { name, status: data.verdict, report: data.report,
           sources: data.sources, vulnerable_code: data.vulnerable_code };
}

async function postJSON(url, payload) {
  const res = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload || {}) });
  return res.json();
}

// ---------- actions ----------
async function fuzzCase(name) {
  switchView("analyze");
  renderResults([], { busy: name });
  try {
    const data = await postJSON("/api/fuzz", { case: name, mode: currentMode });
    renderResults([fromFuzz(data, name)]);
  } catch (e) { errorPanel(results, String(e)); }
}

// ---------- contract detail modal (library: view code, then fuzz) ----------
function closeCaseModal() { caseModal.classList.add("hidden"); }

async function openCaseModal(name) {
  caseModal.classList.remove("hidden");
  caseModalBody.innerHTML = `<div class="loading"><div class="spinner"></div><p>Loading ${esc(name)}…</p></div>`;
  try {
    const data = await postJSON("/api/case-source", { case: name });
    if (!data.ok) return (caseModalBody.innerHTML = `<div class="error-panel">${esc(data.error || "could not load")}</div>`);
    renderCaseModal(data);
  } catch (e) { caseModalBody.innerHTML = `<div class="error-panel">${esc(String(e))}</div>`; }
}

function renderCaseModal(data) {
  const path = data.code ? data.code.path : "";
  const code = data.code
    ? `<pre class="modal-code"><code>${esc(data.code.code)}</code></pre>`
    : "<p class='hint'>(source unavailable)</p>";
  caseModalBody.innerHTML = `
    <div class="modal-head">
      <span class="badge type">${esc(data.vuln_type)}</span>
      <h2 class="modal-title">${esc(data.name)}</h2>
      <div class="code-path">${esc(path)}</div>
    </div>
    ${code}
    <div class="modal-actions">
      <button id="case-analyze-btn" class="btn btn-primary">Analyze this contract</button>
      <span class="modal-hint">Runs Echidna in the local EVM (~30–90s).</span>
    </div>
    <div id="case-result"></div>`;
  document.getElementById("case-analyze-btn").addEventListener("click", () => analyzeCase(data.name));
}

async function analyzeCase(name) {
  const btn = document.getElementById("case-analyze-btn");
  const out = document.getElementById("case-result");
  btn.disabled = true; btn.textContent = "Analyzing…";
  out.innerHTML = `<div class="loading"><div class="spinner"></div><p>Running thousands of transactions…</p></div>`;
  try {
    const data = await postJSON("/api/fuzz", { case: name, mode: currentMode });
    const entry = fromFuzz(data, name);
    out.innerHTML = `<div class="modal-result">${statusBadge(entry.status)}</div>
      <div class="result-body">${reportBody(entry)}</div>`;
  } catch (e) { out.innerHTML = `<div class="error-panel">${esc(String(e))}</div>`; }
  btn.disabled = false; btn.textContent = "Analyze again";
}

async function analyzeBatch() {
  const pasted = document.getElementById("source").value.trim();
  const pastedName = document.getElementById("contract-name").value.trim() || "Pasted.sol";
  const contracts = uploadedFiles.length
    ? uploadedFiles.slice()
    : (pasted ? [{ name: pastedName, source: pasted }] : []);
  if (!contracts.length) return errorPanel(results, "Add one or more .sol files, or paste a contract.");

  const entries = [];
  for (let i = 0; i < contracts.length; i++) {
    renderResults(entries, { busy: `${contracts[i].name} (${i + 1}/${contracts.length})` });
    try {
      const data = await postJSON("/api/analyze", { source: contracts[i].source, name: contracts[i].name, mode: currentMode });
      entries.push(fromAnalyze(data, contracts[i].name));
    } catch (e) { entries.push({ name: contracts[i].name, status: "skipped", reason: String(e) }); }
  }
  renderResults(entries);
}

async function scanGit() {
  const repo_url = document.getElementById("repo-url").value.trim();
  const branch = document.getElementById("repo-branch").value.trim();
  const token = document.getElementById("repo-token").value.trim();
  if (!repo_url) return errorPanel(results, "Enter a repository URL.");
  // Paginate: fetch one batch at a time and keep going until the server says
  // there are no more files. Results stream in and progress is shown live.
  let all = [], offset = 0, total = null;
  renderResults([], { busy: "cloning and scanning the repository" });
  try {
    do {
      const data = await postJSON("/api/scan-git", { repo_url, branch, token, offset });
      if (!data.ok) return errorPanel(results, data.error || "repository scan failed");
      total = data.found;
      all = all.concat(data.results);
      const meta = `found ${total} .sol file${total === 1 ? "" : "s"} · scanned ${all.length}/${total}`;
      renderResults(all, { meta, busy: data.has_more ? `next batch (${all.length}/${total} done)` : null });
      offset = data.next_offset;
    } while (offset !== null && offset !== undefined);
  } catch (e) { errorPanel(results, String(e)); }
}

// ---------- evaluation ----------
function renderSuite(rows) {
  const passed = rows.filter((r) => r.passed).length;
  const head = `<div class="report-head"><div><h2>Fuzzer vs. ground truth</h2>
      <div class="report-meta">labeled dataset · engine: echidna</div></div>
    <div class="verdict ${passed === rows.length ? "v-pass" : "v-fail"}">
      <div class="big">${passed}/${rows.length}</div><div class="sub">correct verdicts</div></div></div>`;
  const body = `<table class="suite-table"><thead><tr><th>Case</th><th>Type</th><th>Ground truth</th><th>Fuzzer verdict</th><th>Match</th></tr></thead>
    <tbody>${rows.map((r) => { const v = r.findings >= 1 ? "vulnerable" : "clean";
      return `<tr><td>${esc(r.name)}</td><td>${esc(r.vuln_type)}</td><td>${esc(r.expect)}</td>
        <td>${v} (${r.findings})</td><td class="${r.passed ? "res-pass" : "res-fail"}">${r.passed ? "PASS" : "FAIL"}</td></tr>`;
    }).join("")}</tbody></table>`;
  evalResults.innerHTML = head + body;
}
function fmtStat(s) { return s ? `${s.mean.toFixed(2)} ± ${s.stdev.toFixed(2)}` : "—"; }
function renderBenchmark(payload) {
  if (!payload.available) {
    benchResults.innerHTML = `<div class="note-panel">No benchmark results yet. Run
      <code>docker compose run --rm --no-deps aifuzz python benchmark.py</code> to generate
      <code>results/benchmark.json</code>, then revisit this tab.</div>`;
    return;
  }
  const d = payload.data, rnd = d.random, ai = d.ai_guided;
  const aiCell = (k) => ai ? fmtStat(ai[k]) : `<span class="pending">pending (M3)</span>`;
  const rows = [["Bugs found (TP)", "bugs_found"], ["Recall", "recall"], ["Precision", "precision"], ["F1", "f1"], ["FPR", "fpr"]];
  benchResults.innerHTML = `<table class="suite-table"><thead><tr><th>Metric</th><th>Random (baseline)</th><th>AI-guided</th></tr></thead>
    <tbody>${rows.map(([l, k]) => `<tr><td>${l}</td><td>${fmtStat(rnd[k])}</td><td>${aiCell(k)}</td></tr>`).join("")}</tbody></table>
    <p class="hint">Mean ± stdev over ${rnd.trials || "?"} trials · identical budget per mode.
      AI-guided enables automatically once <code>aifuzz.ai_guidance</code> (M3) lands.</p>`;
}
async function runEval() {
  evalResults.innerHTML = `<div class="loading"><div class="spinner"></div><p>Running suite (all labeled cases)…</p></div>`;
  try {
    const data = await postJSON("/api/suite", {});
    if (!data.ok) return errorPanel(evalResults, "suite failed");
    renderSuite(data.results);
  } catch (e) { errorPanel(evalResults, String(e)); }
}
let benchLoaded = false;
async function loadBenchmark() {
  if (!benchResults || benchLoaded) return; benchLoaded = true;
  try {
    const data = await (await fetch("/api/benchmark")).json();
    if (data.ok) renderBenchmark(data); else errorPanel(benchResults, data.error || "benchmark failed");
  } catch (e) { errorPanel(benchResults, String(e)); }
}

function switchView(view) {
  document.querySelectorAll(".navlink[data-view]").forEach((n) => n.classList.toggle("active", n.dataset.view === view));
  document.getElementById("view-analyze").classList.toggle("hidden", view !== "analyze");
  const ve = document.getElementById("view-evaluation");      // absent in production build (AIFUZZ_DEV=0)
  if (ve) ve.classList.toggle("hidden", view !== "evaluation");
  if (view === "evaluation") loadBenchmark();
}

// ---------- file handling ----------
function renderFileList() {
  const el = document.getElementById("file-list");
  el.innerHTML = uploadedFiles.map((f, i) =>
    `<span class="file-chip">${esc(f.name)}<button class="chip-x" data-i="${i}">×</button></span>`).join("");
  el.querySelectorAll(".chip-x").forEach((b) =>
    b.addEventListener("click", () => { uploadedFiles.splice(+b.dataset.i, 1); renderFileList(); }));
}
function addFiles(fileList) {
  const files = [...fileList].filter((f) => f.name.endsWith(".sol"));
  Promise.all(files.map((f) => f.text().then((source) => ({ name: f.name, source }))))
    .then((loaded) => { uploadedFiles.push(...loaded); renderFileList(); });
}

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".lib-desc").forEach((d) => { d.textContent = TYPE_DESC[d.dataset.type] || ""; });
  document.querySelectorAll(".navlink[data-view]").forEach((n) => n.addEventListener("click", () => switchView(n.dataset.view)));
  document.querySelectorAll(".lib-card").forEach((b) => b.addEventListener("click", () => openCaseModal(b.dataset.case)));
  document.getElementById("case-modal-close").addEventListener("click", closeCaseModal);
  caseModal.addEventListener("click", (e) => { if (e.target === caseModal) closeCaseModal(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeCaseModal(); });
  document.querySelectorAll(".mode-btn").forEach((b) => b.addEventListener("click", () => {
    currentMode = b.dataset.mode;
    document.querySelectorAll(".mode-btn").forEach((x) => x.classList.toggle("active", x === b));
  }));
  document.getElementById("analyze-btn").addEventListener("click", analyzeBatch);
  document.getElementById("scan-git-btn").addEventListener("click", scanGit);
  const runEvalBtn = document.getElementById("run-eval");      // absent in production build
  if (runEvalBtn) runEvalBtn.addEventListener("click", runEval);

  // upload: browse + drag/drop (multiple)
  const dz = document.getElementById("dropzone");
  const fi = document.getElementById("file-input");
  document.getElementById("browse-btn").addEventListener("click", (e) => { e.stopPropagation(); fi.click(); });
  dz.addEventListener("click", () => fi.click());
  fi.addEventListener("change", () => addFiles(fi.files));
  ["dragover", "dragenter"].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.add("over"); }));
  ["dragleave", "drop"].forEach((ev) => dz.addEventListener(ev, (e) => { e.preventDefault(); dz.classList.remove("over"); }));
  dz.addEventListener("drop", (e) => { if (e.dataTransfer.files.length) addFiles(e.dataTransfer.files); });
});
