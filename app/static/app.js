const $ = (selector) => document.querySelector(selector);
const escapeHtml = (value) => String(value)
  .replaceAll("&", "&amp;")
  .replaceAll("<", "&lt;")
  .replaceAll(">", "&gt;")
  .replaceAll('"', "&quot;")
  .replaceAll("'", "&#039;");

function selected(name) {
  return document.querySelector(`input[name="${name}"]:checked`).value;
}

function renderMarkdownLite(text) {
  return escapeHtml(text)
    .replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>")
    .split("\n\n")
    .map((paragraph) => `<p>${paragraph.replaceAll("\n", "<br>")}</p>`)
    .join("");
}

async function checkHealth() {
  try {
    const response = await fetch("/api/health");
    const data = await response.json();
    $("#health").classList.add("ready");
    $("#health").innerHTML = `<span></span> Ready · ${data.knowledge_documents} sources indexed`;
  } catch (_) {
    $("#health").textContent = "System unavailable";
  }
}

async function loadSample() {
  const response = await fetch("/api/sample");
  const data = await response.json();
  $("#logs").value = data.logs;
}

function renderResults(data) {
  $("#results").hidden = false;
  $("#risk-score").textContent = data.risk_score;
  $("#risk-ring").style.setProperty("--risk", `${data.risk_score * 3.6}deg`);
  $("#severity").textContent = data.severity.toUpperCase();
  $("#confidence").textContent = `${Math.round(data.confidence * 100)}% detection confidence`;
  $("#latency").textContent = `${data.metadata.events_parsed} events · ${data.metadata.latency_ms} ms`;
  $("#answer").innerHTML = renderMarkdownLite(data.answer);

  $("#risk-factors").innerHTML = data.risk_factors.map((factor) => `
    <div class="risk-factor">
      <span>${escapeHtml(factor.reason)}</span><strong>+${factor.points}</strong>
    </div>
  `).join("");

  $("#findings").innerHTML = data.findings.map((finding) => `
    <div class="finding">
      <div class="finding-title">
        <span>${escapeHtml(finding.title)}</span>
        <span class="badge">${escapeHtml(finding.severity.toUpperCase())}</span>
      </div>
      <p>${escapeHtml(finding.evidence)}</p>
      ${finding.mitre_technique ? `<span class="mitre">${escapeHtml(finding.mitre_technique)} · ${escapeHtml(finding.mitre_name)}</span>` : ""}
    </div>
  `).join("");

  $("#timeline").innerHTML = data.timeline.map((event) => `
    <div class="timeline-item ${event.suspicious ? "suspicious" : ""}">
      <div class="timeline-time">${escapeHtml(event.timestamp)}</div>
      <div class="timeline-label">${escapeHtml(event.label)}</div>
      <div class="timeline-detail">${escapeHtml(event.detail)}</div>
    </div>
  `).join("");

  $("#actions").innerHTML = data.recommended_actions
    .map((action) => `<li>${escapeHtml(action)}</li>`).join("");

  $("#sources").innerHTML = data.citations.map((source) => `
    <div class="source">
      <div class="source-score">[${source.number}] MATCH ${Math.round(source.score * 100)}%</div>
      <a href="${escapeHtml(source.url)}" target="_blank" rel="noreferrer">${escapeHtml(source.title)} ↗</a>
      <p>${escapeHtml(source.excerpt)}</p>
    </div>
  `).join("");

  $("#metadata").textContent = Object.entries(data.metadata)
    .map(([key, value]) => `${key}=${value}`).join("  ·  ");
  $("#results").scrollIntoView({ behavior: "smooth", block: "start" });
}

async function analyze() {
  const button = $("#analyze");
  const error = $("#error");
  error.hidden = true;
  button.disabled = true;
  button.textContent = "Investigating…";

  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        question: $("#question").value,
        logs: $("#logs").value,
        mode: selected("mode"),
        explanation_mode: selected("explanation"),
      }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.detail || "Analysis failed");
    renderResults(data);
  } catch (problem) {
    error.textContent = problem.message;
    error.hidden = false;
  } finally {
    button.disabled = false;
    button.innerHTML = "Run investigation <span>→</span>";
  }
}

$("#load-sample").addEventListener("click", loadSample);
$("#load-php2shell").addEventListener("click", async () => {
  const response = await fetch("/api/sample/php2shell");
  if (!response.ok) return;
  const data = await response.json();
  $("#logs").value = data.logs;
  $("#question").value = "Is this PHP runtime affected by PHP2Shell, and which patch should be applied?";
});
$("#analyze").addEventListener("click", analyze);
checkHealth();
loadSample();

