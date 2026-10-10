const $ = (id) => document.getElementById(id);

function safe(value) {
  return String(value ?? "-")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

function setText(id, value) {
  const element = $(id);
  if (element) element.textContent = value ?? 0;
}

function showMessage(message) {
  const element = $("responseResult");
  if (element) element.textContent = message;
}

function riskClass(risk) {
  return String(risk || "").toLowerCase();
}

function renderServers(servers) {
  const grid = $("serverGrid");
  if (!grid) return;

  grid.innerHTML = servers.length
    ? servers.map((server) => `
      <article class="server-card">
        <h3>${safe(server.name || "Cloud Server")}</h3>
        <span class="status ${riskClass(server.status)}">
          ${safe(server.status || "Healthy")}
        </span>
        <p><strong>${safe(server.metric || "Metric unavailable")}</strong></p>
        <p>Role: <strong>${safe(server.role || "-")}</strong></p>
      </article>
    `).join("")
    : "<p>No server data available.</p>";
}

function renderIncidents(incidents) {
  const body = $("incidentBody");
  if (!body) return;

  body.innerHTML = incidents.length
    ? incidents.map((incident) => `
      <tr>
        <td>${safe(incident.id)}</td>
        <td>${safe(incident.timestamp)}</td>
        <td>${safe(incident.event_type)}</td>
        <td>${safe(incident.server)}</td>
        <td>${safe(incident.source_ip || "Internal")}</td>
        <td>
          <span class="severity ${riskClass(incident.risk)}">
            ${safe(incident.risk)}
          </span>
        </td>
        <td>${safe(incident.response)}</td>
        <td>${safe(incident.status)}</td>
      </tr>
    `).join("")
    : `<tr><td colspan="8">No incidents recorded yet.</td></tr>`;
}

function renderTimeline(incidents) {
  const timeline = $("timeline");
  if (!timeline) return;

  timeline.innerHTML = incidents.length
    ? incidents.slice(0, 8).map((incident) => `
      <div class="timeline-item ${riskClass(incident.risk)}">
        <strong>${safe(incident.event_type)}</strong>
        <span>${safe(incident.timestamp)} — ${safe(incident.response)}</span>
      </div>
    `).join("")
    : "<p>No activity recorded yet.</p>";
}

function renderNotifications(notifications) {
  const list = $("notificationList");
  if (!list) return;

  list.innerHTML = notifications.length
    ? notifications.slice(0, 5).map((notification) => `
      <article class="notification-card ${riskClass(notification.risk)}">
        <div class="notification-title">
          <strong>${safe(notification.id)} — ${safe(notification.subject)}</strong>
          <span class="severity ${riskClass(notification.risk)}">
            ${safe(notification.risk)}
          </span>
        </div>
        <p>${safe(notification.details)}</p>
        <p><strong>Server:</strong> ${safe(notification.server)}</p>
        <p><strong>Response:</strong> ${safe(notification.response)}</p>
        <small>${safe(notification.timestamp)} · ${safe(notification.status)}</small>
      </article>
    `).join("")
    : "<p class='empty-message'>No company notifications yet. Alerts appear at a risk score of 20 or above.</p>";
}

function renderSecurityAdvisor(notifications) {
  const advisor = $("advisorReport");
  if (!advisor) return;

  const latest = notifications[0];

  if (!latest) {
    advisor.innerHTML = `
      <p class="empty-message">
        AI Security Advisor is monitoring simulated server activity.
        Recommendations will appear after a Medium or High-risk alert.
      </p>
    `;
    return;
  }

  const recommendations = (latest.recommendations || [])
    .map((item) => `<li>${safe(item)}</li>`)
    .join("");

  advisor.innerHTML = `
    <div class="advisor-risk">
      <span class="severity ${riskClass(latest.risk)}">${safe(latest.risk)} RISK</span>
      <strong>Risk score: ${safe(latest.risk_score)}/100</strong>
    </div>
    <h3>${safe(latest.subject)}</h3>
    <p>${safe(latest.details)}</p>
    <p><strong>Automated response:</strong> ${safe(latest.response)}</p>
    <h4>Recommended security actions</h4>
    <ul>${recommendations}</ul>
  `;
}
function renderEventVisuals(incidents) {
  const graph = $("eventGraph");
  const flowList = $("eventFlowList");

  if (!graph || !flowList) return;

  const recentEvents = incidents.slice(0, 12).reverse();

  if (!recentEvents.length) {
    graph.innerHTML = "<p class='empty-message'>Waiting for simulated events.</p>";
    flowList.innerHTML = "<p class='empty-message'>Event flows will appear here.</p>";
    return;
  }

  graph.innerHTML = recentEvents.map((incident) => {
    const score = Math.min(Math.max(Number(incident.score) || 0, 0), 100);
    const level = riskClass(incident.risk);
    const shortId = safe(incident.id || "Event").replace("INC-", "#");

    return `
      <div class="graph-bar-item" data-tooltip="${safe(incident.event_type)} — Score ${score}/100">
        <span class="graph-score">${score}</span>
        <div class="graph-track">
          <div class="graph-bar ${level}" style="height: ${Math.max(score, 7)}%;"></div>
        </div>
        <span class="graph-label">${shortId}</span>
      </div>
    `;
  }).join("");

  flowList.innerHTML = incidents.slice(0, 8).map((incident) => {
    const score = Number(incident.score) || 0;
    const level = riskClass(incident.risk);

    return `
      <article class="flow-row">
        <div class="flow-node">
          <strong>Source</strong>
          ${safe(incident.source_ip || "Internal monitor")}
        </div>

        <div class="flow-arrow">→</div>

        <div class="flow-node">
          <strong>Detected event</strong>
          ${safe(incident.event_type)}
        </div>

        <div class="flow-arrow">→</div>

        <div class="flow-risk ${level}">
          ${safe(incident.risk)}<br>${score}/100
        </div>

        <div class="flow-arrow">→</div>

        <div class="flow-node">
          <strong>Automated response</strong>
          ${safe(incident.response)}
        </div>
      </article>
    `;
  }).join("");
}
function updateDashboard(data) {
  const incidents = data.incidents || [];
  const notifications = data.notifications || [];
  const stats = data.stats || {};

  setText("totalEvents", stats.total_events ?? incidents.length);
  setText("highRisk", stats.high_risk ?? 0);
  setText("monitoring", stats.monitoring ?? 0);
  setText("isolated", stats.isolated ?? 0);

  renderServers(data.servers || []);
  renderIncidents(incidents);
  renderTimeline(incidents);
  renderEventVisuals(incidents);
  renderNotifications(notifications);
  renderSecurityAdvisor(notifications);
}

async function refreshDashboard() {
  try {
    const response = await fetch("/api/dashboard");

    if (response.status === 401) {
      window.location.href = "/login";
      return;
    }

    if (!response.ok) {
      throw new Error("Could not load dashboard data.");
    }

    updateDashboard(await response.json());
  } catch (error) {
    showMessage(error.message);
  }
}

async function simulateScenario(scenario, button) {
  button.disabled = true;

  try {
    const response = await fetch(`/api/simulate/${scenario}`, {
      method: "POST",
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.message || "Simulation failed.");
    }

    showMessage(data.message || "Simulation completed.");
    await refreshDashboard();
  } catch (error) {
    showMessage(error.message);
  } finally {
    button.disabled = false;
  }
}

async function resetDemo() {
  try {
    const response = await fetch("/api/reset", { method: "POST" });
    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.message || "Reset failed.");
    }

    showMessage(data.message || "Demo data reset.");
    await refreshDashboard();
  } catch (error) {
    showMessage(error.message);
  }
}

document.querySelectorAll("[data-scenario]").forEach((button) => {
  button.addEventListener("click", () => {
    simulateScenario(button.dataset.scenario, button);
  });
});
$("loginThreatForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();

  const username = $("loginThreatUsername")?.value.trim();
  const password = $("loginThreatPassword")?.value;
  const location = $("loginThreatLocation")?.value.trim();

  const button = $("loginThreatSubmit");
  const hint = $("loginThreatHint");

  if (!username || !password || !location) {
    if (hint) {
      hint.textContent = "Enter a username, password, and location.";
    }
    return;
  }

  if (button) button.disabled = true;

  try {
    const response = await fetch("/api/login-threat", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username,
        password,
        location,
      }),
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.message || "Login simulation failed.");
    }

    showMessage(data.message);

    if (hint) {
      hint.textContent =
        `Different passwords entered for ${username}: ${data.attempt_count}.`;
    }

    $("loginThreatPassword").value = "";

    await refreshDashboard();
  } catch (error) {
    const message = error.message || "Login simulation failed.";

    showMessage(message);

    if (hint) {
      hint.textContent = message;
    }
  } finally {
    if (button) button.disabled = false;
  }
});
function addShieldBotMessage(message, sender) {
  const messages = $("shieldbotMessages");
  if (!messages) return;

  const bubble = document.createElement("div");
  bubble.className = `shieldbot-message ${sender}`;
  bubble.textContent = message;

  messages.appendChild(bubble);
  messages.scrollTop = messages.scrollHeight;
}

$("shieldbotForm")?.addEventListener("submit", async (event) => {
  event.preventDefault();

  const input = $("shieldbotInput");
  const question = input?.value.trim();

  if (!question) return;

  addShieldBotMessage(question, "user");
  input.value = "";

  try {
    const response = await fetch("/api/shieldbot", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question }),
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.message || "ShieldBot could not answer right now.");
    }

    addShieldBotMessage(data.answer, "bot");
  } catch (error) {
    addShieldBotMessage(error.message, "bot");
  }
});
$("resetButton")?.addEventListener("click", resetDemo);

refreshDashboard();
setInterval(refreshDashboard, 3000);