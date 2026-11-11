/**
 * Incident Response Queue & Investigation Drawer Manager.
 * Handles dynamic search, filters, sorting, detail view, AI explainability, and status transitions.
 */

let currentPage = 1;
const pageSize = 15;
let activeIncidentId = null;

async function loadIncidents() {
  const tableBody = document.getElementById("incidents-table-body");
  if (!tableBody) return;

  const search = document.getElementById("search-input") ? document.getElementById("search-input").value : "";
  const status = document.getElementById("status-filter") ? document.getElementById("status-filter").value : "all";
  const severity = document.getElementById("severity-filter") ? document.getElementById("severity-filter").value : "all";
  const sortBy = document.getElementById("sort-select") ? document.getElementById("sort-select").value : "risk_score";

  tableBody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding: 2rem; color: var(--text-muted);">Loading incidents from security database...</td></tr>`;

  try {
    const queryParams = new URLSearchParams({
      page: currentPage,
      limit: pageSize,
      search: search,
      status: status,
      severity: severity,
      sort_by: sortBy,
      sort_order: "DESC",
    });

    const res = await fetch(`/api/incidents?${queryParams.toString()}`);
    const data = await res.json();

    if (!data.incidents || data.incidents.length === 0) {
      tableBody.innerHTML = `<tr><td colspan="7" style="text-align:center; padding: 2rem; color: var(--text-muted);">No matching security incidents found.</td></tr>`;
      renderPagination(0, 1);
      return;
    }

    tableBody.innerHTML = data.incidents
      .map(
        (inc) => `
      <tr>
        <td style="font-family: monospace; font-weight: 600;">${inc.incident_id}</td>
        <td>
          <div style="font-weight: 600;">${escapeHtml(inc.title)}</div>
          <div style="font-size: 0.78rem; color: var(--text-muted);">${inc.rule_id} &bull; ${escapeHtml(inc.rule_name)}</div>
        </td>
        <td>
          <span class="badge badge-${inc.severity.toLowerCase()}">${inc.severity} (${inc.risk_score})</span>
        </td>
        <td style="font-family: monospace;">${escapeHtml(inc.username)}</td>
        <td style="font-family: monospace;">${escapeHtml(inc.source_ip)}</td>
        <td>
          <span class="badge badge-status-${inc.status.toLowerCase()}">${inc.status}</span>
        </td>
        <td>
          <button class="btn btn-secondary btn-sm" onclick="openIncidentModal('${inc.incident_id}')">
            Investigate &rarr;
          </button>
        </td>
      </tr>
    `
      )
      .join("");

    renderPagination(data.total, data.page, data.total_pages);
  } catch (err) {
    console.error("Failed to load incidents:", err);
    tableBody.innerHTML = `<tr><td colspan="7" style="text-align:center; color: var(--status-critical); padding: 2rem;">Error loading incidents.</td></tr>`;
  }
}

function renderPagination(total, page, totalPages) {
  const container = document.getElementById("pagination-container");
  if (!container) return;

  if (total === 0) {
    container.innerHTML = "";
    return;
  }

  container.innerHTML = `
    <span style="font-size: 0.85rem; color: var(--text-muted);">
      Showing ${(page - 1) * pageSize + 1} - ${Math.min(page * pageSize, total)} of ${total} incidents
    </span>
    <div style="display: flex; gap: 0.5rem;">
      <button class="btn btn-secondary btn-sm" ${page <= 1 ? "disabled" : ""} onclick="changePage(${page - 1})">Previous</button>
      <button class="btn btn-secondary btn-sm" ${page >= totalPages ? "disabled" : ""} onclick="changePage(${page + 1})">Next</button>
    </div>
  `;
}

function changePage(newPage) {
  currentPage = newPage;
  loadIncidents();
}

async function openIncidentModal(incidentId) {
  activeIncidentId = incidentId;
  const modal = document.getElementById("incident-modal");
  if (!modal) return;

  modal.classList.add("active");
  document.getElementById("modal-title").textContent = `Incident: ${incidentId}`;
  document.getElementById("modal-details-body").innerHTML = `<div style="text-align: center; padding: 2rem; color: var(--text-muted);">Analyzing incident telemetry...</div>`;

  try {
    const [detailRes, explainRes] = await Promise.all([
      fetch(`/api/incidents/${incidentId}`).then((r) => r.json()),
      fetch(`/api/incidents/${incidentId}/explain`).then((r) => r.json()),
    ]);

    const inc = detailRes;
    const exp = explainRes;

    document.getElementById("modal-details-body").innerHTML = `
      <!-- Incident Overview -->
      <div class="detail-section">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 0.75rem;">
          <div>
            <h3 style="font-size: 1.1rem; font-weight: 700;">${escapeHtml(inc.title)}</h3>
            <p style="font-size: 0.82rem; color: var(--text-muted);">${inc.rule_id} &bull; ${escapeHtml(inc.rule_name)}</p>
          </div>
          <div>
            <span class="badge badge-${inc.severity.toLowerCase()}">${inc.severity} &bull; Risk: ${inc.risk_score}/100</span>
          </div>
        </div>
        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.75rem; font-size: 0.85rem;">
          <div><strong>Target Entity:</strong> ${escapeHtml(inc.username)}</div>
          <div><strong>Source IP:</strong> ${escapeHtml(inc.source_ip)}</div>
          <div><strong>Observed Attempts:</strong> ${inc.attempt_count}</div>
          <div><strong>Window Start:</strong> ${inc.time_window_start ? inc.time_window_start.substring(0, 19) : "N/A"}</div>
          <div><strong>Window End:</strong> ${inc.time_window_end ? inc.time_window_end.substring(0, 19) : "N/A"}</div>
          <div><strong>Current Status:</strong> <span class="badge badge-status-${inc.status.toLowerCase()}">${inc.status}</span></div>
        </div>
      </div>

      <!-- Explainable SOC AI Reasoning (CPPE Module 3) -->
      <div class="detail-section" style="border-left: 3px solid var(--accent-blue);">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.5rem;">
          <h4 style="display: flex; align-items: center; gap: 0.4rem;">
            <svg class="soc-icon" style="color: var(--accent-blue);" viewBox="0 0 24 24"><path d="M12 2a4 4 0 0 1 4 4c0 1.95-1.4 3.58-3.25 3.93L13 14h-2v-4.07C9.4 9.58 8 7.95 8 6a4 4 0 0 1 4-4z"/><circle cx="12" cy="18" r="2"/></svg>
            Explainable SOC Reasoning Engine (CPPE Module 3)
          </h4>
          <span style="font-size: 0.75rem; background: var(--bg-hover); padding: 2px 6px; border-radius: 4px; color: var(--accent-blue);">${exp.mode}</span>
        </div>
        <p style="font-size: 0.88rem; line-height: 1.45; margin-bottom: 0.5rem;"><strong>Analysis:</strong> ${escapeHtml(exp.why_flagged)}</p>
        <p style="font-size: 0.85rem; color: var(--text-secondary); margin-bottom: 0.5rem;"><strong>Risk Justification:</strong> ${escapeHtml(exp.score_justification)}</p>
        <div style="font-size: 0.82rem; background: var(--bg-surface); padding: 0.65rem; border-radius: 4px; border: 1px solid var(--border-subtle);">
          <strong>MITRE ATT&CK Mapping:</strong> ${exp.mitre_mapping.technique} (${exp.mitre_mapping.tactic}) | <strong>Runbook:</strong> ${exp.mitre_mapping.runbook_id}
        </div>
      </div>

      <!-- Evidence Telemetry -->
      <div class="detail-section">
        <h4>Correlated Event Evidence (${(inc.evidence || []).length} records)</h4>
        <div class="table-responsive" style="max-height: 150px; overflow-y: auto;">
          <table class="soc-table" style="font-size: 0.8rem;">
            <thead>
              <tr><th>Timestamp</th><th>Details</th></tr>
            </thead>
            <tbody>
              ${(inc.evidence || [])
                .slice(0, 10)
                .map(
                  (e) => `
                <tr>
                  <td style="font-family: monospace;">${e.timestamp || "N/A"}</td>
                  <td>${escapeHtml(JSON.stringify(e))}</td>
                </tr>
              `
                )
                .join("")}
            </tbody>
          </table>
        </div>
      </div>

      <!-- Actionable SOC Investigation Checklist -->
      <div class="detail-section">
        <h4>Recommended Investigation Playbook</h4>
        <ul style="padding-left: 1.25rem; font-size: 0.85rem; line-height: 1.5; color: var(--text-secondary);">
          ${(exp.investigation_checklist || []).map((step) => `<li>${escapeHtml(step)}</li>`).join("")}
        </ul>
      </div>
    `;

    // Update status button group
    updateModalActionButtons(inc.status);
  } catch (err) {
    console.error("Error loading modal details:", err);
    document.getElementById("modal-details-body").innerHTML = `<div style="color: var(--status-critical); padding: 2rem;">Failed to fetch incident details.</div>`;
  }
}

function updateModalActionButtons(currentStatus) {
  const container = document.getElementById("modal-status-actions");
  if (!container) return;

  container.innerHTML = `
    <span style="font-size: 0.85rem; color: var(--text-muted); margin-right: 0.75rem;">Transition Workflow:</span>
    <button class="btn btn-sm ${currentStatus === 'New' ? 'btn-primary' : 'btn-secondary'}" onclick="setIncidentStatus('New')">New</button>
    <button class="btn btn-sm ${currentStatus === 'Investigating' ? 'btn-primary' : 'btn-secondary'}" onclick="setIncidentStatus('Investigating')">Investigating</button>
    <button class="btn btn-sm ${currentStatus === 'Resolved' ? 'btn-primary' : 'btn-secondary'}" onclick="setIncidentStatus('Resolved')">Resolved</button>
  `;
}

async function setIncidentStatus(newStatus) {
  if (!activeIncidentId) return;

  try {
    const res = await fetch(`/api/incidents/${activeIncidentId}/status`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status: newStatus, actor: "SOC Analyst" }),
    });
    const result = await res.json();
    if (result.success) {
      showToast(`Incident ${activeIncidentId} marked as ${newStatus}`, "success");
      updateModalActionButtons(newStatus);
      loadIncidents();
    } else {
      showToast(result.error || "Failed to update status", "error");
    }
  } catch (err) {
    showToast("Network error updating status", "error");
  }
}

function closeIncidentModal() {
  const modal = document.getElementById("incident-modal");
  if (modal) modal.classList.remove("active");
  activeIncidentId = null;
}

function escapeHtml(str) {
  if (!str) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

document.addEventListener("DOMContentLoaded", () => {
  if (document.getElementById("incidents-table-body")) {
    loadIncidents();

    // Setup filter listeners
    const searchInput = document.getElementById("search-input");
    if (searchInput) {
      searchInput.addEventListener("input", () => {
        currentPage = 1;
        loadIncidents();
      });
    }

    const statusFilter = document.getElementById("status-filter");
    if (statusFilter) {
      statusFilter.addEventListener("change", () => {
        currentPage = 1;
        loadIncidents();
      });
    }

    const severityFilter = document.getElementById("severity-filter");
    if (severityFilter) {
      severityFilter.addEventListener("change", () => {
        currentPage = 1;
        loadIncidents();
      });
    }

    const sortSelect = document.getElementById("sort-select");
    if (sortSelect) {
      sortSelect.addEventListener("change", () => {
        currentPage = 1;
        loadIncidents();
      });
    }
  }
});
