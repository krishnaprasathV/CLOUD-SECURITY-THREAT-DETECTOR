/**
 * Theme & UI Manager for Cloud Security Threat Detector.
 * Manages Dark/Light mode persistence, collapsible sidebar, real-time clock, and toasts.
 */

// Theme Management
(function initTheme() {
  const savedTheme = localStorage.getItem("soc_theme") || "dark";
  document.documentElement.setAttribute("data-theme", savedTheme);
})();

function toggleTheme() {
  const currentTheme = document.documentElement.getAttribute("data-theme") || "dark";
  const newTheme = currentTheme === "dark" ? "light" : "dark";
  document.documentElement.setAttribute("data-theme", newTheme);
  localStorage.setItem("soc_theme", newTheme);
  
  const themeLabel = document.getElementById("theme-label");
  const themeIcon = document.getElementById("theme-icon");
  const moonSvg = `<svg class="soc-icon" viewBox="0 0 24 24"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>`;
  const sunSvg = `<svg class="soc-icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>`;
  if (themeLabel && themeIcon) {
    themeLabel.textContent = newTheme === "dark" ? "Dark" : "Light";
    themeIcon.innerHTML = newTheme === "dark" ? moonSvg : sunSvg;
  }

  // Trigger chart re-render if chart objects exist
  if (window.renderSOCCharts) {
    window.renderSOCCharts();
  }
}

// Sidebar Toggle Management
function toggleSidebar() {
  const sidebar = document.getElementById("soc-sidebar");
  if (sidebar) {
    sidebar.classList.toggle("collapsed");
    localStorage.setItem("sidebar_collapsed", sidebar.classList.contains("collapsed"));
  }
}

// Live SOC Clock (UTC)
function startSOCClock() {
  const clockEl = document.getElementById("soc-clock-time");
  if (!clockEl) return;

  function update() {
    const now = new Date();
    const utcStr = now.toISOString().replace("T", " ").substring(0, 19) + " UTC";
    clockEl.textContent = utcStr;
  }
  update();
  setInterval(update, 1000);
}

// Toast Notifications
function showToast(message, type = "info") {
  let toastContainer = document.getElementById("soc-toast-container");
  if (!toastContainer) {
    toastContainer = document.createElement("div");
    toastContainer.id = "soc-toast-container";
    toastContainer.style.cssText = "position: fixed; bottom: 20px; right: 20px; z-index: 9999; display: flex; flex-direction: column; gap: 8px;";
    document.body.appendChild(toastContainer);
  }

  const toast = document.createElement("div");
  const bgColor = type === "success" ? "#10b981" : type === "error" ? "#ef4444" : "#3b82f6";
  toast.style.cssText = `background: ${bgColor}; color: #fff; padding: 10px 18px; border-radius: 6px; font-size: 0.88rem; font-weight: 500; box-shadow: 0 4px 6px rgba(0,0,0,0.3); transition: opacity 0.3s;`;
  toast.textContent = message;

  toastContainer.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = "0";
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}

// Global initialization
document.addEventListener("DOMContentLoaded", () => {
  startSOCClock();

  // Restore sidebar state
  if (localStorage.getItem("sidebar_collapsed") === "true") {
    const sidebar = document.getElementById("soc-sidebar");
    if (sidebar) sidebar.classList.add("collapsed");
  }

  // Update theme button icon
  const currentTheme = document.documentElement.getAttribute("data-theme") || "dark";
  const themeLabel = document.getElementById("theme-label");
  const themeIcon = document.getElementById("theme-icon");
  const moonSvg = `<svg class="soc-icon" viewBox="0 0 24 24"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>`;
  const sunSvg = `<svg class="soc-icon" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>`;
  if (themeLabel && themeIcon) {
    themeLabel.textContent = currentTheme === "dark" ? "Dark" : "Light";
    themeIcon.innerHTML = currentTheme === "dark" ? moonSvg : sunSvg;
  }
});
