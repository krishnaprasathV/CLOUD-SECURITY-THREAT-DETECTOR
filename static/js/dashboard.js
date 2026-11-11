/**
 * Dashboard Analytics and Visualization Manager.
 * Renders Chart.js Timeline and Risk Distribution charts.
 */

let timelineChartInstance = null;
let riskChartInstance = null;

function getChartColors() {
  const isDark = (document.documentElement.getAttribute("data-theme") || "dark") === "dark";
  return {
    textColor: isDark ? "#9ca3af" : "#475569",
    gridColor: isDark ? "#374151" : "#e2e8f0",
    bgCard: isDark ? "#111827" : "#ffffff",
  };
}

async function fetchAndRenderTimeline() {
  const canvas = document.getElementById("timelineChart");
  if (!canvas) return;

  try {
    const res = await fetch("/api/timeline");
    const data = await res.json();
    const colors = getChartColors();

    if (timelineChartInstance) {
      timelineChartInstance.destroy();
    }

    const ctx = canvas.getContext("2d");
    timelineChartInstance = new Chart(ctx, {
      type: "line",
      data: {
        labels: data.labels.map(l => l.substring(11, 16)), // HH:MM
        datasets: [
          {
            label: "Failed Logins",
            data: data.failed,
            borderColor: "#ef4444",
            backgroundColor: "rgba(239, 68, 68, 0.15)",
            borderWidth: 2,
            tension: 0.3,
            fill: true,
          },
          {
            label: "Successful Logins",
            data: data.success,
            borderColor: "#10b981",
            backgroundColor: "rgba(16, 185, 129, 0.08)",
            borderWidth: 2,
            tension: 0.3,
            fill: true,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "top",
            labels: { color: colors.textColor, font: { size: 12 } },
          },
          tooltip: { mode: "index", intersect: false },
        },
        scales: {
          x: {
            grid: { color: colors.gridColor },
            ticks: { color: colors.textColor },
          },
          y: {
            grid: { color: colors.gridColor },
            ticks: { color: colors.textColor, precision: 0 },
            beginAtZero: true,
          },
        },
      },
    });
  } catch (err) {
    console.error("Error loading timeline chart:", err);
  }
}

async function fetchAndRenderRiskDistribution() {
  const canvas = document.getElementById("riskChart");
  if (!canvas) return;

  try {
    const res = await fetch("/api/stats");
    const stats = await res.json();
    const colors = getChartColors();

    if (riskChartInstance) {
      riskChartInstance.destroy();
    }

    const ctx = canvas.getContext("2d");
    const counts = [
      stats.critical_incidents || 0,
      stats.high_incidents || 0,
      stats.medium_incidents || 0,
      stats.low_incidents || 0,
    ];

    riskChartInstance = new Chart(ctx, {
      type: "doughnut",
      data: {
        labels: ["Critical", "High", "Medium", "Low"],
        datasets: [
          {
            data: counts,
            backgroundColor: ["#ef4444", "#f97316", "#eab308", "#10b981"],
            borderWidth: 1,
            borderColor: colors.bgCard,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: "bottom",
            labels: { color: colors.textColor, boxWidth: 12, font: { size: 11 } },
          },
        },
        cutout: "68%",
      },
    });
  } catch (err) {
    console.error("Error loading risk chart:", err);
  }
}

window.renderSOCCharts = function () {
  fetchAndRenderTimeline();
  fetchAndRenderRiskDistribution();
};

document.addEventListener("DOMContentLoaded", () => {
  window.renderSOCCharts();
});
