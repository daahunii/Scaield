(function () {
  function loadChartData() {
    var node = document.getElementById("chart-data");
    if (!node || !node.textContent) {
      return null;
    }

    try {
      return JSON.parse(node.textContent);
    } catch (error) {
      console.error("Failed to parse chart data:", error);
      return null;
    }
  }

  function renderCharts(chartData) {
    if (!chartData || typeof Chart === "undefined") {
      return;
    }

    var vulnCanvas = document.getElementById("vulnTypeChart");
    if (vulnCanvas) {
      new Chart(vulnCanvas, {
        type: "doughnut",
        data: {
          labels: chartData.vuln_labels || [],
          datasets: [
            {
              label: "취약점 수",
              data: chartData.vuln_counts || [],
            },
          ],
        },
      });
    }

    var runCanvas = document.getElementById("runTrendChart");
    if (runCanvas) {
      new Chart(runCanvas, {
        type: "bar",
        data: {
          labels: chartData.run_labels || [],
          datasets: [
            {
              label: "탐지 건수",
              data: chartData.run_counts || [],
            },
          ],
        },
        options: {
          scales: {
            y: { beginAtZero: true },
          },
        },
      });
    }
  }

  document.addEventListener("DOMContentLoaded", function () {
    var chartData = loadChartData();
    renderCharts(chartData);
  });
})();
