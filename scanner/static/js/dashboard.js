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
    // Charts are removed in Crawler Mode.
  }

  // Real-time asynchronous scan orchestration and progress bar polling
  function initRealTimeScanner() {
    var form = document.getElementById("scan-form");
    if (!form) return;

    var targetInput = document.getElementById("target_url");
    var approvedDomainsInput = document.getElementById("approved_domains_text");

    // Real-time hostname extractor for Pre-approved Domains field
    function autoExtractDomain() {
      var val = targetInput.value.trim();
      if (!val) return;
      
      try {
        var hostname = "";
        if (val.indexOf("://") === -1) {
          // If no protocol schema, try extracting path safely
          hostname = val.split("/")[0].split(":")[0];
        } else {
          var parsedUrl = new URL(val);
          hostname = parsedUrl.hostname;
        }

        if (hostname) {
          var currentVal = approvedDomainsInput.value.trim();
          var list = currentVal ? currentVal.split(",").map(function(s) { return s.trim().toLowerCase(); }) : [];
          
          // Guarantee localhost and target hostname are always present in the field
          if (list.indexOf("localhost") === -1) {
            list.push("localhost");
          }
          if (list.indexOf(hostname.toLowerCase()) === -1 && hostname !== "localhost") {
            list.push(hostname.toLowerCase());
          }
          
          // Re-serialize
          approvedDomainsInput.value = list.filter(Boolean).join(",");
        }
      } catch (e) {
        // Invalid URL - fail silently or ignore during typing
      }
    }

    // Bind event listeners for real-time extraction experience
    targetInput.addEventListener("blur", autoExtractDomain);
    targetInput.addEventListener("input", function() {
      // Delay slightly to prevent interrupted typing experience
      clearTimeout(targetInput.autoExtractTimeout);
      targetInput.autoExtractTimeout = setTimeout(autoExtractDomain, 800);
    });

    var submitBtn = document.getElementById("submit-btn");
    var progressCard = document.getElementById("progress-card");
    var progressBarFill = document.getElementById("progress-bar-fill");
    var progressStage = document.getElementById("progress-stage");
    var progressPercent = document.getElementById("progress-percent");
    var logDisplay = document.getElementById("log-display");

    form.addEventListener("submit", function (e) {
      e.preventDefault();

      // Disable submission button
      submitBtn.disabled = true;
      submitBtn.textContent = "스캔 진행 중...";

      // Display real-time progress card
      progressCard.style.display = "block";
      progressBarFill.style.width = "5%";
      progressStage.textContent = "스캔 작업 초기화 중...";
      progressPercent.textContent = "5%";

      var formData = new FormData(form);

      fetch("/api/scan", {
        method: "POST",
        body: formData,
      })
        .then(function (res) {
          if (!res.ok) {
            throw new Error("HTTP error " + res.status);
          }
          return res.json();
        })
        .then(function (data) {
          if (data.error) {
            alert("오류: " + data.error);
            resetFormState();
            return;
          }
          var scanId = data.scan_id;
          pollScanStatus(scanId);
        })
        .catch(function (err) {
          alert("스캔 시작 중 네트워크 오류 발생: " + err.message);
          resetFormState();
        });
    });

    function pollScanStatus(scanId) {
      var intervalId = setInterval(function () {
        fetch("/api/scan-status/" + scanId)
          .then(function (res) {
            if (!res.ok) {
              throw new Error("HTTP error " + res.status);
            }
            return res.json();
          })
          .then(function (data) {
            if (data.error) {
              clearInterval(intervalId);
              alert("상태 조회 오류: " + data.error);
              resetFormState();
              return;
            }

            // Update progress filling and metadata
            var progress = data.progress || 0;
            progressBarFill.style.width = progress + "%";
            progressPercent.textContent = progress + "%";
            progressStage.textContent = data.stage || "분석 중...";

            // Append and scroll logs
            if (data.logs && data.logs.length > 0) {
              logDisplay.textContent = data.logs.join("\n");
              logDisplay.scrollTop = logDisplay.scrollHeight;
            }

            if (data.status === "completed" || data.status === "failed") {
              clearInterval(intervalId);
              progressBarFill.style.width = "100%";
              progressPercent.textContent = "100%";
              // Redirect to populate tables and reload charts with fresh results
              setTimeout(function () {
                window.location.href = "/?scan_id=" + scanId;
              }, 600);
            }
          })
          .catch(function (err) {
            clearInterval(intervalId);
            console.error("Polling status error:", err);
            resetFormState();
          });
      }, 500);
    }

    function resetFormState() {
      submitBtn.disabled = false;
      submitBtn.textContent = "스캔 시작";
      progressCard.style.display = "none";
    }
  }

  document.addEventListener("DOMContentLoaded", function () {
    var chartData = loadChartData();
    renderCharts(chartData);
    initRealTimeScanner();
  });
})();
