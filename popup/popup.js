document.addEventListener("DOMContentLoaded", () => {
  const scoreEl = document.getElementById("score");
  const messageEl = document.getElementById("message");
  const techListEl = document.getElementById("techList");
  const malwareBoxEl = document.getElementById("malwareBox");
  const threatsEl = document.getElementById("threats");
  const rescanBtn = document.getElementById("rescanBtn");
  const riskLevelEl = document.getElementById("riskLevel");
  const exportBtn = document.getElementById("exportBtn");

  // ================= RENDER RESULT =================
  function renderResult(result) {
    if (!result) {
      messageEl.textContent = "Failed to analyze site.";
      return;
    }

    const score = result.score ?? 0;
    scoreEl.textContent = score;
    messageEl.textContent = result.message ?? "No message";

    scoreEl.className = "";
    riskLevelEl.className = "risk-level";

    if (score >= 80) {
      scoreEl.classList.add("score-safe");
      riskLevelEl.textContent = "LOW RISK";
      riskLevelEl.classList.add("risk-safe");
    } else if (score >= 40) {
      scoreEl.classList.add("score-warning");
      riskLevelEl.textContent = "MEDIUM RISK";
      riskLevelEl.classList.add("risk-warning");
    } else {
      scoreEl.classList.add("score-danger");
      riskLevelEl.textContent = "HIGH RISK";
      riskLevelEl.classList.add("risk-danger");
    }

    // Malware
    if (result.malware?.malicious) {
      malwareBoxEl.classList.remove("hidden");
      threatsEl.textContent =
        result.malware.threats?.join(", ") || "Unknown threat";
    } else {
      malwareBoxEl.classList.add("hidden");
      threatsEl.textContent = "";
    }

    // Technologies
    techListEl.innerHTML = "";
    if (result.technologies?.length) {
      result.technologies.forEach(tech => {
        const li = document.createElement("li");
        li.textContent = tech;
        techListEl.appendChild(li);
      });
    } else {
      techListEl.innerHTML = "<li>No technologies detected.</li>";
    }

    // WHOIS
    const whoisBoxEl = document.getElementById("whoisBox");
    if (result.whois?.registrar) {
      document.getElementById("whoisRegistrar").textContent =
        result.whois.registrar;

      document.getElementById("whoisDate").textContent =
        result.whois.creationDate
          ? new Date(result.whois.creationDate).toDateString()
          : "--";

      whoisBoxEl.classList.remove("hidden");
    } else {
      whoisBoxEl.classList.add("hidden");
    }
  }

  // ================= SCAN FLOW (OPTION A) =================
  function scan(type = "GET_RISK") {
    chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
      if (!tab?.id || !tab?.url) {
        messageEl.textContent = "Unable to access tab.";
        return;
      }

      if (
        tab.url.startsWith("chrome://") ||
        tab.url.startsWith("edge://") ||
        tab.url.startsWith("chrome-extension://")
      ) {
        messageEl.textContent = "Cannot scan internal browser pages.";
        return;
      }

      // STEP 1: Force inject content script
      chrome.scripting.executeScript(
        {
          target: { tabId: tab.id },
          files: ["content/content.js"]
        },
        () => {
          if (chrome.runtime.lastError) {
            messageEl.textContent = "Failed to inject scanner.";
            return;
          }

          // STEP 2: Handshake
          chrome.tabs.sendMessage(tab.id, { type: "PING" }, (pong) => {
            if (!pong?.ready) {
              messageEl.textContent = "Page not ready. Reload and try again.";
              return;
            }

            // STEP 3: Get page info from content
            chrome.tabs.sendMessage(
              tab.id,
              { type: "GET_PAGE_INFO" },
              (pageRes) => {
                if (!pageRes?.pageInfo) {
                  messageEl.textContent = "Failed to collect page data.";
                  return;
                }

                // STEP 4: Send to background for analysis
                chrome.runtime.sendMessage(
                  {
                    type,
                    url: pageRes.url,
                    pageInfo: pageRes.pageInfo
                  },
                  (result) => {
                    if (!result) {
                      messageEl.textContent = "Scan failed.";
                      return;
                    }
                    renderResult(result);
                  }
                );
              }
            );
          });
        }
      );
    });
  }

  // ================= EXPORT SECURITY REPORT =================
  function exportReport() {
    chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
      if (!tab?.id) return;

      chrome.tabs.sendMessage(tab.id, { type: "COLLECT_VULNS" }, (data) => {
        if (!data) {
          alert("Unable to collect vulnerability data.");
          return;
        }

        chrome.runtime.sendMessage(
          { type: "GENERATE_REPORT", data },
          (res) => {
            if (!res?.report) {
              alert("Failed to generate report.");
              return;
            }

            const blob = new Blob([res.report], { type: "text/plain" });
            const url = URL.createObjectURL(blob);

            chrome.downloads.download({
              url,
              filename: "security_report.txt",
              saveAs: true
            });
          }
        );
      });
    });
  }

  // ================= INIT =================
  scan("GET_RISK");
  rescanBtn.addEventListener("click", () => scan("RESCAN"));
  if (exportBtn) exportBtn.addEventListener("click", exportReport);
});
