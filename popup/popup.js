document.addEventListener("DOMContentLoaded", () => {
  const siteUrlEl = document.getElementById("site-url");
  const riskScoreEl = document.getElementById("risk-score");
  const riskMessageEl = document.getElementById("risk-message");
  const techListEl = document.getElementById("tech-list");
  const registrarEl = document.getElementById("whois-registrar");
  const creationDateEl = document.getElementById("whois-date");
  const rescanBtn = document.getElementById("rescan-btn");

  // Get current tab URL
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const url = tabs[0].url;
    siteUrlEl.textContent = url;

    // Request risk analysis
    chrome.runtime.sendMessage({ type: "GET_RISK", url }, (result) => {
      if (!result) {
        riskMessageEl.textContent = "Failed to analyze site.";
        return;
      }

      // Risk score
      riskScoreEl.textContent = result.score ?? "--";
      riskMessageEl.textContent = result.message ?? "No message";

      // Technologies
      techListEl.innerHTML = "";
      if (result.technologies?.length > 0) {
        result.technologies.forEach(tech => {
          const li = document.createElement("li");
          li.textContent = tech;
          techListEl.appendChild(li);
        });
      } else {
        techListEl.innerHTML = "<li>No technologies detected.</li>";
      }

      // WHOIS info
      registrarEl.textContent = result.whois?.registrar ?? "--";
      creationDateEl.textContent = result.whois?.creationDate ?? "--";
    });
  });

  // Rescan button
  rescanBtn.addEventListener("click", () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const url = tabs[0].url;
      chrome.runtime.sendMessage({ type: "RESCAN", url }, (result) => {
        if (result) {
          riskScoreEl.textContent = result.score ?? "--";
          riskMessageEl.textContent = result.message ?? "No message";
          registrarEl.textContent = result.whois?.registrar ?? "--";
          creationDateEl.textContent = result.whois?.creationDate ?? "--";

          techListEl.innerHTML = "";
          if (result.technologies?.length > 0) {
            result.technologies.forEach(tech => {
              const li = document.createElement("li");
              li.textContent = tech;
              techListEl.appendChild(li);
            });
          } else {
            techListEl.innerHTML = "<li>No technologies detected.</li>";
          }
        }
      });
    });
  });
});