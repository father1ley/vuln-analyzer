(() => {
  console.log("✅ Content script injected:", location.href);

  // ======================================================
  // PASSIVE VULNERABILITY COLLECTOR
  // ======================================================
  function collectVulnerabilities() {
    const findings = [];

    // -------- SQLi indicators (forms) --------
    [...document.forms].forEach((form, index) => {
      const inputs = [...form.elements]
        .filter(e => e.name)
        .map(e => e.name);

      const hasPassword = [...form.elements].some(e => e.type === "password");
      const hasCSRF = [...form.elements].some(e =>
        /csrf|token/i.test(e.name)
      );

      if (hasPassword && !hasCSRF) {
        findings.push({
          type: "SQL_INJECTION_RISK",
          location: `${form.method || "GET"} ${form.action || location.href}`,
          details: {
            formIndex: index,
            inputs,
            csrf: false
          }
        });
      }
    });

    // -------- XSS indicators (DOM sinks) --------
    const sinks = ["innerHTML", "outerHTML", "document.write"];
    [...document.scripts].forEach((script, index) => {
      const code = script.textContent || "";
      sinks.forEach(sink => {
        if (code.includes(sink)) {
          findings.push({
            type: "XSS_RISK",
            location: script.src || `inline script #${index + 1}`,
            details: { sink }
          });
        }
      });
    });

    return findings;
  }

  // ======================================================
  // MESSAGE ROUTER
  // ======================================================
  chrome.runtime.onMessage.addListener((req, sender, sendResponse) => {

    // 🔑 Handshake
    if (req.type === "PING") {
      sendResponse({ ready: true });
      return;
    }

    // ===== PAGE INFO COLLECTION =====
    if (req.type === "GET_PAGE_INFO") {
      sendResponse({
        url: location.href,
        pageInfo: {
          metaGenerator:
            document.querySelector("meta[name='generator']")?.content || null,
          scripts: [...document.scripts].map(s => s.src).filter(Boolean)
        }
      });
      return;
    }

    // ===== VULNERABILITY EXPORT =====
    if (req.type === "COLLECT_VULNS") {
      sendResponse({
        url: location.href,
        findings: collectVulnerabilities()
      });
    }
  });
})();
