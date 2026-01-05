const WHOIS_API_KEY = "at_jYvHDBuLvObJXbWcWGw4gAVXxnfmg";

// 🔎 WHOIS lookup helper
async function fetchWhoisData(domain) {
  try {
    const resp = await fetch(`https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${WHOIS_API_KEY}&domainName=${domain}&outputFormat=JSON`);
    if (!resp.ok) throw new Error("WHOIS API request failed");
    const data = await resp.json();
    return {
      creationDate: data?.WhoisRecord?.registryData?.createdDate,
      registrar: data?.WhoisRecord?.registryData?.registrarName
    };
  } catch (err) {
    console.warn("WHOIS lookup failed:", err.message);
    return null;
  }
}

// 🧩 Technology scan helper
function detectTechnologies(pageInfo = {}) {
  const tech = [];

  // Meta generator
  if (pageInfo.metaGenerator) {
    tech.push(`CMS: ${pageInfo.metaGenerator}`);
  }

  // Script URLs
  if (pageInfo.scripts) {
    pageInfo.scripts.forEach(src => {
      if (/jquery/i.test(src)) tech.push("jQuery");
      if (/react/i.test(src)) tech.push("React");
      if (/angular/i.test(src)) tech.push("Angular");
      if (/vue/i.test(src)) tech.push("Vue.js");
      if (/wp-content/i.test(src)) tech.push("WordPress");
      if (/analytics/i.test(src)) tech.push("Google Analytics");
      if (/fbq/i.test(src)) tech.push("Facebook Pixel");
    });
  }

  return [...new Set(tech)]; // deduplicate
}

// 🛡️ Risk scoring function
async function analyzeSite(url, pageInfo = {}) {
  let score = 100;
  let message = "Site looks safe.";
  let color = "green";

  const domain = new URL(url).hostname;
  const whois = await fetchWhoisData(domain);

  if (whois?.creationDate) {
    const creationYear = new Date(whois.creationDate).getFullYear();
    const currentYear = new Date().getFullYear();
    if (currentYear - creationYear < 1) {
      score -= 30;
      message = "Domain is very new — possible risk.";
      color = "orange";
    }
  }

  if (!url.startsWith("https://")) {
    score -= 20;
    message = "Site is not using HTTPS.";
    color = "orange";
  }

  if (pageInfo.scripts) {
    const riskyPatterns = [/eval\(/, /document\.write\(/, /Function\(/];
    const flagged = pageInfo.scripts.filter(code =>
      riskyPatterns.some(p => p.test(code))
    );
    if (flagged.length > 0) {
      score -= 40;
      message = "Suspicious scripts detected!";
      color = "red";
    }
  }

  score = Math.max(0, Math.min(100, score));

  // 🔍 Technology detection
  const technologies = detectTechnologies(pageInfo);

  return { score, message, color, whois, technologies };
}

// 📩 Message listener
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.type === "GET_RISK" || request.type === "RESCAN") {
    (async () => {
      try {
        const result = await analyzeSite(request.url, request.pageInfo || {});
        sendResponse(result);

        if (result && typeof result.score === "number" && sender?.tab?.id) {
          chrome.action.setBadgeText({
            text: result.score.toString(),
            tabId: sender.tab.id
          });
          chrome.action.setBadgeBackgroundColor({
            color: result.color || "gray",
            tabId: sender.tab.id
          });
        }
      } catch (err) {
        console.error("Error analyzing site:", err);
        sendResponse({ score: 0, message: "Analysis failed", color: "gray" });
      }
    })();
    return true;
  }
});