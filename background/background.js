console.log("✅ Background service worker started");

// ================= API KEYS =================
const WHOIS_API_KEY = "at_jYvHDBuLvObJXbWcWGw4gAVXxnfmg";
const SAFE_BROWSING_API_KEY = "AIzaSyDLrnrsH7t51zg0iqncZ7zsjh5vvILOAFk";

// ================= WHOIS =================
async function fetchWhoisData(domain) {
  try {
    const resp = await fetch(
      `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${WHOIS_API_KEY}&domainName=${domain}&outputFormat=JSON`
    );
    if (!resp.ok) throw new Error("WHOIS request failed");

    const data = await resp.json();
    return {
      creationDate: data?.WhoisRecord?.registryData?.createdDate || null,
      registrar: data?.WhoisRecord?.registryData?.registrarName || null
    };
  } catch {
    return null;
  }
}

// ================= MALWARE =================
async function checkMalware(url) {
  try {
    const resp = await fetch(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${SAFE_BROWSING_API_KEY}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          client: { clientId: "tech-safety", clientVersion: "1.0" },
          threatInfo: {
            threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            platformTypes: ["ANY_PLATFORM"],
            threatEntryTypes: ["URL"],
            threatEntries: [{ url }]
          }
        })
      }
    );

    const data = await resp.json();
    if (data?.matches?.length) {
      return { malicious: true, threats: data.matches.map(m => m.threatType) };
    }
    return { malicious: false, threats: [] };
  } catch {
    return null;
  }
}

// ================= TECH DETECTION =================
function detectTechnologies(pageInfo = {}) {
  const tech = [];

  if (pageInfo.metaGenerator) {
    tech.push(`CMS: ${pageInfo.metaGenerator}`);
  }

  (pageInfo.scripts || []).forEach(src => {
    if (/react/i.test(src)) tech.push("React");
    if (/vue/i.test(src)) tech.push("Vue.js");
    if (/angular/i.test(src)) tech.push("Angular");
    if (/jquery/i.test(src)) tech.push("jQuery");
    if (/wp-content/i.test(src)) tech.push("WordPress");
    if (/analytics/i.test(src)) tech.push("Google Analytics");
    if (/fbq/i.test(src)) tech.push("Facebook Pixel");
  });

  return [...new Set(tech)];
}

// ================= MAIN SCAN =================
async function analyzeSite(url, pageInfo) {
  let score = 100;
  let message = "Site looks safe.";
  let color = "green";

  const domain = new URL(url).hostname;

  const whois = await fetchWhoisData(domain);
  if (whois?.creationDate) {
    const age =
      new Date().getFullYear() -
      new Date(whois.creationDate).getFullYear();
    if (age < 1) {
      score -= 30;
      message = "Domain is very new.";
      color = "orange";
    }
  }

  if (!url.startsWith("https://")) {
    score -= 20;
    message = "Site is not using HTTPS.";
    color = "orange";
  }

  const malware = await checkMalware(url);
  if (malware?.malicious) {
    score = 0;
    message = "Malicious or phishing site detected!";
    color = "red";
  }

  const technologies = detectTechnologies(pageInfo);

  score = Math.max(0, Math.min(100, score));

  return {
    score,
    message,
    color,
    whois,
    malware,
    technologies
  };
}

// ================= REPORT GENERATOR =================
function generateReport(data) {
  const { url, findings } = data;
  const lines = [];

  lines.push("SECURITY ANALYSIS REPORT");
  lines.push("==============================");
  lines.push(`Target URL: ${url}`);
  lines.push(`Scan Time: ${new Date().toUTCString()}`);
  lines.push("");

  if (!findings?.length) {
    lines.push("No obvious vulnerability indicators were detected.");
  } else {
    findings.forEach((f, i) => {
      lines.push(`[${i + 1}] ${f.type.replaceAll("_", " ")}`);
      lines.push(`Location: ${f.location}`);
      if (f.details?.inputs)
        lines.push(`Inputs: ${f.details.inputs.join(", ")}`);
      if (f.details?.sink)
        lines.push(`DOM Sink: ${f.details.sink}`);
      lines.push("");
    });
  }

  lines.push("==============================");
  lines.push("END OF REPORT");
  return lines.join("\n");
}

// ================= MESSAGE ROUTER =================
chrome.runtime.onMessage.addListener((req, sender, sendResponse) => {

  if (req.type === "GET_RISK" || req.type === "RESCAN") {
    analyzeSite(req.url, req.pageInfo).then(result => {
      if (sender?.tab?.id) {
        chrome.action.setBadgeText({
          text: result.score.toString(),
          tabId: sender.tab.id
        });
        chrome.action.setBadgeBackgroundColor({
          color: result.color,
          tabId: sender.tab.id
        });
      }
      sendResponse(result);
    });
    return true;
  }

  if (req.type === "GENERATE_REPORT") {
    sendResponse({ report: generateReport(req.data) });
    return true;
  }
});
