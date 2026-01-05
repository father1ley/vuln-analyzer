// backdoor-scanner.js

(function() {
  const riskyPatterns = [
    /eval\(/,
    /Function\(/,
    /document\.write\(/,
    /atob\(/,              // often used in obfuscation
    /unescape\(/,          // legacy obfuscation
    /XMLHttpRequest/       // suspicious hidden requests
  ];

  const flaggedScripts = [];

  // Scan inline scripts
  const scriptTags = [...document.scripts];
  scriptTags.forEach(script => {
    const code = script.textContent || "";
    if (riskyPatterns.some(p => p.test(code))) {
      flaggedScripts.push(code.slice(0, 200)); // send snippet only
    }
  });

  // Scan for hidden iframes (common backdoor technique)
  const iframeTags = [...document.querySelectorAll("iframe")];
  const hiddenIframes = iframeTags
    .filter(f => f.style.display === "none" || f.width === "0" || f.height === "0")
    .map(f => f.src);

  if (flaggedScripts.length > 0 || hiddenIframes.length > 0) {
    chrome.runtime.sendMessage({
      type: "RISK_ALERT",
      data: {
        scripts: flaggedScripts,
        iframes: hiddenIframes
      }
    });
    console.warn("Potential backdoor indicators detected:", { flaggedScripts, hiddenIframes });
  }
})();