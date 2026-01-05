(function () {
  // 🔍 Collect page info for tech scan
  const pageInfo = {
    scripts: [],
    metaGenerator: null
  };

  // 1️⃣ Collect script URLs
  document.querySelectorAll("script[src]").forEach(script => {
    pageInfo.scripts.push(script.src);
  });

  // 2️⃣ Detect meta generator (e.g., WordPress, Joomla)
  const generatorMeta = document.querySelector("meta[name='generator']");
  if (generatorMeta) {
    pageInfo.metaGenerator = generatorMeta.content;
  }

  // 3️⃣ Send initial scan to background
  chrome.runtime.sendMessage({
    type: "GET_RISK",
    url: window.location.href,
    pageInfo
  });

  // 4️⃣ Monitor redirects and rescan
  let lastHref = window.location.href;
  setInterval(() => {
    if (window.location.href !== lastHref) {
      chrome.runtime.sendMessage({
        type: "RESCAN",
        url: window.location.href,
        pageInfo
      });
      lastHref = window.location.href;
    }
  }, 500);
})();