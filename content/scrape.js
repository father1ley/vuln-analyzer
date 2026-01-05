// scrape.js

(function() {
  // Collect basic page info
  const pageInfo = {
    title: document.title,
    metaDescription: document.querySelector("meta[name='description']")?.content || "",
    canonical: document.querySelector("link[rel='canonical']")?.href || "",
    scripts: [],
    iframes: []
  };

  // Collect script sources and inline code
  const scriptTags = [...document.scripts];
  pageInfo.scripts = scriptTags.map(s => s.src ? `src: ${s.src}` : `inline: ${s.textContent.slice(0, 100)}...`);

  // Collect hidden iframes (potential backdoor indicators)
  const iframeTags = [...document.querySelectorAll("iframe")];
  pageInfo.iframes = iframeTags
    .filter(f => f.style.display === "none" || f.width === "0" || f.height === "0")
    .map(f => f.src);

  // Send collected info to background script
  chrome.runtime.sendMessage({ type: "PAGE_INFO", data: pageInfo });
})();