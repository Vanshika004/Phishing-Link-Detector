const DEFAULT_API_BASE_URL = "http://localhost:5000";
const MAX_CONCURRENT_SCANS = 6;

let activeScans = 0;
const scanQueue = [];
const RESULT_SEVERITY = {
  Safe: 0,
  Suspicious: 1,
  Phishing: 2
};
let currentWorstResult = null;
let pageFlaggedCount = 0;
let alertPanel = null;

function isHiddenLink(link) {
  const styles = window.getComputedStyle(link);
  const rect = link.getBoundingClientRect();

  return (
    link.offsetParent === null ||
    styles.display === "none" ||
    styles.visibility === "hidden" ||
    styles.opacity === "0" ||
    rect.width === 0 ||
    rect.height === 0
  );
}

function normalizeReasons(reasons) {
  return Array.isArray(reasons) && reasons.length > 0
    ? reasons
    : ["No specific issues found"];
}

function createAlertPanel() {
  const panel = document.createElement("div");
  panel.id = "phishing-detector-alert";
  panel.style.position = "fixed";
  panel.style.right = "18px";
  panel.style.bottom = "18px";
  panel.style.zIndex = "2147483647";
  panel.style.maxWidth = "360px";
  panel.style.padding = "14px";
  panel.style.border = "2px solid #dc2626";
  panel.style.borderRadius = "8px";
  panel.style.background = "#ffffff";
  panel.style.boxShadow = "0 12px 32px rgba(15, 23, 42, 0.22)";
  panel.style.color = "#111827";
  panel.style.fontFamily = "Arial, Helvetica, sans-serif";
  panel.style.fontSize = "13px";
  panel.style.lineHeight = "1.4";

  document.documentElement.appendChild(panel);
  return panel;
}

function showThreatAlert(analysis) {
  const reasons = normalizeReasons(analysis.reasons);
  alertPanel = alertPanel || createAlertPanel();

  alertPanel.innerHTML = "";

  const title = document.createElement("strong");
  title.textContent = `${analysis.result} link detected`;
  title.style.display = "block";
  title.style.marginBottom = "6px";
  title.style.color = analysis.result === "Phishing" ? "#b91c1c" : "#b45309";
  title.style.fontSize = "15px";

  const summary = document.createElement("div");
  summary.textContent = `Score: ${analysis.score ?? 0} | Flagged links on page: ${pageFlaggedCount}`;
  summary.style.marginBottom = "8px";

  const list = document.createElement("ul");
  list.style.margin = "0 0 10px";
  list.style.paddingLeft = "18px";

  reasons.slice(0, 4).forEach((reason) => {
    const item = document.createElement("li");
    item.textContent = reason;
    list.appendChild(item);
  });

  const closeButton = document.createElement("button");
  closeButton.type = "button";
  closeButton.textContent = "Dismiss";
  closeButton.style.border = "0";
  closeButton.style.borderRadius = "6px";
  closeButton.style.padding = "7px 10px";
  closeButton.style.color = "#ffffff";
  closeButton.style.background = "#1d4ed8";
  closeButton.style.cursor = "pointer";
  closeButton.addEventListener("click", () => {
    alertPanel.remove();
    alertPanel = null;
  });

  alertPanel.append(title, summary, list, closeButton);
}

function applyLinkStyle(link, analysis) {
  const reasons = normalizeReasons(analysis.reasons);
  const result = analysis.result || "Safe";

  link.dataset.phishingResult = result;
  link.dataset.phishingScore = String(analysis.score ?? 0);
  link.dataset.phishingReasons = JSON.stringify(reasons);
  link.title = `${result} (score: ${analysis.score ?? 0})\n${reasons.join("\n")}`;

  if (result === "Phishing") {
    link.style.border = "2px solid #dc2626";
    link.style.backgroundColor = "#fee2e2";
    link.style.borderRadius = "4px";
    link.style.padding = "1px 3px";
  } else if (result === "Suspicious") {
    link.style.border = "2px solid #f59e0b";
    link.style.borderRadius = "4px";
    link.style.padding = "1px 3px";
  }
}

function protectLinkClick(event) {
  const link = event.currentTarget;
  const result = link.dataset.phishingResult;

  if (result !== "Phishing" && result !== "Suspicious") {
    return;
  }

  const score = link.dataset.phishingScore || "0";
  const reasons = normalizeReasons(JSON.parse(link.dataset.phishingReasons || "[]"));
  const warning = [
    `${result} link detected. Score: ${score}`,
    "",
    "Reasons:",
    ...reasons.map((reason) => `- ${reason}`),
    "",
    "Press OK to continue anyway, or Cancel to stay on this page."
  ].join("\n");

  if (!window.confirm(warning)) {
    event.preventDefault();
    event.stopPropagation();
  }
}

function pickWorstResult(currentWorst, analysis) {
  if (!currentWorst) {
    return analysis;
  }

  const currentSeverity = RESULT_SEVERITY[currentWorst.result] ?? 0;
  const nextSeverity = RESULT_SEVERITY[analysis.result] ?? 0;

  if (nextSeverity > currentSeverity) {
    return analysis;
  }

  if (nextSeverity === currentSeverity && (analysis.score ?? 0) > (currentWorst.score ?? 0)) {
    return analysis;
  }

  return currentWorst;
}

function getApiEndpoint() {
  return new Promise((resolve) => {
    chrome.storage.sync.get(
      {
        apiBaseUrl: DEFAULT_API_BASE_URL
      },
      (settings) => {
        const baseUrl = settings.apiBaseUrl.replace(/\/+$/, "");
        resolve(`${baseUrl}/api/check-url`);
      }
    );
  });
}

function updateStats(analysis) {
  chrome.storage.local.get(
    {
      totalScanned: 0,
      suspiciousCount: 0,
      phishingCount: 0,
      lastResult: null,
      worstResult: null
    },
    (stats) => {
      const worstResult = pickWorstResult(stats.worstResult, analysis);
      const nextStats = {
        totalScanned: stats.totalScanned + 1,
        suspiciousCount:
          stats.suspiciousCount + (analysis.result === "Suspicious" ? 1 : 0),
        phishingCount:
          stats.phishingCount + (analysis.result === "Phishing" ? 1 : 0),
        lastResult: analysis,
        worstResult
      };

      chrome.storage.local.set(nextStats);
      currentWorstResult = worstResult;
      pageFlaggedCount = nextStats.suspiciousCount + nextStats.phishingCount;

      chrome.runtime.sendMessage({
        type: "PAGE_THREAT_UPDATE",
        result: worstResult.result,
        flaggedCount: pageFlaggedCount
      });

      if (analysis.result === "Suspicious" || analysis.result === "Phishing") {
        showThreatAlert(worstResult);
      }
    }
  );
}

async function requestAnalysis(url, metadata = {}) {
  const apiEndpoint = await getApiEndpoint();
  const response = await fetch(apiEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({ url, ...metadata })
  });

  const analysis = await response.json().catch(() => null);

  if (analysis?.result && typeof analysis.score !== "undefined") {
    return analysis;
  }

  if (!response.ok) {
    throw new Error(`Backend returned HTTP ${response.status}`);
  }

  throw new Error("Backend returned an invalid response");
}

async function scanLink(link) {
  const href = link.href;

  if (!href || link.dataset.scanned === "true") {
    return;
  }

  link.dataset.scanned = "true";
  link.dataset.linkText = (link.innerText || "").trim();
  link.addEventListener("click", protectLinkClick);

  try {
    const analysis = await requestAnalysis(href, {
      text: link.innerText || "",
      hidden: isHiddenLink(link)
    });
    applyLinkStyle(link, analysis);
    updateStats(analysis);
  } catch (error) {
    link.dataset.scanError = error.message;
    link.title = `Unable to scan link: ${error.message}`;
  }
}

function runNextScan() {
  while (activeScans < MAX_CONCURRENT_SCANS && scanQueue.length > 0) {
    const link = scanQueue.shift();
    activeScans += 1;

    scanLink(link)
      .catch(() => {
        // Individual link errors are stored on the link and should not stop scanning.
      })
      .finally(() => {
        activeScans -= 1;
        runNextScan();
      });
  }
}

function enqueueLink(link) {
  if (link instanceof HTMLAnchorElement && link.dataset.scanned !== "true") {
    scanQueue.push(link);
  }
}

function scanPageLinks(root = document) {
  root.querySelectorAll("a[href]").forEach(enqueueLink);
  runNextScan();
}

function resetPageStats() {
  currentWorstResult = null;
  pageFlaggedCount = 0;

  chrome.storage.local.set({
    pageUrl: window.location.href,
    totalScanned: 0,
    suspiciousCount: 0,
    phishingCount: 0,
    lastResult: null,
    worstResult: null
  });

  chrome.runtime.sendMessage({
    type: "PAGE_THREAT_UPDATE",
    result: "Safe",
    flaggedCount: 0
  });
}

const observer = new MutationObserver((mutations) => {
  for (const mutation of mutations) {
    for (const node of mutation.addedNodes) {
      if (node instanceof HTMLAnchorElement) {
        enqueueLink(node);
      } else if (node instanceof HTMLElement) {
        scanPageLinks(node);
      }
    }
  }

  runNextScan();
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === "SCAN_PAGE") {
    scanPageLinks();
    sendResponse({ ok: true });
  }

  return true;
});

resetPageStats();
scanPageLinks();
observer.observe(document.body || document.documentElement, {
  childList: true,
  subtree: true
});
