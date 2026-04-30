const currentUrlEl = document.getElementById("currentUrl");
const resultBadgeEl = document.getElementById("resultBadge");
const scoreValueEl = document.getElementById("scoreValue");
const totalScannedEl = document.getElementById("totalScanned");
const flaggedLinksEl = document.getElementById("flaggedLinks");
const reasonListEl = document.getElementById("reasonList");
const scanButton = document.getElementById("scanButton");
const statusMessageEl = document.getElementById("statusMessage");

function setResultBadge(result) {
  const normalized = result || "Safe";

  resultBadgeEl.textContent = normalized;
  resultBadgeEl.className = `result ${normalized.toLowerCase()}`;
  document.body.dataset.result = normalized.toLowerCase();
}

function renderStats(stats) {
  const displayResult = stats.worstResult || stats.lastResult || {};
  const flagged = (stats.suspiciousCount || 0) + (stats.phishingCount || 0);
  const reasons = Array.isArray(displayResult.reasons) && displayResult.reasons.length > 0
    ? displayResult.reasons
    : ["No suspicious indicators found."];

  setResultBadge(displayResult.result || (flagged > 0 ? "Suspicious" : "Safe"));
  scoreValueEl.textContent = displayResult.score ?? 0;
  totalScannedEl.textContent = stats.totalScanned || 0;
  flaggedLinksEl.textContent = flagged;
  currentUrlEl.textContent = stats.pageUrl || "No active page detected";
  reasonListEl.replaceChildren(
    ...reasons.map((reason) => {
      const item = document.createElement("li");
      item.textContent = reason;
      return item;
    })
  );
}

function loadStats() {
  chrome.storage.local.get(
    {
      pageUrl: "",
      totalScanned: 0,
      suspiciousCount: 0,
      phishingCount: 0,
      lastResult: null,
      worstResult: null
    },
    renderStats
  );
}

async function getActiveTab() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs[0];
}

scanButton.addEventListener("click", async () => {
  scanButton.disabled = true;
  statusMessageEl.textContent = "Rescanning current page...";

  try {
    const tab = await getActiveTab();

    if (!tab?.id) {
      throw new Error("No active tab found");
    }

    await chrome.tabs.sendMessage(tab.id, { type: "SCAN_PAGE" });
    statusMessageEl.textContent = "Rescan requested. Results update automatically.";
  } catch (error) {
    statusMessageEl.textContent = `Could not start scan: ${error.message}`;
  } finally {
    scanButton.disabled = false;
  }
});

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName === "local") {
    loadStats();
  }
});

loadStats();
