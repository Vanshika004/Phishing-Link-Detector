const BADGE_COLORS = {
  Safe: "#15803d",
  Suspicious: "#f59e0b",
  Phishing: "#dc2626"
};
const DEFAULT_API_BASE_URL = "http://localhost:5000";

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

async function checkUrl(payload) {
  const apiEndpoint = await getApiEndpoint();
  const response = await fetch(apiEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify(payload)
  });

  const analysis = await response.json().catch(() => null);

  if (analysis?.result && typeof analysis.score !== "undefined") {
    return analysis;
  }

  throw new Error(`Backend returned HTTP ${response.status}`);
}

function updateBadge(message, sender) {
  if (!sender.tab?.id) {
    return;
  }

  const result = message.result || "Safe";
  const flaggedCount = Number(message.flaggedCount || 0);

  chrome.action.setBadgeText({
    tabId: sender.tab.id,
    text: flaggedCount > 0 ? String(flaggedCount) : ""
  });

  chrome.action.setBadgeBackgroundColor({
    tabId: sender.tab.id,
    color: BADGE_COLORS[result] || BADGE_COLORS.Safe
  });
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type === "PAGE_THREAT_UPDATE") {
    updateBadge(message, sender);
    return false;
  }

  if (message?.type === "CHECK_URL") {
    checkUrl(message.payload)
      .then((analysis) => sendResponse({ ok: true, analysis }))
      .catch((error) => sendResponse({ ok: false, error: error.message }));

    return true;
  }

  return false;
});
