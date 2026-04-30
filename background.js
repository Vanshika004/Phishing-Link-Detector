const BADGE_COLORS = {
  Safe: "#15803d",
  Suspicious: "#f59e0b",
  Phishing: "#dc2626"
};

chrome.runtime.onMessage.addListener((message, sender) => {
  if (message?.type !== "PAGE_THREAT_UPDATE" || !sender.tab?.id) {
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
});
