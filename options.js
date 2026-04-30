const DEFAULT_API_BASE_URL = "http://localhost:5000";

const apiBaseUrlInput = document.getElementById("apiBaseUrl");
const saveOptionsButton = document.getElementById("saveOptions");
const optionsStatus = document.getElementById("optionsStatus");

function cleanBaseUrl(value) {
  return value.trim().replace(/\/+$/, "");
}

function isValidBackendUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
}

function loadOptions() {
  chrome.storage.sync.get(
    {
      apiBaseUrl: DEFAULT_API_BASE_URL
    },
    (settings) => {
      apiBaseUrlInput.value = settings.apiBaseUrl;
    }
  );
}

saveOptionsButton.addEventListener("click", () => {
  const apiBaseUrl = cleanBaseUrl(apiBaseUrlInput.value || DEFAULT_API_BASE_URL);

  if (!isValidBackendUrl(apiBaseUrl)) {
    optionsStatus.textContent = "Please enter a valid http or https backend URL.";
    return;
  }

  chrome.storage.sync.set({ apiBaseUrl }, () => {
    optionsStatus.textContent = `Saved: ${apiBaseUrl}`;
  });
});

loadOptions();
