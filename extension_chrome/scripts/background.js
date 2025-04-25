// --- Configuration ---
const DEFAULT_API_BASE_URL = 'https://btl-python.onrender.com/api';
const DEFAULT_CACHE_EXPIRY_MINUTES = 60;
const UPDATE_ALARM_NAME = 'updateBlocklistsAlarm';
const MIN_CACHE_EXPIRY = 5;
const MAX_CACHE_EXPIRY = 1440; // 1 day

let currentApiBaseUrl = DEFAULT_API_BASE_URL;
let currentCacheExpiryMinutes = DEFAULT_CACHE_EXPIRY_MINUTES;

// --- Utility Functions ---
function isValidUrl(string) {
  try {
    new URL(string);
    return true;
  } catch (_) {
    return false;
  }
}

function normalizeDomain(domain) {
    if (!domain) return null;
    try {
        // Handle potential IDN domains (Punycode) - requires a library usually,
        // but basic handling for www removal is fine here.
        let normalized = domain.toLowerCase().trim();
        if (normalized.startsWith('www.')) {
            normalized = normalized.substring(4);
        }
        // Basic validation to avoid empty strings or invalid characters if needed
        if (normalized.length === 0 || normalized.includes(' ')) {
             return null;
        }
        return normalized;
    } catch (e) {
        console.error("Error normalizing domain:", domain, e);
        return null;
    }
}


function normalizeEmail(email) {
    if (!email) return null;
    try {
        const trimmed = email.toLowerCase().trim();
        // Basic email format check
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (emailRegex.test(trimmed)) {
            return trimmed;
        }
        return null; // Invalid format
    } catch(e) {
        console.error("Error normalizing email:", email, e);
        return null;
    }
}


// --- Settings Loading ---
async function loadSettings() {
    try {
        const settings = await chrome.storage.sync.get(['apiUrl', 'cacheExpiryMinutes']);
        currentApiBaseUrl = settings.apiUrl && isValidUrl(settings.apiUrl) ? settings.apiUrl : DEFAULT_API_BASE_URL;
        currentCacheExpiryMinutes = settings.cacheExpiryMinutes >= MIN_CACHE_EXPIRY && settings.cacheExpiryMinutes <= MAX_CACHE_EXPIRY
                                     ? settings.cacheExpiryMinutes
                                     : DEFAULT_CACHE_EXPIRY_MINUTES;
        console.log(`Phishing Guard Pro: Settings loaded. API: ${currentApiBaseUrl}, Cache Expiry: ${currentCacheExpiryMinutes} min`);
        // Reschedule alarm based on loaded settings
        chrome.alarms.create(UPDATE_ALARM_NAME, { periodInMinutes: currentCacheExpiryMinutes });

    } catch (error) {
        console.error("Phishing Guard Pro: Error loading settings, using defaults.", error);
        currentApiBaseUrl = DEFAULT_API_BASE_URL;
        currentCacheExpiryMinutes = DEFAULT_CACHE_EXPIRY_MINUTES;
         chrome.alarms.create(UPDATE_ALARM_NAME, { periodInMinutes: currentCacheExpiryMinutes });
    }
     // Ensure the endpoint ends with /api if needed, or remove trailing slashes if base URL is expected
     if (currentApiBaseUrl.endsWith('/')) {
         currentApiBaseUrl = currentApiBaseUrl.slice(0, -1);
     }
      if (!currentApiBaseUrl.endsWith('/api')) {
           console.warn("API URL might need '/api' suffix depending on backend setup.");
           // currentApiBaseUrl += '/api'; // Uncomment if your routes need /api prefix and URL doesn't include it
       }

}

// --- Caching Logic ---
async function getCachedData(key) {
  try {
    const result = await chrome.storage.local.get([key, `${key}Timestamp`]);
    const data = result[key];
    const timestamp = result[`${key}Timestamp`];
    const now = Date.now();

    if (data && timestamp && (now - timestamp < currentCacheExpiryMinutes * 60 * 1000)) {
      // console.log(`Phishing Guard Pro: Using cached ${key}.`);
      return new Set(data);
    }
    // console.log(`Phishing Guard Pro: Cache expired or missing for ${key}.`);
    return null; // Cache miss or expired
  } catch (error) {
     console.error(`Phishing Guard Pro: Error reading cache for ${key}:`, error);
     return null;
  }
}

async function updateCache(type = 'domain') {
  const key = type === 'domain' ? 'phishingDomains' : 'phishingEmails';
  const listKey = type === 'domain' ? 'domains' : 'emails'; // Key in API response
  const versionKey = `${key}Version`;

  try {
     const currentVersion = (await chrome.storage.local.get([versionKey]))[versionKey] || 0;
     const fetchUrl = `${currentApiBaseUrl}/blocklist?type=${type}&since=${currentVersion}`;
     // console.log(`Phishing Guard Pro: Fetching ${key} updates from ${fetchUrl}`);

     const response = await fetch(fetchUrl, {
         method: 'GET',
         headers: { 'Accept': 'application/json' }
         // TODO: Add Authentication headers if needed (API Key, etc.)
         // 'Authorization': 'Bearer YOUR_API_KEY'
     });

     if (!response.ok) {
         if (response.status === 304) { // Not Modified
             console.log(`Phishing Guard Pro: ${key} cache is up to date (304 Not Modified).`);
             // Refresh timestamp even if not modified to reset expiry timer
              await chrome.storage.local.set({ [`${key}Timestamp`]: Date.now() });
             return await getCachedData(key); // Return existing data
         }
         throw new Error(`API Error (${fetchUrl}): ${response.status} ${response.statusText}`);
     }

     const data = await response.json();

     if (!data || typeof data !== 'object' || !Array.isArray(data[listKey])) {
        throw new Error(`Invalid API response structure for ${key} from ${fetchUrl}`);
     }

     const newList = data[listKey];
     const newVersion = data.version || Date.now();

     // Logic for handling updates (replace or merge based on API design)
     // Assuming the API returns the full list if 'since' is 0 or invalid,
     // and only *new* items if 'since' is valid. Adjust if API behaves differently.
     let updatedSet;
     if (currentVersion === 0 || String(currentVersion) !== String(data.request_since)) { // Assuming API echoes back the 'since' value it used
         // Replace cache with the full list received
         updatedSet = new Set(newList.map(item => type === 'domain' ? normalizeDomain(item) : normalizeEmail(item)).filter(Boolean));
         console.log(`Phishing Guard Pro: ${key} cache completely refreshed. Items: ${updatedSet.size}, Version: ${newVersion}`);
     } else {
         // Merge new items with existing cache
         const currentSet = await getCachedData(key) || new Set();
         newList.forEach(item => {
             const normalized = type === 'domain' ? normalizeDomain(item) : normalizeEmail(item);
             if (normalized) currentSet.add(normalized);
         });
         updatedSet = currentSet;
         console.log(`Phishing Guard Pro: ${key} cache merged with new items. Total Items: ${updatedSet.size}, New API Version: ${newVersion}`);
     }

     await chrome.storage.local.set({
        [key]: Array.from(updatedSet), // Store as array
        [`${key}Timestamp`]: Date.now(),
        [versionKey]: newVersion
     });

     return updatedSet; // Return the updated set

  } catch (error) {
    console.error(`Phishing Guard Pro: Failed to update ${key} cache:`, error);
    // Fallback to existing cache if update fails
    return await getCachedData(key) || new Set();
  }
}

async function getBlocklist(type = 'domain') {
    let list = await getCachedData(key);
    if (!list) {
        list = await updateCache(type);
    }
    return list;
}


// --- API Interaction Logic ---
async function checkPhishingAPI(type, value) {
    const key = type === 'domain' ? 'phishingDomains' : 'phishingEmails';
    const normalizedValue = type === 'domain' ? normalizeDomain(value) : normalizeEmail(value);

    if (!normalizedValue) {
         console.warn(`Phishing Guard Pro: Invalid value provided for ${type} check: ${value}`);
         return { isPhishing: false, reason: "Giá trị không hợp lệ" };
    }

    try {
        // 1. Check Cache
        const cachedList = await getCachedData(key); // Use getCachedData to check expiry
        if (cachedList?.has(normalizedValue)) {
            // console.log(`Phishing Guard Pro: Cache hit for ${type} - ${normalizedValue}`);
            return { isPhishing: true, reason: "Đã biết (từ cache)" };
        }

        // 2. Check API
        // console.log(`Phishing Guard Pro: Checking API for ${type} - ${normalizedValue}`);
        const checkUrl = `${currentApiBaseUrl}/check?type=${type}&value=${encodeURIComponent(normalizedValue)}`;
        const response = await fetch(checkUrl); // Add auth headers if needed

        if (!response.ok) {
            console.warn(`Phishing Guard Pro: API check failed for ${type} - ${normalizedValue}. Status: ${response.status}`);
            return { isPhishing: false, reason: "Lỗi API" }; // Default safe on API error, cache was already checked
        }
        const result = await response.json();

        // Optional: Update cache immediately if API confirms phishing but cache didn't have it
        if (result.isPhishing && !(cachedList?.has(normalizedValue))) {
             console.log(`Phishing Guard Pro: API confirmed ${type} ${normalizedValue} as phishing. Updating cache.`);
             const currentSet = await getCachedData(key) || new Set();
             currentSet.add(normalizedValue);
             await chrome.storage.local.set({
                 [key]: Array.from(currentSet),
                 [`${key}Timestamp`]: Date.now() // Refresh timestamp
             });
        }

        return result; // { isPhishing: true/false, reason: "..." }
    } catch (error) {
        console.error(`Phishing Guard Pro: Error checking ${type} '${normalizedValue}' via API:`, error);
        // Fallback to cache again in case of network error after initial cache check
         const cachedList = await getCachedData(key);
         if (cachedList?.has(normalizedValue)) {
            return { isPhishing: true, reason: "Đã biết (từ cache - API lỗi)" };
         }
        return { isPhishing: false, reason: "Lỗi kết nối API" };
    }
}

async function reportToAPI(type, value, context = "User report via extension") {
  const normalizedValue = type === 'domain' ? normalizeDomain(value) : (type === 'email' ? normalizeEmail(value) : value);

  if (!normalizedValue) {
     console.error(`Phishing Guard Pro: Invalid value provided for report: type=${type}, value=${value}`);
      chrome.notifications.create({
        type: 'basic', iconUrl: chrome.runtime.getURL('icons/icon-128.png'),
        title: 'Báo cáo thất bại', message: `Dữ liệu báo cáo không hợp lệ: ${value}`
      });
      return false; // Indicate failure
  }

  try {
    const reportUrl = `${currentApiBaseUrl}/report`;
    const response = await fetch(reportUrl, {
      method: 'POST',
      headers: {
          'Content-Type': 'application/json',
          // Add Auth headers if needed
      },
      body: JSON.stringify({ type: type, value: normalizedValue, context: context })
    });

    const result = await response.json();

    if (response.ok && result.success) {
      console.log(`Phishing Guard Pro: Report successful for ${type}: ${normalizedValue}`);
      chrome.notifications.create({
        type: 'basic', iconUrl: chrome.runtime.getURL('icons/icon-128.png'),
        title: 'Báo cáo thành công', message: `Cảm ơn bạn đã báo cáo ${type}: ${normalizedValue}`
      });

      // Add reported item to local cache for immediate effect
      if (type === 'domain' || type === 'email') {
          const key = type === 'domain' ? 'phishingDomains' : 'phishingEmails';
          const currentSet = await getCachedData(key) || new Set();
          if (!currentSet.has(normalizedValue)) {
              currentSet.add(normalizedValue);
              await chrome.storage.local.set({
                  [key]: Array.from(currentSet),
                  [`${key}Timestamp`]: Date.now() // Refresh timestamp
              });
              console.log(`Phishing Guard Pro: Added reported ${type} to local cache.`);
          }
      }
      return true;

    } else {
      throw new Error(result.message || 'Phản hồi API báo cáo không thành công.');
    }
  } catch (error) {
    console.error(`Phishing Guard Pro: Lỗi khi gửi báo cáo cho ${type} '${normalizedValue}':`, error);
    chrome.notifications.create({
      type: 'basic', iconUrl: chrome.runtime.getURL('icons/icon-128.png'),
      title: 'Báo cáo thất bại', message: `Không thể gửi báo cáo cho ${type}: ${normalizedValue}. Lỗi: ${error.message}`
    });
    return false; // Indicate failure
  }
}


// --- Event Listeners ---

// Load settings on startup
loadSettings();

// Initial Setup & Update Scheduling
chrome.runtime.onInstalled.addListener(async (details) => {
  console.log("Phishing Guard Pro: onInstalled event, reason:", details.reason);
  await loadSettings(); // Load settings first
  // Initialize/Update cache on install/update
  console.log("Phishing Guard Pro: Initializing cache on install/update...");
  await updateCache('domain');
  await updateCache('email');
  // Setup context menus
  setupContextMenus();
  // Ensure alarm is set correctly after potential settings load/update
  chrome.alarms.create(UPDATE_ALARM_NAME, { periodInMinutes: currentCacheExpiryMinutes });
  console.log(`Phishing Guard Pro: Update alarm set for every ${currentCacheExpiryMinutes} minutes.`);
});

// Listen for settings changes from options page
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
     if (request.action === 'settingsUpdated') {
         console.log("Phishing Guard Pro: Settings updated message received. Reloading settings...");
         loadSettings(); // Reload settings and reschedule alarm
         sendResponse({success: true});
         return false; // No async response needed here
     }
     // Keep other message handlers below...
     return false; // Indicate message not handled here if it falls through
});


// Handle scheduled updates
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === UPDATE_ALARM_NAME) {
    console.log("Phishing Guard Pro: Chạy cập nhật blocklist định kỳ...");
    await updateCache('domain');
    await updateCache('email');
  }
});

// Website Scanning
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    // Check if URL exists and is a http/https URL, ignore internal/extension pages
   if (changeInfo.url && isValidUrl(changeInfo.url) && !changeInfo.url.startsWith('chrome://') && !changeInfo.url.startsWith('about:') && !changeInfo.url.startsWith(chrome.runtime.getURL(''))) {
      const url = changeInfo.url;
      try {
          const urlObject = new URL(url);
          const domain = normalizeDomain(urlObject.hostname);
          if (!domain) return; // Skip if domain normalization fails

          const result = await checkPhishingAPI('domain', domain);

          if (result.isPhishing) {
              console.warn(`Phishing Guard Pro: Phát hiện trang lừa đảo [${result.reason}] - ${domain}`);
              // Check if we are already on the warning page to prevent redirect loop
              const warningPageUrl = chrome.runtime.getURL('warning/warning.html');
               if (!tab.url.startsWith(warningPageUrl)) {
                    chrome.tabs.update(tabId, { url: `${warningPageUrl}?url=${encodeURIComponent(url)}&domain=${encodeURIComponent(domain)}&reason=${encodeURIComponent(result.reason || 'Đã biết')}` });
               }
          }
      } catch (error) {
          console.error(`Phishing Guard Pro: Lỗi khi quét URL ${url}:`, error);
      }
   }
});


// Message Handling (from content scripts, popup, options)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    // --- Check Actions ---
    if (request.action === 'checkDomain' || request.action === 'checkEmailSender') {
        const type = request.action === 'checkDomain' ? 'domain' : 'email';
        checkPhishingAPI(type, request.value)
          .then(result => sendResponse(result))
          .catch(error => sendResponse({ isPhishing: false, error: error.message, reason: "Lỗi xử lý" }));
        return true; // Indicate async response
    }
    // --- Report Action ---
    else if (request.action === 'reportItem') {
        reportToAPI(request.type, request.value, request.context) // Pass context if available
          .then(success => sendResponse({ success: success }))
          .catch(error => sendResponse({ success: false, message: error.message }));
        return true; // Indicate async response
    }
     // --- Whitelist Action (Placeholder) ---
     else if (request.action === 'whitelistItem') {
         console.log(`Phishing Guard Pro: Whitelist request received (Backend implementation needed): type=${request.type}, value=${request.value}`);
          // TODO: Send whitelist request to backend API
          // Example: fetch(`${currentApiBaseUrl}/whitelist`, { method: 'POST', ... })
         sendResponse({ success: true, message: "Chức năng Whitelist đang phát triển (Backend)" }); // Placeholder response
          return true;
     }
    // --- Get Status/Info Actions ---
    else if (request.action === 'getApiStatus') {
        fetch(`${currentApiBaseUrl}/check?type=domain&value=google.com`) // Use a known safe, common domain
          .then(response => sendResponse({ reachable: response.ok }))
          .catch(() => sendResponse({ reachable: false }));
        return true; // Indicate async response
    }
    else if (request.action === 'getCurrentTabInfo') {
        const queryOptions = { active: true, currentWindow: true };
        chrome.tabs.query(queryOptions, (tabs) => {
            if (chrome.runtime.lastError || tabs.length === 0) {
                sendResponse({ url: null, domain: null, error: chrome.runtime.lastError?.message || "No active tab found" });
                return;
            }
            const tab = tabs[0];
            if (tab.url && isValidUrl(tab.url) && !tab.url.startsWith('chrome://') && !tab.url.startsWith('about:') && !tab.url.startsWith(chrome.runtime.getURL(''))) {
                 try {
                     const domain = normalizeDomain(new URL(tab.url).hostname);
                     sendResponse({ url: tab.url, domain: domain });
                 } catch (e) {
                     sendResponse({ url: tab.url, domain: null, error: "Invalid URL hostname" });
                 }
            } else {
                sendResponse({ url: null, domain: null, error: "Tab has no valid URL" }); // Not a valid URL to report/check
            }
        });
        return true; // Indicate async response
    }

    // --- Fallback ---
    console.log("Background: Received unhandled message", request);
    return false; // Indicate sync response or unhandled message
});


// --- Context Menu Setup & Handling ---
function setupContextMenus() {
    // Remove existing menus first to avoid duplicates on update
    chrome.contextMenus.removeAll(() => {
        chrome.contextMenus.create({
            id: "reportPhishingLink", title: "VN Guard: Báo cáo liên kết lừa đảo này", contexts: ["link"]
        });
        chrome.contextMenus.create({
            id: "reportPhishingSelection", title: "VN Guard: Báo cáo email/nội dung đáng ngờ này", contexts: ["selection"]
        });
        chrome.contextMenus.create({
            id: "reportPhishingPage", title: "VN Guard: Báo cáo trang này là lừa đảo", contexts: ["page"]
        });
         console.log("Phishing Guard Pro: Context menus created.");
    });
}

chrome.contextMenus.onClicked.addListener((info, tab) => {
    if (info.menuItemId === "reportPhishingLink" && info.linkUrl) {
         if (!isValidUrl(info.linkUrl)) { console.warn("Invalid link URL for reporting:", info.linkUrl); return; }
        try {
            const domain = normalizeDomain(new URL(info.linkUrl).hostname);
            if (domain) {
                reportToAPI('domain', domain, `Reported link: ${info.linkUrl}`);
            } else { // Report the full URL if domain extraction fails somehow
                reportToAPI('url', info.linkUrl, 'Reported link (no domain extracted)');
            }
        } catch (e) { reportToAPI('url', info.linkUrl, `Reported link (error: ${e.message})`); }

    } else if (info.menuItemId === "reportPhishingSelection" && info.selectionText) {
        const selection = info.selectionText.trim();
        const potentialEmail = normalizeEmail(selection);
        if (potentialEmail) {
            reportToAPI('email', potentialEmail, 'Reported selected email address');
        } else {
             // Maybe report selection as suspicious text? Requires backend handling.
            console.log("Reporting text selection (feature pending backend):", selection);
             reportToAPI('text_selection', selection, `Reported selected text from: ${info.pageUrl}`);
             // chrome.notifications.create({type: 'basic', iconUrl: 'icons/icon-128.png', title: 'Chức năng đang phát triển', message: 'Báo cáo lựa chọn văn bản đang được xử lý.'});
        }
    } else if (info.menuItemId === "reportPhishingPage" && info.pageUrl) {
         if (!isValidUrl(info.pageUrl) || info.pageUrl.startsWith('chrome://') || info.pageUrl.startsWith('about:') || info.pageUrl.startsWith(chrome.runtime.getURL(''))) {
              console.warn("Invalid page URL for reporting:", info.pageUrl);
              chrome.notifications.create({type: 'basic', iconUrl: 'icons/icon-128.png', title: 'Không thể báo cáo', message: 'Không thể báo cáo các trang nội bộ hoặc trang cảnh báo.'});
              return;
         }
         try {
             const domain = normalizeDomain(new URL(info.pageUrl).hostname);
             if(domain){
                 reportToAPI('domain', domain, `Reported page: ${info.pageUrl}`);
             } else { reportToAPI('url', info.pageUrl, 'Reported page (no domain extracted)'); }
         } catch (e) { reportToAPI('url', info.pageUrl, `Reported page (error: ${e.message})`); }
    }
});

console.log("VN Phishing Guard Pro Background Script Loaded (v2.1)");