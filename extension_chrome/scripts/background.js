// --- Configuration ---
const DEFAULT_API_BASE_URL = 'https://btl-python.onrender.com/api';
const DEFAULT_CACHE_EXPIRY_MINUTES = 60;
const UPDATE_ALARM_NAME = 'updateBlocklistsAlarm';
const MIN_CACHE_EXPIRY = 5;
const MAX_CACHE_EXPIRY = 1440; // 1 day

let currentApiBaseUrl = DEFAULT_API_BASE_URL;
let currentCacheExpiryMinutes = DEFAULT_CACHE_EXPIRY_MINUTES;

// --- Utility Functions ---
function isValidUrl(string) { try { new URL(string); return true; } catch (_) { return false; } }
function normalizeDomain(domain) {
    if (!domain || typeof domain !== 'string') return null;
    try {
        let normalized = domain.toLowerCase().trim();
        if (normalized.startsWith('www.')) normalized = normalized.substring(4);
        if (normalized.length === 0 || !/^[a-z0-9.-]+$/.test(normalized) || !normalized.includes('.') || normalized.startsWith('.') || normalized.endsWith('.')) return null;
        return normalized;
    } catch (e) { console.error("BG: Error normalizing domain:", domain, e); return null; }
}
function normalizeEmail(email) {
    if (!email || typeof email !== 'string') return null;
    try {
        const trimmed = email.toLowerCase().trim();
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (emailRegex.test(trimmed)) return trimmed;
        return null;
    } catch(e) { console.error("BG: Error normalizing email:", email, e); return null; }
}

// --- Settings Loading ---
async function loadSettings() {
    try {
        const settings = await chrome.storage.sync.get(['apiUrl', 'cacheExpiryMinutes']);
        const storedApiUrl = settings.apiUrl && isValidUrl(settings.apiUrl) ? settings.apiUrl : DEFAULT_API_BASE_URL;
        currentApiBaseUrl = storedApiUrl.endsWith('/') ? storedApiUrl.slice(0, -1) : storedApiUrl; // Remove trailing slash if exists

        currentCacheExpiryMinutes = settings.cacheExpiryMinutes >= MIN_CACHE_EXPIRY && settings.cacheExpiryMinutes <= MAX_CACHE_EXPIRY
                                     ? settings.cacheExpiryMinutes : DEFAULT_CACHE_EXPIRY_MINUTES;
        console.log(`BG: Settings loaded. API: ${currentApiBaseUrl}, Cache Expiry: ${currentCacheExpiryMinutes} min`);
        await chrome.alarms.create(UPDATE_ALARM_NAME, { periodInMinutes: currentCacheExpiryMinutes });
        console.log(`BG: Update alarm (re)set for every ${currentCacheExpiryMinutes} minutes.`);
    } catch (error) {
        console.error("BG: Error loading settings, using defaults.", error);
        currentApiBaseUrl = DEFAULT_API_BASE_URL.endsWith('/') ? DEFAULT_API_BASE_URL.slice(0, -1) : DEFAULT_API_BASE_URL;
        currentCacheExpiryMinutes = DEFAULT_CACHE_EXPIRY_MINUTES;
        await chrome.alarms.create(UPDATE_ALARM_NAME, { periodInMinutes: currentCacheExpiryMinutes });
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
      return new Set(data);
    }
    return null;
  } catch (error) { console.error(`BG: Error reading cache for ${key}:`, error); return null; }
}

async function updateCache(type = 'domain') {
    const key = type === 'domain' ? 'phishingDomains' : 'phishingEmails';
    const listKey = type === 'domain' ? 'domains' : 'emails';
    const versionKey = `${key}Version`;
    console.log(`BG: Attempting to update ${key} cache...`);
    try {
        const currentVersion = (await chrome.storage.local.get([versionKey]))[versionKey] || 0;
        const fetchUrl = `<span class="math-inline">\{currentApiBaseUrl\}/blocklist?type\=</span>{type}&since=${currentVersion}`;
        const response = await fetch(fetchUrl); // Add auth headers if needed

        if (response.status === 304) {
            console.log(`BG: ${key} cache is up to date (304 Not Modified). Refreshing timestamp.`);
            await chrome.storage.local.set({ [`${key}Timestamp`]: Date.now() });
            return await getCachedData(key) || new Set(); // Return existing data but ensure timestamp is fresh
        }
        if (!response.ok) throw new Error(`API Error (${fetchUrl}): ${response.status} ${response.statusText}`);

        const data = await response.json();
        if (!data || typeof data !== 'object' || !Array.isArray(data[listKey])) {
           throw new Error(`Invalid API response structure for ${key} from ${fetchUrl}`);
        }

        const newList = data[listKey];
        const newVersion = data.version || Date.now();
        const normalizedList = newList.map(item => type === 'domain' ? normalizeDomain(item) : normalizeEmail(item)).filter(Boolean);
        const updatedSet = new Set(normalizedList);

        await chrome.storage.local.set({
           [key]: Array.from(updatedSet),
           [`${key}Timestamp`]: Date.now(),
           [versionKey]: newVersion
        });
        console.log(`BG: ${key} cache updated. Items: ${updatedSet.size}, Version: ${newVersion}`);
        return updatedSet;
    } catch (error) {
        console.error(`BG: Failed to update ${key} cache:`, error);
        return await getCachedData(key) || new Set(); // Return old cache on error
    }
}

// --- API Interaction ---
async function checkPhishingAPI(type, value) {
    const key = type === 'domain' ? 'phishingDomains' : 'phishingEmails';
    const normalizedValue = type === 'domain' ? normalizeDomain(value) : normalizeEmail(value);
    if (!normalizedValue) return { isPhishing: false, reason: "Giá trị không hợp lệ" };
    try {
        const cachedList = await getCachedData(key);
        if (cachedList?.has(normalizedValue)) return { isPhishing: true, reason: "Đã biết (từ cache)" };

        const checkUrl = `<span class="math-inline">\{currentApiBaseUrl\}/check?type\=</span>{type}&value=${encodeURIComponent(normalizedValue)}`;
        const response = await fetch(checkUrl); // Add auth headers if needed
        if (!response.ok) { console.warn(`BG: API check failed ${response.status}`); return { isPhishing: false, reason: "Lỗi API" }; }
        const result = await response.json();

        // Update cache if API confirms phishing and cache didn't know
        if (result.isPhishing && !(cachedList?.has(normalizedValue))) {
             console.log(`BG: API confirmed phishing, updating cache for ${normalizedValue}`);
             const currentSet = await getCachedData(key) || new Set();
             currentSet.add(normalizedValue);
             await chrome.storage.local.set({ [key]: Array.from(currentSet), [`${key}Timestamp`]: Date.now() });
        }
        return result;
    } catch (error) {
        console.error(`BG: Error checking <span class="math-inline">\{type\} '</span>{normalizedValue}' via API:`, error);
        const cachedList = await getCachedData(key); // Check cache again on network error
        if (cachedList?.has(normalizedValue)) return { isPhishing: true, reason: "Đã biết (từ cache - API lỗi)" };
        return { isPhishing: false, reason: "Lỗi kết nối API" };
    }
}

async function reportToAPI(type, value, context = "User report via extension") {
  const normalizedValue = type === 'domain' ? normalizeDomain(value) : (type === 'email' ? normalizeEmail(value) : (value || '').trim());
  if (!normalizedValue) {
     console.error(`BG: Invalid value for report: type=<span class="math-inline">\{type\}, value\=</span>{value}`);
     chrome.notifications.create({ type: 'basic', iconUrl: 'icons/icon-128.png', title: 'Báo cáo thất bại', message: `Dữ liệu không hợp lệ: ${value}` });
     return false;
  }
  try {
    const reportUrl = `${currentApiBaseUrl}/report`;
    const response = await fetch(reportUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' /* Add Auth? */ }, body: JSON.stringify({ type: type, value: normalizedValue, context: context }) });
    const result = await response.json();
    if (response.ok && result.success) {
      console.log(`BG: Report successful for ${type}: ${normalizedValue}`);
      chrome.notifications.create({ type: 'basic', iconUrl: 'icons/icon-128.png', title: 'Báo cáo thành công', message: `Cảm ơn bạn đã báo cáo ${type}: ${normalizedValue}` });
      // Add to local cache immediately if it's a phishing report
      if (type === 'domain' || type === 'email') {
          const key = type === 'domain' ? 'phishingDomains' : 'phishingEmails';
          const currentSet = await getCachedData(key) || new Set();
          if (!currentSet.has(normalizedValue)) {
              currentSet.add(normalizedValue);
              await chrome.storage.local.set({ [key]: Array.from(currentSet), [`${key}Timestamp`]: Date.now() });
              console.log(`BG: Added reported ${type} to local cache.`);
          }
      }
      return true;
    } else { throw new Error(result.message || 'Phản hồi API báo cáo không thành công.'); }
  } catch (error) {
    console.error(`BG: Lỗi khi gửi báo cáo <span class="math-inline">\{type\} '</span>{normalizedValue}':`, error);
    chrome.notifications.create({ type: 'basic', iconUrl: 'icons/icon-128.png', title: 'Báo cáo thất bại', message: `Không thể gửi báo cáo. Lỗi: ${error.message}` });
    return false;
  }
}

// --- Event Listeners ---
chrome.runtime.onInstalled.addListener(async (details) => {
  console.log("BG: onInstalled event, reason:", details.reason);
  await loadSettings(); // Load settings first
  console.log("BG: Initializing cache on install/update...");
  await updateCache('domain'); await updateCache('email'); // Populate cache
  setupContextMenus();
  console.log(`BG: Initialization complete. Update alarm set for ${currentCacheExpiryMinutes} min.`);
});

chrome.runtime.onStartup.addListener(async () => {
    console.log("BG: onStartup event.");
    await loadSettings(); // Load settings on browser start
    // Optional: Trigger an immediate update check on startup?
    // await updateCache('domain'); await updateCache('email');
});

chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === UPDATE_ALARM_NAME) {
    console.log("BG: Chạy cập nhật blocklist định kỳ...");
    await updateCache('domain'); await updateCache('email');
  }
});

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
   if (changeInfo.url && isValidUrl(changeInfo.url) && !changeInfo.url.startsWith('chrome://') && !changeInfo.url.startsWith('about:') && !changeInfo.url.startsWith(chrome.runtime.getURL(''))) {
      const url = changeInfo.url;
      try {
          const domain = normalizeDomain(new URL(url).hostname);
          if (!domain) return;
          const result = await checkPhishingAPI('domain', domain);
          if (result.isPhishing) {
              console.warn(`BG: Phát hiện trang lừa đảo [${result.reason}] - ${domain}`);
              const warningPageUrl = chrome.runtime.getURL('warning/warning.html');
               try {
                   const currentTab = await chrome.tabs.get(tabId);
                   // Only redirect if the tab hasn't already been redirected to our warning page
                   if (currentTab && currentTab.url && !currentTab.url.startsWith(warningPageUrl)) {
                       chrome.tabs.update(tabId, { url: `<span class="math-inline">\{warningPageUrl\}?url\=</span>{encodeURIComponent(url)}&domain=<span class="math-inline">\{encodeURIComponent\(domain\)\}&reason\=</span>{encodeURIComponent(result.reason || 'Đã biết')}` });
                   }
               } catch (tabError) {
                   // Handle cases where tab might be closed before update finishes
                   console.warn("BG: Error getting tab info before redirect:", tabError);
               }
          }
      } catch (error) { console.error(`BG: Lỗi khi quét URL ${url}:`, error); }
   }
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'checkDomain' || request.action === 'checkEmailSender') {
        const type = request.action === 'checkDomain' ? 'domain' : 'email';
        checkPhishingAPI(type, request.value)
          .then(sendResponse) // Directly send the result object
          .catch(error => sendResponse({ isPhishing: false, error: error.message, reason: "Lỗi xử lý" }));
        return true; // Async
    }
    else if (request.action === 'reportItem') {
        reportToAPI(request.type, request.value, request.context)
          .then(success => sendResponse({ success: success }))
          .catch(error => sendResponse({ success: false, message: error.message }));
        return true; // Async
    }
    else if (request.action === 'whitelistItem') { // Placeholder
         console.log(`BG: Whitelist request: type=<span class="math-inline">\{request\.type\}, value\=</span>{request.value}`);
         // TODO: Send request to backend API /api/whitelist (POST)
         sendResponse({ success: true, message: "Chức năng Whitelist đang phát triển (Backend)" });
         return true; // Async
     }
    else if (request.action === 'getApiStatus') {
        const healthUrl = `${currentApiBaseUrl}/health`;
        fetch(healthUrl)
          .then(response => sendResponse({ reachable: response.ok }))
          .catch(() => sendResponse({ reachable: false }));
        return true; // Async
    }
    else if (request.action === 'getCurrentTabInfo') {
        const queryOptions = { active: true, currentWindow: true };
        chrome.tabs.query(queryOptions, (tabs) => {
            if (chrome.runtime.lastError || !tabs || tabs.length === 0) { sendResponse({ url: null, domain: null, error: chrome.runtime.lastError?.message || "No active tab" }); return; }
            const tab = tabs[0];
            if (tab.url && isValidUrl(tab.url) && !tab.url.startsWith('chrome://') && !tab.url.startsWith('about:') && !tab.url.startsWith(chrome.runtime.getURL(''))) {
                try { sendResponse({ url: tab.url, domain: normalizeDomain(new URL(tab.url).hostname) }); }
                catch (e) { sendResponse({ url: tab.url, domain: null, error: "Invalid hostname" }); }
            } else { sendResponse({ url: null, domain: null, error: "No valid URL" }); }
        });
        return true; // Async
    }
     else if (request.action === 'settingsUpdated') {
         console.log("BG: Settings updated message received. Reloading...");
         loadSettings(); // Reload settings and reschedule alarm
         sendResponse({success: true});
         return false; // Sync response OK here
     }

    console.log("BG: Received unhandled message", request);
    return false; // Sync response or unhandled
});

// --- Context Menu Setup & Handling ---
function setupContextMenus() {
    chrome.contextMenus.removeAll(() => {
        chrome.contextMenus.create({ id: "reportPhishingLink", title: "VN Guard: Báo cáo liên kết lừa đảo", contexts: ["link"] });
        chrome.contextMenus.create({ id: "reportPhishingSelection", title: "VN Guard: Báo cáo email/nội dung đáng ngờ", contexts: ["selection"] });
        chrome.contextMenus.create({ id: "reportPhishingPage", title: "VN Guard: Báo cáo trang này là lừa đảo", contexts: ["page"] });
        console.log("BG: Context menus created/updated.");
    });
}

chrome.contextMenus.onClicked.addListener((info) => {
    if (info.menuItemId === "reportPhishingLink" && info.linkUrl) {
         if (!isValidUrl(info.linkUrl)) return;
        try {
            const domain = normalizeDomain(new URL(info.linkUrl).hostname);
            if (domain) reportToAPI('domain', domain, `Reported link: ${info.linkUrl}`);
            else reportToAPI('url', info.linkUrl, 'Reported link (no domain)');
        } catch (e) { reportToAPI('url', info.linkUrl, `Reported link (error: ${e.message})`); }
    } else if (info.menuItemId === "reportPhishingSelection" && info.selectionText) {
        const selection = info.selectionText.trim();
        const potentialEmail = normalizeEmail(selection);
        if (potentialEmail) reportToAPI('email', potentialEmail, 'Reported selected email');
        else reportToAPI('text_selection', selection, `Reported text from: ${info.pageUrl}`); // Report as text
    } else if (info.menuItemId === "reportPhishingPage" && info.pageUrl) {
         if (!isValidUrl(info.pageUrl) || info.pageUrl.startsWith('chrome://') || info.pageUrl.startsWith('about:') || info.pageUrl.startsWith(chrome.runtime.getURL(''))) return;
         try {
             const domain = normalizeDomain(new URL(info.pageUrl).hostname);
             if(domain) reportToAPI('domain', domain, `Reported page: ${info.pageUrl}`);
             else reportToAPI('url', info.pageUrl, 'Reported page (no domain)');
         } catch (e) { reportToAPI('url', info.pageUrl, `Reported page (error: ${e.message})`); }
    }
});

console.log("VN Phishing Guard Pro Background Script Loaded (v2.1)");
// Load initial settings when the script first loads
loadSettings();