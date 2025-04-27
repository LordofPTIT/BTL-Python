// --- Configuration ---
const DEFAULT_API_BASE_URL = 'YOUR_ACTUAL_RENDER_API_URL/api'; // *** THAY THẾ URL API (bao gồm /api nếu cần) ***
const DEFAULT_CACHE_EXPIRY_MINUTES = 60;
const UPDATE_ALARM_NAME = 'updateBlocklistsAlarm';
const MIN_CACHE_EXPIRY = 5; const MAX_CACHE_EXPIRY = 1440;

let currentApiBaseUrl = DEFAULT_API_BASE_URL;
let currentCacheExpiryMinutes = DEFAULT_CACHE_EXPIRY_MINUTES;

// --- Utility Functions ---
function isValidUrl(string) { try { const url = new URL(string); return url.protocol === "http:" || url.protocol === "https:"; } catch (_) { return false; } }
function normalizeDomain(domain) { /* ... Giữ nguyên hàm chuẩn hóa domain ... */
    if (!domain || typeof domain !== 'string') return null;
    try {
        let normalized = domain.toLowerCase().trim();
        if (normalized.startsWith('www.')) normalized = normalized.substring(4);
        if (normalized.length === 0 || !/^[a-z0-9.-]+$/.test(normalized) || !normalized.includes('.') || normalized.startsWith('.') || normalized.endsWith('.')) return null;
        // Loại bỏ các domain quá ngắn hoặc chỉ có TLD (ví dụ: ".com")
        if (normalized.split('.').length < 2 || normalized.split('.').pop().length < 2) return null;
        return normalized;
    } catch (e) { console.error("BG: Error normalizing domain:", domain, e); return null; }
}
function normalizeEmail(email) { /* ... Giữ nguyên hàm chuẩn hóa email ... */
    if (!email || typeof email !== 'string') return null;
    try {
        const trimmed = email.toLowerCase().trim();
        // Regex chặt chẽ hơn, không cho phép các trường hợp như "a@b.c"
        const emailRegex = /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;
        if (emailRegex.test(trimmed)) return trimmed;
        return null;
    } catch(e) { console.error("BG: Error normalizing email:", email, e); return null; }
}

// --- Settings & Caching (Giữ nguyên logic loadSettings, getCachedData, updateCache, getBlocklist) ---
async function loadSettings() { /* ... Giữ nguyên ... */
    try {
        const settings = await chrome.storage.sync.get(['apiUrl', 'cacheExpiryMinutes']);
        const storedApiUrl = settings.apiUrl && isValidUrl(settings.apiUrl) ? settings.apiUrl : DEFAULT_API_BASE_URL;
        currentApiBaseUrl = storedApiUrl.endsWith('/') ? storedApiUrl.slice(0, -1) : storedApiUrl;
        currentCacheExpiryMinutes = settings.cacheExpiryMinutes >= MIN_CACHE_EXPIRY && settings.cacheExpiryMinutes <= MAX_CACHE_EXPIRY
                                        ? settings.cacheExpiryMinutes : DEFAULT_CACHE_EXPIRY_MINUTES;
        console.log(`BG: Settings loaded. API: ${currentApiBaseUrl}, Cache Expiry: ${currentCacheExpiryMinutes} min`);
        // Ensure alarm exists and has the correct period
        const currentAlarm = await chrome.alarms.get(UPDATE_ALARM_NAME);
        if (!currentAlarm || currentAlarm.periodInMinutes !== currentCacheExpiryMinutes) {
             await chrome.alarms.create(UPDATE_ALARM_NAME, { periodInMinutes: currentCacheExpiryMinutes });
             console.log(`BG: Update alarm created/updated for every ${currentCacheExpiryMinutes} minutes.`);
        } else {
             console.log(`BG: Update alarm already set correctly.`);
        }
    } catch (error) {
        console.error("BG: Error loading settings, using defaults.", error);
        currentApiBaseUrl = DEFAULT_API_BASE_URL.endsWith('/') ? DEFAULT_API_BASE_URL.slice(0, -1) : DEFAULT_API_BASE_URL;
        currentCacheExpiryMinutes = DEFAULT_CACHE_EXPIRY_MINUTES;
        await chrome.alarms.create(UPDATE_ALARM_NAME, { periodInMinutes: currentCacheExpiryMinutes });
    }
}
async function getCachedData(key) { /* ... Giữ nguyên ... */
    try {
        const result = await chrome.storage.local.get([key, `${key}Timestamp`]);
        const data = result[key]; const timestamp = result[`${key}Timestamp`]; const now = Date.now();
        if (data && timestamp && (now - timestamp < currentCacheExpiryMinutes * 60 * 1000)) return new Set(data);
        return null;
      } catch (error) { console.error(`BG: Error reading cache for ${key}:`, error); return null; }
}
async function updateCache(type = 'domain') { /* ... Giữ nguyên ... */
    const key = type === 'domain' ? 'phishingDomains' : 'phishingEmails'; const listKey = type === 'domain' ? 'domains' : 'emails'; const versionKey = `${key}Version`;
    console.log(`BG: Attempting to update ${key} cache...`);
    try {
        const currentVersion = (await chrome.storage.local.get([versionKey]))[versionKey] || 0;
        const fetchUrl = `${currentApiBaseUrl}/blocklist?type=${type}&since=${currentVersion}`;
        const response = await fetch(fetchUrl);
        if (response.status === 304) { console.log(`BG: ${key} cache up to date (304). Refreshing timestamp.`); await chrome.storage.local.set({ [`${key}Timestamp`]: Date.now() }); return await getCachedData(key) || new Set(); }
        if (!response.ok) throw new Error(`API Error (${fetchUrl}): ${response.status} ${response.statusText}`);
        const data = await response.json();
        if (!data || typeof data !== 'object' || !Array.isArray(data[listKey])) throw new Error(`Invalid API response for ${key}`);
        const newList = data[listKey]; const newVersion = data.version || Date.now();
        const normalizedList = newList.map(item => type === 'domain' ? normalizeDomain(item) : normalizeEmail(item)).filter(Boolean);
        const updatedSet = new Set(normalizedList);
        await chrome.storage.local.set({ [key]: Array.from(updatedSet), [`${key}Timestamp`]: Date.now(), [versionKey]: newVersion });
        console.log(`BG: ${key} cache updated. Items: ${updatedSet.size}, Version: ${newVersion}`);
        return updatedSet;
    } catch (error) { console.error(`BG: Failed to update ${key} cache:`, error); return await getCachedData(key) || new Set(); }
}

// --- API Interaction (Giữ nguyên checkPhishingAPI, reportToAPI) ---
async function checkPhishingAPI(type, value) { /* ... Giữ nguyên ... */
    const key = type === 'domain' ? 'phishingDomains' : 'phishingEmails';
    const normalizedValue = type === 'domain' ? normalizeDomain(value) : normalizeEmail(value);
    if (!normalizedValue) return { isPhishing: false, reason: "Giá trị không hợp lệ" };
    try {
        const cachedList = await getCachedData(key);
        if (cachedList?.has(normalizedValue)) return { isPhishing: true, reason: "Đã biết (từ cache)" };
        const checkUrl = `${currentApiBaseUrl}/check?type=${type}&value=${encodeURIComponent(normalizedValue)}`;
        const response = await fetch(checkUrl);
        if (!response.ok) { console.warn(`BG: API check failed ${response.status}`); return { isPhishing: false, reason: "Lỗi API" }; }
        const result = await response.json();
        if (result.isPhishing && !(cachedList?.has(normalizedValue))) {
             const currentSet = await getCachedData(key) || new Set(); currentSet.add(normalizedValue);
             await chrome.storage.local.set({ [key]: Array.from(currentSet), [`${key}Timestamp`]: Date.now() });
        }
        return result;
    } catch (error) {
        console.error(`BG: Error checking API ${type} '${normalizedValue}':`, error);
        const cachedList = await getCachedData(key);
        if (cachedList?.has(normalizedValue)) return { isPhishing: true, reason: "Đã biết (từ cache - API lỗi)" };
        return { isPhishing: false, reason: "Lỗi kết nối API" };
    }
}
async function reportToAPI(type, value, context = "User report via extension") { /* ... Giữ nguyên ... */
    const normalizedValue = type === 'domain' ? normalizeDomain(value) : (type === 'email' ? normalizeEmail(value) : (value || '').trim());
      if (!normalizedValue) { console.error(`BG: Invalid value for report: type=${type}, value=${value}`); chrome.notifications.create({ type: 'basic', iconUrl: 'icons/icon-128.png', title: 'Báo cáo thất bại', message: `Dữ liệu không hợp lệ: ${value}` }); return false; }
      try {
        const reportUrl = `${currentApiBaseUrl}/report`;
        const response = await fetch(reportUrl, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ type: type, value: normalizedValue, context: context }) });
        const result = await response.json();
        if (response.ok && result.success) {
          console.log(`BG: Report successful for ${type}: ${normalizedValue}`);
          chrome.notifications.create({ type: 'basic', iconUrl: 'icons/icon-128.png', title: 'Báo cáo thành công', message: `Cảm ơn bạn đã báo cáo ${type}: ${normalizedValue}` });
          // Add to local cache immediately
          if (type === 'domain' || type === 'email') {
              const key = type === 'domain' ? 'phishingDomains' : 'phishingEmails';
              const currentSet = await getCachedData(key) || new Set();
              if (!currentSet.has(normalizedValue)) { currentSet.add(normalizedValue); await chrome.storage.local.set({ [key]: Array.from(currentSet), [`${key}Timestamp`]: Date.now() }); console.log(`BG: Added reported ${type} to local cache.`); }
          }
          return true;
        } else { throw new Error(result.message || 'API report failed.'); }
      } catch (error) { console.error(`BG: Lỗi khi gửi báo cáo ${type} '${normalizedValue}':`, error); chrome.notifications.create({ type: 'basic', iconUrl: 'icons/icon-128.png', title: 'Báo cáo thất bại', message: `Lỗi: ${error.message}` }); return false; }
}

// --- Event Listeners ---
chrome.runtime.onInstalled.addListener(async (details) => { /* ... Giữ nguyên ... */
    console.log("BG: onInstalled event, reason:", details.reason);
      await loadSettings(); // Load settings first
      console.log("BG: Initializing cache on install/update...");
      await updateCache('domain'); await updateCache('email'); // Populate cache
      setupContextMenus(); // Setup menus after install/update
      console.log(`BG: Initialization complete.`);
});
chrome.runtime.onStartup.addListener(loadSettings); // Load settings on browser start
chrome.alarms.onAlarm.addListener(async (alarm) => { /* ... Giữ nguyên ... */
    if (alarm.name === UPDATE_ALARM_NAME) { console.log("BG: Running scheduled blocklist update..."); await updateCache('domain'); await updateCache('email'); }
});

// Website Scanning (Kiểm tra URL hợp lệ kỹ hơn)
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    // Chỉ chạy khi URL thay đổi VÀ URL đó là http/https
   if (changeInfo.url && isValidUrl(changeInfo.url)) {
      const url = changeInfo.url;
      // Bỏ qua các trang nội bộ và trang cảnh báo của chính extension
      if (url.startsWith('chrome://') || url.startsWith('about:') || url.startsWith(chrome.runtime.getURL(''))) {
          return;
      }
      // console.log(`BG: Tab updated URL: ${url}`); // Debug
      try {
          const domain = normalizeDomain(new URL(url).hostname);
          if (!domain) return; // Bỏ qua nếu không lấy được domain hợp lệ

          const result = await checkPhishingAPI('domain', domain);

          if (result.isPhishing) {
              console.warn(`BG: PHISHING DETECTED [${result.reason}] - Domain: ${domain} - URL: ${url}`);
              const warningPageUrl = chrome.runtime.getURL('warning/warning.html');
               try {
                   // Lấy thông tin tab MỚI NHẤT trước khi chuyển hướng
                   const currentTab = await chrome.tabs.get(tabId);
                   // Chỉ chuyển hướng nếu tab hiện tại KHÔNG PHẢI là trang cảnh báo
                   if (currentTab && currentTab.url && !currentTab.url.startsWith(warningPageUrl)) {
                        console.log(`BG: Redirecting tab ${tabId} to warning page.`);
                        chrome.tabs.update(tabId, { url: `${warningPageUrl}?url=${encodeURIComponent(url)}&domain=${encodeURIComponent(domain)}&reason=${encodeURIComponent(result.reason || 'Đã biết')}` });
                   } else {
                        // console.log(`BG: Tab ${tabId} is already on warning page or invalid, skipping redirect.`);
                   }
               } catch (tabError) {
                   // Lỗi này có thể xảy ra nếu tab bị đóng rất nhanh sau khi update
                   console.warn("BG: Error getting tab info before redirect:", tabError.message);
               }
          }
      } catch (error) { console.error(`BG: Lỗi khi quét URL ${url}:`, error); }
   }
});

// Message Handling (Giữ nguyên các handler khác, thêm settingsUpdated)
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    // ... (Giữ nguyên các handler checkDomain, checkEmailSender, reportItem, whitelistItem, getApiStatus, getCurrentTabInfo) ...
    if (request.action === 'checkDomain' || request.action === 'checkEmailSender') { const type = request.action === 'checkDomain' ? 'domain' : 'email'; checkPhishingAPI(type, request.value).then(sendResponse).catch(error => sendResponse({ isPhishing: false, error: error.message, reason: "Lỗi xử lý" })); return true; }
    else if (request.action === 'reportItem') { reportToAPI(request.type, request.value, request.context).then(success => sendResponse({ success: success })).catch(error => sendResponse({ success: false, message: error.message })); return true; }
    else if (request.action === 'whitelistItem') { console.log(`BG: Whitelist request: type=${request.type}, value=${request.value}`); sendResponse({ success: true, message: "Chức năng Whitelist đang phát triển (Backend)" }); return true; }
    else if (request.action === 'getApiStatus') { const healthUrl = `${currentApiBaseUrl}/health`; fetch(healthUrl).then(response => sendResponse({ reachable: response.ok })).catch(() => sendResponse({ reachable: false })); return true; }
    else if (request.action === 'getCurrentTabInfo') { const queryOptions = { active: true, currentWindow: true }; chrome.tabs.query(queryOptions, (tabs) => { if (chrome.runtime.lastError || !tabs || tabs.length === 0) { sendResponse({ url: null, domain: null, error: chrome.runtime.lastError?.message || "No active tab" }); return; } const tab = tabs[0]; if (tab.url && isValidUrl(tab.url) && !tab.url.startsWith('chrome://') && !tab.url.startsWith('about:') && !tab.url.startsWith(chrome.runtime.getURL(''))) { try { sendResponse({ url: tab.url, domain: normalizeDomain(new URL(tab.url).hostname) }); } catch (e) { sendResponse({ url: tab.url, domain: null, error: "Invalid hostname" }); } } else { sendResponse({ url: null, domain: null, error: "No valid URL" }); } }); return true; }

    else if (request.action === 'settingsUpdated') { // Handler mới
         console.log("BG: Settings updated message received. Reloading settings...");
         loadSettings(); // Tải lại cài đặt và đặt lại alarm
         sendResponse({success: true});
         return false; // Không cần phản hồi bất đồng bộ
     }
    console.log("BG: Received unhandled message", request);
    return false; // Quan trọng: trả về false nếu không xử lý bất đồng bộ
});

// --- Context Menu ---
function setupContextMenus() {
    chrome.contextMenus.removeAll(() => { // Xóa menu cũ trước khi tạo mới
        chrome.contextMenus.create({ id: "reportPhishingLink", title: "VN Guard: Báo cáo liên kết lừa đảo này", contexts: ["link"] });
        chrome.contextMenus.create({ id: "reportPhishingSelection", title: "VN Guard: Báo cáo domain/email đã chọn", contexts: ["selection"] }); // Sửa title rõ hơn
        chrome.contextMenus.create({ id: "reportPhishingPage", title: "VN Guard: Báo cáo trang này là lừa đảo", contexts: ["page"] });
        console.log("BG: Context menus created/updated.");
    });
}

chrome.contextMenus.onClicked.addListener((info, tab) => {
    console.log("Context menu clicked:", info.menuItemId); // Debug

    if (info.menuItemId === "reportPhishingLink") {
        if (info.linkUrl && isValidUrl(info.linkUrl)) {
            try {
                const domain = normalizeDomain(new URL(info.linkUrl).hostname);
                if (domain) reportToAPI('domain', domain, `Reported link: ${info.linkUrl}`);
                else reportToAPI('url', info.linkUrl, 'Reported link (no domain)'); // Báo cáo cả URL nếu không lấy được domain
            } catch (e) { reportToAPI('url', info.linkUrl, `Reported link (error: ${e.message})`); }
        } else { console.warn("BG: Invalid or missing linkUrl for reportPhishingLink", info.linkUrl); }

    } else if (info.menuItemId === "reportPhishingSelection") {
        const selection = (info.selectionText || '').trim();
        if (selection) {
            console.log("Selected text:", selection); // Debug
            // Ưu tiên kiểm tra xem có phải là email không
            const potentialEmail = normalizeEmail(selection);
            if (potentialEmail) {
                console.log("Reporting as email:", potentialEmail);
                reportToAPI('email', potentialEmail, `Reported selected text as email from: ${info.pageUrl}`);
            } else {
                // Nếu không phải email, kiểm tra xem có phải là domain không
                const potentialDomain = normalizeDomain(selection);
                if (potentialDomain) {
                     console.log("Reporting as domain:", potentialDomain);
                    reportToAPI('domain', potentialDomain, `Reported selected text as domain from: ${info.pageUrl}`);
                } else {
                    // Nếu không phải cả hai, có thể báo cáo là text (nếu backend hỗ trợ)
                    console.log("Selection is not a valid email or domain, reporting as text:", selection);
                    reportToAPI('text_selection', selection, `Reported selected text from: ${info.pageUrl}`);
                     // Hoặc thông báo cho người dùng
                     // chrome.notifications.create({ type: 'basic', iconUrl: 'icons/icon-128.png', title: 'Không thể báo cáo', message: 'Văn bản bạn chọn không phải là domain hoặc email hợp lệ.' });
                }
            }
        } else { console.warn("BG: Empty selection for reportPhishingSelection"); }

    } else if (info.menuItemId === "reportPhishingPage") {
         if (info.pageUrl && isValidUrl(info.pageUrl) && !info.pageUrl.startsWith('chrome://') && !info.pageUrl.startsWith('about:') && !info.pageUrl.startsWith(chrome.runtime.getURL(''))) {
             try {
                 const domain = normalizeDomain(new URL(info.pageUrl).hostname);
                 if(domain) reportToAPI('domain', domain, `Reported page: ${info.pageUrl}`);
                 else reportToAPI('url', info.pageUrl, 'Reported page (no domain)');
             } catch (e) { reportToAPI('url', info.pageUrl, `Reported page (error: ${e.message})`); }
         } else { console.warn("BG: Invalid or missing pageUrl for reportPhishingPage", info.pageUrl); }
    }
});

// --- Initialize ---
console.log("VN Phishing Guard Pro Background Script Initializing (v2.2)...");
loadSettings(); // Load settings on initial load