'use strict';


const DEFAULT_API_BASE_URL = 'https://btl-python.onrender.com/api';
const DEFAULT_CACHE_EXPIRY_MINUTES = 60;
const UPDATE_ALARM_NAME = 'updateBlocklistsAlarm';
const MIN_CACHE_EXPIRY = 5;
const MAX_CACHE_EXPIRY = 1440;


let currentApiBaseUrl = DEFAULT_API_BASE_URL;
let currentCacheExpiryMinutes = DEFAULT_CACHE_EXPIRY_MINUTES;
let phishingDomainsCache = new Set();
let phishingEmailsCache = new Set();
let cacheTimestampDomains = 0;
let cacheTimestampEmails = 0;



function isValidUrl(string) {
    if (!string) return false;
    try {
        const url = new URL(string);

        return ['http:', 'https:'].includes(url.protocol);
    } catch (_) {
        return false;
    }
}


function normalizeDomain(domain) {
    if (!domain || typeof domain !== 'string') return null;
    try {
        let normalized = domain.toLowerCase().trim();

        if (normalized.startsWith('http://')) normalized = normalized.substring(7);
        if (normalized.startsWith('https://')) normalized = normalized.substring(8);
        // Remove trailing slash and path if present
        normalized = normalized.split('/')[0];
        // Remove www. prefix
        if (normalized.startsWith('www.')) normalized = normalized.substring(4);
        // Basic validation
        if (normalized.length === 0 ||
            !/^[a-z0-9.-]+$/.test(normalized) ||
            !normalized.includes('.') ||
            normalized.startsWith('.') || normalized.endsWith('.') ||
            normalized.startsWith('-') || normalized.endsWith('-') ||
            normalized.includes('..') || normalized.includes('--'))
        {
            return null;
        }

        const parts = normalized.split('.');
        if (parts.length < 2 || parts[parts.length - 1].length < 2) {
            return null;
        }
        return normalized;
    } catch (e) {
        console.error(`BG: Error normalizing domain "${domain}":`, e);
        return null;
    }
}



function normalizeEmail(email) {
    if (!email || typeof email !== 'string') return null;
    try {
        const trimmed = email.toLowerCase().trim();

        const emailRegex = /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i;
        return emailRegex.test(trimmed) ? trimmed : null;
    } catch (e) {
        console.error(`BG: Error normalizing email "${email}":`, e);
        return null;
    }
}


function extractAndNormalizeDomain(text) {
    if (!text || typeof text !== 'string') return null;

    const domainPattern = /(?:https?:\/\/)?([a-z0-9\u00A1-\uFFFF][a-z0-9\u00A1-\uFFFF.-]*\.[a-z\u00A1-\uFFFF]{2,})/gi;
    let match;
    while ((match = domainPattern.exec(text)) !== null) {
        const potentialDomain = normalizeDomain(match[1]);
        if (potentialDomain) {
            return potentialDomain;
        }
    }

    const fallbackDomain = normalizeDomain(text);
    if (fallbackDomain) {
        return fallbackDomain;
    }
    return null;
}




async function loadSettings() {
    console.log("BG: Loading settings...");
    try {

        const settings = await chrome.storage.sync.get({
            apiUrl: DEFAULT_API_BASE_URL,
            cacheExpiryMinutes: DEFAULT_CACHE_EXPIRY_MINUTES
        });


        const rawApiUrl = settings.apiUrl || DEFAULT_API_BASE_URL;
        currentApiBaseUrl = isValidUrl(rawApiUrl) ? rawApiUrl.replace(/\/$/, '') : DEFAULT_API_BASE_URL.replace(/\/$/, '');


        const rawExpiry = parseInt(settings.cacheExpiryMinutes, 10);
        currentCacheExpiryMinutes = (isNaN(rawExpiry) || rawExpiry < MIN_CACHE_EXPIRY || rawExpiry > MAX_CACHE_EXPIRY)
            ? DEFAULT_CACHE_EXPIRY_MINUTES
            : rawExpiry;

        console.log(`BG: Settings loaded. API: ${currentApiBaseUrl}, Cache Expiry: ${currentCacheExpiryMinutes} min`);


        await setupUpdateAlarm();

    } catch (error) {
        console.error("BG: CRITICAL - Error loading settings from chrome.storage.sync.", error);

        currentApiBaseUrl = DEFAULT_API_BASE_URL.replace(/\/$/, '');
        currentCacheExpiryMinutes = DEFAULT_CACHE_EXPIRY_MINUTES;
        console.warn("BG: Falling back to default settings due to error.");

        await setupUpdateAlarm();
    }
}

async function setupUpdateAlarm() {
    try {
        const currentAlarm = await chrome.alarms.get(UPDATE_ALARM_NAME);

        if (!currentAlarm || currentAlarm.periodInMinutes !== currentCacheExpiryMinutes) {
            await chrome.alarms.create(UPDATE_ALARM_NAME, {
                delayInMinutes: 1,
                periodInMinutes: currentCacheExpiryMinutes
            });
            console.log(`BG: Cache update alarm created/updated. Period: ${currentCacheExpiryMinutes} min.`);
        }
    } catch (error) {
        console.error("BG: Failed to create/update cache update alarm.", error);
    }
}


async function getValidCachedData(type) {
    const key = type === 'domain' ? 'phishingDomains' : 'phishingEmails';
    const timestampKey = `${key}Timestamp`;
    const globalCache = type === 'domain' ? phishingDomainsCache : phishingEmailsCache;
    const globalTimestamp = type === 'domain' ? cacheTimestampDomains : cacheTimestampEmails;
    const now = Date.now();

    // 1. Check in-memory cache first
    if (globalCache.size > 0 && globalTimestamp && (now - globalTimestamp < currentCacheExpiryMinutes * 60 * 1000)) {

        return globalCache;
    }

    // 2. If memory cache invalid/empty, check local storage
    try {
        const result = await chrome.storage.local.get([key, timestampKey]);
        if (chrome.runtime.lastError) {
            console.error(`BG: Error reading local storage for ${key}:`, chrome.runtime.lastError.message);
            return null;
        }

        const data = result[key];
        const timestamp = result[timestampKey];

        if (data && Array.isArray(data) && timestamp && (now - timestamp < currentCacheExpiryMinutes * 60 * 1000)) {
            console.log(`BG: Cache hit in local storage for ${type}`);
            const loadedSet = new Set(data);

            if (type === 'domain') {
                phishingDomainsCache = loadedSet;
                cacheTimestampDomains = timestamp;
            } else {
                phishingEmailsCache = loadedSet;
                cacheTimestampEmails = timestamp;
            }
            return loadedSet;
        } else {
            console.log(`BG: Cache miss or expired for ${type} in local storage.`);
            return null;
        }
    } catch (error) {
        console.error(`BG: Exception reading cache for ${key}:`, error);
        return null;
    }
}


async function updateCacheFromAPI(type = 'domain') {
    const key = type === 'domain' ? 'phishingDomains' : 'phishingEmails';
    const listKey = type === 'domain' ? 'domains' : 'emails';
    const versionKey = `${key}Version`;
    const timestampKey = `${key}Timestamp`;

    console.log(`BG: Starting update for ${key} cache...`);

    try {

        const storedData = await chrome.storage.local.get([versionKey]);
        if (chrome.runtime.lastError) {
             console.warn(`BG: Error getting cache version for ${key}:`, chrome.runtime.lastError.message);
        }
        const currentVersion = storedData[versionKey] || 0;

        const fetchUrl = `${currentApiBaseUrl}/blocklist?type=${type}&since=${currentVersion}`;
        console.log(`BG: Fetching cache update from: ${fetchUrl}`);

        const response = await fetch(fetchUrl, {
             method: 'GET',
             headers: { 'Accept': 'application/json' }

        });


        if (response.status === 304) {
            console.log(`BG: ${key} cache is up to date (API returned 304 Not Modified).`);

            const now = Date.now();
            await chrome.storage.local.set({ [timestampKey]: now });
             if (type === 'domain') cacheTimestampDomains = now; else cacheTimestampEmails = now;

            return (type === 'domain' ? phishingDomainsCache : phishingEmailsCache) || new Set();
        }

        if (!response.ok) {

            throw new Error(`API Error ${response.status} - ${response.statusText}. URL: ${fetchUrl}`);
        }

        const data = await response.json();


        if (!data || typeof data !== 'object' || !Array.isArray(data[listKey])) {
            throw new Error(`Invalid API response structure for ${key}. Expected '{ "${listKey}": [], "version": ... }'`);
        }

        const newList = data[listKey];
        const newVersion = data.version || Date.now();


        const normalizedList = newList
            .map(item => (type === 'domain' ? normalizeDomain(item) : normalizeEmail(item)))
            .filter(Boolean);

        const updatedSet = new Set(normalizedList);
        const now = Date.now();


        await chrome.storage.local.set({
            [key]: Array.from(updatedSet),
            [timestampKey]: now,
            [versionKey]: newVersion
        });
         if (chrome.runtime.lastError) {
             console.error(`BG: Error saving updated cache for ${key}:`, chrome.runtime.lastError.message);

             throw new Error(`Failed to save updated ${key} cache to local storage.`);
         } else {

             if (type === 'domain') {
                 phishingDomainsCache = updatedSet;
                 cacheTimestampDomains = now;
             } else {
                 phishingEmailsCache = updatedSet;
                 cacheTimestampEmails = now;
             }
             console.log(`BG: ${key} cache updated successfully. Items: ${updatedSet.size}, New Version: ${newVersion}`);
         }

        return updatedSet;

    } catch (error) {
        console.error(`BG: CRITICAL - Failed to update ${key} cache from API. Error:`, error);

        const existingCache = await getValidCachedData(type);
        console.warn(`BG: Returning potentially outdated ${key} cache due to update failure.`);
        return existingCache || new Set();
    }
}


async function checkPhishing(type, value) {
    const key = type === 'domain' ? 'phishingDomains' : 'phishingEmails';
    const normalizedValue = type === 'domain' ? normalizeDomain(value) : normalizeEmail(value);

    if (!normalizedValue) {
        console.warn(`BG: Invalid ${type} value provided for checking: "${value}"`);
        return { isPhishing: false, reason: "Giá trị không hợp lệ", source: 'invalid' };
    }

    // 1. Check valid cache (memory or local storage)
    const cachedList = await getValidCachedData(type);
    if (cachedList && cachedList.has(normalizedValue)) {

        return { isPhishing: true, reason: "Đã biết (cache)", source: 'cache' };
    }

    // 2. If not in cache or cache expired, query the API
    console.log(`BG: Cache miss for ${type}: ${normalizedValue}. Querying API...`);
    const checkUrl = `${currentApiBaseUrl}/check?type=${type}&value=${encodeURIComponent(normalizedValue)}`;

    try {
        const response = await fetch(checkUrl, {
             method: 'GET',
             headers: { 'Accept': 'application/json' }

        });

        if (!response.ok) {

             console.warn(`BG: API check for ${type} ${normalizedValue} failed with status ${response.status}. URL: ${checkUrl}`);
             const potentiallyOutdatedCache = type === 'domain' ? phishingDomainsCache : phishingEmailsCache;
             if (potentiallyOutdatedCache.has(normalizedValue)) {
                 console.warn(`BG: Reporting as phishing based on potentially outdated cache for ${normalizedValue} after API error.`);
                 return { isPhishing: true, reason: "Đã biết (cache - API lỗi)", source: 'cache' };
             }

            return { isPhishing: false, reason: `Lỗi API ${response.status}`, source: 'error' };
        }

        const result = await response.json();


        if (typeof result?.isPhishing !== 'boolean') {
             console.error(`BG: Invalid API response structure for check ${type} ${normalizedValue}. Got:`, result);
             return { isPhishing: false, reason: "Phản hồi API không hợp lệ", source: 'error' };
        }

        console.log(`BG: API check result for ${type} ${normalizedValue}: isPhishing=${result.isPhishing}`);


        if (result.isPhishing && (!cachedList || !cachedList.has(normalizedValue))) {
            console.log(`BG: Adding API-confirmed phishing ${type} ${normalizedValue} to immediate in-memory cache.`);
            const immediateCache = type === 'domain' ? phishingDomainsCache : phishingEmailsCache;
            immediateCache.add(normalizedValue);

        }

        return {
             isPhishing: result.isPhishing,
             reason: result.reason || (result.isPhishing ? "Đã biết (API)" : "An toàn (API)"),
             source: 'api'
         };

    } catch (error) {

        console.error(`BG: CRITICAL - Exception during API check for ${type} '${normalizedValue}'. Error:`, error);

        const potentiallyOutdatedCache = type === 'domain' ? phishingDomainsCache : phishingEmailsCache;
        if (potentiallyOutdatedCache.has(normalizedValue)) {
             console.warn(`BG: Reporting as phishing based on potentially outdated cache for ${normalizedValue} after connection error.`);
             return { isPhishing: true, reason: "Đã biết (cache - API lỗi kết nối)", source: 'cache' };
        }
        return { isPhishing: false, reason: "Lỗi kết nối API", source: 'error' };
    }
}



async function reportToAPI(type, value, context = "User report via extension") {
    let normalizedValue;
    let blocklistType = null;
    let isFalsePositive = false;


    switch (type) {
        case 'domain':
        case 'false_positive_domain':
            normalizedValue = normalizeDomain(value);
            blocklistType = 'domain';
            isFalsePositive = type.includes('false_positive');
            break;
        case 'email':
        case 'false_positive_email':
            normalizedValue = normalizeEmail(value);
            blocklistType = 'email';
            isFalsePositive = type.includes('false_positive');
            break;
        case 'url':
            normalizedValue = (value || '').trim();

             const extractedDomain = extractAndNormalizeDomain(value);
             if (extractedDomain) context += ` (URL contains domain: ${extractedDomain})`;
            break;
        case 'text_selection':
            normalizedValue = (value || '').trim();
            break;
        default:
            console.error(`BG: Invalid report type: ${type}`);
            return false; // Invalid type
    }

    if (!normalizedValue) {
        console.error(`BG: Invalid or empty value provided for report type ${type}: "${value}"`);
        showNotification('Báo cáo thất bại', `Dữ liệu không hợp lệ cho loại báo cáo '${type}': ${value || '(trống)'}`);
        return false;
    }

    console.log(`BG: Attempting to report ${type}: ${normalizedValue}`);
    const reportUrl = `${currentApiBaseUrl}/report`;

    try {
        const response = await fetch(reportUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'

            },
            body: JSON.stringify({ type: type, value: normalizedValue, context: context })
        });


        let result = {};
        try {
             result = await response.json();
        } catch (jsonError) {
             console.warn(`BG: Could not parse JSON response for report ${type} ${normalizedValue} (Status: ${response.status}). Body:`, await response.text());

             throw new Error(`API report failed with status ${response.status} - ${response.statusText}. Unable to parse response body.`);
        }


        if (!response.ok) {

            throw new Error(result.message || `API report failed with status ${response.status}.`);
        }


        console.log(`BG: API report successful for ${type}: ${normalizedValue}. API Response:`, result);
        showNotification('Báo cáo thành công', `Cảm ơn bạn đã báo cáo ${type}: ${normalizedValue}`);


        if (blocklistType) {
            const cacheKey = blocklistType === 'domain' ? 'phishingDomains' : 'phishingEmails';
            const timestampKey = `${cacheKey}Timestamp`;
            const versionKey = `${cacheKey}Version`;
            const currentSet = await getValidCachedData(blocklistType) || new Set();
            let cacheNeedsUpdate = false;

            if (isFalsePositive) {

                if (currentSet.has(normalizedValue)) {
                    currentSet.delete(normalizedValue);
                    cacheNeedsUpdate = true;
                    console.log(`BG: Removed false positive ${blocklistType} '${normalizedValue}' from local cache.`);
                }
            } else {

                if (!currentSet.has(normalizedValue)) {
                    currentSet.add(normalizedValue);
                    cacheNeedsUpdate = true;
                    console.log(`BG: Added reported phishing ${blocklistType} '${normalizedValue}' to local cache for immediate blocking.`);
                }
            }

            if (cacheNeedsUpdate) {
                try {
                    const now = Date.now();

                    const versionData = await chrome.storage.local.get([versionKey]);
                    await chrome.storage.local.set({
                        [cacheKey]: Array.from(currentSet),
                        [timestampKey]: now,
                        [versionKey]: versionData[versionKey] || 0
                    });
                    if (chrome.runtime.lastError) {
                         console.error(`BG: Error saving updated cache after report for ${cacheKey}:`, chrome.runtime.lastError.message);
                    } else {

                         if (blocklistType === 'domain') {
                            phishingDomainsCache = currentSet;
                            cacheTimestampDomains = now;
                         } else {
                            phishingEmailsCache = currentSet;
                            cacheTimestampEmails = now;
                         }
                    }
                } catch (storageError) {
                    console.error(`BG: Exception saving updated cache after report for ${cacheKey}:`, storageError);
                }
            }
        }

        return true;

    } catch (error) {

        console.error(`BG: CRITICAL - Failed to send report for ${type} '${normalizedValue}'. Error:`, error);
        showNotification('Báo cáo thất bại', `Không thể gửi báo cáo tới máy chủ. Lỗi: ${error.message}`);
        return false; // Report failed
    }
}



chrome.runtime.onInstalled.addListener(async (details) => {
    console.log(`BG: Extension ${details.reason}. Version: ${chrome.runtime.getManifest().version}`);
    await loadSettings();
    console.log("BG: Initializing blocklist cache...");

    await updateCacheFromAPI('domain');
    await updateCacheFromAPI('email');
    setupContextMenus();
    console.log("BG: Initialization complete.");
});


chrome.runtime.onStartup.addListener(async () => {
    console.log("BG: Browser startup detected.");
    await loadSettings();

    console.log("BG: Triggering cache update on startup...");
    await updateCacheFromAPI('domain');
    await updateCacheFromAPI('email');
});


chrome.alarms.onAlarm.addListener(async (alarm) => {
    if (alarm.name === UPDATE_ALARM_NAME) {
        console.log(`BG: Received alarm "${alarm.name}". Running scheduled blocklist update...`);
        try {
             await updateCacheFromAPI('domain');
             await updateCacheFromAPI('email');
             console.log("BG: Scheduled blocklist update finished.");
        } catch (error) {

             console.error("BG: Error during scheduled update execution.", error);
        }
    }
});


chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {

    if (changeInfo.url && isValidUrl(changeInfo.url)) {
        const url = changeInfo.url;

        if (url.startsWith('chrome://') || url.startsWith('about:') || url.startsWith('moz-extension://') || url.startsWith(chrome.runtime.getURL(''))) {
            return;
        }

        console.log(`BG: URL changed in tab ${tabId}: ${url}`);
        let domainToCheck = null;
        try {
            domainToCheck = normalizeDomain(new URL(url).hostname);
        } catch (urlError) {
            console.warn(`BG: Could not parse domain from changed URL "${url}":`, urlError.message);
            return;
        }

        if (!domainToCheck) {
            console.warn(`BG: Could not normalize domain from changed URL "${url}"`);
            return;
        }


        const result = await checkPhishing('domain', domainToCheck);

        if (result.isPhishing) {
            console.warn(`BG: PHISHING DETECTED [${result.reason}, Source: ${result.source}] - Domain: ${domainToCheck} from URL: ${url}`);

            const warningPageUrlBase = chrome.runtime.getURL('warning/warning.html');
            const targetUrl = `${warningPageUrlBase}?url=${encodeURIComponent(url)}&domain=${encodeURIComponent(domainToCheck)}&reason=${encodeURIComponent(result.reason || 'Đã biết')}`;

            try {

                const currentTab = await chrome.tabs.get(tabId);
                 if (currentTab && currentTab.url && currentTab.url !== targetUrl && currentTab.url === url) {
                     console.log(`BG: Redirecting tab ${tabId} to warning page for ${domainToCheck}`);
                     await chrome.tabs.update(tabId, { url: targetUrl });
                 } else {
                      console.log(`BG: Tab ${tabId} navigation changed or already on warning page before redirection could complete. URL: ${currentTab?.url}`);
                 }
            } catch (tabError) {

                if (tabError.message.includes("No tab with id") || tabError.message.includes("Invalid tab ID")) {
                     console.warn(`BG: Tab ${tabId} closed before phishing redirection could occur for ${domainToCheck}.`);
                } else {
                    console.error(`BG: Error updating tab ${tabId} to warning page:`, tabError);
                }
            }
        }
    }
});



chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    console.log("BG: Received message:", request.action, "from:", sender.tab ? `Tab ${sender.tab.id}`: "Extension");

    if (!request || !request.action) {
        console.warn("BG: Received invalid message structure:", request);

        return false;
    }

    switch (request.action) {
        case 'checkDomain':
        case 'checkEmailSender': {
            const type = request.action === 'checkDomain' ? 'domain' : 'email';
            checkPhishing(type, request.value)
                .then(sendResponse)
                .catch(error => {
                    console.error(`BG: Error processing ${request.action}:`, error);

                    sendResponse({ isPhishing: false, error: error.message, reason: "Lỗi xử lý nội bộ", source: 'error' });
                });
            return true;
        }
        case 'reportItem': {
            reportToAPI(request.type, request.value, request.context)
                .then(success => sendResponse({ success: success }))
                .catch(error => {
                     console.error(`BG: Error processing ${request.action}:`, error);
                     sendResponse({ success: false, message: error.message });
                });
            return true;
        }
        case 'getApiStatus': {
            const healthUrl = `${currentApiBaseUrl}/health`;
            fetch(healthUrl, { method: 'GET', cache: 'no-cache' })
                .then(response => sendResponse({ reachable: response.ok, status: response.status }))
                .catch(error => {
                    console.warn(`BG: API health check failed: ${error.message}`);
                    sendResponse({ reachable: false, error: error.message });
                 });
            return true;
        }
         case 'getCurrentTabInfo': {
             const queryOptions = { active: true, currentWindow: true };
             chrome.tabs.query(queryOptions, (tabs) => {
                 if (chrome.runtime.lastError || !tabs || tabs.length === 0) {
                      console.warn("BG: Error getting current tab:", chrome.runtime.lastError?.message);
                      sendResponse({ url: null, domain: null, error: chrome.runtime.lastError?.message || "Không tìm thấy tab hoạt động" });
                      return;
                 }
                 const tab = tabs[0];
                 if (tab.url && isValidUrl(tab.url) && !tab.url.startsWith('chrome://') && !tab.url.startsWith('about:') && !tab.url.startsWith(chrome.runtime.getURL(''))) {
                     try {
                         const domain = normalizeDomain(new URL(tab.url).hostname);
                         sendResponse({ url: tab.url, domain: domain });
                     } catch (e) {
                          console.warn(`BG: Error parsing domain from tab URL ${tab.url}:`, e.message);
                          sendResponse({ url: tab.url, domain: null, error: "Tên miền không hợp lệ" });
                     }
                 } else {
                     sendResponse({ url: tab.url, domain: null, error: "URL không hợp lệ hoặc không được hỗ trợ" });
                 }
             });
             return true;
         }
        case 'settingsUpdated': {
            console.log("BG: Received settingsUpdated message. Reloading settings and rescheduling alarm...");
            loadSettings().then(() => {

                 sendResponse({ success: true });
            }).catch(error => {
                 console.error("BG: Error reloading settings after update message:", error);
                 sendResponse({ success: false, message: error.message });
            });
            return true;
        }

        default:
            console.warn("BG: Received unhandled message action:", request.action);
            return false;
    }
});



function setupContextMenus() {

    const contexts = ["link", "selection", "page"];
    const menuItems = [
        { id: "reportPhishingLink", title: "VN Guard: Báo cáo liên kết lừa đảo này", contexts: ["link"] },
        { id: "reportPhishingSelection", title: "VN Guard: Báo cáo domain/email đã chọn", contexts: ["selection"] },
        { id: "reportPhishingPage", title: "VN Guard: Báo cáo trang này là lừa đảo", contexts: ["page"] },
         // Add menus for reporting false positives
         { id: "reportFalsePositiveLink", title: "VN Guard: Báo cáo liên kết AN TOÀN (nhầm lẫn)", contexts: ["link"] },
         { id: "reportFalsePositiveSelection", title: "VN Guard: Báo cáo domain/email AN TOÀN (nhầm lẫn)", contexts: ["selection"] },
         { id: "reportFalsePositivePage", title: "VN Guard: Báo cáo trang AN TOÀN (nhầm lẫn)", contexts: ["page"] }
    ];

    menuItems.forEach(item => {
        chrome.contextMenus.create(item, () => {
             if (chrome.runtime.lastError) {

                 if (!chrome.runtime.lastError.message.includes("Duplicate")) {
                    console.error(`BG: Error creating context menu item "${item.id}":`, chrome.runtime.lastError.message);
                 }
             }
        });
    });
     console.log("BG: Context menus created/updated.");
}

chrome.contextMenus.onClicked.addListener((info, tab) => {
    console.log(`BG: Context menu clicked: ${info.menuItemId}`);

    switch (info.menuItemId) {
        case "reportPhishingLink":
        case "reportFalsePositiveLink": {
            const isFalsePositive = info.menuItemId.includes("FalsePositive");
            const reportType = isFalsePositive ? 'false_positive_domain' : 'domain';
            const contextPrefix = isFalsePositive ? "Reported SAFE link" : "Reported PHISHING link";
            if (info.linkUrl && isValidUrl(info.linkUrl)) {
                try {
                    const domain = normalizeDomain(new URL(info.linkUrl).hostname);
                    if (domain) {
                        reportToAPI(reportType, domain, `${contextPrefix}: ${info.linkUrl}`);
                    } else {

                        console.warn(`BG: Could not normalize domain from link ${info.linkUrl} for ${info.menuItemId}.`);

                    }
                } catch (e) {
                     console.error(`BG: Error processing ${info.menuItemId} for link ${info.linkUrl}:`, e);

                }
            } else {
                console.warn(`BG: Invalid or missing linkUrl for ${info.menuItemId}:`, info.linkUrl);
            }
            break;
        }
        case "reportPhishingSelection":
        case "reportFalsePositiveSelection": {
             const isFalsePositive = info.menuItemId.includes("FalsePositive");
             const contextPrefix = isFalsePositive ? "Reported SAFE selection" : "Reported PHISHING selection";
             const selection = (info.selectionText || '').trim();
             if (selection) {
                 // 1. Try as Email
                 const potentialEmail = normalizeEmail(selection);
                 if (potentialEmail) {
                      const reportType = isFalsePositive ? 'false_positive_email' : 'email';
                      reportToAPI(reportType, potentialEmail, `${contextPrefix} (as email) from: ${info.pageUrl}`);
                      break; // Done
                 }
                 // 2. Try as Domain
                 const potentialDomain = extractAndNormalizeDomain(selection);
                 if (potentialDomain) {
                     const reportType = isFalsePositive ? 'false_positive_domain' : 'domain';
                     reportToAPI(reportType, potentialDomain, `${contextPrefix} (as domain, extracted from: "${selection}") from: ${info.pageUrl}`);
                     break; // Done
                 }
                 // 3. Report as Text
                 if (!isFalsePositive) {
                     reportToAPI('text_selection', selection, `${contextPrefix} (as text) from: ${info.pageUrl}`);
                 } else {
                     console.log(`BG: Selection "${selection}" is not a valid email or domain, cannot report as false positive text.`);
                     showNotification("Không thể báo cáo", "Vui lòng chọn đúng địa chỉ email hoặc tên miền cần báo cáo là an toàn.");
                 }
             } else {
                 console.warn(`BG: Empty selection text for ${info.menuItemId}`);
             }
            break;
        }
        case "reportPhishingPage":
        case "reportFalsePositivePage": {
            const isFalsePositive = info.menuItemId.includes("FalsePositive");
            const reportType = isFalsePositive ? 'false_positive_domain' : 'domain';
            const contextPrefix = isFalsePositive ? "Reported SAFE page" : "Reported PHISHING page";

            if (info.pageUrl && isValidUrl(info.pageUrl) && !info.pageUrl.startsWith('chrome://') && !info.pageUrl.startsWith('about:') && !info.pageUrl.startsWith(chrome.runtime.getURL(''))) {
                 try {
                     const domain = normalizeDomain(new URL(info.pageUrl).hostname);
                     if(domain) {
                         reportToAPI(reportType, domain, `${contextPrefix}: ${info.pageUrl}`);
                     } else {
                         console.warn(`BG: Could not normalize domain from page URL ${info.pageUrl} for ${info.menuItemId}.`);

                     }
                 } catch (e) {
                      console.error(`BG: Error processing ${info.menuItemId} for page ${info.pageUrl}:`, e);

                 }
            } else {
                 console.warn(`BG: Invalid or non-reportable pageUrl for ${info.menuItemId}:`, info.pageUrl);
            }
            break;
        }
        default:
             console.warn(`BG: Unhandled context menu item ID: ${info.menuItemId}`);
    }
});


function showNotification(title, message) {
    try {
        chrome.notifications.create({
            type: 'basic',
            iconUrl: 'icons/icon-128.png',
            title: title || 'VN Phishing Guard Pro',
            message: message || '',
            priority: 1
        }, (notificationId) => {
             if (chrome.runtime.lastError) {
                 console.error("BG: Error showing notification:", chrome.runtime.lastError.message);
             }
        });
    } catch (e) {
         console.error("BG: Exception while trying to show notification:", e);
    }
}



console.log(`VN Phishing Guard Pro Background Script Initializing (v${chrome.runtime.getManifest().version})...`);
