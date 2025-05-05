const DEFAULT_API_BASE_URL = 'http://127.0.0.1:5001/api';
const DEFAULT_CACHE_UPDATE_INTERVAL_MINUTES = 60;
const MIN_CACHE_UPDATE_INTERVAL_MINUTES = 5;
const MAX_CACHE_UPDATE_INTERVAL_MINUTES = 1440;

const CACHE_EXPIRY_MS = DEFAULT_CACHE_UPDATE_INTERVAL_MINUTES * 60 * 1000 * 1.5;
const CACHE_KEYS = {
    PHISHING_DOMAINS: 'phishingDomainsCache',
    PHISHING_EMAILS: 'phishingEmailsCache',
    WHITELISTED_DOMAINS: 'whitelistedDomainsCache',
    WHITELISTED_EMAILS: 'whitelistedEmailsCache',
    API_BASE_URL: 'apiBaseUrl',
    CACHE_UPDATE_INTERVAL: 'cacheUpdateIntervalMinutes'
};
const ALARM_NAME = 'phishingUpdateAlarm';
const WARNING_PAGE_URL = chrome.runtime.getURL('warning/warning.html');


const SUSPICIOUS_EMAIL_KEYWORDS = [
    'xác minh tài khoản', 'verify your account', 'cập nhật thông tin', 'update your information',
    'mật khẩu', 'password', 'đăng nhập', 'login', 'locked', 'khóa', 'restricted', 'hạn chế',
    'ngân hàng', 'bank', 'thẻ tín dụng', 'credit card', 'số an sinh xã hội', 'ssn',
    'khẩn cấp', 'urgent', 'quan trọng', 'important', 'hành động ngay', 'action required',
    'truy cập bị hạn chế', 'access restricted', 'vấn đề bảo mật', 'security issue',
    'thừa kế', 'inheritance', 'trúng thưởng', 'prize', 'xổ số', 'lottery', 'miễn phí', 'free offer',
    'nhấp vào đây', 'click here', 'liên kết', 'link', 'tải xuống', 'download',
    'hóa đơn', 'invoice', 'thanh toán', 'payment due', 'refund', 'hoàn tiền',
    // Thêm các từ khóa hoặc cụm từ nhạy cảm khác
    'yêu cầu đăng nhập', 'login required', 'xác thực', 'authenticate', 'secure message',
    'tài khoản của bạn gặp rủi ro', 'your account is at risk'
];
const MIN_KEYWORD_MATCHES_FOR_WARNING = 2; // Require at least N keywords to trigger warning

// --- State ---
let currentApiBaseUrl = DEFAULT_API_BASE_URL;
let currentCacheUpdateIntervalMinutes = DEFAULT_CACHE_UPDATE_INTERVAL_MINUTES;
let memoryCache = {
    phishingDomains: new Set(),
    phishingEmails: new Set(),
    whitelistedDomains: new Set(),
    whitelistedEmails: new Set(),
    lastUpdated: { phishingDomains: 0, phishingEmails: 0, whitelistedDomains: 0, whitelistedEmails: 0 },
    version: { phishingDomains: null, phishingEmails: null, whitelistedDomains: null, whitelistedEmails: null }
};
// CHANGE: Store temporary allowances in session storage (cleared when browser closes)
const TEMP_ALLOW_SESSION_KEY = 'tempAllowedDomains';

// --- Initialization ---
async function initialize() {
    console.log("BG: Initializing Phishing Detector Extension (Local)...");
    try {
        await loadSettings();
        await loadInitialCache();
        setupAlarms();
        setupListeners();
        await clearExpiredTempAllows(); // Clear old allows on startup
        // Perform initial update shortly after startup
        setTimeout(updateAllCaches, 5000); // Update 5 seconds after launch
        console.log("BG: Initialization complete.");
    } catch (error) {
        console.error("BG: CRITICAL - Initialization failed:", error);
        // Consider disabling parts of the extension if init fails?
    }
}

async function loadSettings() {
    try {
        // Use sync storage for settings that should persist across devices if logged in
        const settings = await chrome.storage.sync.get([CACHE_KEYS.API_BASE_URL, CACHE_KEYS.CACHE_UPDATE_INTERVAL]);
        currentApiBaseUrl = settings[CACHE_KEYS.API_BASE_URL] || DEFAULT_API_BASE_URL;
        currentCacheUpdateIntervalMinutes = settings[CACHE_KEYS.CACHE_UPDATE_INTERVAL] || DEFAULT_CACHE_UPDATE_INTERVAL_MINUTES;
        console.log(`BG: Loaded settings - API URL: ${currentApiBaseUrl}, Update Interval: ${currentCacheUpdateIntervalMinutes} min`);
    } catch (error) {
        console.error("BG: Error loading settings from sync storage:", error);
        currentApiBaseUrl = DEFAULT_API_BASE_URL; // Fallback to defaults
        currentCacheUpdateIntervalMinutes = DEFAULT_CACHE_UPDATE_INTERVAL_MINUTES;
    }
}

async function loadInitialCache() {
    console.log("BG: Loading initial cache from local storage...");
    const loadPromises = Object.keys(memoryCache.version).map(async (memoryKey) => {
        const storageKey = CACHE_KEYS[memoryKey.replace(/([A-Z])/g, '_$1').toUpperCase()]; // e.g., phishingDomains -> PHISHING_DOMAINS
        if (!storageKey) return; // Skip if key mapping fails

        try {
            const result = await chrome.storage.local.get(storageKey);
            if (result && result[storageKey] && Array.isArray(result[storageKey].items)) { // Check if items is an array
                memoryCache[memoryKey] = new Set(result[storageKey].items);
                memoryCache.lastUpdated[memoryKey] = result[storageKey].timestamp || 0;
                memoryCache.version[memoryKey] = result[storageKey].version || null;
                console.log(`BG: Loaded ${memoryCache[memoryKey].size} items into ${memoryKey} (Version: ${memoryCache.version[memoryKey]}, Last updated: ${new Date(memoryCache.lastUpdated[memoryKey]).toLocaleString()})`);
            } else {
                console.log(`BG: No valid cache found in local storage for ${storageKey}. Initializing empty set.`);
                memoryCache[memoryKey] = new Set();
                memoryCache.lastUpdated[memoryKey] = 0;
                memoryCache.version[memoryKey] = null;
            }
        } catch (error) {
            console.error(`BG: Error loading cache for ${storageKey}:`, error);
            memoryCache[memoryKey] = new Set(); // Fallback to empty set on error
            memoryCache.lastUpdated[memoryKey] = 0;
            memoryCache.version[memoryKey] = null;
        }
    });
    await Promise.all(loadPromises);
    console.log("BG: Initial cache loading finished.");
}


function setupAlarms() {
    // Ensure interval is within bounds
    const interval = Math.max(MIN_CACHE_UPDATE_INTERVAL_MINUTES, Math.min(currentCacheUpdateIntervalMinutes, MAX_CACHE_UPDATE_INTERVAL_MINUTES));
    console.log(`BG: Setting up cache update alarm with interval: ${interval} minutes.`);

    // Use chrome.alarms.create directly - it replaces alarms with the same name
    chrome.alarms.create(ALARM_NAME, {
        // delayInMinutes: 1, // Delay first run slightly
        periodInMinutes: interval
    });
    console.log(`BG: Created/Updated cache update alarm '${ALARM_NAME}'.`);

    // Remove previous listener if any to avoid duplicates (defensive coding)
    if (chrome.alarms.onAlarm.hasListener(handleAlarm)) {
        chrome.alarms.onAlarm.removeListener(handleAlarm);
        console.log("BG: Removed existing alarm listener.");
    }
    // Add the listener
    chrome.alarms.onAlarm.addListener(handleAlarm);
    console.log("BG: Added alarm listener.");
}

function handleAlarm(alarm) {
    if (alarm.name === ALARM_NAME) {
        console.log(`BG: Alarm '${ALARM_NAME}' triggered. Updating caches...`);
        updateAllCaches().catch(error => {
            console.error("BG: Error during scheduled cache update:", error);
        });
    }
}


function setupListeners() {
    // --- Message Listener ---
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        console.log(`BG: Received message: Action=${message.action}`, message); // Log received messages

        switch (message.action) {
            case 'checkDomain':
                checkPhishing('domain', message.domain)
                    .then(sendResponse)
                    .catch(error => {
                        console.error(`BG: Error checking domain ${message.domain}:`, error);
                        sendResponse({ isPhishing: false, status: 'error', reason: 'Lỗi kiểm tra' });
                    });
                return true; // Indicates async response

            case 'checkEmail': // Original check for sender email only
                checkPhishing('email', message.email)
                    .then(sendResponse)
                    .catch(error => {
                        console.error(`BG: Error checking email ${message.email}:`, error);
                        sendResponse({ isPhishing: false, status: 'error', reason: 'Lỗi kiểm tra' });
                    });
                return true;

            // CHANGE: New action to handle both sender and content
            case 'checkEmailDetails':
                handleCheckEmailDetails(message.senderEmail, message.emailContent)
                    .then(sendResponse)
                    .catch(error => {
                       console.error(`BG: Error checking email details for ${message.senderEmail}:`, error);
                       sendResponse({ isPhishing: false, status: 'error', reason: 'Lỗi kiểm tra nội dung', keywordsFound: [] });
                    });
                return true;

            case 'reportItem':
                reportItem(message.type, message.value, message.reason, message.context)
                    .then(sendResponse)
                    .catch(error => {
                        console.error(`BG: Error reporting item (${message.type}: ${message.value}):`, error);
                        sendResponse({ success: false, message: 'Lỗi gửi báo cáo.' });
                    });
                return true;

            case 'settingsUpdated':
                console.log("BG: Settings updated message received. Reloading settings and resetting alarm...");
                loadSettings().then(() => {
                    setupAlarms(); // Re-create alarm with new interval
                    updateAllCaches(); // Trigger update immediately
                }).catch(error => console.error("BG: Error applying updated settings:", error));
                // No async response needed here
                break; // Use break in switch

            case 'getWarningDetails': { // Use block scope for const
                 const urlParams = new URLSearchParams(sender.url.split('?')[1]);
                 const blockedUrl = urlParams.get('url');
                 if (blockedUrl) {
                      const decodedUrl = decodeURIComponent(blockedUrl);
                      const blockedDomain = normalizeDomain(decodedUrl);
                      sendResponse({ blockedUrl: decodedUrl, blockedDomain });
                 } else {
                      console.error("BG: Missing URL parameter in getWarningDetails request from:", sender.url);
                      sendResponse({ error: "Missing URL parameter" });
                 }
                 return false; // Synchronous response
            }

            // CHANGE: Handle temporary allowance using session storage
            case 'allowTemporarily': {
                const domain = message.domain;
                if (domain) {
                    addTemporaryAllow(domain)
                       .then(() => sendResponse({ success: true }))
                       .catch(error => {
                           console.error(`BG: Error adding temporary allow for ${domain}:`, error);
                           sendResponse({ success: false, message: 'Lỗi khi cho phép tạm thời.' });
                        });
                    return true; // Async due to storage access
                } else {
                    sendResponse({ success: false, message: 'Domain không hợp lệ.' });
                    return false;
                }
            }

            default:
                console.warn(`BG: Received unknown message action: ${message.action}`);
                // Send a default response or nothing
                sendResponse({ error: 'Unknown action' });
                return false; // No async response needed
        }
        // Ensure 'return true' is only used for async responses
    });

    // --- Web Request Listener ---
    // FIX: Wrap listener setup in try-catch and ensure permissions are requested
    try {
        if (chrome.webRequest && chrome.webRequest.onBeforeRequest) {
            // Remove listener if it exists before adding again (safer on reloads)
            if (chrome.webRequest.onBeforeRequest.hasListener(handleWebRequest)) {
                 chrome.webRequest.onBeforeRequest.removeListener(handleWebRequest);
                 console.log("BG: Removed existing webRequest listener.");
            }

            chrome.webRequest.onBeforeRequest.addListener(
                handleWebRequest, // Reference the handler function
                { urls: ["<all_urls>"], types: ["main_frame"] }, // Only block top-level navigations
                ["blocking"] // Required for redirection. Needs "webRequestBlocking" permission.
            );
            console.log("BG: Added webRequest listener for main_frame requests.");
        } else {
             // THIS IS LIKELY THE CAUSE OF THE ORIGINAL ERROR
             console.error("BG: CRITICAL - chrome.webRequest.onBeforeRequest API is not available. Check 'webRequest' permission in manifest.json.");
             // Optionally notify the user or disable blocking functionality
             chrome.notifications.create({
                type: 'basic',
                iconUrl: 'icons/icon-128.png',
                title: 'Lỗi Tiện Ích Phishing Guard',
                message: 'Không thể chặn trang web lừa đảo do thiếu quyền hoặc lỗi API. Vui lòng kiểm tra cài đặt tiện ích.',
                priority: 2
             });
        }
    } catch (error) {
        console.error("BG: CRITICAL - Error setting up webRequest listener:", error);
         // This catch might grab errors *during* listener execution if not handled inside handleWebRequest
    }

}

// Separate handler function for web requests
async function handleWebRequest(details) {
    // Ignore requests initiated by the extension itself or non-http(s) schemes
    if (details.initiator && details.initiator.startsWith(`chrome-extension://${chrome.runtime.id}`)) {
        return { cancel: false };
    }
    if (!details.url || (!details.url.startsWith('http:') && !details.url.startsWith('https:'))) {
        return { cancel: false }; // Ignore chrome://, file:// etc.
    }

    const url = details.url;
    const domain = normalizeDomain(url);

    if (!domain) {
        // console.log(`BG: Cannot normalize domain for URL: ${url}`);
        return { cancel: false }; // Cannot check invalid domains
    }

    // --- Check Flow ---
    // 0. Check Temporary Allowances (Session Storage)
    const isTemporarilyAllowed = await checkTemporaryAllow(domain);
    if (isTemporarilyAllowed) {
         console.log(`BG: Domain ${domain} is temporarily allowed. Allowing navigation.`);
         return { cancel: false };
    }

    // 1. Check Memory Whitelist (Fastest)
    if (memoryCache.whitelistedDomains.has(domain)) {
        console.log(`BG: Domain ${domain} is whitelisted (memory cache). Allowing navigation.`);
        return { cancel: false };
    }

    // 2. Check Memory Blocklist (Fast)
    if (memoryCache.phishingDomains.has(domain)) {
        console.warn(`BG: BLOCKING navigation to phishing domain ${domain} (from memory cache). URL: ${url}`);
        const redirectUrl = `${WARNING_PAGE_URL}?url=${encodeURIComponent(url)}`;
        // IMPORTANT: Ensure the warning page URL is correct and accessible
        console.log(`BG: Redirecting to: ${redirectUrl}`);
        return { redirectUrl: redirectUrl };
    }

    // 3. Optional: Live API check if cache is potentially stale? (Adds latency)
    // This is generally discouraged within a blocking webRequest listener.
    // Rely on the periodic cache updates.

    // 4. Default: Allow if not explicitly blocked or whitelisted in cache
    // console.log(`BG: Domain ${domain} not found in active lists. Allowing navigation.`);
    return { cancel: false };
}


// --- Core Logic ---

// CHANGE: Add functions for temporary allowance using session storage
async function addTemporaryAllow(domain) {
    if (!domain) return;
    const normalizedDomain = normalizeDomain(domain); // Ensure normalized
    if (!normalizedDomain) return;

    const expiryTime = Date.now() + (15 * 60 * 1000); // Allow for 15 minutes
    try {
        const data = await chrome.storage.session.get(TEMP_ALLOW_SESSION_KEY);
        const allows = data[TEMP_ALLOW_SESSION_KEY] || {};
        allows[normalizedDomain] = expiryTime;
        await chrome.storage.session.set({ [TEMP_ALLOW_SESSION_KEY]: allows });
        console.log(`BG: Temporarily allowed domain ${normalizedDomain} until ${new Date(expiryTime).toLocaleTimeString()}`);
    } catch (error) {
        console.error(`BG: Failed to save temporary allow for ${normalizedDomain}:`, error);
        throw error; // Re-throw to be caught by caller
    }
}

async function checkTemporaryAllow(domain) {
    if (!domain) return false;
    const normalizedDomain = normalizeDomain(domain);
     if (!normalizedDomain) return false;

    try {
        const data = await chrome.storage.session.get(TEMP_ALLOW_SESSION_KEY);
        const allows = data[TEMP_ALLOW_SESSION_KEY] || {};
        const expiryTime = allows[normalizedDomain];

        if (expiryTime && Date.now() < expiryTime) {
            return true; // Still valid
        } else if (expiryTime) {
            // Expired, remove it (optional cleanup)
            delete allows[normalizedDomain];
            await chrome.storage.session.set({ [TEMP_ALLOW_SESSION_KEY]: allows });
            console.log(`BG: Removed expired temporary allow for ${normalizedDomain}`);
        }
        return false;
    } catch (error) {
         console.error(`BG: Failed to check temporary allow for ${normalizedDomain}:`, error);
         return false; // Fail safe (don't allow)
    }
}

async function clearExpiredTempAllows() {
     try {
        const data = await chrome.storage.session.get(TEMP_ALLOW_SESSION_KEY);
        let allows = data[TEMP_ALLOW_SESSION_KEY] || {};
        const now = Date.now();
        let changed = false;
        for (const domain in allows) {
            if (allows[domain] < now) {
                delete allows[domain];
                changed = true;
                console.log(`BG: Cleaned up expired temp allow for ${domain}`);
            }
        }
        if (changed) {
             await chrome.storage.session.set({ [TEMP_ALLOW_SESSION_KEY]: allows });
        }
     } catch (error) {
          console.error("BG: Error clearing expired temporary allows:", error);
     }
}


function normalizeDomain(url) {
    if (!url || typeof url !== 'string') return null;
    try {
        let hostname = url;
        // If it looks like a full URL, parse it
        if (url.includes('://') || url.startsWith('//')) {
             // Prepend https:// if scheme is missing but // exists, for URL parser
             if (url.startsWith('//')) {
                  hostname = 'https:' + url;
             } else {
                   hostname = url;
             }
             hostname = new URL(hostname).hostname;
        }
        // Basic cleanup
        hostname = hostname.toLowerCase().replace(/^www\./, '').replace(/\.$/, '').trim();
        // Ignore IPs? (Keep consistent with backend)
        // if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) return null;
        if (!hostname || !hostname.includes('.')) return null; // Must have at least one dot
        return hostname;
    } catch (e) {
        // console.warn(`BG: Error normalizing URL/domain "${url}":`, e); // Can be noisy
        return null;
    }
}

function normalizeEmail(email) {
   if (!email || typeof email !== 'string') return null;
   const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
   const normalized = email.toLowerCase().trim();
   return emailRegex.test(normalized) ? normalized : null;
}

// CHANGE: Function to scan email content
function scanEmailContentForKeywords(content) {
    if (!content || typeof content !== 'string') {
        return { hasSuspiciousKeywords: false, keywordsFound: [] };
    }

    const lowerContent = content.toLowerCase();
    const foundKeywords = [];
    let matchCount = 0;

    for (const keyword of SUSPICIOUS_EMAIL_KEYWORDS) {
        // Use regex for whole word matching (optional, can be slow)
        // const regex = new RegExp(`\\b${keyword.toLowerCase()}\\b`, 'g');
        // if (lowerContent.match(regex)) {
        // Or simple includes check (faster)
        if (lowerContent.includes(keyword.toLowerCase())) {
            foundKeywords.push(keyword);
            matchCount++;
        }
    }

    const isSuspicious = matchCount >= MIN_KEYWORD_MATCHES_FOR_WARNING;

    if (isSuspicious) {
       console.log(`BG: Found ${matchCount} suspicious keywords in email content:`, foundKeywords);
    }

    return {
        hasSuspiciousKeywords: isSuspicious,
        keywordsFound: foundKeywords
    };
}

// CHANGE: Combined handler for email sender and content
async function handleCheckEmailDetails(senderEmail, emailContent) {
    const normalizedSender = normalizeEmail(senderEmail);
    let senderCheckResult = { isPhishing: false, status: 'safe', reason: 'Chưa kiểm tra', source: 'none' };

    // 1. Check Sender Email Address
    if (normalizedSender) {
        senderCheckResult = await checkPhishing('email', normalizedSender);
        if (senderCheckResult.isPhishing) {
            // If sender is known phishing, return immediately
            return {
                isPhishing: true, // Overall result
                senderStatus: senderCheckResult.status,
                senderReason: senderCheckResult.reason,
                contentScan: { hasSuspiciousKeywords: false, keywordsFound: [] }
            };
        }
    } else {
         senderCheckResult = { isPhishing: false, status: 'invalid', reason: 'Địa chỉ người gửi không hợp lệ', source: 'invalid' };
    }

    // 2. If sender is OK or invalid, check Content Keywords
    const contentScanResult = scanEmailContentForKeywords(emailContent);

    // Combine results: Phishing if sender known OR content is suspicious
    const overallPhishing = senderCheckResult.isPhishing || contentScanResult.hasSuspiciousKeywords;
    let overallReason = senderCheckResult.reason;
    if (contentScanResult.hasSuspiciousKeywords) {
        overallReason += (overallReason ? '; ' : '') + `Nội dung chứa từ khóa đáng ngờ (${contentScanResult.keywordsFound.slice(0, 3).join(', ')}${contentScanResult.keywordsFound.length > 3 ? '...' : ''})`;
    }


    return {
        isPhishing: overallPhishing,
        senderStatus: senderCheckResult.status,
        senderReason: senderCheckResult.reason,
        contentScan: contentScanResult // Include details about keyword scan
    };
}


async function fetchApiData(endpoint) {
    // Ensure endpoint starts with / if it's relative
    const urlPath = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
    const url = `${currentApiBaseUrl}${urlPath}`;
    console.log(`BG: Fetching API data from: ${url}`);
    try {
        const response = await fetch(url, {
            method: 'GET',
            headers: { 'Accept': 'application/json' }
            // Add timeout? Requires AbortController
        });

        if (!response.ok) {
            let errorBodyText = await response.text(); // Get text first
            let errorJson = null;
            try { errorJson = JSON.parse(errorBodyText); } catch (e) { /* Ignore */ }
            const errorMessage = errorJson?.error || response.statusText || `HTTP Error ${response.status}`;
            console.error(`BG: API request failed for ${url}. Status: ${response.status}. Body: ${errorBodyText}`);
            throw new Error(errorMessage); // Throw specific error message
        }

        const data = await response.json();
        // Basic validation (can be more specific based on endpoint)
        if (typeof data !== 'object' || data === null) {
             throw new Error('Invalid API response format (not an object).');
        }
        if ((endpoint.includes('/blocklist') || endpoint.includes('/whitelist')) && (!Array.isArray(data.items) || typeof data.version === 'undefined')) {
             throw new Error('Invalid list API response structure (missing items array or version).');
        }
         if (endpoint.includes('/check') && typeof data.status === 'undefined') {
              throw new Error('Invalid check API response structure (missing status).');
         }

        // console.log(`BG: Successfully fetched API data for ${url}.`);
        return data;

    } catch (error) {
        // Handle specific fetch errors (e.g., network, DNS)
        if (error instanceof TypeError && error.message.includes('Failed to fetch')) {
             console.error(`BG: Network error fetching ${url}. Is the local backend server running at ${currentApiBaseUrl}?`, error);
             throw new Error(`Không thể kết nối tới máy chủ cục bộ (${currentApiBaseUrl}). Hãy đảm bảo nó đang chạy.`);
        }
        console.error(`BG: Error during fetch API data from ${url}:`, error);
        throw error; // Re-throw the original or wrapped error
    }
}


async function updateCacheFromAPI(listType, itemType) { // listType: 'blocklist' or 'whitelist', itemType: 'domain' or 'email'
    const memoryKey = listType === 'blocklist' ?
        (itemType === 'domain' ? 'phishingDomains' : 'phishingEmails') :
        (itemType === 'domain' ? 'whitelistedDomains' : 'whitelistedEmails');
    const storageKey = CACHE_KEYS[memoryKey.replace(/([A-Z])/g, '_$1').toUpperCase()];
    const endpoint = `/${listType}?type=${itemType}`; // e.g. /blocklist?type=domain

    console.log(`BG: Attempting to update ${memoryKey} cache from API...`);
    try {
        const apiData = await fetchApiData(endpoint);

        // **FIX:** Check if apiData.items is actually an array before creating Set
        if (!Array.isArray(apiData.items)) {
            console.error(`BG: API response for ${endpoint} did not contain a valid 'items' array. Got:`, apiData);
            throw new Error(`Invalid items data received from API for ${memoryKey}.`);
        }

        const currentVersion = memoryCache.version[memoryKey];
        const newVersion = apiData.version;

        // Don't update if version is the same (and not null)
        if (newVersion !== null && newVersion !== undefined && newVersion === currentVersion) {
            console.log(`BG: Cache for ${memoryKey} is already up to date (Version: ${newVersion}). Updating timestamp.`);
            memoryCache.lastUpdated[memoryKey] = Date.now();
            // Save timestamp update to storage as well
            const currentItems = Array.from(memoryCache[memoryKey]); // Get current items
            await chrome.storage.local.set({
                [storageKey]: {
                    items: currentItems, // Keep existing items if version same
                    timestamp: memoryCache.lastUpdated[memoryKey],
                    version: newVersion
                }
            });
            return; // Exit early
        }

        // Update needed
        const newItemsSet = new Set(apiData.items); // Safe now due to Array.isArray check
        const oldSize = memoryCache[memoryKey]?.size ?? 0;
        memoryCache[memoryKey] = newItemsSet;
        memoryCache.lastUpdated[memoryKey] = Date.now();
        memoryCache.version[memoryKey] = newVersion;

        await chrome.storage.local.set({
            [storageKey]: {
                items: apiData.items, // Save the array from API
                timestamp: memoryCache.lastUpdated[memoryKey],
                version: newVersion
            }
        });
        console.log(`BG: Successfully updated ${memoryKey} cache. Version: ${currentVersion} -> ${newVersion}. Size: ${oldSize} -> ${newItemsSet.size}. Saved to local storage.`);

    } catch (error) {
        console.error(`BG: CRITICAL - Failed to update ${memoryKey} cache from API (${endpoint}). Error:`, error);
        // Keep potentially stale cache on error
        console.warn(`BG: Using potentially outdated ${memoryKey} cache due to update failure.`);
        // Rethrow or handle as needed - maybe notify user?
    }
}

async function updateAllCaches() {
    console.log("BG: Starting scheduled cache update...");
    const updatePromises = [
        updateCacheFromAPI('blocklist', 'domain'),
        updateCacheFromAPI('blocklist', 'email'),
        updateCacheFromAPI('whitelist', 'domain'),
        updateCacheFromAPI('whitelist', 'email')
    ];
    try {
         await Promise.allSettled(updatePromises); // Use allSettled to continue even if one fails
         console.log("BG: Scheduled cache update process finished (check logs for individual errors).");
    } catch(e) {
         // This catch is unlikely needed with Promise.allSettled unless there's an error *outside* the promises
         console.error("BG: Unexpected error during updateAllCaches:", e);
    }
}


function isCacheValid(memoryKey) {
     const lastUpdate = memoryCache.lastUpdated[memoryKey] || 0;
     const isValid = (Date.now() - lastUpdate) < CACHE_EXPIRY_MS;
     if (!isValid) {
         console.warn(`BG: Cache for ${memoryKey} is considered stale (Last update: ${new Date(lastUpdate).toLocaleString()}).`);
     }
     return isValid;
}

async function checkPhishing(type, value) {
    const normalizedValue = type === 'domain' ? normalizeDomain(value) : normalizeEmail(value);

    if (!normalizedValue) {
        console.warn(`BG: Invalid ${type} value for checking: "${value}"`);
        return { isPhishing: false, status: 'invalid', reason: "Giá trị không hợp lệ", source: 'local', details: null };
    }

    // --- Check Flow ---
    // 1. Memory Whitelist
    const whitelistKey = type === 'domain' ? 'whitelistedDomains' : 'whitelistedEmails';
    if (memoryCache[whitelistKey]?.has(normalizedValue)) {
        console.log(`BG: Check ${type} '${normalizedValue}' is whitelisted (cache).`);
        return { isPhishing: false, status: 'whitelisted', reason: "Được cho phép (cache)", source: 'cache', details: { value: normalizedValue } };
    }

    // 2. Memory Blocklist
    const blocklistKey = type === 'domain' ? 'phishingDomains' : 'phishingEmails';
    if (memoryCache[blocklistKey]?.has(normalizedValue)) {
        console.log(`BG: Check ${type} '${normalizedValue}' is blocked (cache).`);
        return { isPhishing: true, status: 'blocked', reason: "Đã biết (cache)", source: 'cache', details: { value: normalizedValue } };
    }

    // 3. Live API Check (as fallback or primary if cache is unreliable)
    console.log(`BG: Check - Cache miss for ${type}: ${normalizedValue}. Querying API...`);
    const checkUrl = `/check?type=${type}&value=${encodeURIComponent(normalizedValue)}`;

    try {
        const responseData = await fetchApiData(checkUrl);
        console.log(`BG: Check - API response for ${normalizedValue}: Status: ${responseData.status}`);

        // Optional: Update cache async if API finds something new *not* in cache
        // Be careful with this to avoid excessive updates or race conditions
        if (responseData.status === 'blocked' && !memoryCache[blocklistKey]?.has(normalizedValue)) {
             console.warn(`BG: API found new blocked ${type} '${normalizedValue}' not in cache. Triggering cache update.`);
             // Don't await this, let it run in background
             updateCacheFromAPI('blocklist', type).catch(e => console.error("BG: Async cache update failed:", e));
        } else if (responseData.status === 'whitelisted' && !memoryCache[whitelistKey]?.has(normalizedValue)) {
             console.warn(`BG: API found new whitelisted ${type} '${normalizedValue}' not in cache. Triggering cache update.`);
             updateCacheFromAPI('whitelist', type).catch(e => console.error("BG: Async cache update failed:", e));;
        }

        return {
            isPhishing: responseData.status === 'blocked',
            status: responseData.status, // 'blocked', 'whitelisted', 'safe', 'error'
            reason: `Kiểm tra API (${responseData.status || 'unknown'})`,
            source: 'api',
            details: responseData // Include full details from API
        };

    } catch (error) {
        console.error(`BG: API check failed for ${type} '${normalizedValue}'. Error:`, error.message);
        // Fallback: Assume safe on API error? Or maintain previous status? Assume safe.
        return { isPhishing: false, status: 'error', reason: `Lỗi kiểm tra API: ${error.message}`, source: 'api_error', details: null };
    }
}

async function reportItem(reportType, value, reason = '', context = '') {
    // Determine base type for normalization
    let apiType = reportType.replace('false_positive_', '');
    let apiValue = value;
    let apiReason = reason;

    if (reportType.startsWith('false_positive_')) {
        apiReason = `False Positive Report: ${reason || value}. Context: ${context}`;
        console.log(`BG: Reporting ${apiType} '${value}' as false positive.`);
    } else {
        console.log(`BG: Reporting suspicious ${apiType} '${value}'. Reason: ${reason}`);
    }

    // Normalize value based on the base type
    if (apiType === 'domain') {
        apiValue = normalizeDomain(value);
    } else if (apiType === 'email') {
        apiValue = normalizeEmail(value);
    }

    if (!apiValue) {
        console.error(`BG: Cannot report invalid ${apiType}: ${value}`);
        return { success: false, message: `Giá trị ${apiType} không hợp lệ.` };
    }

    const reportUrl = `${currentApiBaseUrl}/report`;
    console.log(`BG: Sending report to ${reportUrl}: Type=${reportType}, Value=${apiValue}`);

    try {
        const response = await fetch(reportUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({
                type: reportType, // Send original report type
                value: apiValue,   // Send normalized value
                reason: apiReason,
                source: 'chrome_extension'
            })
        });

        const responseData = await response.json(); // Assume API always returns JSON

        if (!response.ok) {
             console.error(`BG: API report failed (${response.status}):`, responseData);
             throw new Error(responseData.error || `API Error ${response.status}`);
        }

        console.log(`BG: Report for ${apiValue} submitted successfully. API Response:`, responseData);
        // Return success and potentially message/status from API
        return { success: true, ...responseData }; // Spread API response fields

    } catch (error) {
        console.error(`BG: Failed to submit report for ${apiValue}:`, error);
         // Handle specific fetch errors
         let errorMessage = 'Không thể gửi báo cáo.';
         if (error instanceof TypeError && error.message.includes('Failed to fetch')) {
              errorMessage = `Lỗi mạng khi gửi báo cáo. Máy chủ cục bộ có đang chạy không? (${currentApiBaseUrl})`;
         } else if (error.message) {
              errorMessage = `Lỗi gửi báo cáo: ${error.message}`;
         }
        return { success: false, message: errorMessage };
    }
}


// --- Run Initialization ---
initialize();