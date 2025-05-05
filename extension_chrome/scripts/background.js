/* eslint-disable no-undef */ // Tells eslint that 'chrome' is a global object

// --- Configuration ---
const DEFAULT_API_BASE_URL = 'http://127.0.0.1:5001/api'; // Default for local dev
const DEFAULT_CACHE_UPDATE_INTERVAL_MINUTES = 60; // Default: check every 60 minutes
const MIN_CACHE_UPDATE_INTERVAL_MINUTES = 5; // Minimum allowed interval
const MAX_CACHE_UPDATE_INTERVAL_MINUTES = 1440; // Maximum allowed interval (24 hours)
const CACHE_EXPIRY_MS = DEFAULT_CACHE_UPDATE_INTERVAL_MINUTES * 60 * 1000 * 1.5; // Cache considered stale after 1.5x update interval
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


// --- State ---
let currentApiBaseUrl = DEFAULT_API_BASE_URL;
let currentCacheUpdateIntervalMinutes = DEFAULT_CACHE_UPDATE_INTERVAL_MINUTES;
// In-memory cache for faster checks (populated from storage on startup)
let memoryCache = {
    phishingDomains: new Set(),
    phishingEmails: new Set(),
    whitelistedDomains: new Set(),
    whitelistedEmails: new Set(),
    lastUpdated: {
        phishingDomains: 0,
        phishingEmails: 0,
        whitelistedDomains: 0,
        whitelistedEmails: 0
    },
    version: { // Store API versions
        phishingDomains: null,
        phishingEmails: null,
        whitelistedDomains: null,
        whitelistedEmails: null
    }
};

// --- Initialization ---
async function initialize() {
    console.log("BG: Initializing Phishing Detector Extension...");
    await loadSettings();
    await loadInitialCache();
    setupAlarms();
    setupListeners();
    // Perform initial update shortly after startup
    setTimeout(updateAllCaches, 5000); // Update 5 seconds after launch
    console.log("BG: Initialization complete.");
}

async function loadSettings() {
    try {
        const settings = await chrome.storage.sync.get([CACHE_KEYS.API_BASE_URL, CACHE_KEYS.CACHE_UPDATE_INTERVAL]);
        currentApiBaseUrl = settings[CACHE_KEYS.API_BASE_URL] || DEFAULT_API_BASE_URL;
        currentCacheUpdateIntervalMinutes = settings[CACHE_KEYS.CACHE_UPDATE_INTERVAL] || DEFAULT_CACHE_UPDATE_INTERVAL_MINUTES;
        console.log(`BG: Loaded settings - API URL: ${currentApiBaseUrl}, Update Interval: ${currentCacheUpdateIntervalMinutes} min`);
    } catch (error) {
        console.error("BG: Error loading settings from sync storage:", error);
        // Use defaults if loading fails
        currentApiBaseUrl = DEFAULT_API_BASE_URL;
        currentCacheUpdateIntervalMinutes = DEFAULT_CACHE_UPDATE_INTERVAL_MINUTES;
    }
}

async function loadInitialCache() {
    console.log("BG: Loading initial cache from local storage...");
    const loadPromises = Object.keys(CACHE_KEYS).filter(k => k.endsWith('Cache')).map(async (storageKey) => {
        const type = storageKey.includes('Domain') ? 'domain' : 'email';
        const listType = storageKey.includes('PHISHING') ? 'phishing' : 'whitelisted';
        const memoryKey = `${listType}${type.charAt(0).toUpperCase() + type.slice(1)}s`; // e.g., phishingDomains

        try {
            const result = await chrome.storage.local.get(storageKey);
            if (result && result[storageKey] && result[storageKey].items) {
                memoryCache[memoryKey] = new Set(result[storageKey].items);
                memoryCache.lastUpdated[memoryKey] = result[storageKey].timestamp || 0;
                memoryCache.version[memoryKey] = result[storageKey].version || null; // Load version
                console.log(`BG: Loaded ${memoryCache[memoryKey].size} items into memory cache for ${memoryKey} (Version: ${memoryCache.version[memoryKey]}, Last updated: ${new Date(memoryCache.lastUpdated[memoryKey]).toLocaleString()})`);
            } else {
                 console.log(`BG: No valid cache found in local storage for ${storageKey}.`);
                 // Ensure it's an empty set if nothing is loaded
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
    chrome.alarms.get(ALARM_NAME, (alarm) => {
        const interval = Math.max(MIN_CACHE_UPDATE_INTERVAL_MINUTES, Math.min(currentCacheUpdateIntervalMinutes, MAX_CACHE_UPDATE_INTERVAL_MINUTES));
        if (!alarm || alarm.periodInMinutes !== interval) {
            chrome.alarms.create(ALARM_NAME, {
                delayInMinutes: 1, // Start first update 1 minute after setup
                periodInMinutes: interval
            });
            console.log(`BG: Created/Updated cache update alarm (${ALARM_NAME}) to run every ${interval} minutes.`);
        } else {
             console.log(`BG: Cache update alarm (${ALARM_NAME}) already exists with correct interval (${interval} min).`);
        }
    });

    chrome.alarms.onAlarm.addListener((alarm) => {
        if (alarm.name === ALARM_NAME) {
            console.log(`BG: Alarm '${ALARM_NAME}' triggered. Updating caches...`);
            updateAllCaches();
        }
    });
}

function setupListeners() {
    // Listen for messages from content scripts or popup
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        console.log(`BG: Received message: ${message.action}`, message); // Log received messages

        if (message.action === 'checkDomain') {
            checkPhishing('domain', message.domain)
                .then(result => sendResponse(result))
                .catch(error => {
                    console.error(`BG: Error checking domain ${message.domain}:`, error);
                    sendResponse({ isPhishing: false, error: 'Check failed' });
                });
            return true; // Indicates async response
        }

        if (message.action === 'checkEmail') {
            checkPhishing('email', message.email)
                .then(result => sendResponse(result))
                .catch(error => {
                    console.error(`BG: Error checking email ${message.email}:`, error);
                    sendResponse({ isPhishing: false, error: 'Check failed' });
                });
            return true; // Indicates async response
        }

        if (message.action === 'reportItem') {
            reportItem(message.type, message.value, message.reason || 'Reported via extension', message.context)
                .then(response => sendResponse(response)) // Forward API response
                .catch(error => {
                    console.error(`BG: Error reporting item (${message.type}: ${message.value}):`, error);
                    sendResponse({ success: false, message: 'Failed to send report.' });
                });
            return true; // Indicates async response
        }

        // Listen for settings changes from options page
        if (message.action === 'settingsUpdated') {
            console.log("BG: Settings updated message received. Reloading settings and resetting alarm...");
            loadSettings().then(() => {
                setupAlarms(); // Re-create alarm with new interval if needed
                 // Optionally trigger an immediate cache update if URL/interval changed significantly
                 updateAllCaches();
            });
            // No async response needed here
        }

        // Handle requests from warning page
         if (message.action === 'getWarningDetails') {
            // The warning page URL should contain the blocked URL as a query param
            const urlParams = new URLSearchParams(sender.url.split('?')[1]);
            const blockedUrl = urlParams.get('url');
             if (blockedUrl) {
                 const blockedDomain = normalizeDomain(blockedUrl);
                 sendResponse({ blockedUrl: decodeURIComponent(blockedUrl), blockedDomain });
             } else {
                 sendResponse({ error: "Missing URL parameter" });
             }
             return false; // Synchronous response
         }

         if (message.action === 'allowTemporarily') {
             // Basic temporary allow - add to a temporary memory set (not persisted)
             // A more robust solution would use session storage or timestamps
             const domain = message.domain;
             if (domain) {
                // This is a simplified example. A real implementation might need
                // a dedicated temporary whitelist with expiry.
                console.warn(`BG: Temporarily allowing ${domain} (In-memory only, will reset on restart)`);
                // For now, just log it. Need a proper mechanism.
                sendResponse({ success: true });
             } else {
                 sendResponse({ success: false });
             }
             return false;
         }


    });

    // Listen for navigation events to block malicious sites
    chrome.webRequest.onBeforeRequest.addListener(
        (details) => {
            // Ignore requests initiated by the extension itself (e.g., API calls, warning page)
            if (details.initiator && details.initiator.startsWith(`chrome-extension://${chrome.runtime.id}`)) {
                return { cancel: false };
            }
            // Only interested in main frame navigations (top-level)
             if (details.type !== 'main_frame' || !details.url || details.method !== 'GET') {
                 return { cancel: false };
             }

            const url = details.url;
            const domain = normalizeDomain(url);

            if (!domain) {
                return { cancel: false }; // Cannot check invalid/non-standard URLs
            }

             // --- Check Flow ---
             // 1. Check memory whitelist (Fastest)
             if (memoryCache.whitelistedDomains.has(domain)) {
                 console.log(`BG: Domain ${domain} is whitelisted (memory cache). Allowing navigation.`);
                 return { cancel: false };
             }

             // 2. Check memory blocklist (Fast)
             if (memoryCache.phishingDomains.has(domain)) {
                 console.log(`BG: Blocking navigation to ${domain} (memory cache). Redirecting to warning page.`);
                 const redirectUrl = `${WARNING_PAGE_URL}?url=${encodeURIComponent(url)}`;
                 return { redirectUrl: redirectUrl };
             }

             // 3. If not in memory caches, potentially make a live API call
             // NOTE: Blocking webRequest listeners for async operations is complex and
             // can slow down Browse. The primary reliance should be on the cache.
             // A live check here might be too slow. We rely on the cache being updated.
             // If needed, one could implement a non-blocking check that updates the cache
             // but might not block the *first* visit if the cache is stale.

             // For now, if not in memory cache, allow it but maybe trigger an async check?
             // console.log(`BG: Domain ${domain} not found in memory cache. Allowing navigation (cache might be stale).`);
             // Optionally trigger an async check here without blocking:
             // checkPhishing('domain', domain).then(result => {
             //     if (result.isPhishing) console.warn(`BG: Post-navigation check found ${domain} to be phishing! Cache was stale.`);
             // });

            return { cancel: false }; // Allow by default if not explicitly blocked by cache
        },
        { urls: ["<all_urls>"] }, // Listen to all URLs
        ["blocking"] // Use "blocking" to allow redirection
    );

     // Clear temporary allows on startup (if implemented that way)
     // Or use chrome.storage.session for non-persistent allows
}


// --- Core Logic ---

function normalizeDomain(url) {
    if (!url) return null;
    try {
        let hostname = url;
        // If it's a full URL, extract hostname
        if (url.includes('://')) {
            hostname = new URL(url).hostname;
        }
        // Basic cleanup: lowercase, remove www., remove trailing dot
        hostname = hostname.toLowerCase().replace(/^www\./, '').replace(/\.$/, '');
        // Very basic IP address check - might need refinement
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
            return null; // Don't treat IPs as domains for typical phishing lists
        }
        return hostname;
    } catch (e) {
        // console.error(`BG: Error normalizing URL/domain "${url}":`, e);
        return null; // Return null for invalid URLs/hostnames
    }
}

function normalizeEmail(email) {
     if (!email || typeof email !== 'string') return null;
     // Basic email regex (consider using a more robust library if complex validation needed)
     const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
     if (!emailRegex.test(email)) {
         return null; // Invalid format
     }
     return email.toLowerCase(); // Normalize to lowercase
}

async function fetchApiData(endpoint) {
    const url = `${currentApiBaseUrl}${endpoint}`;
    console.log(`BG: Fetching API data from: ${url}`);
    try {
        const response = await fetch(url, {
            method: 'GET',
            headers: {
                'Accept': 'application/json'
            }
        });

        if (!response.ok) {
            // Try to get error message from response body
            let errorBody = null;
            try {
                errorBody = await response.json();
            } catch (parseError) {
                 // Ignore if body isn't valid JSON
                 errorBody = await response.text(); // Get as text if not JSON
            }
             console.error(`BG: API request failed for ${url}. Status: ${response.status}. Body:`, errorBody || response.statusText);
            throw new Error(`API Error ${response.status}: ${errorBody?.error || response.statusText}`);
        }

        const data = await response.json();
        // **FIX:** Validate structure specifically for list endpoints
        if (endpoint.includes('/blocklist') || endpoint.includes('/whitelist')) {
             if (!data || !Array.isArray(data.items) || typeof data.version === 'undefined') {
                 console.error(`BG: Invalid API response structure for ${url}. Expected '{ "items": [], "version": ... }'. Got:`, data);
                 throw new Error('Invalid API response structure for list.');
             }
        } else if (endpoint.includes('/check')) {
            // Validate structure for check endpoint if needed (e.g., presence of 'status')
             if (!data || typeof data.status === 'undefined') {
                 console.error(`BG: Invalid API response structure for check ${url}. Expected '{ "status": "...", ... }'. Got:`, data);
                 throw new Error('Invalid API response structure for check.');
             }
        }

        console.log(`BG: Successfully fetched data for ${url}. Items: ${data.items?.length ?? 'N/A'}, Version: ${data.version ?? 'N/A'}, Status: ${data.status ?? 'N/A'}`);
        return data; // Return the parsed JSON data

    } catch (error) {
         console.error(`BG: Network or fetch error for ${url}:`, error);
         // Rethrow the error to be handled by the caller
         throw error;
    }
}


async function updateLocalCache(type) { // type = 'domain' or 'email'
    const listType = 'phishing'; // or 'whitelisted'
    const memoryKey = `${listType}${type.charAt(0).toUpperCase() + type.slice(1)}s`; // e.g., phishingDomains
    const storageKey = CACHE_KEYS[`${listType.toUpperCase()}_${type.toUpperCase()}S`]; // e.g., PHISHING_DOMAINS
    const endpoint = `/blocklist?type=${type}`; // or /whitelist

    console.log(`BG: Attempting to update ${memoryKey} cache...`);
    try {
        const apiData = await fetchApiData(endpoint);

        // **FIX:** Check received version against stored version
         const currentVersion = memoryCache.version[memoryKey];
         const newVersion = apiData.version;

         if (newVersion !== null && newVersion === currentVersion) {
             console.log(`BG: Cache for ${memoryKey} is already up to date (Version: ${newVersion}). No update needed.`);
             // Update timestamp even if data hasn't changed, to reflect successful check
             memoryCache.lastUpdated[memoryKey] = Date.now();
              // Save timestamp update to storage as well
              await chrome.storage.local.set({
                  [storageKey]: {
                      items: Array.from(memoryCache[memoryKey]), // Keep existing items
                      timestamp: memoryCache.lastUpdated[memoryKey],
                      version: newVersion
                  }
              });
             return; // Exit early, no changes
         }

        // Update needed
        const newItemsSet = new Set(apiData.items);
        memoryCache[memoryKey] = newItemsSet;
        memoryCache.lastUpdated[memoryKey] = Date.now();
        memoryCache.version[memoryKey] = newVersion; // Store the new version

        // Save updated data to local storage
        await chrome.storage.local.set({
            [storageKey]: {
                items: apiData.items, // Save the array from API
                timestamp: memoryCache.lastUpdated[memoryKey],
                version: newVersion // Save the new version
            }
        });
        console.log(`BG: Successfully updated ${memoryKey} cache. New Version: ${newVersion}. Items: ${newItemsSet.size}. Saved to local storage.`);

    } catch (error) {
        // Log the CRITICAL error as per user request
        console.error(`BG: CRITICAL - Failed to update ${memoryKey} cache from API. Error:`, error);
        // Do not clear the cache on failure, keep the old data
        console.warn(`BG: Using potentially outdated ${memoryKey} cache due to update failure.`);
    }
}

async function updateWhitelistCache(type) { // type = 'domain' or 'email'
    const listType = 'whitelisted';
    const memoryKey = `${listType}${type.charAt(0).toUpperCase() + type.slice(1)}s`; // e.g., whitelistedDomains
    const storageKey = CACHE_KEYS[`${listType.toUpperCase()}_${type.toUpperCase()}S`]; // e.g., WHITELISTED_DOMAINS
    const endpoint = `/whitelist?type=${type}`;

    console.log(`BG: Attempting to update ${memoryKey} cache...`);
     try {
         const apiData = await fetchApiData(endpoint);

         const currentVersion = memoryCache.version[memoryKey];
         const newVersion = apiData.version;

         if (newVersion !== null && newVersion === currentVersion) {
             console.log(`BG: Cache for ${memoryKey} is already up to date (Version: ${newVersion}).`);
             memoryCache.lastUpdated[memoryKey] = Date.now();
              await chrome.storage.local.set({
                  [storageKey]: {
                      items: Array.from(memoryCache[memoryKey]),
                      timestamp: memoryCache.lastUpdated[memoryKey],
                      version: newVersion
                  }
              });
             return;
         }


        const newItemsSet = new Set(apiData.items);
        memoryCache[memoryKey] = newItemsSet;
        memoryCache.lastUpdated[memoryKey] = Date.now();
        memoryCache.version[memoryKey] = newVersion;


        await chrome.storage.local.set({
            [storageKey]: {
                items: apiData.items,
                timestamp: memoryCache.lastUpdated[memoryKey],
                version: newVersion
            }
        });
        console.log(`BG: Successfully updated ${memoryKey} cache. New Version: ${newVersion}. Items: ${newItemsSet.size}. Saved to local storage.`);

    } catch (error) {
        console.error(`BG: CRITICAL - Failed to update ${memoryKey} cache from API. Error:`, error);
        console.warn(`BG: Using potentially outdated ${memoryKey} cache due to update failure.`);
    }
}


async function updateAllCaches() {
    console.log("BG: Starting scheduled cache update...");
    const updatePromises = [
        updateLocalCache('domain'),
        updateLocalCache('email'),
        updateWhitelistCache('domain'),
        updateWhitelistCache('email')
    ];
    await Promise.all(updatePromises);
    console.log("BG: Scheduled cache update finished.");
}

function isCacheValid(type, listType = 'phishing') {
     const memoryKey = `${listType}${type.charAt(0).toUpperCase() + type.slice(1)}s`;
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
        console.warn(`BG: Invalid ${type} value provided for checking: "${value}"`);
        return { isPhishing: false, status: 'safe', reason: "Giá trị không hợp lệ", source: 'invalid', details: null };
    }

    // --- Check Flow ---
    // 1. Check Memory Whitelist (Highest Priority)
    const whitelistKey = type === 'domain' ? 'whitelistedDomains' : 'whitelistedEmails';
    if (memoryCache[whitelistKey]?.has(normalizedValue)) {
         console.log(`BG: Check - ${type} '${normalizedValue}' is whitelisted (memory cache).`);
         return { isPhishing: false, status: 'whitelisted', reason: "Được cho phép (whitelist)", source: 'cache', details: { value: normalizedValue } };
    }

    // 2. Check Memory Blocklist
    const blocklistKey = type === 'domain' ? 'phishingDomains' : 'phishingEmails';
    if (memoryCache[blocklistKey]?.has(normalizedValue)) {
        console.log(`BG: Check - ${type} '${normalizedValue}' is blocked (memory cache).`);
        return { isPhishing: true, status: 'blocked', reason: "Đã biết (cache)", source: 'cache', details: { value: normalizedValue } };
    }

    // 3. If not in memory caches, query the API (Live Check)
    // This provides the most up-to-date check but adds latency.
    console.log(`BG: Check - Cache miss for ${type}: ${normalizedValue}. Querying API...`);
    const checkUrl = `/check?type=${type}&value=${encodeURIComponent(normalizedValue)}`; // Use relative path

    try {
        const responseData = await fetchApiData(checkUrl); // Use the robust fetch function

        // **FIX:** Check responseData.status and provide details
         console.log(`BG: Check - API response for ${normalizedValue}: Status: ${responseData.status}`);

         // Update cache asynchronously if API finds a new blocked/whitelisted item?
         // Be careful not to trigger infinite loops or race conditions.
         // if (responseData.status === 'blocked' && !memoryCache[blocklistKey]?.has(normalizedValue)) {
         //     console.log(`BG: API check found new blocked ${type}: ${normalizedValue}. Updating cache async.`);
         //     updateLocalCache(type); // Trigger background update
         // } // Similar logic for whitelist if needed

        return {
            isPhishing: responseData.status === 'blocked',
            status: responseData.status, // 'blocked', 'whitelisted', 'safe'
            reason: `Kiểm tra API (${responseData.status})`,
            source: 'api',
            details: responseData.details || null // Include details from API if available
        };

    } catch (error) {
        // Log the specific error during check
        console.error(`BG: API check failed for ${type} '${normalizedValue}'. Error:`, error);
        // Fallback: assume safe if API check fails? Or maintain previous status?
        // Assuming safe on API failure is a common approach to avoid blocking unnecessarily.
        return { isPhishing: false, status: 'safe', reason: "Lỗi kiểm tra API", source: 'error', details: null, error: error.message };
    }
}

async function reportItem(reportType, value, reason = '', context = '') {
     // reportType could be 'domain', 'email', 'false_positive_domain', etc.
     let apiType;
     let apiValue = value;
     let apiReason = reason;

     if (reportType.startsWith('false_positive_')) {
         apiType = reportType.replace('false_positive_', ''); // 'domain' or 'email'
         apiReason = `False Positive Report: ${reason || value}`; // Add context to reason
         // Potentially report to a different endpoint or add specific flag?
         // For now, use the standard report endpoint but modify reason.
          console.log(`BG: Reporting ${apiType} '${apiValue}' as false positive. Context: ${context}`);
     } else {
         apiType = reportType; // 'domain' or 'email'
         console.log(`BG: Reporting suspicious ${apiType} '${apiValue}'. Reason: ${reason}`);
     }

     // Normalize before sending
     if (apiType === 'domain') {
         apiValue = normalizeDomain(apiValue);
     } else if (apiType === 'email') {
         apiValue = normalizeEmail(apiValue);
     }

     if (!apiValue) {
         console.error(`BG: Cannot report invalid ${apiType}: ${value}`);
         return { success: false, message: `Giá trị ${apiType} không hợp lệ.` };
     }


    const reportUrl = `${currentApiBaseUrl}/report`; // Use configured base URL
    try {
        const response = await fetch(reportUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            body: JSON.stringify({
                type: apiType,
                value: apiValue,
                reason: apiReason,
                source: 'chrome_extension' // Identify source
            })
        });

        const responseData = await response.json();

        if (!response.ok) {
             console.error(`BG: API report failed (${response.status}):`, responseData);
             // Provide specific error from API if available
             throw new Error(responseData.error || `API Error ${response.status}`);
        }

        console.log(`BG: Report for ${apiValue} submitted successfully. API Response:`, responseData);
        return { success: true, message: responseData.message || 'Báo cáo thành công!', status: responseData.status, report: responseData.report }; // Include API status if returned

    } catch (error) {
        console.error(`BG: Failed to submit report for ${apiValue}:`, error);
        return { success: false, message: error.message || 'Không thể gửi báo cáo.' };
    }
}


// --- Run Initialization ---
initialize();