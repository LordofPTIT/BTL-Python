'use strict';

// --- Configuration ---
const DEFAULT_API_BASE_URL = 'https://btl-python.onrender.com/api'; 
const DEFAULT_CACHE_EXPIRY_MINUTES = 60; // Default cache time in minutes
const UPDATE_ALARM_NAME = 'updateBlocklistsAlarm';
const MIN_CACHE_EXPIRY = 5; // Minimum allowed cache expiry
const MAX_CACHE_EXPIRY = 1440; // Maximum allowed cache expiry (1 day)

// --- Global State (Initialized on load/startup) ---
let currentApiBaseUrl = DEFAULT_API_BASE_URL;
let currentCacheExpiryMinutes = DEFAULT_CACHE_EXPIRY_MINUTES;
let phishingDomainsCache = new Set();
let phishingEmailsCache = new Set();
let cacheTimestampDomains = 0;
let cacheTimestampEmails = 0;

// --- Utility Functions ---

function isValidUrl(string) {
    if (!string) return false;
    try {
        const url = new URL(string);
        // Allow http, https, and potentially ftp if needed in the future
        return ['http:', 'https:'].includes(url.protocol);
    } catch (_) {
        return false;
    }
}

/**
 * Normalizes a domain name.
 * - Converts to lowercase.
 * - Removes leading 'www.'
 * - Removes trailing '/'.
 * - Validates basic domain structure.
 * @param {string | null | undefined} domain The domain string to normalize.
 * @returns {string | null} The normalized domain or null if invalid.
 */
function normalizeDomain(domain) {
    if (!domain || typeof domain !== 'string') return null;
    try {
        let normalized = domain.toLowerCase().trim();
        // Remove protocol if present (handle cases like "http://example.com")
        if (normalized.startsWith('http://')) normalized = normalized.substring(7);
        if (normalized.startsWith('https://')) normalized = normalized.substring(8);
        // Remove trailing slash and path if present
        normalized = normalized.split('/')[0];
        // Remove www. prefix
        if (normalized.startsWith('www.')) normalized = normalized.substring(4);
        // Basic validation
        if (normalized.length === 0 ||
            !/^[a-z0-9.-]+$/.test(normalized) || // Allow letters, numbers, dots, hyphens
            !normalized.includes('.') || // Must contain at least one dot
            normalized.startsWith('.') || normalized.endsWith('.') || // Cannot start/end with dot
            normalized.startsWith('-') || normalized.endsWith('-') || // Cannot start/end with hyphen
            normalized.includes('..') || normalized.includes('--')) // Avoid double dots/hyphens (common in invalid names)
        {
            return null;
        }
        // Check TLD length (basic check)
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


/**
 * Normalizes an email address.
 * - Converts to lowercase.
 * - Trims whitespace.
 * - Validates using a standard regex.
 * @param {string | null | undefined} email The email string to normalize.
 * @returns {string | null} The normalized email or null if invalid.
 */
function normalizeEmail(email) {
    if (!email || typeof email !== 'string') return null;
    try {
        const trimmed = email.toLowerCase().trim();
        // Standard Email Regex (RFC 5322 subset) - Allows international characters in local part if needed later
        const emailRegex = /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i;
        return emailRegex.test(trimmed) ? trimmed : null;
    } catch (e) {
        console.error(`BG: Error normalizing email "${email}":`, e);
        return null;
    }
}

/**
 * Extracts a potential domain from a string (like selected text).
 * @param {string} text The input text.
 * @returns {string | null} The extracted, normalized domain or null.
 */
function extractAndNormalizeDomain(text) {
    if (!text || typeof text !== 'string') return null;
    // Regex to find potential domain-like patterns (more flexible)
    // Looks for patterns like sub.domain.tld, possibly preceded by http/https or followed by /path
    const domainPattern = /(?:https?:\/\/)?([a-z0-9\u00A1-\uFFFF][a-z0-9\u00A1-\uFFFF.-]*\.[a-z\u00A1-\uFFFF]{2,})/gi;
    let match;
    while ((match = domainPattern.exec(text)) !== null) {
        const potentialDomain = normalizeDomain(match[1]); // Group 1 captures the domain part
        if (potentialDomain) {
            return potentialDomain; // Return the first valid domain found
        }
    }
    // Fallback: Try normalizing the whole text if no pattern matched
    const fallbackDomain = normalizeDomain(text);
    if (fallbackDomain) {
        return fallbackDomain;
    }
    return null;
}


// --- Settings & Caching Logic ---

async function loadSettings() {
    console.log("BG: Loading settings...");
    try {
        // Default values are used if sync storage is empty or invalid
        const settings = await chrome.storage.sync.get({
            apiUrl: DEFAULT_API_BASE_URL,
            cacheExpiryMinutes: DEFAULT_CACHE_EXPIRY_MINUTES
        });

        // Validate and sanitize API URL
        const rawApiUrl = settings.apiUrl || DEFAULT_API_BASE_URL;
        currentApiBaseUrl = isValidUrl(rawApiUrl) ? rawApiUrl.replace(/\/$/, '') : DEFAULT_API_BASE_URL.replace(/\/$/, '');

        // Validate and sanitize Cache Expiry
        const rawExpiry = parseInt(settings.cacheExpiryMinutes, 10);
        currentCacheExpiryMinutes = (isNaN(rawExpiry) || rawExpiry < MIN_CACHE_EXPIRY || rawExpiry > MAX_CACHE_EXPIRY)
            ? DEFAULT_CACHE_EXPIRY_MINUTES
            : rawExpiry;

        console.log(`BG: Settings loaded. API: ${currentApiBaseUrl}, Cache Expiry: ${currentCacheExpiryMinutes} min`);

        // Setup or update the periodic cache update alarm
        await setupUpdateAlarm();

    } catch (error) {
        console.error("BG: CRITICAL - Error loading settings from chrome.storage.sync.", error);
        // Fallback to defaults in case of storage read error
        currentApiBaseUrl = DEFAULT_API_BASE_URL.replace(/\/$/, '');
        currentCacheExpiryMinutes = DEFAULT_CACHE_EXPIRY_MINUTES;
        console.warn("BG: Falling back to default settings due to error.");
        // Still try to set up the alarm with defaults
        await setupUpdateAlarm();
    }
}

async function setupUpdateAlarm() {
    try {
        const currentAlarm = await chrome.alarms.get(UPDATE_ALARM_NAME);
        // Create or update the alarm only if it doesn't exist or its period has changed
        if (!currentAlarm || currentAlarm.periodInMinutes !== currentCacheExpiryMinutes) {
            await chrome.alarms.create(UPDATE_ALARM_NAME, {
                delayInMinutes: 1, // Start first update 1 minute after setup/load
                periodInMinutes: currentCacheExpiryMinutes
            });
            console.log(`BG: Cache update alarm created/updated. Period: ${currentCacheExpiryMinutes} min.`);
        }
    } catch (error) {
        console.error("BG: Failed to create/update cache update alarm.", error);
    }
}

/**
 * Retrieves cached data (domains or emails) if it's not expired.
 * @param {'domain' | 'email'} type - The type of data to retrieve.
 * @returns {Promise<Set<string> | null>} A Set containing the cached items or null if expired/not found.
 */
async function getValidCachedData(type) {
    const key = type === 'domain' ? 'phishingDomains' : 'phishingEmails';
    const timestampKey = `${key}Timestamp`;
    const globalCache = type === 'domain' ? phishingDomainsCache : phishingEmailsCache;
    const globalTimestamp = type === 'domain' ? cacheTimestampDomains : cacheTimestampEmails;
    const now = Date.now();

    // 1. Check in-memory cache first
    if (globalCache.size > 0 && globalTimestamp && (now - globalTimestamp < currentCacheExpiryMinutes * 60 * 1000)) {
         // console.log(`BG: Cache hit in memory for ${type}`);
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
            // Update in-memory cache
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
            return null; // Cache is invalid or expired
        }
    } catch (error) {
        console.error(`BG: Exception reading cache for ${key}:`, error);
        return null;
    }
}

/**
 * Updates the specified blocklist cache from the API.
 * @param {'domain' | 'email'} type - The type of blocklist to update.
 * @returns {Promise<Set<string>>} The updated Set of blocked items.
 */
async function updateCacheFromAPI(type = 'domain') {
    const key = type === 'domain' ? 'phishingDomains' : 'phishingEmails';
    const listKey = type === 'domain' ? 'domains' : 'emails'; // Key in API response JSON
    const versionKey = `${key}Version`; // Key for storing the version/timestamp from API
    const timestampKey = `${key}Timestamp`; // Key for storing local update time

    console.log(`BG: Starting update for ${key} cache...`);

    try {
        // Get current version from local storage to request incremental updates if supported by API
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
             // Add Authentication headers if required by the API
        });

        // Handle "Not Modified" response efficiently
        if (response.status === 304) {
            console.log(`BG: ${key} cache is up to date (API returned 304 Not Modified).`);
            // Update timestamp even if not modified, to extend cache validity
            const now = Date.now();
            await chrome.storage.local.set({ [timestampKey]: now });
             if (type === 'domain') cacheTimestampDomains = now; else cacheTimestampEmails = now;
            // Return the existing valid cache
            return (type === 'domain' ? phishingDomainsCache : phishingEmailsCache) || new Set();
        }

        if (!response.ok) {
            // Log detailed error but don't clear cache immediately, rely on old cache
            throw new Error(`API Error ${response.status} - ${response.statusText}. URL: ${fetchUrl}`);
        }

        const data = await response.json();

        // Validate API response structure
        if (!data || typeof data !== 'object' || !Array.isArray(data[listKey])) {
            throw new Error(`Invalid API response structure for ${key}. Expected '{ "${listKey}": [], "version": ... }'`);
        }

        const newList = data[listKey];
        const newVersion = data.version || Date.now(); // Use API version or current time

        // Normalize items received from the API
        const normalizedList = newList
            .map(item => (type === 'domain' ? normalizeDomain(item) : normalizeEmail(item)))
            .filter(Boolean); // Filter out any nulls from normalization

        const updatedSet = new Set(normalizedList);
        const now = Date.now();

        // Store the updated list, timestamp, and version in local storage
        await chrome.storage.local.set({
            [key]: Array.from(updatedSet),
            [timestampKey]: now,
            [versionKey]: newVersion
        });
         if (chrome.runtime.lastError) {
             console.error(`BG: Error saving updated cache for ${key}:`, chrome.runtime.lastError.message);
             // If saving fails, the in-memory cache might be newer, but don't update it yet
             throw new Error(`Failed to save updated ${key} cache to local storage.`);
         } else {
             // Update in-memory cache ONLY after successful save to local storage
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
        // In case of error, return the existing valid cache (could be outdated but better than nothing)
        const existingCache = await getValidCachedData(type);
        console.warn(`BG: Returning potentially outdated ${key} cache due to update failure.`);
        return existingCache || new Set(); // Return empty set if no valid cache exists
    }
}


// --- API Interaction ---

/**
 * Checks if a given domain or email is present in the phishing blocklist (cache first, then API).
 * @param {'domain' | 'email'} type - The type of item to check.
 * @param {string} value - The domain or email value to check.
 * @returns {Promise<{isPhishing: boolean, reason: string, source: 'cache' | 'api' | 'error' | 'invalid'}>} Result object.
 */
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
        // console.log(`BG: Phishing ${type} detected in cache: ${normalizedValue}`);
        return { isPhishing: true, reason: "Đã biết (cache)", source: 'cache' };
    }

    // 2. If not in cache or cache expired, query the API
    console.log(`BG: Cache miss for ${type}: ${normalizedValue}. Querying API...`);
    const checkUrl = `${currentApiBaseUrl}/check?type=${type}&value=${encodeURIComponent(normalizedValue)}`;

    try {
        const response = await fetch(checkUrl, {
             method: 'GET',
             headers: { 'Accept': 'application/json' }
             // Add Auth if needed
        });

        if (!response.ok) {
            // API error, but don't assume it's safe. Rely on potentially outdated cache if it existed.
             console.warn(`BG: API check for ${type} ${normalizedValue} failed with status ${response.status}. URL: ${checkUrl}`);
             const potentiallyOutdatedCache = type === 'domain' ? phishingDomainsCache : phishingEmailsCache;
             if (potentiallyOutdatedCache.has(normalizedValue)) {
                 console.warn(`BG: Reporting as phishing based on potentially outdated cache for ${normalizedValue} after API error.`);
                 return { isPhishing: true, reason: "Đã biết (cache - API lỗi)", source: 'cache' };
             }
             // If not even in outdated cache, assume not phishing but log error
            return { isPhishing: false, reason: `Lỗi API ${response.status}`, source: 'error' };
        }

        const result = await response.json();

        // Validate API response
        if (typeof result?.isPhishing !== 'boolean') {
             console.error(`BG: Invalid API response structure for check ${type} ${normalizedValue}. Got:`, result);
             return { isPhishing: false, reason: "Phản hồi API không hợp lệ", source: 'error' };
        }

        console.log(`BG: API check result for ${type} ${normalizedValue}: isPhishing=${result.isPhishing}`);

        // If API confirms phishing AND it wasn't in our valid cache, add it to the *in-memory* cache for immediate use.
        // The next full cache update will persist it based on the main blocklist.
        if (result.isPhishing && (!cachedList || !cachedList.has(normalizedValue))) {
            console.log(`BG: Adding API-confirmed phishing ${type} ${normalizedValue} to immediate in-memory cache.`);
            const immediateCache = type === 'domain' ? phishingDomainsCache : phishingEmailsCache;
            immediateCache.add(normalizedValue);
            // We don't update the timestamp here, let the main cache update handle persistence.
        }

        return {
             isPhishing: result.isPhishing,
             reason: result.reason || (result.isPhishing ? "Đã biết (API)" : "An toàn (API)"),
             source: 'api'
         };

    } catch (error) {
        // Network errors (like Failed to fetch) or other exceptions
        console.error(`BG: CRITICAL - Exception during API check for ${type} '${normalizedValue}'. Error:`, error);
        // Again, check potentially outdated cache as a last resort
        const potentiallyOutdatedCache = type === 'domain' ? phishingDomainsCache : phishingEmailsCache;
        if (potentiallyOutdatedCache.has(normalizedValue)) {
             console.warn(`BG: Reporting as phishing based on potentially outdated cache for ${normalizedValue} after connection error.`);
             return { isPhishing: true, reason: "Đã biết (cache - API lỗi kết nối)", source: 'cache' };
        }
        return { isPhishing: false, reason: "Lỗi kết nối API", source: 'error' };
    }
}


/**
 * Reports an item (domain, email, text, url, false positive) to the backend API.
 * Also updates the local cache immediately for phishing reports.
 * @param {'domain' | 'email' | 'url' | 'text_selection' | 'false_positive_domain' | 'false_positive_email'} type
 * @param {string} value
 * @param {string} [context="User report via extension"] - Optional context.
 * @returns {Promise<boolean>} True if the report was likely successful, false otherwise.
 */
async function reportToAPI(type, value, context = "User report via extension") {
    let normalizedValue;
    let blocklistType = null; // 'domain' or 'email' for cache updates
    let isFalsePositive = false;

    // Normalize based on type
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
            normalizedValue = (value || '').trim(); // Report raw URL
             // Try to extract domain for context, but report the URL itself
             const extractedDomain = extractAndNormalizeDomain(value);
             if (extractedDomain) context += ` (URL contains domain: ${extractedDomain})`;
            break;
        case 'text_selection':
            normalizedValue = (value || '').trim(); // Report raw text
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
                // Add Authentication headers if needed
            },
            body: JSON.stringify({ type: type, value: normalizedValue, context: context })
        });

        // Try to parse JSON even if response is not ok, it might contain error details
        let result = {};
        try {
             result = await response.json();
        } catch (jsonError) {
             console.warn(`BG: Could not parse JSON response for report ${type} ${normalizedValue} (Status: ${response.status}). Body:`, await response.text());
             // If parsing fails, use the status text for the error
             throw new Error(`API report failed with status ${response.status} - ${response.statusText}. Unable to parse response body.`);
        }


        if (!response.ok) {
            // Throw error using message from API response if available
            throw new Error(result.message || `API report failed with status ${response.status}.`);
        }

        // --- Report Success ---
        console.log(`BG: API report successful for ${type}: ${normalizedValue}. API Response:`, result);
        showNotification('Báo cáo thành công', `Cảm ơn bạn đã báo cáo ${type}: ${normalizedValue}`);

        // --- Update Local Cache Immediately ---
        if (blocklistType) { // Only update cache for domain/email types
            const cacheKey = blocklistType === 'domain' ? 'phishingDomains' : 'phishingEmails';
            const timestampKey = `${cacheKey}Timestamp`;
            const versionKey = `${cacheKey}Version`; // Need version key too
            const currentSet = await getValidCachedData(blocklistType) || new Set(); // Get current valid cache
            let cacheNeedsUpdate = false;

            if (isFalsePositive) {
                // Remove from cache if it was a false positive report
                if (currentSet.has(normalizedValue)) {
                    currentSet.delete(normalizedValue);
                    cacheNeedsUpdate = true;
                    console.log(`BG: Removed false positive ${blocklistType} '${normalizedValue}' from local cache.`);
                }
            } else {
                // Add to cache if it was a phishing report and not already present
                if (!currentSet.has(normalizedValue)) {
                    currentSet.add(normalizedValue);
                    cacheNeedsUpdate = true;
                    console.log(`BG: Added reported phishing ${blocklistType} '${normalizedValue}' to local cache for immediate blocking.`);
                }
            }

            if (cacheNeedsUpdate) {
                try {
                    const now = Date.now();
                    // Get the current version to save it back, preventing version reset
                    const versionData = await chrome.storage.local.get([versionKey]);
                    await chrome.storage.local.set({
                        [cacheKey]: Array.from(currentSet),
                        [timestampKey]: now, // Update timestamp
                        [versionKey]: versionData[versionKey] || 0 // Preserve version
                    });
                    if (chrome.runtime.lastError) {
                         console.error(`BG: Error saving updated cache after report for ${cacheKey}:`, chrome.runtime.lastError.message);
                    } else {
                         // Update in-memory cache as well
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
        } // end if (blocklistType)

        return true; // Report successful

    } catch (error) {
        // Includes network errors (Failed to fetch) and errors thrown above
        console.error(`BG: CRITICAL - Failed to send report for ${type} '${normalizedValue}'. Error:`, error);
        showNotification('Báo cáo thất bại', `Không thể gửi báo cáo tới máy chủ. Lỗi: ${error.message}`);
        return false; // Report failed
    }
}


// --- Event Listeners ---

// --- Installation & Startup ---
chrome.runtime.onInstalled.addListener(async (details) => {
    console.log(`BG: Extension ${details.reason}. Version: ${chrome.runtime.getManifest().version}`);
    await loadSettings(); // Load settings immediately
    console.log("BG: Initializing blocklist cache...");
    // Run initial cache update after settings are loaded
    await updateCacheFromAPI('domain');
    await updateCacheFromAPI('email');
    setupContextMenus(); // Setup context menus on install/update
    console.log("BG: Initialization complete.");
});

// Load settings on browser startup
chrome.runtime.onStartup.addListener(async () => {
    console.log("BG: Browser startup detected.");
    await loadSettings();
    // Optionally trigger an immediate cache update on startup as well
    console.log("BG: Triggering cache update on startup...");
    await updateCacheFromAPI('domain');
    await updateCacheFromAPI('email');
});

// --- Alarm for Periodic Cache Update ---
chrome.alarms.onAlarm.addListener(async (alarm) => {
    if (alarm.name === UPDATE_ALARM_NAME) {
        console.log(`BG: Received alarm "${alarm.name}". Running scheduled blocklist update...`);
        try {
             await updateCacheFromAPI('domain');
             await updateCacheFromAPI('email');
             console.log("BG: Scheduled blocklist update finished.");
        } catch (error) {
            // Errors are logged within updateCacheFromAPI
             console.error("BG: Error during scheduled update execution.", error);
        }
    }
});

// --- Tab Updates (URL Change Detection) ---
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    // Check if the URL changed and is a valid web URL
    if (changeInfo.url && isValidUrl(changeInfo.url)) {
        const url = changeInfo.url;
        // Ignore internal browser pages and our own extension pages
        if (url.startsWith('chrome://') || url.startsWith('about:') || url.startsWith('moz-extension://') || url.startsWith(chrome.runtime.getURL(''))) {
            return;
        }

        console.log(`BG: URL changed in tab ${tabId}: ${url}`);
        let domainToCheck = null;
        try {
            domainToCheck = normalizeDomain(new URL(url).hostname);
        } catch (urlError) {
            console.warn(`BG: Could not parse domain from changed URL "${url}":`, urlError.message);
            return; // Cannot check if domain is invalid
        }

        if (!domainToCheck) {
            console.warn(`BG: Could not normalize domain from changed URL "${url}"`);
            return;
        }

        // Perform the phishing check
        const result = await checkPhishing('domain', domainToCheck);

        if (result.isPhishing) {
            console.warn(`BG: PHISHING DETECTED [${result.reason}, Source: ${result.source}] - Domain: ${domainToCheck} from URL: ${url}`);
            // Redirect to warning page
            const warningPageUrlBase = chrome.runtime.getURL('warning/warning.html');
            const targetUrl = `${warningPageUrlBase}?url=${encodeURIComponent(url)}&domain=${encodeURIComponent(domainToCheck)}&reason=${encodeURIComponent(result.reason || 'Đã biết')}`;

            try {
                 // Check if the tab still exists and hasn't already been navigated away or to the warning page
                const currentTab = await chrome.tabs.get(tabId);
                 if (currentTab && currentTab.url && currentTab.url !== targetUrl && currentTab.url === url) { // Ensure we are redirecting the correct URL
                     console.log(`BG: Redirecting tab ${tabId} to warning page for ${domainToCheck}`);
                     await chrome.tabs.update(tabId, { url: targetUrl });
                 } else {
                      console.log(`BG: Tab ${tabId} navigation changed or already on warning page before redirection could complete. URL: ${currentTab?.url}`);
                 }
            } catch (tabError) {
                // Handle cases where the tab might have been closed between check and update
                if (tabError.message.includes("No tab with id") || tabError.message.includes("Invalid tab ID")) {
                     console.warn(`BG: Tab ${tabId} closed before phishing redirection could occur for ${domainToCheck}.`);
                } else {
                    console.error(`BG: Error updating tab ${tabId} to warning page:`, tabError);
                }
            }
        }
    }
});


// --- Message Handling (from Content Scripts, Popup, Options) ---
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    console.log("BG: Received message:", request.action, "from:", sender.tab ? `Tab ${sender.tab.id}`: "Extension");

    if (!request || !request.action) {
        console.warn("BG: Received invalid message structure:", request);
        // It's important to return false if not handling asynchronously
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
                    // Send a generic error response back
                    sendResponse({ isPhishing: false, error: error.message, reason: "Lỗi xử lý nội bộ", source: 'error' });
                });
            return true; // Indicates asynchronous response
        }
        case 'reportItem': {
            reportToAPI(request.type, request.value, request.context)
                .then(success => sendResponse({ success: success }))
                .catch(error => {
                     console.error(`BG: Error processing ${request.action}:`, error);
                     sendResponse({ success: false, message: error.message });
                });
            return true; // Indicates asynchronous response
        }
        case 'getApiStatus': {
            const healthUrl = `${currentApiBaseUrl}/health`;
            fetch(healthUrl, { method: 'GET', cache: 'no-cache' }) // Ensure it checks fresh status
                .then(response => sendResponse({ reachable: response.ok, status: response.status }))
                .catch(error => {
                    console.warn(`BG: API health check failed: ${error.message}`);
                    sendResponse({ reachable: false, error: error.message });
                 });
            return true; // Indicates asynchronous response
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
             return true; // Indicates asynchronous response (due to chrome.tabs.query callback)
         }
        case 'settingsUpdated': {
            console.log("BG: Received settingsUpdated message. Reloading settings and rescheduling alarm...");
            loadSettings().then(() => { // Reload settings and implicitly update alarm via loadSettings
                 // Optionally trigger immediate cache update after settings change
                 // updateCacheFromAPI('domain');
                 // updateCacheFromAPI('email');
                 sendResponse({ success: true });
            }).catch(error => {
                 console.error("BG: Error reloading settings after update message:", error);
                 sendResponse({ success: false, message: error.message });
            });
            return true; // Indicates asynchronous response
        }
        // Add cases for other actions if needed (e.g., whitelist)
        default:
            console.warn("BG: Received unhandled message action:", request.action);
            return false; // No asynchronous response planned
    }
});


// --- Context Menu Setup & Handling ---
function setupContextMenus() {
    // Use chrome.contextMenus.update to modify existing items if they exist,
    // or create them if they don't. This is more robust than removeAll + create.
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
                 // Ignore errors like "duplicate item id" if update isn't available in older Chrome versions
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
            const reportType = isFalsePositive ? 'false_positive_domain' : 'domain'; // Default to domain report for links
            const contextPrefix = isFalsePositive ? "Reported SAFE link" : "Reported PHISHING link";
            if (info.linkUrl && isValidUrl(info.linkUrl)) {
                try {
                    const domain = normalizeDomain(new URL(info.linkUrl).hostname);
                    if (domain) {
                        reportToAPI(reportType, domain, `${contextPrefix}: ${info.linkUrl}`);
                    } else {
                         // If domain extraction fails, maybe report the raw URL? Less useful for blocklists.
                        console.warn(`BG: Could not normalize domain from link ${info.linkUrl} for ${info.menuItemId}.`);
                         // reportToAPI('url', info.linkUrl, `${contextPrefix} (no domain): ${info.linkUrl}`); // Optional: report raw URL
                    }
                } catch (e) {
                     console.error(`BG: Error processing ${info.menuItemId} for link ${info.linkUrl}:`, e);
                     // reportToAPI('url', info.linkUrl, `${contextPrefix} (processing error): ${info.linkUrl}`); // Optional
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
                 // 3. Report as Text (only for actual phishing reports, not false positives)
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
                         // Optionally report the raw URL if domain fails for phishing, less useful for false positives
                         // if (!isFalsePositive) reportToAPI('url', info.pageUrl, `${contextPrefix} (no domain): ${info.pageUrl}`);
                     }
                 } catch (e) {
                      console.error(`BG: Error processing ${info.menuItemId} for page ${info.pageUrl}:`, e);
                      // if (!isFalsePositive) reportToAPI('url', info.pageUrl, `${contextPrefix} (processing error): ${info.pageUrl}`); // Optional
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

// --- Utility for Notifications ---
function showNotification(title, message) {
    try {
        chrome.notifications.create({
            type: 'basic',
            iconUrl: 'icons/icon-128.png', // Ensure this path is correct in manifest.json
            title: title || 'VN Phishing Guard Pro',
            message: message || '',
            priority: 1 // 0 is default, 1 and 2 are higher
        }, (notificationId) => {
             if (chrome.runtime.lastError) {
                 console.error("BG: Error showing notification:", chrome.runtime.lastError.message);
             }
        });
    } catch (e) {
         console.error("BG: Exception while trying to show notification:", e);
    }
}


// --- Initial Load ---
console.log(`VN Phishing Guard Pro Background Script Initializing (v${chrome.runtime.getManifest().version})...`);
// Initial setup is handled by onInstalled and onStartup listeners.