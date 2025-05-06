/* global chrome */
const DEFAULT_API_BASE_URL = 'http://127.0.0.1:5001/api';
const DEFAULT_CACHE_UPDATE_INTERVAL_MINUTES = 60;
const MIN_CACHE_UPDATE_INTERVAL_MINUTES = 5;
const MAX_CACHE_UPDATE_INTERVAL_MINUTES = 1440;
const CACHE_KEYS = {
    PHISHING_DOMAINS: 'phishingDomainsCache', PHISHING_EMAILS: 'phishingEmailsCache',
    WHITELISTED_DOMAINS: 'whitelistedDomainsCache', WHITELISTED_EMAILS: 'whitelistedEmailsCache',
    API_BASE_URL: 'apiBaseUrl', CACHE_UPDATE_INTERVAL: 'cacheUpdateIntervalMinutes',
    TEMP_ALLOWED_DOMAINS: 'tempAllowedDomainsSession'
};
const ALARM_NAME = 'phishingUpdateAlarm';
const SUSPICIOUS_EMAIL_KEYWORDS = [
    'xác minh tài khoản', 'verify your account', 'cập nhật thông tin', 'update your information','mật khẩu', 'password', 'đăng nhập', 'login', 'locked', 'khóa', 'restricted', 'hạn chế','ngân hàng', 'bank', 'thẻ tín dụng', 'credit card', 'số an sinh xã hội', 'ssn','khẩn cấp', 'urgent', 'quan trọng', 'important', 'hành động ngay', 'action required','truy cập bị hạn chế', 'access restricted', 'vấn đề bảo mật', 'security issue','thừa kế', 'inheritance', 'trúng thưởng', 'prize', 'xổ số', 'lottery', 'miễn phí', 'free offer','nhấp vào đây', 'click here', 'liên kết', 'link', 'tải xuống', 'download','hóa đơn', 'invoice', 'thanh toán', 'payment due', 'refund', 'hoàn tiền','yêu cầu đăng nhập', 'login required', 'xác thực', 'authenticate', 'secure message','tài khoản của bạn gặp rủi ro', 'your account is at risk'
];
const MIN_KEYWORD_MATCHES_FOR_WARNING = 2;

let currentApiBaseUrl = DEFAULT_API_BASE_URL;
let currentCacheUpdateIntervalMinutes = DEFAULT_CACHE_UPDATE_INTERVAL_MINUTES;
let memoryCache = {
    phishingDomains: new Set(), phishingEmails: new Set(),
    whitelistedDomains: new Set(), whitelistedEmails: new Set(),
    lastUpdated: { phishingDomains: 0, phishingEmails: 0, whitelistedDomains: 0, whitelistedEmails: 0 },
    version: { phishingDomains: null, phishingEmails: null, whitelistedDomains: null, whitelistedEmails: null }
};

async function initialize() {
    console.log("BG: Initializing...");
    try {
        await loadSettings(); await loadInitialCache(); setupAlarms(); setupListeners(); await clearExpiredTempAllows();
        setTimeout(updateAllCaches, 2000); // Cập nhật cache sớm hơn một chút
        console.log("BG: Initialization complete.");
    } catch (error) { console.error("BG: CRITICAL - Initialization failed:", error); }
}

async function loadSettings() {
    try {
        const settings = await chrome.storage.sync.get([CACHE_KEYS.API_BASE_URL, CACHE_KEYS.CACHE_UPDATE_INTERVAL]);
        currentApiBaseUrl = settings[CACHE_KEYS.API_BASE_URL] || DEFAULT_API_BASE_URL;
        currentCacheUpdateIntervalMinutes = settings[CACHE_KEYS.CACHE_UPDATE_INTERVAL] || DEFAULT_CACHE_UPDATE_INTERVAL_MINUTES;
    } catch (error) { console.error("BG: Error loading settings:", error); currentApiBaseUrl = DEFAULT_API_BASE_URL; currentCacheUpdateIntervalMinutes = DEFAULT_CACHE_UPDATE_INTERVAL_MINUTES; }
}

async function loadInitialCache() {
    const cacheTypes = ['phishingDomains', 'phishingEmails', 'whitelistedDomains', 'whitelistedEmails'];
    for (const type of cacheTypes) {
        const storageKey = CACHE_KEYS[type.replace(/([A-Z])/g, '_$1').toUpperCase()];
        try {
            const result = await chrome.storage.local.get(storageKey);
            if (result?.[storageKey]?.items && Array.isArray(result[storageKey].items)) {
                memoryCache[type] = new Set(result[storageKey].items);
                memoryCache.lastUpdated[type] = result[storageKey].timestamp || 0;
                memoryCache.version[type] = result[storageKey].version || null;
                 console.log(`BG: Loaded ${memoryCache[type].size} items into ${type}`);
            } else { memoryCache[type] = new Set(); memoryCache.lastUpdated[type] = 0; memoryCache.version[type] = null; }
        } catch (error) { console.error(`BG: Error loading cache ${storageKey}:`, error); memoryCache[type] = new Set(); }
    }
}

function setupAlarms() {
    const interval = Math.max(MIN_CACHE_UPDATE_INTERVAL_MINUTES, Math.min(currentCacheUpdateIntervalMinutes, MAX_CACHE_UPDATE_INTERVAL_MINUTES));
    chrome.alarms.create(ALARM_NAME, { periodInMinutes: interval });
    if (chrome.alarms.onAlarm.hasListener(handleAlarm)) { chrome.alarms.onAlarm.removeListener(handleAlarm); } // Tránh listener trùng lặp
    chrome.alarms.onAlarm.addListener(handleAlarm);
}

function handleAlarm(alarm) {
    if (alarm.name === ALARM_NAME) updateAllCaches().catch(e => console.error("BG: Error in scheduled cache update:", e));
}

function setupListeners() {
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        const action = message.action;
        if (action === 'checkDomain') { checkPhishing('domain', message.domain).then(sendResponse).catch(e => sendResponse({ isPhishing: false, status: 'error', reason: 'Lỗi kiểm tra' })); return true; }
        if (action === 'checkEmailDetails') { handleCheckEmailDetails(message.senderEmail, message.emailContent, message.emailSubject).then(sendResponse).catch(e => sendResponse({ isPhishing: false, status: 'error', reason: 'Lỗi kiểm tra nội dung' })); return true; }
        if (action === 'reportItem') { reportItem(message.type, message.value, message.reason, message.context).then(sendResponse).catch(e => sendResponse({ success: false, message: 'Lỗi gửi báo cáo' })); return true; }
        if (action === 'settingsUpdated') { loadSettings().then(() => { setupAlarms(); updateAllCaches(); }); }
        if (action === 'addTemporaryAllowDomain') { addTemporaryAllow(message.domain).then(() => sendResponse({success: true})).catch(e => sendResponse({success: false, error: e.message})); return true; }
        return false;
    });

    if (chrome.webRequest?.onBeforeRequest) {
        if (chrome.webRequest.onBeforeRequest.hasListener(handleWebRequest)) { chrome.webRequest.onBeforeRequest.removeListener(handleWebRequest); } // Tránh listener trùng lặp
        chrome.webRequest.onBeforeRequest.addListener(handleWebRequest, { urls: ["<all_urls>"], types: ["main_frame"] });
    } else { console.error("BG: chrome.webRequest API not available."); }
}

async function handleWebRequest(details) {
    // Bỏ qua nếu là yêu cầu từ chính extension hoặc không phải http/https
    if ((details.initiator && details.initiator.startsWith(`chrome-extension://${chrome.runtime.id}`)) || !details.url?.startsWith('http')) return;

    const domain = normalizeDomain(details.url);
    if (!domain) return;

    const isTempAllowed = await checkTemporaryAllow(domain);
    if (isTempAllowed) { console.log(`BG: Temp allow for ${domain}. Skipping check.`); return; }

    if (memoryCache.whitelistedDomains.has(domain)) { console.log(`BG: Whitelisted domain ${domain}. Skipping check.`); return; }

    // Kiểm tra cache trước
    if (memoryCache.phishingDomains.has(domain)) {
        console.warn(`BG: Phishing domain DETECTED (cache): ${domain}`);
        injectWarningScript(details.tabId, 'domain', domain, details.url, "Trang web này nằm trong danh sách chặn đã biết (cache).");
        return; // Không chặn, chỉ cảnh báo
    }

    // Nếu không có trong cache, kiểm tra API (không đồng bộ)
    // Điều này có thể không hiển thị cảnh báo cho lần truy cập *đầu tiên* nếu cache cũ,
    // nhưng sẽ cập nhật cache cho lần sau và tránh làm chậm điều hướng.
    checkPhishing('domain', domain).then(result => {
         if(result.isPhishing && !memoryCache.phishingDomains.has(domain)) { // Chỉ cảnh báo nếu API tìm thấy và chưa có trong cache
              console.warn(`BG: Phishing domain DETECTED (API): ${domain}`);
              // Cần lấy lại tabId vì hàm này chạy bất đồng bộ. Sử dụng details.tabId có thể không còn chính xác
              // nếu tab đã thay đổi. Cách tốt hơn là query tab hiện tại dựa trên URL nếu cần.
              // Tuy nhiên, để đơn giản, ta vẫn dùng details.tabId nhưng có thể không đáng tin cậy 100%.
              injectWarningScript(details.tabId, 'domain', domain, details.url, `Trang web này bị chặn bởi API (${result.reason || ''}).`);
         }
    }).catch(e => console.error(`BG: фоновая проверка API для ${domain} не удалась:`, e));
}

function injectWarningScript(tabId, type, item, fullUrl, reason) {
    chrome.scripting.executeScript({
        target: { tabId: tabId },
        files: ['scripts/show_warning_popup.js']
    }).then(() => {
        setTimeout(() => { // Đảm bảo script đã inject
            chrome.tabs.sendMessage(tabId, {
                 action: 'showPhishingWarningPopup', type: type, blockedItem: item, fullUrl: fullUrl, reason: reason
            }).catch(e => { /* Lỗi gửi tin nhắn có thể xảy ra nếu tab đóng nhanh */ });
        }, 150);
    }).catch(e => console.error(`BG: Failed to inject script into tab ${tabId}:`, e));
}


async function addTemporaryAllow(domain) {
    if (!domain) return; const normalizedDomain = normalizeDomain(domain); if (!normalizedDomain) return;
    const expiryTime = Date.now() + (30 * 60 * 1000);
    try {
        const data = await chrome.storage.session.get(CACHE_KEYS.TEMP_ALLOWED_DOMAINS);
        const allows = data[CACHE_KEYS.TEMP_ALLOWED_DOMAINS] || {}; allows[normalizedDomain] = expiryTime;
        await chrome.storage.session.set({ [CACHE_KEYS.TEMP_ALLOWED_DOMAINS]: allows });
    } catch (error) { console.error(`BG: Failed save temp allow ${normalizedDomain}:`, error); throw error; }
}

async function checkTemporaryAllow(domain) {
    if (!domain) return false; const normalizedDomain = normalizeDomain(domain); if (!normalizedDomain) return false;
    try {
        const data = await chrome.storage.session.get(CACHE_KEYS.TEMP_ALLOWED_DOMAINS); const allows = data[CACHE_KEYS.TEMP_ALLOWED_DOMAINS] || {};
        const expiryTime = allows[normalizedDomain];
        if (expiryTime && Date.now() < expiryTime) return true;
        if (expiryTime) { delete allows[normalizedDomain]; await chrome.storage.session.set({ [CACHE_KEYS.TEMP_ALLOWED_DOMAINS]: allows }); }
        return false;
    } catch (error) { console.error(`BG: Failed check temp allow ${normalizedDomain}:`, error); return false; }
}

async function clearExpiredTempAllows() {
     try {
        const data = await chrome.storage.session.get(CACHE_KEYS.TEMP_ALLOWED_DOMAINS); let allows = data[CACHE_KEYS.TEMP_ALLOWED_DOMAINS] || {};
        const now = Date.now(); let changed = false;
        for (const domain in allows) { if (allows[domain] < now) { delete allows[domain]; changed = true; } }
        if (changed) await chrome.storage.session.set({ [CACHE_KEYS.TEMP_ALLOWED_DOMAINS]: allows });
     } catch (error) { console.error("BG: Error clearing expired temp allows:", error); }
}

function normalizeDomain(url) {
    if (!url || typeof url !== 'string') return null;
    try {
        let hostname = url; if (url.includes('://') || url.startsWith('//')) { hostname = new URL(url.startsWith('//') ? 'http:' + url : url).hostname; }
        hostname = hostname.toLowerCase().replace(/^www\./, '').replace(/\.$/, '').trim();
        if (!hostname || !hostname.includes('.') || /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) return null;
        return hostname;
    } catch (e) { return null; }
}

function normalizeEmail(email) {
   if (!email || typeof email !== 'string') return null;
   const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
   const normalized = email.toLowerCase().trim(); return emailRegex.test(normalized) ? normalized : null;
}

function scanTextForKeywords(text, subject = '') {
    if (!text && !subject) return { hasSuspiciousKeywords: false, keywordsFound: [] };
    const combinedText = ((text || '') + ' ' + (subject || '')).toLowerCase();
    const foundKeywords = SUSPICIOUS_EMAIL_KEYWORDS.filter(keyword => combinedText.includes(keyword.toLowerCase()));
    return { hasSuspiciousKeywords: foundKeywords.length >= MIN_KEYWORD_MATCHES_FOR_WARNING, keywordsFound: foundKeywords };
}

async function handleCheckEmailDetails(senderEmail, emailContent, emailSubject) {
    const normalizedSender = normalizeEmail(senderEmail);
    let senderResult = { isPhishing: false, status: 'safe', reason: 'N/A' };
    if (normalizedSender) { senderResult = await checkPhishing('email', normalizedSender); }
    else { senderResult = { isPhishing: false, status: 'invalid', reason: 'Invalid sender' }; }

    const contentResult = scanTextForKeywords(emailContent, emailSubject);
    const overallPhishing = senderResult.isPhishing || contentResult.hasSuspiciousKeywords;
    let overallReason = "";
    if (senderResult.isPhishing) overallReason += senderResult.reason;
    if (contentResult.hasSuspiciousKeywords) overallReason += (overallReason ? '; ' : '') + `Nội dung/tiêu đề chứa (${contentResult.keywordsFound.slice(0,2).join(', ')}...).`;
    if (!overallReason && overallPhishing) overallReason = "Email có dấu hiệu đáng ngờ."; // Fallback

    return { isPhishing: overallPhishing, senderStatus: senderResult.status, senderReason: senderResult.reason, contentScan: contentResult };
}

async function fetchApiData(endpoint) {
    const urlPath = endpoint.startsWith('/') ? endpoint : `/${endpoint}`; const url = `${currentApiBaseUrl}${urlPath}`;
    console.log(`BG: Fetching: ${url}`);
    try {
        const response = await fetch(url, { method: 'GET', headers: { 'Accept': 'application/json' }});
        if (!response.ok) {
            let errorBody = await response.text(); let errorMsg = `HTTP ${response.status}`;
            try { errorMsg = JSON.parse(errorBody)?.error || errorMsg; } catch(e){}
            console.error(`BG: API fail ${url}. Status: ${response.status}. Body: ${errorBody}`);
            throw new Error(errorMsg);
        }
        const data = await response.json();
        if (typeof data !== 'object' || data === null) throw new Error('API response not object.');
        if ((urlPath.includes('/list')) && (!Array.isArray(data.items) || typeof data.version === 'undefined')) throw new Error('Invalid list API struct.');
        if (urlPath.includes('/check') && typeof data.status === 'undefined') throw new Error('Invalid check API struct.');
        return data;
    } catch (error) {
        if (error.message.includes('fetch')) {
            console.error(`BG: Network error fetch ${url}. Backend running at ${currentApiBaseUrl}?`, error);
            throw new Error(`Không thể kết nối tới máy chủ cục bộ (${currentApiBaseUrl}). Hãy đảm bảo nó đang chạy.`);
        }
        throw error;
    }
}

async function updateCacheFromAPI(listType, itemType) {
    const memoryKey = `${listType}${itemType.charAt(0).toUpperCase() + itemType.slice(1)}s`;
    const storageKey = CACHE_KEYS[`${listType.toUpperCase()}_${itemType.toUpperCase()}S`];
    const endpoint = `/${listType}?type=${itemType}`;
    try {
        const apiData = await fetchApiData(endpoint);
        if (!Array.isArray(apiData.items)) throw new Error(`Invalid items for ${memoryKey}.`);
        const currentVersion = memoryCache.version[memoryKey]; const newVersion = apiData.version;
        if (newVersion !== null && newVersion !== undefined && newVersion === currentVersion) {
            if (memoryCache.lastUpdated[memoryKey] === 0) {
                 memoryCache.lastUpdated[memoryKey] = Date.now();
                 await chrome.storage.local.set({ [storageKey]: { items: Array.from(memoryCache[memoryKey]), timestamp: Date.now(), version: newVersion }});
            }
            return;
        }
        const oldSize = memoryCache[memoryKey]?.size ?? 0;
        memoryCache[memoryKey] = new Set(apiData.items);
        memoryCache.lastUpdated[memoryKey] = Date.now();
        memoryCache.version[memoryKey] = newVersion;
        await chrome.storage.local.set({ [storageKey]: { items: apiData.items, timestamp: Date.now(), version: newVersion }});
        console.log(`BG: Updated ${memoryKey}. Ver: ${newVersion}. Size: ${oldSize} -> ${apiData.items.length}.`);
    } catch (error) { console.error(`BG: CRITICAL - Failed update ${memoryKey} cache (${endpoint}). Error:`, error.message); }
}

async function updateAllCaches() {
    console.log("BG: Starting cache update...");
    await Promise.allSettled([
        updateCacheFromAPI('blocklist', 'domain'), updateCacheFromAPI('blocklist', 'email'),
        updateCacheFromAPI('whitelist', 'domain'), updateCacheFromAPI('whitelist', 'email')
    ]);
    console.log("BG: Cache update process finished.");
}

async function checkPhishing(type, value) {
    const normalizedValue = type === 'domain' ? normalizeDomain(value) : normalizeEmail(value);
    if (!normalizedValue) return { isPhishing: false, status: 'invalid', reason: "Invalid value", source: 'local' };
    const wKey = `whitelisted${type.charAt(0).toUpperCase() + type.slice(1)}s`;
    const pKey = `phishing${type.charAt(0).toUpperCase() + type.slice(1)}s`;
    if (memoryCache[wKey]?.has(normalizedValue)) return { isPhishing: false, status: 'whitelisted', reason: "Whitelisted (cache)", source: 'cache' };
    if (memoryCache[pKey]?.has(normalizedValue)) return { isPhishing: true, status: 'blocked', reason: "Blocklisted (cache)", source: 'cache' };

    try {
        const responseData = await fetchApiData(`/check?type=${type}&value=${encodeURIComponent(normalizedValue)}`);
        if (responseData.status === 'blocked' && !memoryCache[pKey]?.has(normalizedValue)) { updateCacheFromAPI('blocklist', type).catch(e => {}); }
        else if (responseData.status === 'whitelisted' && !memoryCache[wKey]?.has(normalizedValue)) { updateCacheFromAPI('whitelist', type).catch(e => {}); }
        return { isPhishing: responseData.status === 'blocked', status: responseData.status, reason: `API check (${responseData.status})`, source: 'api', details: responseData.details };
    } catch (error) { console.error(`BG: API check fail ${type} '${normalizedValue}':`, error.message); return { isPhishing: false, status: 'error', reason: `API Error: ${error.message}`, source: 'api_error' }; }
}

async function reportItem(reportType, value, reason = '', context = '') {
    let apiType = reportType.replace('false_positive_', '');
    let apiValue = (apiType === 'domain' ? normalizeDomain(value) : normalizeEmail(value)) || value; // Normalize or keep original if fail
    if (!apiValue) return { success: false, message: `Invalid ${apiType} value.` };
    let apiReason = reportType.startsWith('false_positive_') ? `False Positive: ${reason || value}. Ctx: ${context}` : reason;

    try {
        const response = await fetch(`${currentApiBaseUrl}/report`, {
            method: 'POST', headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
            body: JSON.stringify({ type: reportType, value: apiValue, reason: apiReason, source: 'chrome_extension' })
        });
        const responseData = await response.json();
        if (!response.ok) throw new Error(responseData.error || `API Error ${response.status}`);

         if (!reportType.startsWith('false_positive_') && ['domain', 'email'].includes(apiType)) {
              updateCacheFromAPI('blocklist', apiType).catch(e => {});
         }
        return { success: true, ...responseData };
    } catch (error) {
        let errMsg = error.message.includes('fetch') ? `Network error sending report. Is backend running?` : `Report error: ${error.message}`;
        return { success: false, message: errMsg };
    }
}

initialize();