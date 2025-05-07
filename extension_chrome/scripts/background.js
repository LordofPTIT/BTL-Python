let API_BASE_URL_BG = 'http://127.0.0.1:5000/api'; // Default API URL
let currentPhishingUrl = null;
let currentTabId = null;

const PHISHING_KEYWORDS_VN_DEFAULT = [ "xác minh tài khoản", "đăng nhập khẩn cấp", "tài khoản của bạn đã bị khóa", "thông tin tài khoản", "cập nhật thông tin", "khẩn cấp", "quan trọng", "mật khẩu của bạn đã hết hạn", "quà tặng miễn phí", "trúng thưởng", "ưu đãi đặc biệt", "nhấp vào đây", "liên kết này", "yêu cầu thanh toán", "hóa đơn chưa thanh toán", "ngân hàng", "vietcombank", "techcombank", "agribank", "bidv", "sacombank", "vpbank", "momo", "zalopay", "cảnh báo bảo mật", "hoạt động đáng ngờ", "phiên đăng nhập lạ", "ủy quyền", "xác thực", "mã OTP", "giao dịch đang chờ xử lý", "hỗ trợ khách hàng", "chính phủ", "thuế", "bảo hiểm xã hội", "công an", "thông báo từ cơ quan nhà nước", "apple", "microsoft", "google", "facebook", "amazon", "paypal", "netflix", "lazada", "shopee", "tiki", "thừa kế", "triệu phú", "đầu tư lợi nhuận cao", "cơ hội việc làm", "làm việc tại nhà lương cao", "urgent", "verify your account", "account locked", "update your details", "password expired", "free gift", "you have won", "special offer", "click here", "payment request", "unpaid invoice", "security alert", "suspicious activity", "unusual sign-in", "confirm your identity", "chúng tôi phát hiện", "hoạt động bất thường", "yêu cầu thông tin cá nhân", "cung cấp ngay", "số thẻ tín dụng", "mã bảo mật CVV", "thông tin đăng nhập", "tên người dùng và mật khẩu", "thông báo trúng thưởng lớn", "bạn là người may mắn", "giải thưởng giá trị cao", "đòi tiền chuộc", "dữ liệu của bạn đã bị mã hóa", "thanh toán để giải mã" ];

async function loadApiBaseUrl() {
    try {
        const data = await chrome.storage.sync.get('apiBaseUrl');
        if (data.apiBaseUrl) {
            API_BASE_URL_BG = data.apiBaseUrl;
        } else {
            await chrome.storage.sync.set({ 'apiBaseUrl': API_BASE_URL_BG });
        }
        console.log("Background API URL set to:", API_BASE_URL_BG);
    } catch (e) {
        console.error("Error loading API base URL in background:", e);
    }
}

async function initializeExtension() {
    console.log("VN Phishing Guard Pro initializing...");
    await loadApiBaseUrl();
    await updateLocalBlocklists();
    await loadAndStoreKeywords();
    schedulePeriodicUpdates();
}

chrome.runtime.onInstalled.addListener((details) => {
    console.log("VN Phishing Guard Pro installed/updated. Reason:", details.reason);
    initializeExtension();
    chrome.contextMenus.create({
        id: "reportSelectedText",
        title: "Báo cáo là Phishing/Độc hại",
        contexts: ["selection"]
    });
});

chrome.runtime.onStartup.addListener(() => {
    console.log("VN Phishing Guard Pro started.");
    initializeExtension();
});

function schedulePeriodicUpdates() {
    chrome.alarms.get('periodicBlocklistUpdate', alarm => {
        if (!alarm) {
            chrome.alarms.create('periodicBlocklistUpdate', { periodInMinutes: 60 });
            console.log("Periodic blocklist update alarm created.");
        }
    });
    chrome.alarms.get('periodicKeywordUpdate', alarm => {
        if (!alarm) {
            chrome.alarms.create('periodicKeywordUpdate', { periodInMinutes: 120 });
            console.log("Periodic keyword update alarm created.");
        }
    });
}

chrome.alarms.onAlarm.addListener(alarm => {
    if (alarm.name === 'periodicBlocklistUpdate') {
        console.log("Performing periodic update of local blocklists...");
        updateLocalBlocklists();
    } else if (alarm.name === 'periodicKeywordUpdate'){
        console.log("Performing periodic update of keywords...");
        loadAndStoreKeywords();
    }
});

async function loadAndStoreKeywords() {
    const keywordsFilePath = 'data/phishing_keywords_vn.json';
    const fullKeywordsUrl = chrome.runtime.getURL(keywordsFilePath);
    console.log("Attempting to fetch keywords from:", fullKeywordsUrl);
    try {
        const response = await fetch(fullKeywordsUrl);
        if (response.ok) {
            const keywords = await response.json();
            await chrome.storage.local.set({ localKeywords: keywords });
            console.log("Phishing keywords loaded and stored from JSON.");
        } else {
            console.warn(`Failed to load keywords from JSON (status: ${response.status}), using default list. URL: ${fullKeywordsUrl}`);
            await chrome.storage.local.set({ localKeywords: PHISHING_KEYWORDS_VN_DEFAULT });
        }
    } catch (error) {
        console.error("Error fetching or storing keywords, using default list. URL attempted:", fullKeywordsUrl, error);
        await chrome.storage.local.set({ localKeywords: PHISHING_KEYWORDS_VN_DEFAULT });
    }
}

function parsePlainList(text) {
    const lines = text.split(/\r?\n/);
    const rules = [];
    const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    for (const line of lines) {
        const trimmedLine = line.trim().toLowerCase();
        if (!trimmedLine || trimmedLine.startsWith('!') || trimmedLine.startsWith('#') || trimmedLine.startsWith('/') || trimmedLine.includes('*')) continue;

        if (emailRegex.test(trimmedLine)) {
            continue;
        }
        let domainPart = trimmedLine;
        try {
            if (domainPart.startsWith("http://")) domainPart = domainPart.substring(7);
            if (domainPart.startsWith("https://")) domainPart = domainPart.substring(8);
            if (domainPart.includes("/")) domainPart = domainPart.split("/")[0];
            domainPart = domainPart.replace(/^www\./, '');
            if (domainPart.includes('.')) {
                rules.push({ domain: domainPart, path: null, original: trimmedLine, type: 'domain' });
            }
        } catch (e) {
            // console.warn(`Could not parse plain list item as domain: ${trimmedLine}`, e);
        }
    }
    return rules;
}

function parseABPList(text, originalFileName) {
    const lines = text.split(/\r?\n/);
    const rules = [];
    for (const line of lines) {
        if (line.startsWith('!') || line.startsWith('#') || line.trim() === '') continue;
        let ruleString = line;
        let itemType = 'domain';
        if (ruleString.startsWith('||')) {
            ruleString = ruleString.substring(2);
        }
        const caratIndex = ruleString.indexOf('^');
        if (caratIndex !== -1) ruleString = ruleString.substring(0, caratIndex);
        const dollarIndex = ruleString.indexOf('$');
        if (dollarIndex !== -1) ruleString = ruleString.substring(0, dollarIndex);
        ruleString = ruleString.toLowerCase();
        const slashIndex = ruleString.indexOf('/');
        let domainPart = ruleString;
        let pathPattern = null;
        if (slashIndex !== -1) {
            domainPart = ruleString.substring(0, slashIndex);
            pathPattern = ruleString.substring(slashIndex);
            if (pathPattern.endsWith('/')) {
                pathPattern = pathPattern.slice(0, -1);
            }
        } else {
            if (ruleString.endsWith('/')) {
                domainPart = ruleString.slice(0, -1);
            }
        }
        domainPart = domainPart.replace(/^www\./, '');
        if (domainPart) {
            if (pathPattern && pathPattern !== "/") {
                rules.push({ domain: domainPart, path: pathPattern, original: line, type: itemType });
            } else {
                rules.push({ domain: domainPart, path: null, original: line, type: itemType });
            }
        }
    }
    return rules;
}

async function updateLocalBlocklists() {
    const filesToParse = [
        { path: 'data/CLDBllacklist.txt', type: 'abp', name: 'CLDB' },
        { path: 'data/urls-ABP.txt', type: 'abp', name: 'urls-ABP' },
        { path: 'data/urls.txt', type: 'plain', name: 'urls.txt' }
    ];
    let combinedRules = [];
    const uniqueRuleKeys = new Set();
    for (const file of filesToParse) {
        const fullUrl = chrome.runtime.getURL(file.path);
        console.log(`Processing local list: ${fullUrl} (type: ${file.type})`);
        try {
            const response = await fetch(fullUrl);
            if (!response.ok) {
                console.error(`Failed to fetch ${file.path}: ${response.status}`);
                continue;
            }
            const text = await response.text();
            let parsedItems = [];
            if (file.type === 'abp') {
                parsedItems = parseABPList(text, file.name);
            } else if (file.type === 'plain') {
                parsedItems = parsePlainList(text);
            }
            for (const item of parsedItems) {
                let ruleKey = item.domain;
                if (item.path) {
                    ruleKey += `|${item.path}`;
                }
                if (!uniqueRuleKeys.has(ruleKey)) {
                    uniqueRuleKeys.add(ruleKey);
                    combinedRules.push(item);
                }
            }
        } catch (error) {
            console.error(`Error processing file ${file.path}:`, error);
        }
    }
    await chrome.storage.local.set({ combinedLocalBlocklistRules: combinedRules, lastLocalListUpdate: Date.now() });
    console.log("Combined local blocklist rules updated and stored.", combinedRules.length, "rules processed.");
}

async function isUrlTemporarilyAllowed(urlString) {
    if (!urlString) return false;
    try {
        const data = await chrome.storage.session.get('sessionWhitelistedUrls');
        const sessionWhitelistedUrls = data.sessionWhitelistedUrls || [];
        const urlObj = new URL(urlString);
        const hostname = urlObj.hostname.toLowerCase().replace(/^www\./, '');
        if (sessionWhitelistedUrls.includes(urlString.toLowerCase()) || sessionWhitelistedUrls.includes(hostname)) {
            console.log(`URL ${urlString} is temporarily allowed via session whitelist.`);
            return true;
        }
    } catch (error) {
        console.error("Error checking session whitelist:", error);
    }
    return false;
}

async function isDomainUserWhitelisted(domain) {
    if (!domain) return false;
    try {
        const data = await chrome.storage.sync.get('userAllowlist');
        const userAllowlist = data.userAllowlist || [];
        return userAllowlist.includes(domain.toLowerCase());
    } catch (error) {
        console.error("Error checking user allowlist:", error);
        return false;
    }
}


function isUrlInParsedList(currentUrlString, parsedRules) {
    if (!parsedRules || parsedRules.length === 0) return false;
    try {
        const currentUrl = new URL(currentUrlString);
        const currentHostname = currentUrl.hostname.toLowerCase().replace(/^www\./, '');
        const currentPath = currentUrl.pathname.toLowerCase();
        for (const rule of parsedRules) {
            if (rule.type !== 'domain' && rule.type !== undefined) continue;
            const isExactDomainMatch = currentHostname === rule.domain;
            const isSubdomainMatch = currentHostname.endsWith('.' + rule.domain);
            if (!isExactDomainMatch && !isSubdomainMatch) {
                continue;
            }
            if (rule.path) {
                if (currentPath.startsWith(rule.path)) {
                    return true;
                }
            } else {
                return true;
            }
        }
    } catch (e) {
        console.error("Error in isUrlInParsedList:", currentUrlString, e);
    }
    return false;
}

async function checkUrlAgainstLocalLists(tabId, url) {
    if (!url || (!url.startsWith('http:') && !url.startsWith('https:'))) {
        return {isPhishing: false, reason: "Không phải URL HTTP/HTTPS"};
    }

    const urlObj = new URL(url);
    const domainToCheck = urlObj.hostname.toLowerCase().replace(/^www\./, '');

    if (await isDomainUserWhitelisted(domainToCheck)) {
        console.log(`Domain ${domainToCheck} is whitelisted by user.`);
        return {isPhishing: false, reason: "Nằm trong danh sách người dùng cho phép (Whitelist)."};
    }

    if (await isUrlTemporarilyAllowed(url)) {
        return {isPhishing: false, reason: "Đã được người dùng cho phép tạm thời trong phiên này."};
    }

    try {
        const { combinedLocalBlocklistRules } = await chrome.storage.local.get('combinedLocalBlocklistRules');
        if (combinedLocalBlocklistRules && isUrlInParsedList(url, combinedLocalBlocklistRules)) {
            console.log("URL matched in combined local blocklist:", url);
            const reason = "Trang web này nằm trong danh sách chặn cục bộ của bạn.";
            showCustomNotificationOrWarningPage(tabId, url, "Local Blocklist", reason);
            return {isPhishing: true, reason: reason, listName: "Local Blocklist"};
        }
    } catch (error) {
        console.error("Error checking URL with combined local blocklist:", error);
    }
    return {isPhishing: false, reason: "Không tìm thấy trong danh sách chặn cục bộ."};
}

async function checkUrlWithBackend(tabId, urlString) {
    if (!urlString || (!urlString.startsWith('http:') && !urlString.startsWith('https:'))) {
        return {isPhishing: false, reason: "Không phải URL HTTP/HTTPS"};
    }

    const urlObj = new URL(urlString);
    const domain = urlObj.hostname.toLowerCase().replace(/^www\./, '');

    if (await isDomainUserWhitelisted(domain)) {
      console.log(`Domain ${domain} is whitelisted by user, skipping backend check.`);
      return {isPhishing: false, reason: "Nằm trong danh sách người dùng cho phép (Whitelist)."};
    }

    if (await isUrlTemporarilyAllowed(urlString)) {
        return {isPhishing: false, reason: "Đã được người dùng cho phép tạm thời trong phiên này."};
    }
    try {
        const response = await fetch(`${API_BASE_URL_BG}/check?type=domain&value=${encodeURIComponent(domain)}`);
        if (!response.ok) {
            console.error(`Backend check failed for ${domain}: ${response.status}`);
            return {isPhishing: false, reason: `Lỗi kiểm tra backend: ${response.status}`};
        }
        const data = await response.json();
        if (data.status === 'blocked') {
            console.log(`Domain ${domain} is BLOCKED by backend. Reason: ${data.reason}`);
            const reason = `Tên miền ${domain} bị chặn bởi máy chủ. Lý do: ${data.reason || 'Nằm trong danh sách nguy hiểm.'}`;
            showCustomNotificationOrWarningPage(tabId, urlString, "Backend Blocklist", reason);
            return {isPhishing: true, reason: reason, listName: "Backend Blocklist"};
        } else if (data.status === 'whitelisted') {
            console.log(`Domain ${domain} is whitelisted by backend.`);
            return {isPhishing: false, reason: "Nằm trong danh sách trắng (Whitelist) của máy chủ."};
        }
        return {isPhishing: false, reason: "An toàn theo kiểm tra từ backend."};
    } catch (error) {
        console.error(`Error checking URL ${urlString} with backend:`, error);
        return {isPhishing: false, reason: `Lỗi kết nối backend: ${error.message}`};
    }
}


async function handleUrlCheck(tabId, url, referrer) {
    const localCheckResult = await checkUrlAgainstLocalLists(tabId, url);
    if (localCheckResult.isPhishing) {
        // Đã bị chặn bởi local list, không cần kiểm tra backend nữa
        return;
    }
    // Nếu không bị chặn bởi local list, và cũng không phải user whitelist, thì kiểm tra backend
    if (!localCheckResult.reason || !localCheckResult.reason.includes("Whitelist")) {
        await checkUrlWithBackend(tabId, url);
    }
}


chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url && tab.active) {
        currentPhishingUrl = tab.url;
        currentTabId = tabId;
        console.log(`Navigating to (onUpdated - complete): ${tab.url}`);
        const referrer = changeInfo.url && changeInfo.url !== tab.url ? changeInfo.url : (tab.referrer || '');
        await handleUrlCheck(tabId, tab.url, referrer);
    }
});


function showCustomNotificationOrWarningPage(tabId, url, listName, reason, referrer) {
    currentPhishingUrl = url;
    currentTabId = tabId;

    chrome.storage.local.get(['warningType'], async (settings) => {
        const warningType = settings.warningType || 'warning_page';
        if (warningType === 'notification') {
            chrome.notifications.create('phishingNotif-' + Date.now(), {
                type: 'basic',
                iconUrl: 'icons/icon-128.png',
                title: 'Cảnh Báo Phishing!',
                message: `Trang ${url.substring(0, 100)}... có dấu hiệu lừa đảo (${listName}). Lý do: ${reason.substring(0,100)}...`,
                priority: 2,
                buttons: [{ title: 'Xem chi tiết cảnh báo' }]
            });
        } else {
            let prevSafeUrl = 'chrome://newtab';
            if (tabId) {
                try {
                    const tab = await chrome.tabs.get(tabId);
                    if (tab && tab.openerTabId) {
                        const openerTab = await chrome.tabs.get(tab.openerTabId);
                        if (openerTab && openerTab.url && openerTab.url !== url) {
                           prevSafeUrl = openerTab.url;
                        }
                    } else if (referrer && referrer !== url && (referrer.startsWith('http:') || referrer.startsWith('https:'))) {
                         prevSafeUrl = referrer;
                    }
                } catch (e) {
                    console.warn("Error getting previous tab URL:", e);
                }
            }

            const warningPageUrl = chrome.runtime.getURL('warning/warning.html') +
                `?url=${encodeURIComponent(url)}` +
                `&listName=${encodeURIComponent(listName)}` +
                `&reason=${encodeURIComponent(reason)}` +
                `&tabId=${tabId}` +
                `&prevSafeUrl=${encodeURIComponent(prevSafeUrl)}`;
            chrome.tabs.update(tabId, { url: warningPageUrl });
        }
    });
}

chrome.notifications.onButtonClicked.addListener((notificationId, buttonIndex) => {
    if (notificationId.startsWith('phishingNotif-') && buttonIndex === 0) {
        if (currentPhishingUrl && currentTabId) {
            // Logic để lấy prevSafeUrl tương tự như trong showCustomNotificationOrWarningPage
            // Cần đảm bảo referrer hoặc thông tin tab trước đó có sẵn ở đây nếu cần
            let prevSafeUrlForNotif = 'chrome://newtab'; // Fallback
            // Giả sử currentTabId và currentPhishingUrl là đủ, và warning.js sẽ xử lý logic quay lại

            const warningPageUrl = chrome.runtime.getURL('warning/warning.html') +
                `?url=${encodeURIComponent(currentPhishingUrl)}` +
                `&listName=${encodeURIComponent("Chi tiết từ Notification")}` +
                `&reason=${encodeURIComponent("Người dùng nhấp vào thông báo để xem chi tiết.")}` +
                `&tabId=${currentTabId}` +
                `&prevSafeUrl=${encodeURIComponent(prevSafeUrlForNotif)}`;
            chrome.tabs.create({ url: warningPageUrl });
        }
        chrome.notifications.clear(notificationId);
    }
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    (async () => {
        if (request.action === "getCurrentTabInfo") {
            if (sender.tab && sender.tab.id) {
                try {
                    const tab = await chrome.tabs.get(sender.tab.id);
                    const url = tab.url;
                    if (url && (url.startsWith('http:') || url.startsWith('https:'))) {
                        const urlObj = new URL(url);
                        const domain = urlObj.hostname.toLowerCase().replace(/^www\./, '');
                        sendResponse({ url: url, domain: domain, tabId: tab.id });
                    } else {
                        sendResponse({ url: url, domain: null, tabId: tab.id });
                    }
                } catch (e) {
                    console.error("Error getting current tab info:", e);
                    sendResponse({ url: null, domain: null, tabId: sender.tab?.id });
                }
            } else { // From popup
                 const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
                 if (tab && tab.url && (tab.url.startsWith('http:') || tab.url.startsWith('https:'))) {
                    const urlObj = new URL(tab.url);
                    const domain = urlObj.hostname.toLowerCase().replace(/^www\./, '');
                    sendResponse({ url: tab.url, domain: domain, tabId: tab.id });
                 } else {
                    sendResponse({ url: tab?.url, domain: null, tabId: tab?.id });
                 }
            }
        } else if (request.action === "checkDomain") {
            const localResult = await checkUrlAgainstLocalLists(sender.tab?.id || null, request.value); // value here is domain, but function expects URL
            if (localResult.isPhishing) {
                sendResponse(localResult);
            } else {
                // Construct a dummy URL for checkUrlWithBackend if request.value is just a domain
                const dummyUrl = `http://${request.value}/`;
                const backendResult = await checkUrlWithBackend(sender.tab?.id || null, dummyUrl);
                sendResponse(backendResult);
            }
        } else if (request.action === "getCurrentPhishingUrl") {
            sendResponse({ url: currentPhishingUrl, tabId: currentTabId });
        } else if (request.action === "getKeywords") {
            const data = await chrome.storage.local.get("localKeywords");
            sendResponse(data.localKeywords || PHISHING_KEYWORDS_VN_DEFAULT);
        } else if (request.action === "reportToBackend" || request.action === "reportItem") {
            try {
                const fetchResponse = await fetch(`${API_BASE_URL_BG}/report`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(request.data || { report_type: request.type, value: request.value, context: request.context})
                });

                const contentType = fetchResponse.headers.get("content-type");
                if (fetchResponse.ok && contentType && contentType.includes("application/json")) {
                    const data = await fetchResponse.json();
                    sendResponse({ success: true, data: data });
                } else if (fetchResponse.ok) { // Non-JSON OK response
                    const textData = await fetchResponse.text();
                    sendResponse({ success: true, message: textData || "Report submitted (non-JSON response)." });
                }
                else { // Error response
                    const errorText = await fetchResponse.text();
                    console.error("Error reporting to backend:", errorText);
                    sendResponse({ success: false, error: `HTTP error ${fetchResponse.status}: ${fetchResponse.statusText}. Body: ${errorText.substring(0,100)}` });
                }
            } catch (error) {
                console.error("Error reporting to backend:", error);
                sendResponse({ success: false, error: error.message });
            }
        } else if (request.action === "checkDomainWithBackend") {
            const domain = request.domain;
            try {
                const response = await fetch(`${API_BASE_URL_BG}/check?type=domain&value=${encodeURIComponent(domain)}`);
                const data = await response.json();
                sendResponse(data);
            } catch (error) {
                console.error("Error checking domain with backend:", error);
                sendResponse({ status: 'error', error: error.message });
            }
        } else if (request.action === "getReportedMaliciousEmails") {
            try {
                const fetchUrl = `${API_BASE_URL_BG}/list_items?item_type=email&list_type=blocklist&per_page=1000`;
                const response = await fetch(fetchUrl);
                if (!response.ok) {
                    console.error(`Failed to fetch reported malicious emails from ${fetchUrl}. Status: ${response.status} ${response.statusText}`);
                    sendResponse({ success: true, emails: [], error: `Backend error: ${response.status}` });
                    return;
                }
                const data = await response.json();
                sendResponse({ success: true, emails: data.items || [] });
            } catch (error) {
                console.error("Error fetching reported malicious emails:", error);
                sendResponse({ success: false, error: error.message, emails: [] });
            }
        } else if (request.action === "addToSessionWhitelist") {
            const urlToWhitelist = request.url;
            if (urlToWhitelist) {
                const data = await chrome.storage.session.get('sessionWhitelistedUrls');
                let sessionWhitelistedUrls = data.sessionWhitelistedUrls || [];
                if (!sessionWhitelistedUrls.includes(urlToWhitelist.toLowerCase())) {
                    sessionWhitelistedUrls.push(urlToWhitelist.toLowerCase());
                }
                try {
                    const urlObj = new URL(urlToWhitelist);
                    const hostname = urlObj.hostname.toLowerCase().replace(/^www\./, '');
                    if (!sessionWhitelistedUrls.includes(hostname)) {
                        sessionWhitelistedUrls.push(hostname);
                    }
                } catch (e) { /*ignore invalid URL for hostname part*/ }

                await chrome.storage.session.set({ sessionWhitelistedUrls: sessionWhitelistedUrls });
                console.log(`URL ${urlToWhitelist} added to session whitelist.`);
                sendResponse({ success: true });
            } else {
                sendResponse({ success: false, error: "No URL provided" });
            }
        } else if (request.action === "settingsUpdated") {
             console.log("Received settingsUpdated message, reloading API base URL.");
             await loadApiBaseUrl(); // Reload API URL
             sendResponse({status: "API URL reloaded"});
        } else if (request.action === "markAsSafeAndReport") { // New action for "Báo cáo là an toàn"
            const domainToMarkSafe = request.domainToMarkSafe;
            let reportSuccess = false;
            let whitelistSuccess = false;

            // 1. Report to backend (existing logic)
            try {
                const reportData = request.data; // This should contain the false_positive report details
                const fetchResponse = await fetch(`${API_BASE_URL_BG}/report`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(reportData)
                });
                if (fetchResponse.ok) {
                    reportSuccess = true;
                    console.log("False positive reported to backend for:", domainToMarkSafe);
                } else {
                    const errorText = await fetchResponse.text();
                    console.error("Failed to report false positive to backend:", errorText);
                }
            } catch (error) {
                console.error("Error reporting false positive to backend:", error);
            }

            // 2. Add to user's local allowlist
            if (domainToMarkSafe) {
                try {
                    const data = await chrome.storage.sync.get('userAllowlist');
                    let userAllowlist = data.userAllowlist || [];
                    const lowerDomain = domainToMarkSafe.toLowerCase();
                    if (!userAllowlist.includes(lowerDomain)) {
                        userAllowlist.push(lowerDomain);
                        await chrome.storage.sync.set({ userAllowlist: userAllowlist });
                        whitelistSuccess = true;
                        console.log(`Domain ${lowerDomain} added to user allowlist.`);
                    } else {
                        whitelistSuccess = true; // Already there, still a success
                        console.log(`Domain ${lowerDomain} already in user allowlist.`);
                    }
                } catch (e) {
                    console.error("Error adding to user allowlist:", e);
                }
            }
            sendResponse({ success: whitelistSuccess, reportAttempted: true, reportSuccess: reportSuccess });
        } else if (request.action === "getApiStatus") {
            try {
                const response = await fetch(`${API_BASE_URL_BG}/status`);
                sendResponse({ reachable: response.ok });
            } catch (e) {
                sendResponse({ reachable: false });
            }
        }
    })(); // Immediately-invoked async function
    return true; // Required for async sendResponse
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
    if (info.menuItemId === "reportSelectedText" && info.selectionText) {
        const selection = info.selectionText.trim();
        let reportValue = selection;
        let itemType = "";
        const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

        if (emailRegex.test(selection)) {
            itemType = "email";
            reportValue = selection.toLowerCase();
        } else {
            try {
                let potentialDomain = selection;
                if (!potentialDomain.match(/^https?:\/\//) && potentialDomain.includes('.')) {
                    potentialDomain = 'http://' + potentialDomain;
                }
                const urlObj = new URL(potentialDomain);
                if (urlObj.hostname && urlObj.hostname.includes('.')) {
                     itemType = "domain";
                     reportValue = urlObj.hostname.toLowerCase().replace(/^www\./, '');
                }
            } catch (e) {
                 if (selection.includes('.') && !selection.includes(' ') && !selection.startsWith('/')) {
                    itemType = "domain";
                    reportValue = selection.toLowerCase().replace(/^www\./, '');
                }
            }
        }

        if (itemType && reportValue) {
            try {
                const response = await fetch(`${API_BASE_URL_BG}/report`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        report_type: `suspicious_${itemType}`,
                        value: reportValue,
                        source_url: tab.url,
                        context: `User selection on page: ${selection}`
                    })
                });
                const contentType = response.headers.get("content-type");
                let responseDataMessage = "Báo cáo thành công!";
                if (response.ok && contentType && contentType.includes("application/json")) {
                    const data = await response.json();
                    responseDataMessage = data.message || responseDataMessage;
                } else if (response.ok) {
                    const textData = await response.text();
                    responseDataMessage = textData || responseDataMessage;
                } else {
                    const errorText = await response.text();
                    throw new Error(`HTTP ${response.status}: ${errorText.substring(0,100)}`);
                }

                chrome.notifications.create('reportSubmit-' + Date.now(), {
                    type: 'basic',
                    iconUrl: 'icons/icon-128.png',
                    title: 'Báo Cáo Đã Được Gửi',
                    message: `Đã báo cáo ${itemType}: "${reportValue}". Máy chủ: ${responseDataMessage}`,
                    priority: 2
                });
            } catch (error) {
                console.error("Error submitting report via context menu:", error);
                chrome.notifications.create('reportError-' + Date.now(), {
                    type: 'basic',
                    iconUrl: 'icons/icon-128.png',
                    title: 'Lỗi Báo Cáo',
                    message: `Không thể gửi báo cáo cho "${reportValue}". Lỗi: ${error.message}`,
                    priority: 2
                });
            }
        } else {
            chrome.notifications.create('reportInvalid-' + Date.now(), {
                type: 'basic',
                iconUrl: 'icons/icon-128.png',
                title: 'Không Thể Báo Cáo',
                message: `Văn bản "${selection.substring(0,70)}..." không được nhận dạng là domain/email hợp lệ để báo cáo.`,
                priority: 1
            });
        }
    }
});