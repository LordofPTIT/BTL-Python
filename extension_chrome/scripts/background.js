const API_BASE_URL = 'http://127.0.0.1:5000/api';
let currentPhishingUrl = null;
let currentTabId = null;

const PHISHING_KEYWORDS_VN_DEFAULT = [
    "xác minh tài khoản", "đăng nhập khẩn cấp", "tài khoản của bạn đã bị khóa",
    "thông tin tài khoản", "cập nhật thông tin", "khẩn cấp", "quan trọng",
    "mật khẩu của bạn đã hết hạn", "quà tặng miễn phí", "trúng thưởng", "ưu đãi đặc biệt",
    "nhấp vào đây", "liên kết này", "yêu cầu thanh toán", "hóa đơn chưa thanh toán",
    "ngân hàng", "vietcombank", "techcombank", "agribank", "bidv", "sacombank", "vpbank",
    "momo", "zalopay", "cảnh báo bảo mật", "hoạt động đáng ngờ", "phiên đăng nhập lạ",
    "ủy quyền", "xác thực", "mã OTP", "giao dịch đang chờ xử lý", "hỗ trợ khách hàng",
    "chính phủ", "thuế", "bảo hiểm xã hội", "công an", "thông báo từ cơ quan nhà nước",
    "apple", "microsoft", "google", "facebook", "amazon", "paypal", "netflix", "lazada", "shopee", "tiki",
    "thừa kế", "triệu phú", "đầu tư lợi nhuận cao", "cơ hội việc làm", "làm việc tại nhà lương cao",
    "urgent", "verify your account", "account locked", "update your details", "password expired",
    "free gift", "you have won", "special offer", "click here", "payment request", "unpaid invoice",
    "security alert", "suspicious activity", "unusual sign-in", "confirm your identity",
    "chúng tôi phát hiện", "hoạt động bất thường", "yêu cầu thông tin cá nhân", "cung cấp ngay",
    "số thẻ tín dụng", "mã bảo mật CVV", "thông tin đăng nhập", "tên người dùng và mật khẩu",
    "thông báo trúng thưởng lớn", "bạn là người may mắn", "giải thưởng giá trị cao",
    "đòi tiền chuộc", "dữ liệu của bạn đã bị mã hóa", "thanh toán để giải mã"
];

async function initializeDatabaseAndKeywords() {
    await updateLocalABPBlacklist();
    await loadAndStoreKeywords();
}

chrome.runtime.onInstalled.addListener(() => {
    console.log("VN Phishing Guard Pro installed/updated.");
    initializeDatabaseAndKeywords();
    schedulePeriodicUpdates();

    chrome.contextMenus.create({
        id: "reportSelectedText",
        title: "Báo cáo là Phishing/Độc hại",
        contexts: ["selection"]
    });
});

chrome.runtime.onStartup.addListener(() => {
    console.log("VN Phishing Guard Pro started.");
    initializeDatabaseAndKeywords();
    schedulePeriodicUpdates();
});

function schedulePeriodicUpdates() {
    chrome.alarms.create('periodicUpdate', { periodInMinutes: 60 });
}

chrome.alarms.onAlarm.addListener(alarm => {
    if (alarm.name === 'periodicUpdate') {
        console.log("Performing periodic update of local lists...");
        updateLocalABPBlacklist();
        loadAndStoreKeywords();
    }
});

async function loadAndStoreKeywords() {
    try {
        const response = await fetch(chrome.runtime.getURL('data/phishing_keywords_vn.json'));
        if (response.ok) {
            const keywords = await response.json();
            await chrome.storage.local.set({ localKeywords: keywords });
            console.log("Phishing keywords loaded and stored from JSON.");
        } else {
            await chrome.storage.local.set({ localKeywords: PHISHING_KEYWORDS_VN_DEFAULT });
            console.warn("Failed to load keywords from JSON, using default list.");
        }
    } catch (error) {
        console.error("Error fetching or storing keywords, using default list:", error);
        await chrome.storage.local.set({ localKeywords: PHISHING_KEYWORDS_VN_DEFAULT });
    }
}


function parseABPList(text) {
    const lines = text.split(/\r?\n/);
    const rules = [];
    for (const line of lines) {
        if (line.startsWith('!') || line.startsWith('#') || line.trim() === '') continue;

        let ruleString = line;
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

        if (domainPart) {
            if (pathPattern && pathPattern !== "/") {
                rules.push({ domain: domainPart, path: pathPattern, original: line });
            } else {
                rules.push({ domain: domainPart, path: null, original: line });
            }
        }
    }
    return rules;
}

async function updateLocalABPBlacklist() {
    try {
        const response = await fetch(chrome.runtime.getURL('data/CLDBllacklist.txt'));
        const text = await response.text();
        const parsedRules = parseABPList(text);
        await chrome.storage.local.set({ localBlacklistABPRules: parsedRules, lastABPUpdate: Date.now() });
        console.log("Local ABP blacklist rules updated and stored.", parsedRules.length, "rules processed.");
    } catch (error) {
        console.error("Error fetching or parsing local ABP blacklist:", error);
    }
}


function isUrlInParsedList(currentUrlString, parsedRules) {
    if (!parsedRules || parsedRules.length === 0) return false;
    try {
        const currentUrl = new URL(currentUrlString);
        const currentHostname = currentUrl.hostname.toLowerCase().replace(/^www\./, '');
        const currentPath = currentUrl.pathname.toLowerCase();

        for (const rule of parsedRules) {
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

async function loadAndCheckUrlWithLocalDB(tabId, url) {
    if (!url || (!url.startsWith('http:') && !url.startsWith('https:'))) {
        return false;
    }
    try {
        const { localBlacklistABPRules } = await chrome.storage.local.get('localBlacklistABPRules');
        if (isUrlInParsedList(url, localBlacklistABPRules)) {
            console.log("URL matched in local ABP blacklist:", url);
            showCustomNotificationOrWarningPage(tabId, url, "Local Blocklist", "Trang web này nằm trong danh sách chặn cục bộ (ABP).");
            return true;
        }
    } catch (error) {
        console.error("Error checking URL with local ABP blacklist:", error);
    }
    return false;
}


async function checkUrlWithBackend(tabId, urlString) {
    if (!urlString || (!urlString.startsWith('http:') && !urlString.startsWith('https:'))) {
        return false;
    }

    try {
        const urlObj = new URL(urlString);
        const domain = urlObj.hostname;

        const response = await fetch(`${API_BASE_URL}/check?type=domain&value=${encodeURIComponent(domain)}`);
        if (!response.ok) {
            console.error(`Backend check failed for ${domain}: ${response.status}`);
            return false;
        }
        const data = await response.json();

        if (data.status === 'blocked') {
            console.log(`Domain ${domain} is BLOCKED by backend. Reason: ${data.reason}`);
            showCustomNotificationOrWarningPage(tabId, urlString, "Backend Blocklist", `Tên miền ${domain} bị chặn bởi máy chủ. Lý do: ${data.reason || 'Nằm trong danh sách nguy hiểm.'}`);
            return true;
        } else if (data.status === 'whitelisted') {
            console.log(`Domain ${domain} is whitelisted by backend.`);
        } else {
            console.log(`Domain ${domain} is SAFE according to backend.`);
        }
    } catch (error) {
        console.error(`Error checking URL ${urlString} with backend:`, error);
    }
    return false;
}

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.url && tab.active) {
        currentPhishingUrl = changeInfo.url;
        currentTabId = tabId;
        console.log(`Navigating to (onUpdated): ${changeInfo.url}`);
        if (await loadAndCheckUrlWithLocalDB(tabId, changeInfo.url)) return;
        await checkUrlWithBackend(tabId, changeInfo.url);
    }
});

chrome.webNavigation.onCommitted.addListener(async (details) => {
    if (details.frameId === 0 && details.url && (details.url.startsWith('http:') || details.url.startsWith('https:'))) {
        // Check if this navigation is for an active tab to avoid background tab processing if not desired
        const tab = await chrome.tabs.get(details.tabId);
        if (tab.active) {
            currentPhishingUrl = details.url;
            currentTabId = details.tabId;
            console.log(`Navigating to (onCommitted): ${details.url}`);
            if (await loadAndCheckUrlWithLocalDB(details.tabId, details.url)) return;
            await checkUrlWithBackend(details.tabId, details.url);
        }
    }
});


function showCustomNotificationOrWarningPage(tabId, url, listName, reason) {
    currentPhishingUrl = url;
    currentTabId = tabId;

    chrome.storage.local.get(['warningType', 'autoRedirectPrevention'], async (settings) => {
        const warningType = settings.warningType || 'warning_page';

        if (warningType === 'notification') {
            chrome.notifications.create_('notif-' + Date.now(), { // Unique ID for notification
                type: 'basic',
                iconUrl: 'icons/icon-128.png',
                title: 'Cảnh Báo Phishing!',
                message: `Trang web ${url.substring(0,100)}... có dấu hiệu lừa đảo (${listName}). Lý do: ${reason.substring(0,100)}...`,
                priority: 2,
                buttons: [{ title: 'Tới trang cảnh báo' }]
            });
        } else {
             const warningPageUrl = chrome.runtime.getURL('warning/warning.html') +
                                   `?url=${encodeURIComponent(url)}&listName=${encodeURIComponent(listName)}&reason=${encodeURIComponent(reason)}`;
            chrome.tabs.update(tabId, { url: warningPageUrl });
        }
    });
}

chrome.notifications.onButtonClicked.addListener((notificationId, buttonIndex) => {
    if (buttonIndex === 0 && currentPhishingUrl && currentTabId) {
        const warningPageUrl = chrome.runtime.getURL('warning/warning.html') +
                               `?url=${encodeURIComponent(currentPhishingUrl)}&listName=${encodeURIComponent("Notification Clicked")}&reason=${encodeURIComponent("User clicked notification to see details.")}`;
        chrome.tabs.update(currentTabId, { url: warningPageUrl });
        chrome.notifications.clear(notificationId);
    }
});

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "getCurrentPhishingUrl") {
        sendResponse({ url: currentPhishingUrl, tabId: currentTabId });
    } else if (request.action === "getKeywords") {
        chrome.storage.local.get("localKeywords", (data) => {
            sendResponse(data.localKeywords || PHISHING_KEYWORDS_VN_DEFAULT);
        });
        return true;
    } else if (request.action === "reportToBackend") {
        fetch(`${API_BASE_URL}/report`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(request.data)
        })
        .then(response => response.json())
        .then(data => sendResponse({success: true, data: data}))
        .catch(error => sendResponse({success: false, error: error.message}));
        return true;
    } else if (request.action === "checkDomainWithBackend") {
        const domain = request.domain;
        fetch(`${API_BASE_URL}/check?type=domain&value=${encodeURIComponent(domain)}`)
            .then(response => response.json())
            .then(data => sendResponse(data))
            .catch(error => sendResponse({status: 'error', error: error.message}));
        return true;
    } else if (request.action === "getReportedMaliciousEmails") {
        fetch(`${API_BASE_URL}/list_items?item_type=email&list_type=blocklist&per_page=500`)
            .then(response => {
                if (!response.ok) throw new Error(`HTTP error! status: ${response.status}`);
                return response.json();
            })
            .then(data => sendResponse({ success: true, emails: data.items || [] }))
            .catch(error => {
                console.error("Error fetching reported malicious emails:", error);
                sendResponse({ success: false, error: error.message, emails: [] });
            });
        return true;
    }
    return false;
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
    if (info.menuItemId === "reportSelectedText" && info.selectionText) {
        const selection = info.selectionText.trim();
        let reportValue = selection;
        let itemType = "";

        const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
        if (emailRegex.test(selection)) {
            itemType = "email";
        } else {
            try {
                let potentialDomain = selection;
                if (!potentialDomain.match(/^https?:\/\//)) {
                    potentialDomain = 'http://' + potentialDomain;
                }
                const urlObj = new URL(potentialDomain);
                reportValue = urlObj.hostname;
                if (reportValue.includes('.')) {
                     itemType = "domain";
                }
            } catch (e) {
                // Not a valid URL
            }
        }

        if (itemType) {
            try {
                const response = await fetch(`${API_BASE_URL}/report`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        report_type: `suspicious_${itemType}`,
                        value: reportValue.toLowerCase(),
                        source_url: tab.url,
                        context: `User selection: ${selection}`
                    })
                });
                const data = await response.json();
                chrome.notifications.create('report-' + Date.now(), { // Unique ID
                    type: 'basic',
                    iconUrl: 'icons/icon-128.png',
                    title: 'Báo Cáo Đã Được Gửi',
                    message: `Đã báo cáo ${itemType}: "${reportValue}". Máy chủ phản hồi: ${data.message || 'Thành công!'}`,
                    priority: 2
                });
            } catch (error) {
                console.error("Error submitting report via context menu:", error);
                chrome.notifications.create('report-error-' + Date.now(), { // Unique ID
                    type: 'basic',
                    iconUrl: 'icons/icon-128.png',
                    title: 'Lỗi Báo Cáo',
                    message: `Không thể gửi báo cáo cho "${reportValue}". Lỗi: ${error.message}`,
                    priority: 2
                });
            }
        } else {
            chrome.notifications.create('report-invalid-' + Date.now(), { // Unique ID
                type: 'basic',
                iconUrl: 'icons/icon-128.png',
                title: 'Không Thể Báo Cáo',
                message: `Văn bản "${selection.substring(0,50)}..." không được nhận dạng là domain hoặc email hợp lệ.`,
                priority: 1
            });
        }
    }
});