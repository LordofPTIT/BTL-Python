const API_BASE_URL = 'http://127.0.0.1:5000';
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

async function initializeExtension() {
    console.log("VN Phishing Guard Pro initializing...");
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
        if (!trimmedLine || trimmedLine.startsWith('!') || trimmedLine.startsWith('#') || trimmedLine.startsWith('/') || trimmedLine.includes('*')) continue; // Bỏ qua comment, dòng trống, và các ký tự đặc biệt không phải domain thuần

        if (emailRegex.test(trimmedLine)) {
            // Hiện tại, danh sách chặn cục bộ chủ yếu dùng để chặn URL.
            // Email sẽ được gửi báo cáo lên backend.
            // Nếu muốn chặn email cục bộ, cần cơ chế riêng trong content.js
            // console.log(`Plain list: Skipping email for URL blocklist: ${trimmedLine}`);
            continue;
        }

        // Xử lý domain thuần
        let domainPart = trimmedLine;
        try {
            // Chuẩn hóa domain (loại bỏ http/https nếu có)
            if (domainPart.startsWith("http://")) domainPart = domainPart.substring(7);
            if (domainPart.startsWith("https://")) domainPart = domainPart.substring(8);
            if (domainPart.includes("/")) domainPart = domainPart.split("/")[0]; // Lấy phần domain
            domainPart = domainPart.replace(/^www\./, ''); // Bỏ www.

            if (domainPart.includes('.')) { // Kiểm tra xem có phải là một domain hợp lệ không
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
        let itemType = 'domain'; // Mặc định cho ABP

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
        console.log(`Workspaceing local list: ${fullUrl} (type: ${file.type})`);
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
                // Thêm type vào key để phân biệt domain/email nếu cần sau này,
                // hiện tại type chủ yếu là 'domain' từ các parser này.
                // ruleKey += `|${item.type}`;

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

        // Kiểm tra cả URL đầy đủ và hostname
        if (sessionWhitelistedUrls.includes(urlString.toLowerCase()) || sessionWhitelistedUrls.includes(hostname)) {
            console.log(`URL ${urlString} is temporarily allowed via session whitelist.`);
            return true;
        }
    } catch (error) {
        console.error("Error checking session whitelist:", error);
    }
    return false;
}

function isUrlInParsedList(currentUrlString, parsedRules) {
    if (!parsedRules || parsedRules.length === 0) return false;
    try {
        const currentUrl = new URL(currentUrlString);
        const currentHostname = currentUrl.hostname.toLowerCase().replace(/^www\./, '');
        const currentPath = currentUrl.pathname.toLowerCase(); // Bao gồm dấu / ở đầu

        for (const rule of parsedRules) {
            // Chỉ xử lý rule type 'domain' vì các parser hiện tại trả về vậy
            if (rule.type !== 'domain' && rule.type !== undefined) continue;


            const isExactDomainMatch = currentHostname === rule.domain;
            const isSubdomainMatch = currentHostname.endsWith('.' + rule.domain);

            if (!isExactDomainMatch && !isSubdomainMatch) {
                continue;
            }

            if (rule.path) { // rule.path bao gồm dấu / ở đầu, ví dụ "/some/path"
                if (currentPath.startsWith(rule.path)) {
                    return true; // Khớp cả domain và path
                }
            } else {
                // Không có path trong rule, chỉ cần domain khớp là đủ
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
        return false; // Không phải URL hợp lệ để kiểm tra
    }

    if (await isUrlTemporarilyAllowed(url)) {
        return false; // Bỏ qua kiểm tra nếu URL đã được cho phép tạm thời
    }

    try {
        const { combinedLocalBlocklistRules } = await chrome.storage.local.get('combinedLocalBlocklistRules');
        if (combinedLocalBlocklistRules && isUrlInParsedList(url, combinedLocalBlocklistRules)) {
            console.log("URL matched in combined local blocklist:", url);
            showCustomNotificationOrWarningPage(tabId, url, "Local Blocklist", "Trang web này nằm trong danh sách chặn cục bộ của bạn.");
            return true; // Bị chặn bởi danh sách cục bộ
        }
    } catch (error) {
        console.error("Error checking URL with combined local blocklist:", error);
    }
    return false; // Không bị chặn bởi danh sách cục bộ
}


async function checkUrlWithBackend(tabId, urlString) {
    if (!urlString || (!urlString.startsWith('http:') && !urlString.startsWith('https:'))) {
        return false;
    }
     if (await isUrlTemporarilyAllowed(urlString)) {
        return false; // Bỏ qua kiểm tra nếu URL đã được cho phép tạm thời
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
            // console.log(`Domain ${domain} is SAFE according to backend.`);
        }
    } catch (error) {
        console.error(`Error checking URL ${urlString} with backend:`, error);
    }
    return false;
}

async function handleUrlCheck(tabId, url) {
    if (await checkUrlAgainstLocalLists(tabId, url)) return;
    await checkUrlWithBackend(tabId, url);
}


chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url && tab.active) {
        // changeInfo.url có thể không luôn tồn tại, dùng tab.url an toàn hơn khi status là complete
        currentPhishingUrl = tab.url;
        currentTabId = tabId;
        console.log(`Navigating to (onUpdated - complete): ${tab.url}`);
        await handleUrlCheck(tabId, tab.url);
    }
});

chrome.webNavigation.onCommitted.addListener(async (details) => {
    // onCommitted xảy ra trước onUpdated status=complete.
    // Có thể dùng onCommitted để kiểm tra sớm, nhưng onUpdated + status=complete + tab.active thường đáng tin cậy hơn cho URL cuối cùng người dùng thấy.
    // Nếu dùng cả hai, cần cẩn thận để tránh kiểm tra kép hoặc xử lý xung đột.
    // Hiện tại, onUpdated được ưu tiên. Có thể xem xét lại nếu cần phản hồi nhanh hơn từ onCommitted.
    if (details.frameId === 0 && details.url && (details.url.startsWith('http:') || details.url.startsWith('https:'))) {
        // try {
        //     const tab = await chrome.tabs.get(details.tabId);
        //     if (tab.active) {
        //         console.log(`URL committed (webNavigation): ${details.url}`);
        //         // await handleUrlCheck(details.tabId, details.url); // Cân nhắc nếu muốn kiểm tra ở đây
        //     }
        // } catch (e) {
        //     console.warn("Error getting tab in webNavigation.onCommitted:", e);
        // }
    }
});


function showCustomNotificationOrWarningPage(tabId, url, listName, reason) {
    currentPhishingUrl = url; // Lưu lại URL bị chặn gần nhất
    currentTabId = tabId;    // Lưu lại Tab ID

    chrome.storage.local.get(['warningType'], async (settings) => {
        const warningType = settings.warningType || 'warning_page'; // Mặc định là trang cảnh báo

        if (warningType === 'notification') {
            chrome.notifications.create('phishingNotif-' + Date.now(), { // ID duy nhất cho notification
                type: 'basic',
                iconUrl: 'icons/icon-128.png',
                title: 'Cảnh Báo Phishing!',
                message: `Trang ${url.substring(0, 100)}... có dấu hiệu lừa đảo (${listName}). Lý do: ${reason.substring(0,100)}...`,
                priority: 2,
                buttons: [{ title: 'Xem chi tiết cảnh báo' }]
            });
        } else {
            // Chuyển hướng đến trang cảnh báo tùy chỉnh
            const warningPageUrl = chrome.runtime.getURL('warning/warning.html') +
                                   `?url=${encodeURIComponent(url)}&listName=${encodeURIComponent(listName)}&reason=${encodeURIComponent(reason)}&tabId=${tabId}`;
            chrome.tabs.update(tabId, { url: warningPageUrl });
        }
    });
}

chrome.notifications.onButtonClicked.addListener((notificationId, buttonIndex) => {
    if (notificationId.startsWith('phishingNotif-') && buttonIndex === 0) {
        if (currentPhishingUrl && currentTabId) {
            const warningPageUrl = chrome.runtime.getURL('warning/warning.html') +
                                   `?url=${encodeURIComponent(currentPhishingUrl)}&listName=${encodeURIComponent("Chi tiết từ Notification")}&reason=${encodeURIComponent("Người dùng nhấp vào thông báo để xem chi tiết.")}&tabId=${currentTabId}`;
            chrome.tabs.create({ url: warningPageUrl }); // Mở trang cảnh báo trong tab mới
        }
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
        .catch(error => {
            console.error("Error reporting to backend:", error);
            sendResponse({success: false, error: error.message});
        });
        return true;
    } else if (request.action === "checkDomainWithBackend") { // Dùng cho popup hoặc các kiểm tra theo yêu cầu
        const domain = request.domain;
        fetch(`${API_BASE_URL}/check?type=domain&value=${encodeURIComponent(domain)}`)
            .then(response => response.json())
            .then(data => sendResponse(data))
            .catch(error => {
                 console.error("Error checking domain with backend:", error);
                 sendResponse({status: 'error', error: error.message});
            });
        return true;
    } else if (request.action === "getReportedMaliciousEmails") { // Dùng cho content.js quét email
        fetch(`${API_BASE_URL}/list_items?item_type=email&list_type=blocklist&per_page=1000`) // Lấy nhiều hơn nếu cần
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
    } else if (request.action === "addToSessionWhitelist") {
        const urlToWhitelist = request.url;
        if (urlToWhitelist) {
            chrome.storage.session.get('sessionWhitelistedUrls', (data) => {
                let sessionWhitelistedUrls = data.sessionWhitelistedUrls || [];
                if (!sessionWhitelistedUrls.includes(urlToWhitelist.toLowerCase())) {
                    sessionWhitelistedUrls.push(urlToWhitelist.toLowerCase());
                }
                 // Cũng thêm hostname vào danh sách cho phép tạm thời
                try {
                    const urlObj = new URL(urlToWhitelist);
                    const hostname = urlObj.hostname.toLowerCase().replace(/^www\./, '');
                    if (!sessionWhitelistedUrls.includes(hostname)) {
                        sessionWhitelistedUrls.push(hostname);
                    }
                } catch (e) { /*ignore*/ }

                chrome.storage.session.set({ sessionWhitelistedUrls: sessionWhitelistedUrls }, () => {
                    if (chrome.runtime.lastError) {
                        console.error("Error setting session whitelist:", chrome.runtime.lastError);
                        sendResponse({ success: false, error: chrome.runtime.lastError.message });
                    } else {
                        console.log(`URL ${urlToWhitelist} added to session whitelist.`);
                        sendResponse({ success: true });
                    }
                });
            });
        } else {
            sendResponse({ success: false, error: "No URL provided" });
        }
        return true; // Keep message channel open for async response
    }
    return false; // For synchronous responses or no response
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
            // Cố gắng chuẩn hóa thành domain nếu là URL hoặc chuỗi giống domain
            try {
                let potentialDomain = selection;
                if (!potentialDomain.match(/^https?:\/\//) && potentialDomain.includes('.')) {
                    potentialDomain = 'http://' + potentialDomain;
                }
                const urlObj = new URL(potentialDomain);
                // Chỉ lấy hostname nếu nó khác với selection ban đầu (tức là selection là URL đầy đủ)
                // Hoặc nếu selection là một từ đơn không có dấu chấm (sẽ không phải là domain hợp lệ)
                if (urlObj.hostname && urlObj.hostname !== selection.toLowerCase() && urlObj.hostname.includes('.')) {
                     reportValue = urlObj.hostname.toLowerCase().replace(/^www\./, '');
                } else if (selection.includes('.') && !selection.includes(' ') && !selection.startsWith('/')) {
                    // Nếu selection là một chuỗi giống domain (vd: example.com)
                    reportValue = selection.toLowerCase().replace(/^www\./, '');
                } else {
                    // Nếu không thể xác định là domain, không báo cáo
                    itemType = ""; // Reset itemType
                }

                if(itemType !== "email" && reportValue.includes('.')) { // Đảm bảo reportValue là domain hợp lệ
                    itemType = "domain";
                }

            } catch (e) {
                // Nếu không parse được URL, và không phải email, có thể không phải domain
                 if (selection.includes('.') && !selection.includes(' ') && !selection.startsWith('/')) {
                    itemType = "domain"; // Coi là domain nếu có dấu chấm và không có khoảng trắng
                    reportValue = selection.toLowerCase().replace(/^www\./, '');
                } else {
                    itemType = "";
                }
            }
        }

        if (itemType && reportValue) {
            try {
                const response = await fetch(`${API_BASE_URL}/report`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        report_type: `suspicious_${itemType}`,
                        value: reportValue, // Đã được toLowerCase()
                        source_url: tab.url,
                        context: `User selection on page: ${selection}`
                    })
                });
                const data = await response.json();
                chrome.notifications.create('reportSubmit-' + Date.now(), {
                    type: 'basic',
                    iconUrl: 'icons/icon-128.png',
                    title: 'Báo Cáo Đã Được Gửi',
                    message: `Đã báo cáo ${itemType}: "${reportValue}". Máy chủ: ${data.message || 'Thành công!'}`,
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