'use strict';

console.log(`Phishing Guard Pro: Content script v${chrome.runtime.getManifest().version} loading on:`, window.location.hostname);


const EXT_PREFIX = 'phishing-guard-pro';
const CHECKED_ATTR = `data-${EXT_PREFIX}-checked`;
const KEYWORDS_CHECKED_ATTR = `data-${EXT_PREFIX}-kw-checked`;
const PROCESSED_ATTR = `data-${EXT_PREFIX}-processed`;
const PHISHING_CLASS = `${EXT_PREFIX}-alert-phishing`;
const SUSPICIOUS_CLASS = `${EXT_PREFIX}-alert-suspicious`;
const SUSPICIOUS_BANNER_CLASS = `${EXT_PREFIX}-alert-suspicious-banner`;
const HIGHLIGHT_CLASS = `${EXT_PREFIX}-highlight`;


const DEBOUNCE_DELAY_PROCESS = 750;
const DEBOUNCE_DELAY_MUTATION = 200;


const SUSPICIOUS_KEYWORDS = [
    'xác minh tài khoản', 'cập nhật thông tin', 'mật khẩu của bạn', 'đã hết hạn',
    'đăng nhập ngay', 'khẩn cấp', 'quan trọng', 'tài khoản bị khóa', 'tạm ngưng',
    'ngân hàng', 'thẻ tín dụng', 'chuyển tiền', 'thanh toán', 'hóa đơn',
    'quà tặng', 'trúng thưởng', 'miễn phí', 'yêu cầu hành động', 'số an sinh xã hội',
    'nhấp vào đây', 'liên kết này', 'mã OTP', 'yêu cầu gấp', 'thông tin cá nhân',
    'tài khoản của bạn', 'vấn đề bảo mật', 'khóa tạm thời', 'truy cập trái phép',
    'xác thực', 'cần xác nhận', 'ưu đãi đặc biệt', 'duy nhất hôm nay', 'đăng nhập lại',
    'verify your account', 'update information', 'your password', 'has expired',
    'login immediately', 'urgent', 'important', 'account locked', 'suspended',
    'bank', 'credit card', 'transfer money', 'payment', 'invoice', 'tax refund',
    'gift', 'won prize', 'free', 'action required', 'ssn', 'social security number',
    'click here', 'this link', 'one-time password', 'immediate attention', 'personal details',
    'your account', 'security issue', 'temporary lock', 'unauthorized access',
    'authenticate', 'confirm', 'special offer', 'today only', 'confirm identity', 're-login'
];

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            try {
                func.apply(this, args);
            } catch (e) {
                console.error("CS: Error in debounced function execution:", func.name, e);
            }
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}


function isConnected(element) {
    return !!(element && typeof element.isConnected === 'boolean' && element.isConnected);
}

async function sendMessageToBackground(message) {
    return new Promise((resolve, reject) => {
        try {
            chrome.runtime.sendMessage(message, (response) => {
                if (chrome.runtime.lastError) {

                    console.warn(`CS: Error sending/receiving message for action "${message?.action}":`, chrome.runtime.lastError.message);
                    reject(new Error(chrome.runtime.lastError.message || "Unknown runtime error"));
                } else if (response && response.error) {

                    console.warn(`CS: Background reported error for action "${message?.action}":`, response.error);
                    reject(new Error(response.error));
                } else {
                    resolve(response);
                }
            });
        } catch (error) {

            console.error(`CS: Exception sending message for action "${message?.action}":`, error);
            reject(error);
        }
    });
}

async function checkDomain(domain) {
    if (!domain) return { isPhishing: false, reason: "Tên miền không hợp lệ (CS)" };
    try {

        return await sendMessageToBackground({ action: 'checkDomain', value: domain });
    } catch (error) {

        return { isPhishing: false, reason: `Lỗi kiểm tra tên miền (CS): ${error.message}` };
    }
}

async function checkEmailSender(email) {
    if (!email) return { isPhishing: false, reason: "Email không hợp lệ (CS)" };
    try {

        return await sendMessageToBackground({ action: 'checkEmailSender', value: email });
    } catch (error) {

        return { isPhishing: false, reason: `Lỗi kiểm tra email (CS): ${error.message}` };
    }
}

function applyHighlight(element, cssClass, tooltipText) {

    if (!element || typeof element.classList === 'undefined' || !isConnected(element)) {

        return;
    }
    try {
        if (!element.classList.contains(cssClass)) {
            element.classList.add(cssClass);

            if (cssClass === PHISHING_CLASS || !element.title) {
                 element.title = tooltipText;
            }
        }
    } catch (e) {
        console.error("CS: Failed to apply highlight class:", cssClass, e, element);
    }
}

function addSuspicionWarningBanner(containerElement, tooltipText) {
    if (!containerElement || typeof containerElement.querySelector !== 'function' || !isConnected(containerElement)) {

        return;
    }

    if (containerElement.querySelector(`.${SUSPICIOUS_BANNER_CLASS}`)) {
        return;
    }

    try {

        containerElement.classList.add(SUSPICIOUS_CLASS);

        const banner = document.createElement('div');
        banner.className = SUSPICIOUS_BANNER_CLASS;

        banner.innerHTML = `<strong>⚠️ Nội dung đáng ngờ:</strong> Email này chứa các yếu tố hoặc từ khóa thường thấy trong email lừa đảo. Hãy kiểm tra kỹ người gửi và các yêu cầu trước khi nhấp vào liên kết hoặc cung cấp thông tin.`;
        banner.title = tooltipText;


        containerElement.insertBefore(banner, containerElement.firstChild);

    } catch (e) {
        console.error("CS: Failed to add suspicion warning banner:", e, containerElement);
    }
}

async function scanAndMarkLinks(containerElement, isEmailContentView = false) {

    if (!isEmailContentView || !containerElement || typeof containerElement.querySelectorAll !== 'function' || !isConnected(containerElement)) {
        return;
    }


    try {

        const links = containerElement.querySelectorAll(`a[href]:not([${CHECKED_ATTR}])`);

        for (const link of links) {

             if (!isConnected(link) || link.hasAttribute(CHECKED_ATTR)) continue;
            link.setAttribute(CHECKED_ATTR, 'true');

            let href;
            try {
                href = link.href;


                if (!href || !href.startsWith('http')) {
                    continue;
                }



                const urlObj = new URL(href);
                const domain = normalizeDomain(urlObj.hostname);

                if (!domain) {

                    continue;
                }

                n
                const result = await checkDomain(domain);


                if (result && result.isPhishing) {
                     console.warn(`CS: Phishing link detected: ${domain} (Reason: ${result.reason || 'Đã biết'})`);
                     applyHighlight(link, PHISHING_CLASS, `CẢNH BÁO LỪA ĐẢO! Tên miền đáng ngờ: ${domain}. Lý do: ${result.reason || 'Đã biết'}`);
                }


            } catch (error) {

                 if (error instanceof TypeError && error.message.includes("Invalid URL")) {

                 } else if (!(error instanceof DOMException && error.name === 'SecurityError')) {
                     console.warn(`CS: Error processing link "${href || link.outerHTML}":`, error.message);
                 }
            }
        }
    } catch (e) {

        console.error("CS: Error during link scanning process:", e, containerElement);
    }
}

async function scanAndMarkSender(senderInfoElement, isEmailContentView = false) {
    if (!isEmailContentView || !senderInfoElement || !isConnected(senderInfoElement) || senderInfoElement.hasAttribute(CHECKED_ATTR)) {
        return;
    }
    senderInfoElement.setAttribute(CHECKED_ATTR, 'true');

    let emailAddress = null;
    try {

        emailAddress = senderInfoElement.getAttribute('email') ||
                       senderInfoElement.dataset.senderEmail || // Check data attributes
                       (senderInfoElement.getAttribute('title') || '').match(/[\w.-]+@[\w.-]+\.\w+/)?.[0] ||
                       (senderInfoElement.textContent || '').match(/[\w.-]+@[\w.-]+\.\w+/)?.[0];


        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        const normalizedEmail = (emailAddress || '').toLowerCase().trim();


        if (normalizedEmail && emailRegex.test(normalizedEmail)) {

            const result = await checkEmailSender(normalizedEmail);

            if (result && result.isPhishing) {
                console.warn(`CS: Phishing sender detected: ${normalizedEmail} (Reason: ${result.reason || 'Đã biết'})`);
                applyHighlight(senderInfoElement, PHISHING_CLASS, `CẢNH BÁO LỪA ĐẢO! Email gửi đáng ngờ: ${normalizedEmail}. Lý do: ${result.reason || 'Đã biết'}`);
            }


        } else {

        }
    } catch (error) {
        console.warn(`CS: Error processing sender element (Email: ${emailAddress || 'N/A'}):`, error.message, senderInfoElement);
    }
}


function scanAndMarkKeywords(contentElement, isEmailContentView = false) {

    if (!isEmailContentView || !contentElement || !isConnected(contentElement) || contentElement.hasAttribute(KEYWORDS_CHECKED_ATTR)) {
        return;
    }
    contentElement.setAttribute(KEYWORDS_CHECKED_ATTR, 'true');

    try {

        const textContent = (contentElement.textContent || '').substring(0, 15000).toLowerCase();
        if (!textContent) return;

        let foundKeywords = [];
        for (const keyword of SUSPICIOUS_KEYWORDS) {

            if (textContent.includes(keyword.toLowerCase())) {
                foundKeywords.push(keyword);

                if (foundKeywords.length >= 7) break;
            }
        }

        if (foundKeywords.length > 0) {
            console.log(`CS: Suspicious keywords found: ${foundKeywords.join(', ')}`);
            const tooltip = `Email chứa các từ khóa đáng ngờ: ${foundKeywords.join(', ')}`;
            addSuspicionWarningBanner(contentElement, tooltip);
        }
    } catch (error) {
        console.warn("CS: Error scanning content for keywords:", error.message, contentElement);
    }
}

const processEmailView = (emailContainerNode) => {

    if (!emailContainerNode || typeof emailContainerNode.querySelector !== 'function' || !isConnected(emailContainerNode) || emailContainerNode.hasAttribute(PROCESSED_ATTR)) {
        return;
    }

    emailContainerNode.setAttribute(PROCESSED_ATTR, 'true');



    let isEmailContentView = false;
    let senderElement = null;
    let contentElement = null;
    const hostname = window.location.hostname;

    try {

        if (hostname.includes('mail.google.com')) {

            contentElement = emailContainerNode.querySelector('.a3s.aiL:not([style*="display: none"]), div.ii.gt:not([style*="display: none"])');

            const isListViewRow = emailContainerNode.matches && (emailContainerNode.matches('.zA') || emailContainerNode.closest('.zA'));

            if (contentElement && isConnected(contentElement) && !isListViewRow) {
                isEmailContentView = true;

                const headerArea = emailContainerNode.closest('.nH.hx, .Bs.nH.io.adp') || emailContainerNode;
                 senderElement = headerArea?.querySelector('.gD[email], .go[email], span[email].yP, span[email].go');
             } else {

             }

        } else if (hostname.includes('outlook.')) {

            contentElement = emailContainerNode.querySelector('div[aria-label="Message body"], .rps_*, .PlainText, .x_WordSection1');
            const isListViewRow = emailContainerNode.matches && (emailContainerNode.matches('div[role="option"]') || emailContainerNode.closest('div[role="option"]'));

            if (contentElement && isConnected(contentElement) && !isListViewRow) {
                isEmailContentView = true;

                const headerArea = emailContainerNode.closest('div[role="document"], div[data-testid="readingPaneContainer"], div[autoid^="_lvv_c"]') || emailContainerNode;

                senderElement = headerArea?.querySelector('button[data-is-focusable="true"] span[title*="@"], span[data-automationid="splitbuttonprimary"] span, .LAbQF span[title*="@"], .EnRL7 span[title*="@"], span.BoltText-span[title*="@"]') || headerArea?.querySelector('span[title*="@"]');
            } else {

            }
        }




        if (isEmailContentView) {
            console.log("CS: Identified Email Content View. Starting scans for:", emailContainerNode);


            if (senderElement && isConnected(senderElement)) {
                scanAndMarkSender(senderElement, true);
            } else {

            }


            if (contentElement && isConnected(contentElement)) {
                 scanAndMarkLinks(contentElement, true);
                 scanAndMarkKeywords(contentElement, true);
             } else {
                  console.error("CS: CRITICAL - Content element identified but became disconnected or invalid before scanning:", contentElement);
             }

        }


    } catch (error) {
        console.error("CS: Error during processEmailView execution:", error, emailContainerNode);
    }
};


const processEmailViewDebounced = debounce(processEmailView, DEBOUNCE_DELAY_PROCESS);



let observer = null;
let mutationProcessingTimeout = null;
const observedNodes = new Set();


const mutationCallback = (mutationsList) => {
    let addedRelevantNode = false;
    for (const mutation of mutationsList) {

        if (mutation.addedNodes) {
            mutation.addedNodes.forEach(node => {

                if (node.nodeType === Node.ELEMENT_NODE && isConnected(node)) {


                    if (node.matches && (

                        node.matches('.nH.hx, .Bs.nH.io.adp, .bzA, .Tm') || node.querySelector('.a3s.aiL, div.ii.gt') ||

                        node.matches('div[role="document"], div[data-testid="readingPaneContainer"], div[autoid^="_lvv_c"], div[aria-label="Message body"]') || node.querySelector('div[aria-label="Message body"]')
                    )) {
                        observedNodes.add(node);
                        addedRelevantNode = true;
                    }


                }
            });
        }

        if (addedRelevantNode) {
            clearTimeout(mutationProcessingTimeout);
            mutationProcessingTimeout = setTimeout(() => {

                observedNodes.forEach(node => {

                    if (isConnected(node)) {
                        processEmailViewDebounced(node);
                    }
                });
                observedNodes.clear();
            }, DEBOUNCE_DELAY_MUTATION);
        }
    }
    ;


    function startObserver() {
        if (observer) {
            console.log("CS: Disconnecting existing observer.");
            observer.disconnect();
        }


        const observerOptions = {
            childList: true,
            subtree: true

        };

        observer = new MutationObserver(mutationCallback);

        try {

            observer.observe(document.body, observerOptions);
            console.log("CS: MutationObserver started successfully.");
        } catch (e) {
            console.error("CS: CRITICAL - Failed to start MutationObserver.", e);

        }
    }


    function runInitialScan() {
        console.log("CS: Running initial scan for existing email views...");
        try {

            const initialSelectors = [
                // Gmail
                '.nH.hx:not([style*="display: none"]) .ii.gt',
                '.nH.hx:not([style*="display: none"]) .a3s.aiL',

                // Outlook
                'div[data-testid="readingPaneContainer"]:not([style*="display: none"]) div[aria-label="Message body"]',
                'div[role="document"]:not([style*="display: none"]) div[aria-label="Message body"]',

                // Broader fallbacks
                '.Bs.nH.io.adp',
                'div[autoid^="_lvv_c"]'
            ].join(', ');

            const potentialViews = document.querySelectorAll(initialSelectors);
            console.log(`CS: Found ${potentialViews.length} potential views in initial scan.`);

            potentialViews.forEach(node => {
                if (isConnected(node)) {

                    processEmailView(node);
                }
            });
            console.log("CS: Initial scan finished processing potential views.");

        } catch (e) {
            console.error("CS: Error during initial scan execution:", e);
        }
    }

    function initialize() {
        console.log(`CS: Initializing Phishing Guard Pro content script v${chrome.runtime.getManifest().version}...`);

        startObserver();


        if (document.readyState === 'complete') {

            setTimeout(runInitialScan, 1500);
        } else {

            window.addEventListener('load', () => setTimeout(runInitialScan, 1500), {once: true});
        }

        console.log("CS: Initialization sequence complete.");
    }

}
initialize();