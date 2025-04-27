/**
 * VN Phishing Guard Pro - Content Script (v2.3)
 *
 * Changelog v2.3:
 * - Refined DOM selectors for Gmail/Outlook to differentiate between List View and Email View.
 * - Modified MutationObserver logic to primarily target Email View for keyword/banner warnings.
 * - Prevented keyword scanning and banner addition in List View rows.
 * - Fixed ReferenceError typo in scanAndMarkSender catch block.
 * - Added more checks for element validity/connection before processing.
 */

console.log("Phishing Guard Pro: Content script v2.3 loading on:", window.location.hostname);

// --- Constants (Giữ nguyên) ---
const CHECKED_ATTR = 'data-phishing-checked';
const KEYWORDS_CHECKED_ATTR = 'data-phishing-kw-checked';
const PHISHING_CLASS = 'phishing-guard-alert-phishing';
const SUSPICIOUS_CLASS = 'phishing-guard-alert-suspicious';
const SUSPICIOUS_BANNER_CLASS = 'phishing-guard-alert-suspicious-banner';
const DEBOUNCE_DELAY = 750; // ms
const SUSPICIOUS_KEYWORDS = [ /* ... Giữ nguyên danh sách keywords ... */
    // Tiếng Việt
    'xác minh tài khoản', 'cập nhật thông tin', 'mật khẩu của bạn', 'đã hết hạn',
    'đăng nhập ngay', 'khẩn cấp', 'quan trọng', 'tài khoản bị khóa', 'tạm ngưng',
    'ngân hàng', 'thẻ tín dụng', 'chuyển tiền', 'thanh toán', 'hóa đơn',
    'quà tặng', 'trúng thưởng', 'miễn phí', 'yêu cầu hành động', 'số an sinh xã hội',
    'nhấp vào đây', 'liên kết này', 'mã OTP', 'yêu cầu gấp', 'thông tin cá nhân',
    'tài khoản của bạn', 'vấn đề bảo mật', 'khóa tạm thời', 'truy cập trái phép',
    'xác thực', 'cần xác nhận', 'ưu đãi đặc biệt', 'duy nhất hôm nay', 'đăng nhập lại',
    // Tiếng Anh (phổ biến)
    'verify your account', 'update information', 'your password', 'has expired',
    'login immediately', 'urgent', 'important', 'account locked', 'suspended',
    'bank', 'credit card', 'transfer money', 'payment', 'invoice', 'tax refund',
    'gift', 'won prize', 'free', 'action required', 'ssn', 'social security number',
    'click here', 'this link', 'one-time password', 'immediate attention', 'personal details',
    'your account', 'security issue', 'temporary lock', 'unauthorized access',
    'authenticate', 'confirm', 'special offer', 'today only', 'confirm identity', 're-login'
];

// --- Debounce Function (Giữ nguyên) ---
function debounce(func, wait) { let timeout; return function executedFunction(...args) { const later = () => { clearTimeout(timeout); func.apply(this, args); }; clearTimeout(timeout); timeout = setTimeout(later, wait); }; }

// --- Background Communication (Giữ nguyên checkDomain, checkEmailSender) ---
async function checkDomain(domain) { /* ... Giữ nguyên ... */
    if (!domain) return { isPhishing: false, reason: "Tên miền không hợp lệ (content)" };
    try {
        const response = await chrome.runtime.sendMessage({ action: 'checkDomain', value: domain });
        if (chrome.runtime.lastError) throw new Error(chrome.runtime.lastError.message || "Lỗi runtime");
        return response && typeof response === 'object' ? response : { isPhishing: false, reason: "Phản hồi không hợp lệ (content)" };
    } catch (error) { console.warn(`CS: Lỗi checkDomain '${domain}':`, error.message); return { isPhishing: false, reason: "Lỗi kết nối kiểm tra (content)" }; }
}
async function checkEmailSender(email) { /* ... Giữ nguyên ... */
    if (!email) return { isPhishing: false, reason: "Email không hợp lệ (content)" };
    try {
        const response = await chrome.runtime.sendMessage({ action: 'checkEmailSender', value: email });
        if (chrome.runtime.lastError) throw new Error(chrome.runtime.lastError.message || "Lỗi runtime");
        return response && typeof response === 'object' ? response : { isPhishing: false, reason: "Phản hồi không hợp lệ (content)" };
    } catch (error) { console.warn(`CS: Lỗi checkEmailSender '${email}':`, error.message); return { isPhishing: false, reason: "Lỗi kết nối kiểm tra (content)" }; }
}

// --- DOM Manipulation (Giữ nguyên markElementAsPhishing, addSuspicionWarning) ---
function markElementAsPhishing(element, tooltipText) { /* ... Giữ nguyên ... */
    if (!element || typeof element.classList === 'undefined' || !element.isConnected) return;
    try { if (!element.classList.contains(PHISHING_CLASS)) { element.classList.add(PHISHING_CLASS); if (element.isConnected) element.title = `CẢNH BÁO LỪA ĐẢO! ${tooltipText}`; }
    } catch (e) { console.error("CS: Lỗi đánh dấu phishing:", e, element); }
}
function addSuspicionWarning(element, tooltipText) { /* ... Giữ nguyên ... */
    if (!element || typeof element.querySelector !== 'function' || typeof element.classList === 'undefined' || !element.isConnected) return;
    if (element.querySelector(`.${SUSPICIOUS_BANNER_CLASS}`)) return;
    try {
        element.classList.add(SUSPICIOUS_CLASS);
        const banner = document.createElement('div'); banner.className = SUSPICIOUS_BANNER_CLASS;
        banner.innerHTML = `<strong>⚠️ Nội dung đáng ngờ:</strong> Email này chứa các yếu tố hoặc từ khóa thường thấy trong email lừa đảo. Hãy kiểm tra kỹ người gửi và các yêu cầu trước khi nhấp vào liên kết hoặc cung cấp thông tin.`;
        banner.title = tooltipText;
        if (element.firstChild && element.firstChild.isConnected) element.insertBefore(banner, element.firstChild);
        else element.appendChild(banner);
    } catch (e) { console.error("CS: Lỗi thêm banner cảnh báo:", e, element); }
}

// --- Scanning Logic ---

async function scanAndMarkLinks(containerElement, isEmailContentView = false) { // Thêm cờ isEmailContentView
    if (!containerElement || typeof containerElement.querySelectorAll !== 'function') return;
    // Chỉ quét sâu nếu là content view, nếu là list view chỉ quét link cơ bản (nếu muốn)
    // Hiện tại, chúng ta chỉ quét link bên trong email view được mở
    if (!isEmailContentView) return;

    try {
        const links = containerElement.querySelectorAll('a[href]');
        for (const link of links) {
            if (!link.isConnected || link.hasAttribute(CHECKED_ATTR)) continue;
            link.setAttribute(CHECKED_ATTR, 'true');
            let href;
            try {
                href = link.href;
                if (!href || href.startsWith('mailto:') || href.startsWith('javascript:') || href.startsWith('#')) continue;
                const urlObj = new URL(href);
                const domain = (urlObj.hostname || '').toLowerCase().replace(/^www\./, '');
                if (!domain) continue;
                const result = await checkDomain(domain);
                if (result.isPhishing) markElementAsPhishing(link, `Tên miền đáng ngờ: ${domain}. Lý do: ${result.reason || 'Đã biết'}`);
            } catch (error) {
                if (!(error instanceof DOMException && error.name === 'SecurityError') && !(error instanceof TypeError && (error.message.includes("Invalid URL") || error.message.includes("Invalid hostname")))) {
                    // console.warn("CS: Lỗi xử lý link:", href || link.outerHTML, error.message);
                }
            }
        }
    } catch (e) { console.error("CS: Lỗi quét link:", e, containerElement); }
}

async function scanAndMarkSender(senderInfoElement, isEmailContentView = false) { // Thêm cờ isEmailContentView
    if (!senderInfoElement || !senderInfoElement.isConnected || senderInfoElement.hasAttribute(CHECKED_ATTR)) return;
    senderInfoElement.setAttribute(CHECKED_ATTR, 'true');
    // Chỉ đánh dấu người gửi nếu đang xem email chi tiết
    if (!isEmailContentView) return;

    let emailAddress = null;
    try {
        emailAddress = senderInfoElement.getAttribute('email')
                       || (senderInfoElement.getAttribute('title') || '').match(/[\w.-]+@[\w.-]+\.\w+/)?.[0]
                       || (senderInfoElement.innerText || '').match(/[\w.-]+@[\w.-]+\.\w+/)?.[0];
        const normalizedEmail = (emailAddress || '').toLowerCase().trim();
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (normalizedEmail && emailRegex.test(normalizedEmail)) {
            const result = await checkEmailSender(normalizedEmail);
            if (result.isPhishing) {
                markElementAsPhishing(senderInfoElement, `Email gửi đáng ngờ: ${normalizedEmail}. Lý do: ${result.reason || 'Đã biết'}`);
            }
        }
    } catch (error) {
        // Sửa lỗi ReferenceError
        console.warn("CS: Lỗi khi quét người gửi:", error.message, senderInfoElement);
    }
}

function scanAndMarkKeywords(contentElement, isEmailContentView = false) { // Thêm cờ isEmailContentView
    if (!contentElement || !contentElement.isConnected || contentElement.hasAttribute(KEYWORDS_CHECKED_ATTR)) return;
    contentElement.setAttribute(KEYWORDS_CHECKED_ATTR, 'true');

    // *** Chỉ thêm banner cảnh báo nếu đây là nội dung email chi tiết ***
    if (!isEmailContentView) {
        // console.log("CS: Bỏ qua quét keyword cho list view element:", contentElement); // Debug
        return;
    }

    try {
        const textContent = (contentElement.textContent || '').substring(0, 15000).toLowerCase();
        if (!textContent) return;
        let foundKeywords = [];
        for (const keyword of SUSPICIOUS_KEYWORDS) {
            if (textContent.includes(keyword.toLowerCase())) {
                foundKeywords.push(keyword);
                if (foundKeywords.length > 5) break;
            }
        }
        if (foundKeywords.length > 0) {
            addSuspicionWarning(contentElement, `Email chứa các từ khóa đáng ngờ: ${foundKeywords.join(', ')}`);
        }
    } catch (error) { console.warn("CS: Lỗi quét keywords:", error.message, contentElement); }
}


// --- Main Processing Function ---
const processEmailView = (emailNode) => {
    if (!emailNode || typeof emailNode.querySelector !== 'function' || !emailNode.isConnected || emailNode.hasAttribute('data-phishing-processed')) return;

    // *** Xác định xem đây có phải là view nội dung email chi tiết không ***
    let isEmailContentView = false;
    let senderElement = null;
    let contentElement = null;
    const hostname = window.location.hostname;

    // --- Selectors cần được kiểm tra và cập nhật thường xuyên ---
    try {
        if (hostname.includes('mail.google.com')) {
            // Gmail: Email view thường có class 'a3s' hoặc 'ii gt' cho nội dung
            // List view row thường có class 'zA yO' hoặc role="row"
            contentElement = emailNode.querySelector('.a3s.aiL, div.ii.gt');
            // Kiểm tra xem emailNode có phải là một row trong list không
            const isListViewRow = emailNode.matches && (emailNode.matches('.zA') || emailNode.closest('.zA'));
            if (contentElement && !isListViewRow) { // Chỉ coi là content view nếu tìm thấy content và không phải là list row
                isEmailContentView = true;
                const container = emailNode.closest('.nH.hx, .Bs.nH.io.adp') || emailNode;
                senderElement = container?.querySelector('.gD[email], .go, .gF.gK .gD, span[email]');
            }
        } else if (hostname.includes('outlook.')) {
            // Outlook: Email view content thường là 'div[aria-label="Message body"]' hoặc 'rps_*'
            // List view row thường có role="option" hoặc data-testid="ConversationReadingPaneContainer"
             contentElement = emailNode.querySelector('div[aria-label="Message body"], .rps_*, .PlainText, .x_WordSection1');
             const isListViewRow = emailNode.matches && (emailNode.matches('div[role="option"]') || emailNode.closest('div[role="option"]'));
              if (contentElement && !isListViewRow) {
                 isEmailContentView = true;
                 const container = emailNode.closest('div[role="document"], div[data-testid="readingPaneContainer"], div[autoid^="_lvv_c"]') || emailNode;
                 senderElement = container?.querySelector('button[data-is-focusable="true"] span[title*="@"], span[data-automationid="splitbuttonprimary"] span, .LAbQF, .EnRL7') || container?.querySelector('span[title*="@"]');
              }
        }

        // Đánh dấu đã xử lý để tránh lặp lại bởi observer
        emailNode.setAttribute('data-phishing-processed', 'true');
        // console.log(`CS: Processing Node. Is Email Content View: ${isEmailContentView}`, emailNode); // Debug

        // --- Thực hiện quét dựa trên ngữ cảnh ---
        if (senderElement) scanAndMarkSender(senderElement, isEmailContentView);
        // Quét content và links chỉ khi là email view thực sự
        if (contentElement && isEmailContentView) {
            scanAndMarkLinks(contentElement, true); // Pass true to indicate content view
            scanAndMarkKeywords(contentElement, true); // Pass true
        } else if (emailNode && isEmailContentView) {
             // Fallback nếu contentElement không tìm được nhưng xác định là email view
             scanAndMarkLinks(emailNode, true);
             scanAndMarkKeywords(emailNode, true);
        }
        // Không quét keyword hay thêm banner nếu isEmailContentView là false

    } catch (error) { console.error("CS: Lỗi trong processEmailView:", error, emailNode); }
};

const processEmailViewDebounced = debounce(processEmailView, DEBOUNCE_DELAY);

// --- MutationObserver ---
let observer = null;
const observerOptions = { childList: true, subtree: true, attributes: false }; // Bỏ attributes để giảm tần suất trigger, tập trung vào thêm node mới

function startObserver() {
    if (observer) observer.disconnect();
    observer = new MutationObserver((mutationsList) => {
        mutationsList.forEach((mutation) => {
            if (mutation.addedNodes) {
                mutation.addedNodes.forEach(node => {
                    // Chỉ xử lý Element node và đảm bảo nó còn trong DOM
                    if (node.nodeType === Node.ELEMENT_NODE && node.isConnected) {
                        // Kiểm tra sơ bộ xem node này có khả năng là container email không
                        // Đây là heuristic, cần tinh chỉnh selector
                        if (node.matches && (
                            // Gmail selectors (rộng hơn để bắt container)
                            node.matches('.nH.hx, .Bs.nH.io.adp, .bzA') || node.querySelector('.a3s.aiL, div.ii.gt') ||
                            // Outlook selectors (rộng hơn để bắt container)
                            node.matches('div[role="document"], div[data-testid="readingPaneContainer"], div[autoid^="_lvv_c"]') || node.querySelector('div[aria-label="Message body"]')
                        )) {
                            // Gọi hàm xử lý debounce cho node có khả năng là email view
                            processEmailViewDebounced(node);
                        }
                         // Quét link ngay lập tức cho mọi node được thêm vào (nếu muốn, nhưng có thể thừa)
                         // scanAndMarkLinks(node, false); // false vì chưa chắc là content view
                    }
                });
            }
        });
    });
    try {
        observer.observe(document.body, observerOptions);
        console.log("CS: MutationObserver started (focused on childList).");
    } catch(e) {
        console.error("CS: Failed to start MutationObserver.", e);
    }
}

// --- Initial Scan Logic ---
function runInitialScan() {
     console.log("CS: Running initial scan for already open email views...");
    try {
        // *** CHỈ quét các element có khả năng là Email View ĐANG MỞ ***
        // Selector này cần rất cẩn thận và đặc hiệu
        let openEmailView = null;
         if (window.location.hostname.includes('mail.google.com')) {
             // Gmail thường dùng các class này cho khu vực chính khi email mở
             openEmailView = document.querySelector('.nH.hx:not([style*="display: none"]) .ii.gt, .nH.hx:not([style*="display: none"]) .a3s.aiL');
         } else if (window.location.hostname.includes('outlook.')) {
              // Outlook có thể dùng các data-testid hoặc aria-label
             openEmailView = document.querySelector('div[data-testid="readingPaneContainer"] div[aria-label="Message body"], div[role="document"]:not([style*="display: none"])');
         }

         if (openEmailView && openEmailView.isConnected) {
             console.log("CS: Found potentially open email view, running initial process.", openEmailView);
             processEmailView(openEmailView); // Chạy ngay không debounce
         } else {
             console.log("CS: No obvious open email view found on initial scan.");
         }

    } catch (e) { console.error("CS: Error during initial scan execution:", e); }
}

// --- Initialization ---
function initialize() {
    console.log("CS: Initializing Phishing Guard Pro content script v2.3...");
    startObserver();
    // Chạy initial scan sau khi trang đã tải hoàn toàn và ổn định hơn
    if (document.readyState === 'complete') {
        setTimeout(runInitialScan, 2000); // Chạy sau 2s nếu đã complete
    } else {
        window.addEventListener('load', () => setTimeout(runInitialScan, 1500), { once: true }); // Chạy sau 1.5s khi trang load xong
    }
}

initialize();