/**
 * VN Phishing Guard Pro - Content Script (v2.1)
 *
 * Chịu trách nhiệm:
 * - Inject vào trang Gmail, Outlook.
 * - Phát hiện khi email được hiển thị.
 * - Trích xuất thông tin người gửi, link, nội dung.
 * - Gửi yêu cầu kiểm tra đến background script (domain, email).
 * - Quét từ khóa đáng ngờ cục bộ.
 * - Đánh dấu các thành phần đáng ngờ/lừa đảo trên giao diện người dùng.
 * - Sử dụng MutationObserver để theo dõi các thay đổi động.
 */

console.log("Phishing Guard Pro: Content script v2.1 đang chạy trên:", window.location.hostname);

// --- Các từ khóa đáng ngờ cần quét trong nội dung email ---
const SUSPICIOUS_KEYWORDS = [
    // Tiếng Việt
    'xác minh tài khoản', 'cập nhật thông tin', 'mật khẩu của bạn', 'đã hết hạn',
    'đăng nhập ngay', 'khẩn cấp', 'quan trọng', 'tài khoản bị khóa', 'tạm ngưng',
    'ngân hàng', 'thẻ tín dụng', 'chuyển tiền', 'thanh toán', 'hóa đơn',
    'quà tặng', 'trúng thưởng', 'miễn phí', 'yêu cầu hành động', 'số an sinh xã hội',
    'nhấp vào đây', 'liên kết này', 'mã OTP', 'yêu cầu gấp', 'thông tin cá nhân',
    'tài khoản của bạn', 'vấn đề bảo mật', 'khóa tạm thời', 'truy cập trái phép',
    'xác thực', 'cần xác nhận', 'ưu đãi đặc biệt', 'duy nhất hôm nay',
    // Tiếng Anh (phổ biến)
    'verify your account', 'update information', 'your password', 'has expired',
    'login immediately', 'urgent', 'important', 'account locked', 'suspended',
    'bank', 'credit card', 'transfer money', 'payment', 'invoice', 'tax refund',
    'gift', 'won prize', 'free', 'action required', 'ssn', 'social security number',
    'click here', 'this link', 'one-time password', 'immediate attention', 'personal details',
    'your account', 'security issue', 'temporary lock', 'unauthorized access',
    'authenticate', 'confirm', 'special offer', 'today only', 'confirm identity'
];

// --- Hàm Debounce ---
// Ngăn chặn hàm chạy quá nhiều lần trong khoảng thời gian ngắn
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func.apply(this, args); // Dùng apply để giữ đúng `this` context nếu cần
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// --- Hàm Tương tác với Background Script ---

/**
 * Gửi yêu cầu kiểm tra domain đến background script.
 * @param {string} domain Tên miền cần kiểm tra (đã chuẩn hóa).
 * @returns {Promise<{isPhishing: boolean, reason: string, error?: string}>} Kết quả kiểm tra.
 */
async function checkDomain(domain) {
  if (!domain) return { isPhishing: false, reason: "Tên miền không hợp lệ" };
  try {
    const response = await chrome.runtime.sendMessage({ action: 'checkDomain', value: domain });
     if (chrome.runtime.lastError) {
        console.error("Phishing Guard Pro: Lỗi runtime khi checkDomain:", chrome.runtime.lastError.message);
        // Có thể background script đang khởi động lại sau khi cập nhật
        return { isPhishing: false, reason: "Lỗi giao tiếp với extension" };
    }
    // Trả về response hoặc một object mặc định nếu response không hợp lệ
    return response && typeof response === 'object' ? response : { isPhishing: false, reason: "Phản hồi không hợp lệ từ background" };
  } catch (error) {
    // Xử lý lỗi network hoặc lỗi khi background không tồn tại/không phản hồi
    if (error.message.includes("Could not establish connection") || error.message.includes("Receiving end does not exist")) {
        console.warn("Phishing Guard Pro: Không thể kết nối background (checkDomain).");
        return { isPhishing: false, reason: "Không thể kết nối dịch vụ kiểm tra" };
    } else {
        console.error("Phishing Guard Pro: Lỗi gửi tin nhắn checkDomain:", error);
        return { isPhishing: false, reason: "Lỗi không xác định khi kiểm tra" };
    }
  }
}

/**
 * Gửi yêu cầu kiểm tra email người gửi đến background script.
 * @param {string} email Địa chỉ email cần kiểm tra (đã chuẩn hóa).
 * @returns {Promise<{isPhishing: boolean, reason: string, error?: string}>} Kết quả kiểm tra.
 */
async function checkEmailSender(email) {
  if (!email) return { isPhishing: false, reason: "Địa chỉ email không hợp lệ" };
   try {
    const response = await chrome.runtime.sendMessage({ action: 'checkEmailSender', value: email });
     if (chrome.runtime.lastError) {
        console.error("Phishing Guard Pro: Lỗi runtime khi checkEmailSender:", chrome.runtime.lastError.message);
        return { isPhishing: false, reason: "Lỗi giao tiếp với extension" };
    }
     return response && typeof response === 'object' ? response : { isPhishing: false, reason: "Phản hồi không hợp lệ từ background" };
  } catch (error) {
     if (error.message.includes("Could not establish connection") || error.message.includes("Receiving end does not exist")) {
        console.warn("Phishing Guard Pro: Không thể kết nối background (checkEmailSender).");
        return { isPhishing: false, reason: "Không thể kết nối dịch vụ kiểm tra" };
    } else {
        console.error("Phishing Guard Pro: Lỗi gửi tin nhắn checkEmailSender:", error);
         return { isPhishing: false, reason: "Lỗi không xác định khi kiểm tra" };
    }
  }
}

// --- Hàm Xử Lý Giao Diện ---

/**
 * Đánh dấu một element là lừa đảo (màu đỏ).
 * @param {HTMLElement} element Element cần đánh dấu.
 * @param {string} tooltipText Nội dung giải thích hiển thị khi hover.
 */
function markElementAsPhishing(element, tooltipText) {
    // Kiểm tra element hợp lệ trước khi thao tác
    if (!element || typeof element.classList === 'undefined' || !element.isConnected) return;
    try {
        element.classList.add('phishing-guard-alert-phishing');
        // Cập nhật title an toàn, tránh lỗi nếu element bị xóa khỏi DOM
        if (element.isConnected) {
            element.title = `CẢNH BÁO LỪA ĐẢO! ${tooltipText}`;
        }
    } catch (e) {
        console.error("Phishing Guard Pro: Lỗi khi đánh dấu phishing:", e, element);
    }
}

/**
 * Thêm một banner cảnh báo nội dung đáng ngờ (màu vàng) vào đầu element.
 * @param {HTMLElement} element Element chứa nội dung cần thêm banner.
 * @param {string} tooltipText Nội dung giải thích chi tiết (hiển thị khi hover banner).
 */
function addSuspicionWarning(element, tooltipText) {
     // Kiểm tra element hợp lệ
     if (!element || typeof element.querySelector !== 'function' || typeof element.classList === 'undefined' || !element.isConnected) return;

     // Chỉ thêm banner một lần
     if (element.querySelector('.phishing-guard-alert-suspicious-banner')) return;

     try {
         element.classList.add('phishing-guard-alert-suspicious');

         const banner = document.createElement('div');
         banner.className = 'phishing-guard-alert-suspicious-banner';
         // Có thể thêm icon report trực tiếp vào banner
         banner.innerHTML = `<strong>⚠️ Nội dung đáng ngờ:</strong> Email này chứa các yếu tố hoặc từ khóa thường thấy trong email lừa đảo. Hãy kiểm tra kỹ người gửi và các yêu cầu trước khi thực hiện hành động.`;
         banner.title = tooltipText;

         // Thêm banner vào đầu element một cách an toàn
         if (element.firstChild && element.firstChild.isConnected) {
            element.insertBefore(banner, element.firstChild);
         } else {
            element.appendChild(banner);
         }
     } catch (e) {
         console.error("Phishing Guard Pro: Lỗi khi thêm banner cảnh báo:", e, element);
     }
}

// --- Hàm Quét Logic ---

/**
 * Quét và đánh dấu các liên kết trong một container.
 * @param {HTMLElement} containerElement Element chứa các liên kết cần quét.
 */
async function scanAndMarkLinks(containerElement) {
    if (!containerElement || typeof containerElement.querySelectorAll !== 'function') return;

    // Sử dụng try-catch lớn bao quanh để tránh lỗi dừng toàn bộ script
    try {
        const links = containerElement.querySelectorAll('a[href]');
        // console.log(`Phishing Guard Pro: Found ${links.length} links in container`, containerElement); // Debug

        for (const link of links) {
            // Bỏ qua nếu link không còn trong DOM hoặc đã được kiểm tra
            if (!link.isConnected || link.dataset.phishingChecked) {
                continue;
            }
            link.dataset.phishingChecked = 'true'; // Đánh dấu ngay để tránh xử lý lại

            let href;
            try {
                href = link.href; // Lấy href có thể gây lỗi SecurityError
                // Bỏ qua các loại link không cần kiểm tra
                if (!href || href.startsWith('mailto:') || href.startsWith('javascript:') || href.startsWith('#')) {
                    continue;
                }

                const urlObj = new URL(href); // Phân tích URL, có thể lỗi nếu href không hợp lệ
                const domain = (urlObj.hostname || '').toLowerCase().replace(/^www\./, '');
                if (!domain) continue; // Bỏ qua nếu không có hostname hợp lệ

                const result = await checkDomain(domain); // Gọi hàm kiểm tra
                if (result.isPhishing) {
                    markElementAsPhishing(link, `Tên miền đáng ngờ: ${domain}. Lý do: ${result.reason || 'Đã biết'}`);
                }
                 // TODO: Thêm kiểm tra nâng cao:
                 // 1. Phân tích tham số URL (urlObj.searchParams) tìm thông tin nhạy cảm (email, id...)
                 // 2. So sánh link text (link.innerText) với đích đến (domain) để phát hiện che giấu link
                 // 3. (Nâng cao - Backend) Gửi URL đầy đủ để backend phân tích sâu hơn nếu domain trông bình thường

            } catch (error) {
                // Bắt các lỗi thường gặp khi xử lý link
                if (error instanceof DOMException && error.name === 'SecurityError') {
                    console.warn("Phishing Guard Pro: Không thể truy cập href của link do chính sách bảo mật:", link);
                } else if (error instanceof TypeError && (error.message.includes("Invalid URL") || error.message.includes("Invalid base URL") || error.message.includes("Invalid hostname"))) {
                   // console.warn("Phishing Guard Pro: URL không hợp lệ hoặc không phân tích được:", href || link.outerHTML);
                } else {
                   console.warn("Phishing Guard Pro: Lỗi không xác định khi xử lý link:", href || link.outerHTML, error);
                }
                continue; // Bỏ qua link lỗi và tiếp tục
            }
        }
    } catch (e) {
         console.error("Phishing Guard Pro: Lỗi nghiêm trọng trong quá trình quét link:", e, containerElement);
    }
}

/**
 * Quét và đánh dấu người gửi trong element chứa thông tin người gửi.
 * @param {HTMLElement} senderInfoElement Element chứa thông tin người gửi.
 */
async function scanAndMarkSender(senderInfoElement) {
    if (!senderInfoElement || !senderInfoElement.isConnected || senderInfoElement.dataset.phishingChecked) return;
    senderInfoElement.dataset.phishingChecked = 'true';

    let emailAddress = null;
    try {
        // Cố gắng trích xuất email bằng nhiều cách, ưu tiên attribute 'email'
        emailAddress = senderInfoElement.getAttribute('email')
                       || (senderInfoElement.getAttribute('title') || '').match(/[\w\.-]+@[\w\.-]+\.\w+/)?.[0]
                       || (senderInf)
        !(!oElement.innerText && !'').match(/[\w\.-]+@[\w\.-]+\.\w+/)?.[0];

        const normalizedEmail = (emailAddress || '').toLowerCase().trim();
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/; // Re-check format

        if (normalizedEmail && emailRegex.test(normalizedEmail)) {
            const result = await checkEmailSender(normalizedEmail);
            if (result.isPhishing) {
                markElementAsPhishing(senderInfoElement, `Email gửi đáng ngờ: ${normalizedEmail}. Lý do: ${result.reason || 'Đã biết'}`);
            }
        } else if (emailAddress) { // Extracted something but it was invalid
             // console.warn("Phishing Guard Pro: Extracted invalid email:", emailAddress, "from element:", senderInfoElement);
        }
         // Optional: Check display name vs actual email domain (e.g., Display: "Bank Support", Email: "hacker@dodgy.com")
         // This requires parsing the display name and comparing domains.

    } catch (error) {
        console.warn("Phishing Guard Pro: Lỗi khi quét người gửi:", error, senderInfoElement);
    }
}

/**
 * Quét từ khóa đáng ngờ trong nội dung của một element.
 * @param {HTMLElement} contentElement Element chứa nội dung email.
 */
function scanAndMarkKeywords(contentElement) {
    if (!contentElement || !contentElement.isConnected || contentElement.dataset.phishingKeywordsChecked) return;
    contentElement.dataset.phishingKeywordsChecked = 'true';

    try {
        // Sử dụng textContent để lấy text thuần túy, tránh lấy text từ script/style tags bên trong
        // Giới hạn độ dài text để tránh xử lý quá nặng trên email rất dài
        const textContent = (contentElement.textContent || '').substring(0, 10000).toLowerCase();
        if (!textContent) return;

        let foundKeywords = [];
        // Tối ưu việc tìm kiếm: tạo regex lớn hoặc tìm từng từ
        for (const keyword of SUSPICIOUS_KEYWORDS) {
            if (textContent.includes(keyword.toLowerCase())) { // Tìm kiếm đơn giản
                foundKeywords.push(keyword);
                // Có thể dừng sớm nếu tìm thấy đủ số lượng từ khóa đáng ngờ
                if (foundKeywords.length > 5) break;
            }
        }

        if (foundKeywords.length > 0) {
            addSuspicionWarning(contentElement, `Email chứa các từ khóa/cụm từ đáng ngờ: ${foundKeywords.join(', ')}`);
        }
    } catch (error) {
         console.warn("Phishing Guard Pro: Lỗi khi quét keywords:", error, contentElement);
    }
}

// --- Hàm Xử Lý Chính và MutationObserver ---

/**
 * Hàm xử lý chính khi một khu vực email được xác định là đã hiển thị hoặc thay đổi.
 * @param {HTMLElement} emailNode Element gốc chứa email view.
 */
const processEmailView = (emailNode) => {
    // console.log("Phishing Guard Pro: Processing email view...", emailNode); // Debug
    if (!emailNode || typeof emailNode.querySelector !== 'function' || !emailNode.isConnected) {
        return; // Bỏ qua nếu node không hợp lệ hoặc đã bị xóa
    }

    // --- Xác định các phần tử con một cách linh hoạt và an toàn hơn ---
    let senderElement = null;
    let contentElement = null;
    const hostname = window.location.hostname;

    try {
        // Sử dụng các selectors đã được tinh chỉnh, thêm fallback và kiểm tra null
        if (hostname.includes('mail.google.com')) {
            const container = emailNode.closest('.nH.hx, .Bs.nH.io.adp') || emailNode;
            senderElement = container?.querySelector('.gD[email], .go, .gF.gK .gD, span[email]'); // Thêm span[email]
            contentElement = container?.querySelector('.a3s.aiL, div.ii.gt, .aQH, div[role="document"]'); // Thêm div[role="document"] (trong print view?)
        } else if (hostname.includes('outlook.')) {
            const container = emailNode.closest('div[role="document"], div[data-testid="readingPaneContainer"], div[autoid^="_lvv_c"]') || emailNode; // Thêm autoid selector
            senderElement = container?.querySelector('button[data-is-focusable="true"] span[title*="@"], span[data-automationid="splitbuttonprimary"] span, .LAbQF, .EnRL7') // Thêm class EnRL7
                          || container?.querySelector('span[title*="@"]'); // Fallback tìm span có title chứa @
            contentElement = container?.querySelector('div[aria-label="Message body"], .rps_*, .PlainText, .x_WordSection1'); // Thêm class outlook khác
        }

        // --- Thực hiện quét ---
        if (senderElement) scanAndMarkSender(senderElement);
        // Quét content và links trong contentElement nếu tìm thấy
        if (contentElement) {
            scanAndMarkLinks(contentElement);
            scanAndMarkKeywords(contentElement);
        } else {
            // Fallback: Nếu không tìm thấy contentElement cụ thể, quét toàn bộ emailNode
            // Điều này có thể quét cả header/footer nhưng đảm bảo link/keyword không bị bỏ sót
            // console.warn("Phishing Guard Pro: contentElement not found, scanning entire emailNode:", emailNode);
            scanAndMarkLinks(emailNode);
            scanAndMarkKeywords(emailNode);
        }
    } catch (error) {
        console.error("Phishing Guard Pro: Lỗi nghiêm trọng trong processEmailView:", error, emailNode);
    }
};

// Sử dụng debounce cho hàm xử lý chính
const processEmailViewDebounced = debounce(processEmailView, 750); // Tăng debounce lên 750ms

// --- Thiết lập MutationObserver ---
const observer = new MutationObserver((mutationsList) => {
    // Sử dụng Set để chỉ xử lý mỗi node một lần trong một loạt mutations
    const nodesToProcess = new Set();

    mutationsList.forEach((mutation) => {
        // Kiểm tra node target của mutation (nếu là attribute change)
        if (mutation.target?.nodeType === Node.ELEMENT_NODE && mutation.target.isConnected) {
             nodesToProcess.add(mutation.target);
        }
        // Kiểm tra các node được thêm vào
        if (mutation.addedNodes) {
             mutation.addedNodes.forEach(node => {
                 if (node.nodeType === Node.ELEMENT_NODE && node.isConnected) {
                    nodesToProcess.add(node);
                    // Quét link ngay lập tức trong node mới để phản hồi nhanh hơn
                     if (node.matches('a[href]') || node.querySelector('a[href]')) {
                         scanAndMarkLinks(node);
                     }
                 }
             });
        }
    });

    // Gọi hàm xử lý debounce cho tất cả các node bị ảnh hưởng
    nodesToProcess.forEach(node => {
         // Kiểm tra lại isConnected phòng trường hợp node bị xóa ngay sau khi thêm vào Set
        if (node.isConnected) {
             processEmailViewDebounced(node);
        }
    });
});

// --- Bắt đầu Observe và Quét ban đầu ---
try {
    // Chỉ observe khi trang đã tải tương đối hoàn chỉnh
    if (document.readyState === 'complete' || document.readyState === 'interactive') {
        startObserverAndInitialScan();
    } else {
        window.addEventListener('DOMContentLoaded', startObserverAndInitialScan, { once: true });
    }
} catch (e) {
    console.error("Phishing Guard Pro: Không thể bắt đầu Observer hoặc quét ban đầu.", e);
}

function startObserverAndInitialScan() {
    console.log("Phishing Guard Pro: DOM ready, starting Observer and initial scan...");
    observer.observe(document.body, {
        childList: true,
        subtree: true,
        attributes: true,
        attributeFilter: ['class', 'style', 'id', 'href', 'data-loaded'] // Lọc các thuộc tính có khả năng thay đổi khi load email
    });
    console.log("Phishing Guard Pro: MutationObserver started.");

    // Quét ban đầu sau một khoảng delay ngắn để đảm bảo UI đã ổn định
    setTimeout(() => {
        console.log("Phishing Guard Pro: Running delayed initial scan...");
        try {
            // Sử dụng selector rộng hơn và bao quát hơn cho quét ban đầu
            document.querySelectorAll('div[role="listitem"], div[role="main"], div[aria-label*="email"], div[data-testid="readingPaneContainer"], .ii, .nH').forEach(potentialEmailNode => {
                if (potentialEmailNode.isConnected) {
                    processEmailView(potentialEmailNode); // Chạy không debounce lần đầu
                }
            });
            // Quét link toàn bộ body như fallback cuối cùng
            scanAndMarkLinks(document.body);
            console.log("Phishing Guard Pro: Initial scan complete.");
        } catch (e) {
             console.error("Phishing Guard Pro: Error during initial scan execution:", e);
        }
    }, 2000); // Delay 2 giây
}