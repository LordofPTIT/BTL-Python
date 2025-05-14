let SCAN_KEYWORDS = [];
let REPORTED_MALICIOUS_EMAILS = [];
let observer = null;
const scannedEmailSignatures = new Set();

function getEmailSignature(subject, from, bodySample) {
    const bodyPart = bodySample.substring(0, 100);
    return `${subject}#${from}#${bodyPart}`;
}

async function initializeScanner() {
    try {
        SCAN_KEYWORDS = await chrome.runtime.sendMessage({ action: "getKeywords" });
        if (!SCAN_KEYWORDS || SCAN_KEYWORDS.length === 0) {
            console.warn("VN Phishing Guard Pro: Keyword list is empty. Email scanning may be ineffective.");
        }

        const reportedData = await chrome.runtime.sendMessage({ action: "getReportedMaliciousEmails" });
        if (reportedData && reportedData.success && reportedData.emails) {
            REPORTED_MALICIOUS_EMAILS = reportedData.emails.map(item => item.value.toLowerCase());
        } else {
            console.warn("VN Phishing Guard Pro: Could not load reported malicious emails from backend:", reportedData ? reportedData.error : "No response");
            REPORTED_MALICIOUS_EMAILS = [];
        }
        console.log("VN Phishing Guard Pro: Scanner initialized. Keywords:", SCAN_KEYWORDS.length, "Reported emails:", REPORTED_MALICIOUS_EMAILS.length);
    } catch (e) {
        console.error("VN Phishing Guard Pro: Exception when trying to load reported malicious emails:", e);
        REPORTED_MALICIOUS_EMAILS = [];
    }
}

function getEmailContent() {
    let subject = "";
    let body = "";
    let from = "";
    const { host } = window.location;

    if (host.includes("mail.google.com")) {
        const subjectEl = document.querySelector('h2[data-thread-perm-id]');
        if (subjectEl) subject = subjectEl.textContent.trim();

        const senderNameEl = document.querySelector('span[email][name].gD');
        const senderEmailEl = document.querySelector('span[email][data-hovercard-id].gD');

        if (senderEmailEl && senderEmailEl.getAttribute('email')) {
            from = senderEmailEl.getAttribute('email');
        } else if (senderNameEl && senderNameEl.getAttribute('email')) {
            from = senderNameEl.getAttribute('email');
        } else {
            const fromHeader = Array.from(document.querySelectorAll('.gD')).find(el => el.previousSibling && el.previousSibling.textContent === "From:");
            if (fromHeader) from = fromHeader.textContent.trim();
        }

        const emailBodyEls = document.querySelectorAll('.a3s.aiL, div.adn.ads [role="listitem"] .gs div div[dir="ltr"], .ii.gt div[data-message-id]');
        emailBodyEls.forEach(el => body += el.innerText + "\n");

    } else if (host.includes("outlook.live.com") || host.includes("outlook.office.com")) {
        const subjectEl = document.querySelector('[aria-label^="Subject"], [data-testid="subject-line-text"]');
        if (subjectEl) subject = subjectEl.textContent.trim();

        const emailAddressEl = document.querySelector('div[role="heading"] button span[type="email"]');
        if(emailAddressEl && emailAddressEl.textContent.includes('@')) {
            from = emailAddressEl.textContent.trim();
        } else {
            const fromContainer = document.querySelector('[aria-label="Message actions"]');
            if (fromContainer) {
                const emailSpan = Array.from(fromContainer.querySelectorAll('span')).find(s => s.textContent.includes('@'));
                if (emailSpan) from = emailSpan.textContent.trim();
            }
        }
        const bodyEl = document.querySelector('div[aria-label="Message body"], div[role="document"]');
        if (bodyEl) body = bodyEl.innerText;
    }
    return { subject: subject.toLowerCase(), body: body.toLowerCase(), from: from.toLowerCase() };
}

async function scanEmailContent() {
    const { subject, body, from } = getEmailContent();
    if (!subject && !body && !from) return;
    
    const emailSignature = getEmailSignature(subject, from, body);
    let response = {};
    try {
        // Kiểm tra với background script xem đã hiển thị cảnh báo cho email này chưa
        response = await chrome.runtime.sendMessage({ 
            action: "checkEmailWarning",
            emailSignature: emailSignature
        });
    } catch (e) {
        if (e && e.message && e.message.includes('Extension context invalidated')) {
            // Nếu context invalidated, fallback: luôn hiển thị cảnh báo
            showWarningBanner('Email này có dấu hiệu đáng ngờ hoặc extension không thể kiểm tra trạng thái. Hãy cẩn thận!', emailSignature);
            return;
        } else {
            console.warn('Lỗi gửi message tới background:', e);
        }
    }
    if (response.hasShownWarning) {
        return;
    }

    let keywordFound = null;
    if (SCAN_KEYWORDS && SCAN_KEYWORDS.length > 0) {
        for (const keyword of SCAN_KEYWORDS) {
            if (subject.includes(keyword.toLowerCase()) || body.includes(keyword.toLowerCase())) {
                keywordFound = keyword;
                break;
            }
        }
    }

    if (from && REPORTED_MALICIOUS_EMAILS && REPORTED_MALICIOUS_EMAILS.length > 0) {
        for (const reportedEmail of REPORTED_MALICIOUS_EMAILS) {
            if (from === reportedEmail) {
                showWarningBanner('Đây là email có trong danh sách cảnh báo.', emailSignature);
                return;
            }
        }
    }

    if (keywordFound) {
        showWarningBanner(`Email này chứa từ khóa đáng ngờ: "${keywordFound}". Hãy cẩn thận!`, emailSignature);
        return;
    }
}

function showWarningBanner(message, emailSignature) {
    let popup = document.getElementById('phishing-warning-popup-email');
    if (!popup) {
        popup = document.createElement('div');
        popup.id = 'phishing-warning-popup-email';
        popup.style.position = 'fixed';
        popup.style.top = '50%';
        popup.style.left = '50%';
        popup.style.transform = 'translate(-50%, -50%)';
        popup.style.width = '600px';
        popup.style.height = '300px';
        popup.style.background = '#fff3cd';
        popup.style.color = '#856404';
        popup.style.border = '2px solid #ffeeba';
        popup.style.borderRadius = '12px';
        popup.style.boxShadow = '0 8px 32px rgba(0,0,0,0.18)';
        popup.style.display = 'flex';
        popup.style.flexDirection = 'column';
        popup.style.alignItems = 'center';
        popup.style.justifyContent = 'center';
        popup.style.zIndex = '2147483647';
        popup.style.fontSize = '1.1rem';
        popup.innerHTML = '';
        
        var msg = document.createElement('div');
        msg.style.marginBottom = '32px';
        msg.style.textAlign = 'center';
        msg.style.fontWeight = '600';
        msg.innerText = message;
        popup.appendChild(msg);
        
        var btn = document.createElement('button');
        btn.innerText = 'Tôi đã hiểu';
        btn.style.padding = '12px 32px';
        btn.style.background = '#5cb85c';
        btn.style.color = '#fff';
        btn.style.border = 'none';
        btn.style.borderRadius = '6px';
        btn.style.fontSize = '1rem';
        btn.style.fontWeight = '600';
        btn.style.cursor = 'pointer';
        btn.onclick = async function() {
            popup.remove();
            // Thông báo cho background script rằng đã hiển thị cảnh báo
            await chrome.runtime.sendMessage({
                action: "markEmailWarningShown",
                emailSignature: emailSignature
            });
        };
        popup.appendChild(btn);
        document.body.appendChild(popup);
    } else {
        popup.firstChild.textContent = message;
        popup.style.display = 'flex';
    }
}

function observeEmailChanges() {
    if (observer) observer.disconnect();
    const targetNode = document.body;
    if (!targetNode) {
        console.error("VN Phishing Guard Pro: Target node (document.body) not found for MutationObserver.");
        return;
    }
    const config = { childList: true, subtree: true };
    let debounceTimer;
    const callback = function(mutationsList, observerInstance) {
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
            if (window.location.host.includes("mail.google.com")) {
                if (document.querySelector('h2[data-thread-perm-id]')) scanEmailContent();
            } else if (window.location.host.includes("outlook.live.com") || window.location.host.includes("outlook.office.com")) {
                if (document.querySelector('[aria-label^="Subject"], [data-testid="subject-line-text"]')) scanEmailContent();
            }
        }, 1000);
    };
    observer = new MutationObserver(callback);
    observer.observe(targetNode, config);
    console.log("VN Phishing Guard Pro: MutationObserver started to scan email content.");
}

(async () => {
    await initializeScanner();
    scanEmailContent();
    observeEmailChanges();
})();

let lastUrlContent = location.href;
new MutationObserver(() => {
    const url = location.href;
    if (url !== lastUrlContent) {
        lastUrlContent = url;
        scanEmailContent();
        observeEmailChanges();
    }
}).observe(document, {subtree: true, childList: true});

function showDomainBlockWarning(domain, reason) {
    // Hiển thị popup cảnh báo đơn giản nếu không inject được từ background
    let popup = document.getElementById('phishing-warning-popup-domain');
    if (!popup) {
        popup = document.createElement('div');
        popup.id = 'phishing-warning-popup-domain';
        popup.style.position = 'fixed';
        popup.style.top = '0';
        popup.style.left = '0';
        popup.style.width = '100%';
        popup.style.height = '100%';
        popup.style.background = 'rgba(0,0,0,0.7)';
        popup.style.zIndex = '2147483647';
        popup.style.display = 'flex';
        popup.style.alignItems = 'center';
        popup.style.justifyContent = 'center';
        popup.innerHTML = `<div style="background:#fff;color:#d9534f;padding:32px;border-radius:12px;text-align:center;max-width:420px;width:420px;box-shadow:0 4px 24px rgba(0,0,0,0.13)"><h2>CẢNH BÁO AN NINH!</h2><p>Trang <b>${domain}</b> bị chặn.<br>Lý do: ${reason || 'Không rõ.'}</p><button id="close-domain-warning" style="margin-top:18px;padding:10px 32px;background:#5cb85c;color:#fff;border:none;border-radius:6px;font-size:1rem;font-weight:600;cursor:pointer;">Đã hiểu</button></div>`;
        document.body.appendChild(popup);
        document.getElementById('close-domain-warning').onclick = () => popup.remove();
    }
}