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

function scanEmailContent() {
    const { subject, body, from } = getEmailContent();
    if (!subject && !body && !from) return;

    const emailSignature = getEmailSignature(subject, from, body);
    if (scannedEmailSignatures.has(emailSignature)) {
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

    if (keywordFound) {
        console.log("VN Phishing Guard Pro: Phishing keyword found in email:", keywordFound);
        showWarningBanner(`Email này chứa từ khóa đáng ngờ: "${keywordFound}". Hãy cẩn thận!`);
        scannedEmailSignatures.add(emailSignature);
        return;
    }

    if (from && REPORTED_MALICIOUS_EMAILS && REPORTED_MALICIOUS_EMAILS.length > 0) {
        for (const reportedEmail of REPORTED_MALICIOUS_EMAILS) {
            if (from === reportedEmail) {
                console.log("VN Phishing Guard Pro: Sender email is in reported malicious list:", from);
                showWarningBanner(`Địa chỉ email người gửi (${from}) nằm trong danh sách báo cáo nguy hiểm.`);
                scannedEmailSignatures.add(emailSignature);
                return;
            }
        }
    }
    scannedEmailSignatures.add(emailSignature);
}

function showWarningBanner(message) {
    let banner = document.getElementById('phishing-warning-banner');
    if (!banner) {
        banner = document.createElement('div');
        banner.id = 'phishing-warning-banner';
        banner.style.backgroundColor = 'red';
        banner.style.color = 'white';
        banner.style.padding = '10px';
        banner.style.textAlign = 'center';
        banner.style.position = 'fixed';
        banner.style.top = '0';
        banner.style.left = '0';
        banner.style.width = '100%';
        banner.style.zIndex = '999999';
        banner.style.fontSize = '16px';
        banner.style.fontWeight = 'bold';
        const closeButton = document.createElement('button');
        closeButton.textContent = 'Đã hiểu';
        closeButton.style.marginLeft = '20px';
        closeButton.style.padding = '5px 10px';
        closeButton.style.color = 'red';
        closeButton.style.backgroundColor = 'white';
        closeButton.style.border = '1px solid red';
        closeButton.style.cursor = 'pointer';
        closeButton.onclick = function() {
            banner.style.display = 'none';
        };
        banner.appendChild(closeButton);
        if (document.body) {
            document.body.insertBefore(banner, document.body.firstChild);
        } else {
            document.addEventListener('DOMContentLoaded', () => {
                document.body.insertBefore(banner, document.body.firstChild);
            });
        }
    }
    banner.firstChild.textContent = message;
    banner.style.display = 'block';
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
        scannedEmailSignatures.clear();
        scanEmailContent();
        observeEmailChanges();
    }
}).observe(document, {subtree: true, childList: true});