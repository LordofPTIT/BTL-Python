let SCAN_KEYWORDS = [];
let REPORTED_MALICIOUS_EMAILS = [];
let observer = null;
const scannedEmailSignatures = new Set();

function getEmailSignature(subject, from, bodySample) {
    const bodyPart = bodySample.substring(0, 100); // Use a sample of the body
    return `${subject}#${from}#${bodyPart}`;
}

async function initializeScanner() {
    try {
        SCAN_KEYWORDS = await chrome.runtime.sendMessage({ action: "getKeywords" });
        if (!SCAN_KEYWORDS || SCAN_KEYWORDS.length === 0) {
            console.warn("Keyword list is empty. Email scanning may be ineffective.");
        }

        const reportedData = await chrome.runtime.sendMessage({ action: "getReportedMaliciousEmails" });
        if (reportedData.success && reportedData.emails) {
            REPORTED_MALICIOUS_EMAILS = reportedData.emails.map(item => item.value.toLowerCase());
        } else {
            console.error("Failed to load reported malicious emails:", reportedData.error);
        }
        console.log("Scanner initialized. Keywords:", SCAN_KEYWORDS.length, "Reported emails:", REPORTED_MALICIOUS_EMAILS.length);

    } catch (error) {
        console.error("Error initializing scanner:", error);
    }
}


function getEmailContent() {
    let subject = "";
    let body = "";
    let from = "";
    const { host } = window.location;

    if (host.includes("mail.google.com")) { // Gmail
        const subjectEl = document.querySelector('h2[data-thread-perm-id]');
        if (subjectEl) subject = subjectEl.textContent.trim();

        // More robust sender extraction for Gmail
        const senderNameEl = document.querySelector('span[email][name].gD'); // Sender name
        const senderEmailEl = document.querySelector('span[email][data-hovercard-id].gD'); // Email in hovercard

        if (senderEmailEl && senderEmailEl.getAttribute('email')) {
            from = senderEmailEl.getAttribute('email');
        } else if (senderNameEl && senderNameEl.getAttribute('email')) {
             from = senderNameEl.getAttribute('email');
        } else { // Fallback for older/different Gmail UI structures if any
            const fromHeader = Array.from(document.querySelectorAll('.gD')).find(el => el.previousSibling && el.previousSibling.textContent === "From:");
            if (fromHeader) from = fromHeader.textContent.trim();
        }

        const emailBodyEls = document.querySelectorAll('.a3s.aiL, div.adn.ads [role="listitem"] .gs div div[dir="ltr"], .ii.gt div[data-message-id]');
        emailBodyEls.forEach(el => body += el.innerText + "\n");

    } else if (host.includes("outlook.live.com") || host.includes("outlook.office.com")) { // Outlook
        const subjectEl = document.querySelector('[aria-label^="Subject"], [data-testid="subject-line-text"]');
        if (subjectEl) subject = subjectEl.textContent.trim();

        const fromEl = document.querySelector('[aria-label="From"] .rpHighlightAllClass') || // New UI
                       document.querySelector('span[autoid^="_ariaid_DisplayName"]'); // Older UI
        if (fromEl) from = fromEl.textContent.trim();

        // Extract actual email address for Outlook
        const emailAddressEl = document.querySelector('div[role="heading"] button span[type="email"]');
        if(emailAddressEl && emailAddressEl.textContent.includes('@')) {
            from = emailAddressEl.textContent.trim();
        } else { // Try to get from a more complex structure if the simple one fails
            const fromContainer = document.querySelector('[aria-label="Message actions"]');
            if (fromContainer) {
                 const emailSpan = Array.from(fromContainer.querySelectorAll('span')).find(s => s.textContent.includes('@'));
                 if (emailSpan) from = emailSpan.textContent.trim();
            }
        }


        const bodyEl = document.querySelector('div[aria-label="Message body"], div[role="document"]');
        if (bodyEl) body = bodyEl.innerText;
    }
    // Add Yahoo Mail selectors if needed

    return { subject: subject.toLowerCase(), body: body.toLowerCase(), from: from.toLowerCase() };
}

function scanEmailContent() {
    const { subject, body, from } = getEmailContent();
    if (!subject && !body && !from) return; // Not enough content to scan

    const emailSignature = getEmailSignature(subject, from, body);
    if (scannedEmailSignatures.has(emailSignature)) {
        return; // Already scanned this email
    }

    let keywordFound = null;
    for (const keyword of SCAN_KEYWORDS) {
        if (subject.includes(keyword.toLowerCase()) || body.includes(keyword.toLowerCase())) {
            keywordFound = keyword;
            break;
        }
    }

    if (keywordFound) {
        console.log("Phishing keyword found in email:", keywordFound);
        showWarningBanner(`Email này chứa từ khóa đáng ngờ: "${keywordFound}". Hãy cẩn thận!`);
        scannedEmailSignatures.add(emailSignature);
        return;
    }

    if (from) {
        for (const reportedEmail of REPORTED_MALICIOUS_EMAILS) {
            if (from === reportedEmail) {
                console.log("Sender email is in reported malicious list:", from);
                showWarningBanner(`Địa chỉ email người gửi (${from}) nằm trong danh sách báo cáo nguy hiểm.`);
                scannedEmailSignatures.add(emailSignature);
                return;
            }
        }
    }

    // If no keywords or reported emails matched, add to scanned list to avoid re-scanning immediately
    // but allow re-scan if content changes significantly (though this signature is basic)
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
        } else { // Fallback if body is not ready, though run_at: document_idle should prevent this
            document.addEventListener('DOMContentLoaded', () => {
                document.body.insertBefore(banner, document.body.firstChild);
            });
        }
    }
    banner.firstChild.textContent = message; // Update message text (node before button)
    banner.style.display = 'block';
}

function observeEmailChanges() {
    if (observer) observer.disconnect();

    const targetNode = document.body;
    if (!targetNode) {
        console.error("Target node (document.body) not found for MutationObserver.");
        return;
    }

    const config = { childList: true, subtree: true };

    let debounceTimer;
    const callback = function(mutationsList, observerInstance) {
        // Debounce to avoid excessive scanning during rapid DOM changes
        clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => {
             // Check if email view elements are present before scanning
            if (window.location.host.includes("mail.google.com")) {
                if (document.querySelector('h2[data-thread-perm-id]')) scanEmailContent();
            } else if (window.location.host.includes("outlook.live.com") || window.location.host.includes("outlook.office.com")) {
                if (document.querySelector('[aria-label^="Subject"], [data-testid="subject-line-text"]')) scanEmailContent();
            }
        }, 1000); // Adjust debounce time as needed (e.g., 500-1000ms)
    };

    observer = new MutationObserver(callback);
    observer.observe(targetNode, config);
    console.log("MutationObserver started to scan email content.");
}


// Initial scan and start observing
(async () => {
    await initializeScanner(); // Load keywords and reported emails first
    scanEmailContent(); // Initial scan for already loaded email
    observeEmailChanges(); // Start observing for dynamic changes
})();

// Listen for URL changes within SPA (like Gmail) as well
let lastUrl = location.href;
new MutationObserver(() => {
  const url = location.href;
  if (url !== lastUrl) {
    lastUrl = url;
    scannedEmailSignatures.clear(); // Clear when URL changes to rescan new view
    scanEmailContent(); // Re-scan content for the new view
    observeEmailChanges(); // Re-initialize observer if needed, or ensure it's still relevant
  }
}).observe(document, {subtree: true, childList: true});