/* global chrome */
const WARNING_POPUP_ID_CONTENT_SCRIPT = 'phishing-guard-content-script-popup';
const CHECKED_EMAIL_ELEMENT_ATTR_CONTENT = 'data-phishing-guard-email-processed';
const EMAIL_PROCESS_DEBOUNCE_MS = 1200; // Milliseconds to wait after DOM changes before processing

let emailProcessingTimeoutId = null;
let lastProcessedVisibleEmailElement = null;

// Function to find the main container of the currently viewed email
function findEmailContextForProcessing(targetElement) {
    if (!targetElement || typeof targetElement.closest !== 'function') return null;
    // Add/refine selectors for different webmail clients
    let emailContainer = targetElement.closest('.nH.bkK, .nH.if, .UI, .Cp, .aeF, .aps, .aeJ, .bkK .nH'); // Gmail selectors
    if (emailContainer) return { type: 'gmail', element: emailContainer };
    emailContainer = targetElement.closest('[role="main"] .allowTextSelection, .wide-content-host, .conductorContent, .read-mode-wrap, .BkRhG, #Item.Content'); // Outlook selectors
    if (emailContainer) return { type: 'outlook', element: emailContainer };
    emailContainer = targetElement.closest('.eml-display, #message-viewer, .mail-detail-content, .ThreadView-container'); // Yahoo selectors
    if (emailContainer) return { type: 'yahoo', element: emailContainer };
    return null; // Could not identify email context
}

// Function to extract details (sender, subject, body) from the email container
function extractDetailsFromEmailContext(context) {
    const { type, element } = context;
    let senderEmail = null, subject = '', bodyText = '';
    const emailRegex = /([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/gi; // Global flag is important

    try {
        // Gmail Specific Selectors
        if (type === 'gmail') {
            const senderEl = element.querySelector('.gD[email], .go[email], .gL .gI span[email], span[email].yP'); // More sender variations
            if (senderEl) senderEmail = senderEl.getAttribute('email') || (senderEl.innerText.match(emailRegex) || [])[0];
            const subjectEl = element.querySelector('.hP, .ha h2, .ha .hP'); // Subject variations
            if (subjectEl) subject = subjectEl.innerText;
            const bodyEls = element.querySelectorAll('.a3s.aiL, .ii.gt, div.gs div:not([style*="display:none"])'); // Body elements
            bodyText = Array.from(bodyEls).map(el => el.innerText).filter(Boolean).join(' ');
        }
        // Outlook Specific Selectors
        else if (type === 'outlook') {
            let senderEl = element.querySelector('div[role="heading"] span[role="button"] > span > span, .lMFJL span, .rpHighlightAllClass div > div > div:nth-child(2) > div > div > span, .L72vd');
            if (!senderEl) senderEl = element.querySelector('[data-o oamenattrname="PersonaId"]'); // Try data attribute
            if (senderEl?.textContent) senderEmail = (senderEl.textContent.match(emailRegex) || [])[0];
             if (!senderEmail) { // Another common pattern
                 const senderParent = element.querySelector('div[role="heading"]');
                 if(senderParent) senderEmail = (senderParent.querySelector('span[role="button"] > span > span')?.textContent?.match(emailRegex) || [])[0];
             }
            const subjectEl = element.querySelector('[role="heading"][aria-label*="Subject"], [data-testid="subject-line-text"], .wide-content-host div[role="main"] div[draggable="false"] div:first-child > span, ._3_h_>span');
            if (subjectEl) subject = subjectEl.innerText;

             // FIX: Updated querySelectorAll for Outlook body, handling invalid selectors gracefully
             const bodySelectors = ['[class*="rps_"]', '.PlainText', '.ZoomReadable', '.elementToProof', 'div[role="document"] .ReadWriteField', '.read-mode-content', '.WordSection1'];
             for (const selector of bodySelectors) {
                 try {
                     const bodyContainer = element.querySelector(selector);
                     if (bodyContainer) { bodyText = bodyContainer.innerText; break; }
                 } catch (e) { /* Ignore invalid selector and continue */ }
             }
            if(!bodyText) { // Fallback: Get text from main content area
                 const mainContentArea = element.querySelector('[role="main"], #Item.Body');
                 if (mainContentArea) bodyText = mainContentArea.innerText;
            }

        }
        // Yahoo Specific Selectors
        else if (type === 'yahoo') {
            const senderEl = element.querySelector('[data-test-id="message-sender"], .sender span[role="button"]');
            if (senderEl) senderEmail = (senderEl.textContent.match(emailRegex) || [])[0];
            const subjectEl = element.querySelector('[data-test-id="message-subject"], .subject h2');
            if (subjectEl) subject = subjectEl.innerText;
            const bodyEl = element.querySelector('.SigmaMessage-body, .thread-body, .yahoo-style-wrap');
            if (bodyEl) bodyText = bodyEl.innerText;
        }
    } catch (e) { console.warn("CS: Error extracting details:", e); }

    // Limit content length to avoid sending huge amounts of data
    const MAX_CONTENT_LENGTH = 7000;
    bodyText = bodyText.replace(/\s+/g, ' ').trim().substring(0, MAX_CONTENT_LENGTH);

    return {
        senderEmail: senderEmail?.toLowerCase() || null,
        emailSubject: subject.trim(),
        emailContent: bodyText
    };
}

// Function to create and show the warning popup
function createContentPopupElement(messageText, typeText) {
    removeContentPopupElement(); // Remove any existing popup first
    const popup = document.createElement('div');
    popup.id = WARNING_POPUP_ID_CONTENT_SCRIPT;
    popup.className = 'phishing-guard-popup-content-script';

    const messageDiv = document.createElement('div');
    messageDiv.className = 'phg-popup-message-content-script';
    messageDiv.innerHTML = `⚠️ <strong>Cảnh báo ${typeText}!</strong><br>${messageText}`;
    popup.appendChild(messageDiv);

    const closeButton = document.createElement('button');
    closeButton.className = 'phg-popup-button-content-script';
    closeButton.textContent = 'Tôi đã hiểu';
    closeButton.onclick = removeContentPopupElement; // Set click handler
    popup.appendChild(closeButton);

    document.body.appendChild(popup);
    // Trigger animation
    requestAnimationFrame(() => {
         popup.classList.add('phg-popup-visible');
    });
}

// Function to remove the warning popup
function removeContentPopupElement() {
    const existingPopup = document.getElementById(WARNING_POPUP_ID_CONTENT_SCRIPT);
    if (existingPopup) {
        existingPopup.classList.remove('phg-popup-visible'); // Start fade out
        // Remove from DOM after animation
        setTimeout(() => {
            if(existingPopup) existingPopup.remove();
        }, 300); // Match transition duration
    }
}

// Main function to process a detected email element
async function processEmailElementForPhishing(emailElementContext) {
    if (!emailElementContext?.element || emailElementContext.element.hasAttribute(CHECKED_EMAIL_ELEMENT_ATTR_CONTENT)) return;

    emailElementContext.element.setAttribute(CHECKED_EMAIL_ELEMENT_ATTR_CONTENT, 'true');
    const { senderEmail, emailSubject, emailContent } = extractDetailsFromEmailContext(emailElementContext);

    // Only proceed if we have some data to check
    if (!senderEmail && !emailContent && !emailSubject) {
        emailElementContext.element.removeAttribute(CHECKED_EMAIL_ELEMENT_ATTR_CONTENT);
        return;
    }

    try {
        // Ensure chrome API is available before sending
        if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
            const response = await chrome.runtime.sendMessage({
                action: 'checkEmailDetails', senderEmail, emailSubject, emailContent
            });

            // Check for runtime errors after sending message
            if (chrome.runtime.lastError) {
                console.warn("CS: Error response from background:", chrome.runtime.lastError.message);
                emailElementContext.element.removeAttribute(CHECKED_EMAIL_ELEMENT_ATTR_CONTENT);
                return;
            }

            // Process the response from background script
            if (response && response.isPhishing) {
                let reasonText = response.senderStatus === 'blocked' ? `Người gửi (${senderEmail || 'Không rõ'}) trong danh sách chặn.` : '';
                if (response.contentScan?.hasSuspiciousKeywords) {
                    const keywords = response.contentScan.keywordsFound.slice(0,3).join(', ') + (response.contentScan.keywordsFound.length > 3 ? '...' : '');
                    reasonText += (reasonText ? '<br>' : '') + `Nội dung/tiêu đề chứa từ khóa đáng ngờ: ${keywords}.`;
                }
                if (!reasonText) reasonText = "Email này có dấu hiệu lừa đảo."; // Fallback reason
                createContentPopupElement(reasonText, 'Email');
            } else {
                removeContentPopupElement(); // Email is safe, remove any existing popup
            }
        } else {
            console.warn("CS: Chrome runtime not available to send message.");
            emailElementContext.element.removeAttribute(CHECKED_EMAIL_ELEMENT_ATTR_CONTENT);
        }
    } catch (error) {
        // Handle potential errors during message sending or processing
        if (error.message?.includes("Receiving end does not exist")) {
            console.warn("CS: Background not ready. Check extension state.");
        } else {
            console.error("CS: Exception during email check:", error);
        }
        emailElementContext.element.removeAttribute(CHECKED_EMAIL_ELEMENT_ATTR_CONTENT); // Allow re-check later
    }
}

// Observer to detect changes in the DOM (like opening an email)
// Use mutationsList parameter to satisfy linters if needed, even if not directly used in loop
const mainMutationObserver = new MutationObserver((mutationsList) => {
    // Debounce processing to avoid running too frequently during rapid DOM changes
    if (emailProcessingTimeoutId) clearTimeout(emailProcessingTimeoutId);
    emailProcessingTimeoutId = setTimeout(() => {
        let activeEmailContext = null;
        // Selectors to find potentially active email views
        const potentialViewSelectors = [
            '.nH.bkK:not([style*="display: none"])', '.nH.if:not([style*="display: none"])', '.UI:not([style*="display: none"])', '.Cp:not([style*="display: none"])', '.aeF:not([style*="display: none"])', '.apv', // Gmail
            '[role="main"] .allowTextSelection:not([style*="display: none"])', '.wide-content-host:not([style*="display: none"])', '.BkRhG:not([style*="display: none"])', '#Item\\.Content', // Outlook
            '.eml-display:not([style*="display: none"])', '#message-viewer:not([style*="display: none"])', '.ThreadView-container:not([style*="display: none"])' // Yahoo
        ];
        for (const selector of potentialViewSelectors) {
             // Check multiple elements in case querySelectorAll is better
             const elements = document.querySelectorAll(selector);
             for(const elem of elements){
                // Basic visibility check (might need refinement)
                if (elem.offsetParent !== null && elem.clientHeight > 50) { // Check if element is rendered and has some height
                     activeEmailContext = findEmailContextForProcessing(elem);
                     if (activeEmailContext) break; // Found one
                }
             }
             if(activeEmailContext) break;
        }

        // Process if a new visible email element is found
        if (activeEmailContext && activeEmailContext.element !== lastProcessedVisibleEmailElement) {
            if (lastProcessedVisibleEmailElement) lastProcessedVisibleEmailElement.removeAttribute(CHECKED_EMAIL_ELEMENT_ATTR_CONTENT);
            processEmailElementForPhishing(activeEmailContext);
            lastProcessedVisibleEmailElement = activeEmailContext.element;
        } else if (activeEmailContext && activeEmailContext.element === lastProcessedVisibleEmailElement && !activeEmailContext.element.hasAttribute(CHECKED_EMAIL_ELEMENT_ATTR_CONTENT)){
            // Re-process if the attribute was removed or missed
            processEmailElementForPhishing(activeEmailContext);
        } else if (!activeEmailContext && lastProcessedVisibleEmailElement) {
            // If no active email view is found, clear the last processed element reference
             lastProcessedVisibleEmailElement.removeAttribute(CHECKED_EMAIL_ELEMENT_ATTR_CONTENT);
             lastProcessedVisibleEmailElement = null;
             removeContentPopupElement(); // Remove popup if email view is closed/navigated away
        }
    }, EMAIL_PROCESS_DEBOUNCE_MS);
});

// Start observing
mainMutationObserver.observe(document.body, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['style', 'class', 'hidden'] // Observe relevant attributes
});

// Initial check on load
setTimeout(() => {
    const initialView = document.querySelector('.nH.bkK, .nH.if, .UI, [role="main"] .allowTextSelection, .wide-content-host, .eml-display, #message-viewer');
    if(initialView){
        const context = findEmailContextForProcessing(initialView);
        if(context){ processEmailElementForPhishing(context); lastProcessedVisibleEmailElement = context.element;}
    }
}, 2500);