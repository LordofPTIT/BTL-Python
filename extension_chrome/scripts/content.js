/* eslint-disable no-undef */

console.log("CS: Phishing Detector Content Script Loaded.");

// --- Configuration ---
// Selectors for Gmail elements (might need updates if Gmail changes its structure)
const GMAIL_EMAIL_ROW_SELECTOR = 'tr.zA'; // Selector for an email row in the inbox list
const GMAIL_SENDER_SELECTOR = 'td.yX span[email]'; // Selector for sender email span within a row
const GMAIL_EMAIL_VIEW_SELECTOR = 'div.adn'; // A container usually present when viewing an email
const GMAIL_SENDER_IN_VIEW_SELECTOR = 'span.gD[email]'; // Sender email when viewing an email
const GMAIL_RECIPIENT_IN_VIEW_SELECTOR = 'span.hb[email]'; // Recipient email when viewing
const GMAIL_SUBJECT_SELECTOR = 'h2.hP'; // Subject line when viewing

const WARNING_CLASS = 'phishing-warning-highlight'; // CSS class for highlighting
const WARNING_TOOLTIP_TEXT = 'Cảnh báo: Địa chỉ email này nằm trong danh sách chặn!';

// Simple cache to avoid re-checking the same email repeatedly on the same page view
const checkedEmails = new Set();
let pageObserver = null; // To observe dynamic changes in Gmail

// --- Initialization ---
function init() {
    console.log("CS: Initializing observer and scanning initial content.");
    observePageChanges();
    scanPageForEmails(); // Initial scan
}

// --- Core Logic ---

function observePageChanges() {
    if (pageObserver) {
        pageObserver.disconnect(); // Disconnect previous observer if any
    }

    pageObserver = new MutationObserver(mutations => {
        // Optimization: Check if relevant nodes were added
        let relevantChange = false;
        for (const mutation of mutations) {
             if (mutation.addedNodes.length > 0) {
                 // Basic check: if any added node contains email-like text or specific selectors
                  for (const node of mutation.addedNodes) {
                      if (node.nodeType === Node.ELEMENT_NODE) {
                           // Check if the added node itself or its descendants match our selectors
                            if (node.querySelector(GMAIL_SENDER_SELECTOR) || node.querySelector(GMAIL_SENDER_IN_VIEW_SELECTOR) || node.matches(GMAIL_EMAIL_ROW_SELECTOR) || node.closest(GMAIL_EMAIL_VIEW_SELECTOR) ) {
                                relevantChange = true;
                                break;
                            }
                      }
                       // Rough check for email-like patterns in text nodes (less reliable)
                       else if (node.nodeType === Node.TEXT_NODE && node.textContent.includes('@')) {
                           relevantChange = true;
                           break;
                       }
                  }
             }
             if (relevantChange) break;
        }


        if (relevantChange) {
            // console.log("CS: Relevant page change detected, rescanning...");
            scanPageForEmails();
        }
    });

    pageObserver.observe(document.body, {
        childList: true, // Observe direct children additions/removals
        subtree: true    // Observe all descendants
    });
     console.log("CS: MutationObserver started.");
}

function scanPageForEmails() {
    // console.log("CS: Scanning page for emails...");

    // --- Scan Inbox View ---
    const emailRows = document.querySelectorAll(GMAIL_EMAIL_ROW_SELECTOR);
    emailRows.forEach(row => {
        const senderElement = row.querySelector(GMAIL_SENDER_SELECTOR);
        if (senderElement && senderElement.getAttribute('email')) {
            const email = senderElement.getAttribute('email').toLowerCase();
            checkAndWarnEmail(email, senderElement);
        }
    });

    // --- Scan Email Detail View ---
    if (document.querySelector(GMAIL_EMAIL_VIEW_SELECTOR)) {
        const senderElements = document.querySelectorAll(GMAIL_SENDER_IN_VIEW_SELECTOR);
        senderElements.forEach(element => {
            const email = element.getAttribute('email')?.toLowerCase();
            if (email) checkAndWarnEmail(email, element);
        });

        const recipientElements = document.querySelectorAll(GMAIL_RECIPIENT_IN_VIEW_SELECTOR);
         recipientElements.forEach(element => {
             const email = element.getAttribute('email')?.toLowerCase();
             if (email) checkAndWarnEmail(email, element);
         });

        // Optionally check subject or body for email patterns (more complex)
        // const subjectElement = document.querySelector(GMAIL_SUBJECT_SELECTOR);
        // if (subjectElement) { /* scan subject text */ }
    }

    // --- Generic Scan (Less reliable, more resource intensive) ---
    // Find potential emails in text nodes or other elements if needed
    // This part needs careful implementation to avoid performance issues.
    // Example (simplified):
    // const allTextNodes = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    // let currentNode;
    // while(currentNode = allTextNodes.nextNode()) {
    //     const text = currentNode.textContent;
    //     const potentialEmails = text.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g);
    //     if (potentialEmails) {
    //         potentialEmails.forEach(email => {
    //              // Need to find the corresponding element to highlight - tricky!
    //              // checkAndWarnEmail(email.toLowerCase(), /* element? */);
    //         });
    //     }
    // }
}

function checkAndWarnEmail(email, element) {
    if (!email || !element || checkedEmails.has(email)) {
        return; // Skip invalid, null, or already checked emails
    }

    // Add to cache immediately to prevent repeated checks in this scan cycle
    checkedEmails.add(email);
     // console.log(`CS: Checking email: ${email}`);

    chrome.runtime.sendMessage({ action: 'checkEmail', email: email }, (response) => {
        if (chrome.runtime.lastError) {
            console.error(`CS: Error sending/receiving message for ${email}:`, chrome.runtime.lastError);
             // Remove from cache if check failed, allow retry later
             checkedEmails.delete(email);
            return;
        }

        // console.log(`CS: Response for ${email}:`, response);

        if (response && response.isPhishing) {
            console.warn(`CS: Phishing email detected: ${email}. Highlighting element.`);
            displayWarning(element, email);
        } else {
            // Optional: remove existing warning if email is no longer phishing (e.g., whitelisted)
            removeWarning(element);
        }
    });
}

function displayWarning(element, email) {
    if (!element) return;
    // Add a visual warning style
    element.classList.add(WARNING_CLASS);

    // Add a tooltip for more info (can be improved with custom tooltip UI)
     if (!element.title.includes(WARNING_TOOLTIP_TEXT)) {
          element.title = `${WARNING_TOOLTIP_TEXT}\n${element.title || email}`.trim();
     }

    // Optional: Add an icon or more prominent warning next to the element
    // Example: Create a warning icon span
    // let warningIcon = element.querySelector('.phishing-warning-icon');
    // if (!warningIcon) {
    //     warningIcon = document.createElement('span');
    //     warningIcon.className = 'phishing-warning-icon';
    //     warningIcon.textContent = '⚠️'; // Example icon
    //     warningIcon.style.marginLeft = '5px';
    //     warningIcon.style.cursor = 'help';
    //     warningIcon.title = WARNING_TOOLTIP_TEXT;
    //     element.appendChild(warningIcon); // Append or insert strategically
    // }
}

function removeWarning(element) {
     if (!element) return;
     element.classList.remove(WARNING_CLASS);
     // Remove tooltip text if added by us
     if (element.title.includes(WARNING_TOOLTIP_TEXT)) {
         element.title = element.title.replace(WARNING_TOOLTIP_TEXT, '').replace('\n', '').trim();
          if (element.title === element.getAttribute('email')) { // Reset title if only email was left
              element.title = '';
          }
     }
     // Remove icon if added
     // const warningIcon = element.querySelector('.phishing-warning-icon');
     // if (warningIcon) {
     //     warningIcon.remove();
     // }
}


// Inject CSS for warning styles
function injectStyles() {
    const style = document.createElement('style');
    style.textContent = `
        .${WARNING_CLASS}, .${WARNING_CLASS} * {
            background-color: yellow !important; /* More visible highlight */
            color: black !important;
            outline: 1px solid red !important;
            cursor: help !important;
        }
         /* Example icon style */
         .phishing-warning-icon {
             color: red;
             font-weight: bold;
             margin-left: 4px;
             display: inline-block;
         }
    `;
    document.head.appendChild(style);
}

// --- Run ---
injectStyles(); // Add styles first
init(); // Start observing and scanning

// Optional: Add listener for history changes (for single-page apps like Gmail)
// window.addEventListener('hashchange', () => {
//     console.log("CS: Hash changed, rescanning...");
//     checkedEmails.clear(); // Clear cache on navigation
//     scanPageForEmails();
// });
// window.addEventListener('popstate', () => {
//      console.log("CS: Popstate event, rescanning...");
//      checkedEmails.clear();
//      scanPageForEmails();
// });

// Gmail uses history API, observe pushState/replaceState if necessary
// (More complex, involves wrapping history functions)