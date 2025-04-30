'use strict';

console.log(`Phishing Guard Pro: Content script v${chrome.runtime.getManifest().version} loading on:`, window.location.hostname);

// --- Constants ---
const EXT_PREFIX = 'phishing-guard-pro'; // Prefix for attributes and classes
const CHECKED_ATTR = `data-${EXT_PREFIX}-checked`;
const KEYWORDS_CHECKED_ATTR = `data-${EXT_PREFIX}-kw-checked`;
const PROCESSED_ATTR = `data-${EXT_PREFIX}-processed`; // Mark nodes processed by processEmailView
const PHISHING_CLASS = `${EXT_PREFIX}-alert-phishing`;
const SUSPICIOUS_CLASS = `${EXT_PREFIX}-alert-suspicious`; // For keyword banner container
const SUSPICIOUS_BANNER_CLASS = `${EXT_PREFIX}-alert-suspicious-banner`; // The banner itself
const HIGHLIGHT_CLASS = `${EXT_PREFIX}-highlight`; // General highlight for links/senders


const DEBOUNCE_DELAY_PROCESS = 750; // Debounce for processing email view changes (ms)
const DEBOUNCE_DELAY_MUTATION = 200; // Shorter debounce for handling mutation batches

// Keywords list (Keep this updated)
const SUSPICIOUS_KEYWORDS = [ /* ... Giữ nguyên danh sách keywords v2.3 ... */
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


// --- Utility Functions ---

/**
 * Debounces a function call.
 * @param {Function} func The function to debounce.
 * @param {number} wait The debounce delay in milliseconds.
 * @returns {Function} The debounced function.
 */
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

/**
 * Safely checks if an element is still connected to the main DOM.
 * @param {Node | null | undefined} element The element to check.
 * @returns {boolean} True if connected, false otherwise.
 */
function isConnected(element) {
    return !!(element && typeof element.isConnected === 'boolean' && element.isConnected);
}

// --- Background Script Communication ---

/**
 * Sends a message to the background script and handles the response.
 * @param {object} message The message object to send.
 * @returns {Promise<any>} A promise resolving with the response or rejecting on error.
 */
async function sendMessageToBackground(message) {
    return new Promise((resolve, reject) => {
        try {
            chrome.runtime.sendMessage(message, (response) => {
                if (chrome.runtime.lastError) {
                    // Log specific error if available
                    console.warn(`CS: Error sending/receiving message for action "${message?.action}":`, chrome.runtime.lastError.message);
                    reject(new Error(chrome.runtime.lastError.message || "Unknown runtime error"));
                } else if (response && response.error) {
                     // Handle errors reported within the response object
                    console.warn(`CS: Background reported error for action "${message?.action}":`, response.error);
                    reject(new Error(response.error));
                } else {
                    resolve(response);
                }
            });
        } catch (error) {
            // Catch synchronous errors during send (e.g., if extension context is invalidated)
            console.error(`CS: Exception sending message for action "${message?.action}":`, error);
            reject(error);
        }
    });
}

async function checkDomain(domain) {
    if (!domain) return { isPhishing: false, reason: "Tên miền không hợp lệ (CS)" };
    try {
        // Use the robust sendMessageToBackground function
        return await sendMessageToBackground({ action: 'checkDomain', value: domain });
    } catch (error) {
        // Error already logged by sendMessageToBackground
        return { isPhishing: false, reason: `Lỗi kiểm tra tên miền (CS): ${error.message}` };
    }
}

async function checkEmailSender(email) {
    if (!email) return { isPhishing: false, reason: "Email không hợp lệ (CS)" };
    try {
        // Use the robust sendMessageToBackground function
        return await sendMessageToBackground({ action: 'checkEmailSender', value: email });
    } catch (error) {
        // Error already logged by sendMessageToBackground
        return { isPhishing: false, reason: `Lỗi kiểm tra email (CS): ${error.message}` };
    }
}


// --- DOM Manipulation & Highlighting ---

/**
 * Adds phishing/suspicious visual indicators to an element.
 * @param {Element} element The DOM element to mark.
 * @param {string} cssClass The CSS class to add (PHISHING_CLASS or HIGHLIGHT_CLASS).
 * @param {string} tooltipText Text for the title attribute (tooltip).
 */
function applyHighlight(element, cssClass, tooltipText) {
    // Defensive checks
    if (!element || typeof element.classList === 'undefined' || !isConnected(element)) {
        // console.warn("CS: Attempted to highlight invalid or disconnected element:", element);
        return;
    }
    try {
        if (!element.classList.contains(cssClass)) {
            element.classList.add(cssClass);
             // Avoid overwriting existing titles unless it's specifically a phishing alert
            if (cssClass === PHISHING_CLASS || !element.title) {
                 element.title = tooltipText;
            }
        }
    } catch (e) {
        console.error("CS: Failed to apply highlight class:", cssClass, e, element);
    }
}


/**
 * Adds a prominent warning banner at the top of a container element.
 * Used for keyword-based suspicion.
 * @param {Element} containerElement The element to prepend the banner to.
 * @param {string} tooltipText Text for the banner's title attribute.
 */
function addSuspicionWarningBanner(containerElement, tooltipText) {
    if (!containerElement || typeof containerElement.querySelector !== 'function' || !isConnected(containerElement)) {
        // console.warn("CS: Attempted to add banner to invalid or disconnected container:", containerElement);
        return;
    }
    // Prevent adding multiple banners
    if (containerElement.querySelector(`.${SUSPICIOUS_BANNER_CLASS}`)) {
        return;
    }

    try {
        // Also add a general suspicion class to the container if needed for styling
        containerElement.classList.add(SUSPICIOUS_CLASS);

        const banner = document.createElement('div');
        banner.className = SUSPICIOUS_BANNER_CLASS;
        // Use textContent for security unless HTML is strictly required and controlled
        banner.innerHTML = `<strong>⚠️ Nội dung đáng ngờ:</strong> Email này chứa các yếu tố hoặc từ khóa thường thấy trong email lừa đảo. Hãy kiểm tra kỹ người gửi và các yêu cầu trước khi nhấp vào liên kết hoặc cung cấp thông tin.`;
        banner.title = tooltipText; // Add detailed keywords to title

        // Prepend the banner for visibility
        containerElement.insertBefore(banner, containerElement.firstChild);

    } catch (e) {
        console.error("CS: Failed to add suspicion warning banner:", e, containerElement);
    }
}


// --- Scanning Logic ---

/**
 * Scans and marks suspicious links within a given container.
 * Only processes links that haven't been checked yet.
 * @param {Element} containerElement The parent element containing links to scan.
 * @param {boolean} isEmailContentView Indicates if this is the main email body.
 */
async function scanAndMarkLinks(containerElement, isEmailContentView = false) {
    // Only scan links deeply if it's the main content view
    if (!isEmailContentView || !containerElement || typeof containerElement.querySelectorAll !== 'function' || !isConnected(containerElement)) {
        return;
    }

    // console.log("CS: Scanning links in:", containerElement); // Debug
    try {
        // Query only for links that haven't been checked
        const links = containerElement.querySelectorAll(`a[href]:not([${CHECKED_ATTR}])`);

        for (const link of links) {
             // Double-check connection and attribute just before processing
             if (!isConnected(link) || link.hasAttribute(CHECKED_ATTR)) continue;
            link.setAttribute(CHECKED_ATTR, 'true'); // Mark as checked immediately

            let href;
            try {
                href = link.href; // Get the fully resolved URL

                // Basic filter for non-http/https links or anchors
                if (!href || !href.startsWith('http')) {
                    continue;
                }

                 // Avoid checking links pointing to the same domain as the current page (less common in email)
                 // if (href.includes(window.location.hostname)) continue;

                const urlObj = new URL(href);
                const domain = normalizeDomain(urlObj.hostname); // Use our background's normalization logic idea

                if (!domain) {
                    // console.warn("CS: Could not normalize domain from link:", href);
                    continue;
                }

                // Call background script to check the domain
                const result = await checkDomain(domain);

                // Mark the link visually if phishing
                if (result && result.isPhishing) {
                     console.warn(`CS: Phishing link detected: ${domain} (Reason: ${result.reason || 'Đã biết'})`);
                     applyHighlight(link, PHISHING_CLASS, `CẢNH BÁO LỪA ĐẢO! Tên miền đáng ngờ: ${domain}. Lý do: ${result.reason || 'Đã biết'}`);
                }
                 // else { applyHighlight(link, HIGHLIGHT_CLASS, `Domain: ${domain}`); } // Optional: Highlight all scanned external links

            } catch (error) {
                 // Catch errors during URL parsing or domain checking for a single link
                 if (error instanceof TypeError && error.message.includes("Invalid URL")) {
                     // console.warn("CS: Skipping invalid URL in link:", link.outerHTML);
                 } else if (!(error instanceof DOMException && error.name === 'SecurityError')) { // Ignore cross-origin errors if any
                     console.warn(`CS: Error processing link "${href || link.outerHTML}":`, error.message);
                 }
            }
        } // End for loop
    } catch (e) {
        // Catch errors during the querySelectorAll or main loop setup
        console.error("CS: Error during link scanning process:", e, containerElement);
    }
}


/**
 * Scans and marks the sender information element.
 * @param {Element} senderInfoElement The element containing sender details.
 * @param {boolean} isEmailContentView Indicates if this is the main email body.
 */
async function scanAndMarkSender(senderInfoElement, isEmailContentView = false) {
    if (!isEmailContentView || !senderInfoElement || !isConnected(senderInfoElement) || senderInfoElement.hasAttribute(CHECKED_ATTR)) {
        return;
    }
    senderInfoElement.setAttribute(CHECKED_ATTR, 'true'); // Mark immediately

    let emailAddress = null;
    try {
        // Try multiple ways to extract the email address, common in Gmail/Outlook
        emailAddress = senderInfoElement.getAttribute('email') ||
                       senderInfoElement.dataset.senderEmail || // Check data attributes
                       (senderInfoElement.getAttribute('title') || '').match(/[\w.-]+@[\w.-]+\.\w+/)?.[0] ||
                       (senderInfoElement.textContent || '').match(/[\w.-]+@[\w.-]+\.\w+/)?.[0]; // Less reliable

        // Normalize using the same logic idea as background
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        const normalizedEmail = (emailAddress || '').toLowerCase().trim();


        if (normalizedEmail && emailRegex.test(normalizedEmail)) {
             // console.log("CS: Checking sender email:", normalizedEmail); // Debug
            const result = await checkEmailSender(normalizedEmail);

            if (result && result.isPhishing) {
                console.warn(`CS: Phishing sender detected: ${normalizedEmail} (Reason: ${result.reason || 'Đã biết'})`);
                applyHighlight(senderInfoElement, PHISHING_CLASS, `CẢNH BÁO LỪA ĐẢO! Email gửi đáng ngờ: ${normalizedEmail}. Lý do: ${result.reason || 'Đã biết'}`);
            }
             // else { applyHighlight(senderInfoElement, HIGHLIGHT_CLASS, `Sender: ${normalizedEmail}`); } // Optional: Highlight scanned senders

        } else {
            // console.warn("CS: Could not extract/validate email from sender element:", senderInfoElement);
        }
    } catch (error) {
        console.warn(`CS: Error processing sender element (Email: ${emailAddress || 'N/A'}):`, error.message, senderInfoElement);
    }
}


/**
 * Scans the text content of an element for suspicious keywords.
 * Adds a warning banner if keywords are found.
 * @param {Element} contentElement The element containing the main email text.
 * @param {boolean} isEmailContentView Indicates if this is the main email body.
 */
function scanAndMarkKeywords(contentElement, isEmailContentView = false) {
    // Only scan keywords and add banner in the main content view
    if (!isEmailContentView || !contentElement || !isConnected(contentElement) || contentElement.hasAttribute(KEYWORDS_CHECKED_ATTR)) {
        return;
    }
    contentElement.setAttribute(KEYWORDS_CHECKED_ATTR, 'true'); // Mark immediately

    try {
        // Get text content efficiently, limit length for performance
        const textContent = (contentElement.textContent || '').substring(0, 15000).toLowerCase();
        if (!textContent) return; // Skip if no text

        let foundKeywords = [];
        for (const keyword of SUSPICIOUS_KEYWORDS) {
            // Use word boundary checks for more accuracy (optional, slightly slower)
            // const regex = new RegExp(`\\b${keyword.toLowerCase()}\\b`);
            // if (regex.test(textContent)) {
            if (textContent.includes(keyword.toLowerCase())) { // Faster check
                foundKeywords.push(keyword);
                // Limit the number of keywords reported for brevity
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


// --- Main Processing Logic for Email Views ---

/**
 * Identifies key elements (sender, content) within a potential email view node
 * and triggers the scanning functions.
 * This function is debounced to handle rapid DOM changes.
 * @param {Element} emailContainerNode The potential top-level container of an email view.
 */
const processEmailView = (emailContainerNode) => {
    // Basic validation and check if already processed by this function
    if (!emailContainerNode || typeof emailContainerNode.querySelector !== 'function' || !isConnected(emailContainerNode) || emailContainerNode.hasAttribute(PROCESSED_ATTR)) {
        return;
    }
    // Mark this container as processed *by this specific function instance*
    // Note: Child elements might still be processed by scans if they lack CHECKED_ATTR
    emailContainerNode.setAttribute(PROCESSED_ATTR, 'true');

    // console.log("CS: Processing potential email container:", emailContainerNode); // Debug

    let isEmailContentView = false; // Assume not content view initially
    let senderElement = null;
    let contentElement = null; // The *main body* element
    const hostname = window.location.hostname;

    try {
        // --- DOM Selector Logic (Fragile - Needs Maintenance) ---
        // These selectors try to find the main content area and differentiate from list views.
        // They need regular review and updates based on Gmail/Outlook changes.
        if (hostname.includes('mail.google.com')) {
            // Gmail: Look for specific content divs, avoid list rows (.zA)
            // '.a3s.aiL' and '.ii.gt' are common for email body content.
            contentElement = emailContainerNode.querySelector('.a3s.aiL:not([style*="display: none"]), div.ii.gt:not([style*="display: none"])');
             // Check if the container itself is *not* a list row.
            const isListViewRow = emailContainerNode.matches && (emailContainerNode.matches('.zA') || emailContainerNode.closest('.zA'));

            if (contentElement && isConnected(contentElement) && !isListViewRow) {
                isEmailContentView = true;
                // Find sender within the broader email header area relative to the container
                const headerArea = emailContainerNode.closest('.nH.hx, .Bs.nH.io.adp') || emailContainerNode; // Go up to find common parents
                 senderElement = headerArea?.querySelector('.gD[email], .go[email], span[email].yP, span[email].go'); // More specific sender selectors
             } else {
                 // console.log("CS: Gmail node skipped - Not identified as main content view or is list row:", emailContainerNode);
             }

        } else if (hostname.includes('outlook.')) {
            // Outlook: Look for aria-label="Message body", avoid list rows (role="option")
            contentElement = emailContainerNode.querySelector('div[aria-label="Message body"], .rps_*, .PlainText, .x_WordSection1'); // Common body classes/attributes
            const isListViewRow = emailContainerNode.matches && (emailContainerNode.matches('div[role="option"]') || emailContainerNode.closest('div[role="option"]'));

            if (contentElement && isConnected(contentElement) && !isListViewRow) {
                isEmailContentView = true;
                 // Find sender - Outlook selectors are diverse
                const headerArea = emailContainerNode.closest('div[role="document"], div[data-testid="readingPaneContainer"], div[autoid^="_lvv_c"]') || emailContainerNode;
                // Try various common sender patterns
                senderElement = headerArea?.querySelector('button[data-is-focusable="true"] span[title*="@"], span[data-automationid="splitbuttonprimary"] span, .LAbQF span[title*="@"], .EnRL7 span[title*="@"], span.BoltText-span[title*="@"]') || headerArea?.querySelector('span[title*="@"]'); // Broader fallback
            } else {
                 // console.log("CS: Outlook node skipped - Not identified as main content view or is list row:", emailContainerNode);
            }
        }
        // --- End Selector Logic ---


        // --- Trigger Scans ONLY if identified as Email Content View ---
        if (isEmailContentView) {
            console.log("CS: Identified Email Content View. Starting scans for:", emailContainerNode);

            // Scan Sender (pass the specific element found)
            if (senderElement && isConnected(senderElement)) {
                scanAndMarkSender(senderElement, true); // Pass true flag
            } else {
                // console.warn("CS: Sender element not found within identified content view:", emailContainerNode);
            }

            // Scan Links and Keywords within the identified content body
            if (contentElement && isConnected(contentElement)) {
                 scanAndMarkLinks(contentElement, true); // Pass true flag
                 scanAndMarkKeywords(contentElement, true); // Pass true flag
             } else {
                  console.error("CS: CRITICAL - Content element identified but became disconnected or invalid before scanning:", contentElement);
             }

        }
        // If not isEmailContentView, do nothing further with this container.

    } catch (error) {
        console.error("CS: Error during processEmailView execution:", error, emailContainerNode);
    }
};

// Debounced version of the main processing function
const processEmailViewDebounced = debounce(processEmailView, DEBOUNCE_DELAY_PROCESS);

// --- Mutation Observer Logic ---

let observer = null;
let mutationProcessingTimeout = null;
const observedNodes = new Set(); // Accumulate nodes from mutations before processing

// Callback function for the MutationObserver
const mutationCallback = (mutationsList) => {
    let addedRelevantNode = false;
    for (const mutation of mutationsList) {
        // Check added nodes
        if (mutation.addedNodes) {
            mutation.addedNodes.forEach(node => {
                // Only consider element nodes that are connected
                if (node.nodeType === Node.ELEMENT_NODE && isConnected(node)) {
                    // Heuristic check: Does the node *potentially* contain an email view?
                    // Check for common top-level containers or specific content markers. Loose check.
                     if (node.matches && (
                         // Gmail containers/markers
                         node.matches('.nH.hx, .Bs.nH.io.adp, .bzA, .Tm') || node.querySelector('.a3s.aiL, div.ii.gt') ||
                         // Outlook containers/markers
                         node.matches('div[role="document"], div[data-testid="readingPaneContainer"], div[autoid^="_lvv_c"], div[aria-label="Message body"]') || node.querySelector('div[aria-label="Message body"]')
                         ))
                     {
                        observedNodes.add(node);
                        addedRelevantNode = true;
                     }
                     // Also consider direct addition of sender/link elements if needed, but primary focus is containers
                     // if (node.matches('a[href]')) { observedNodes.add(node.closest(EMAIL_CONTAINER_SELECTOR_GUESS)); addedRelevantNode = true; }

                }
            });
        }
        // Optionally check attribute changes if needed, but childList is primary focus
        // if (mutation.type === 'attributes' && mutation.target.nodeType === Node.ELEMENT_NODE && isConnected(mutation.target)) {
        //     // Check if attributes relevant to view state changed
        // }
    }

    // If relevant nodes were added/changed, schedule processing after a short debounce
    if (addedRelevantNode) {
        clearTimeout(mutationProcessingTimeout);
        mutationProcessingTimeout = setTimeout(() => {
            // console.log(`CS: Processing ${observedNodes.size} observed nodes after debounce.`); // Debug
            observedNodes.forEach(node => {
                 // Final check before processing
                 if (isConnected(node)) {
                     processEmailViewDebounced(node); // Call the debounced processing function
                 }
            });
            observedNodes.clear(); // Clear the set after processing
        }, DEBOUNCE_DELAY_MUTATION);
    }
};

// --- Initialization ---

/**
 * Sets up and starts the MutationObserver.
 */
function startObserver() {
    if (observer) {
        console.log("CS: Disconnecting existing observer.");
        observer.disconnect();
    }

    // Configure the observer: Focus on added nodes in the subtree
    const observerOptions = {
        childList: true, // Observe additions/removals of children
        subtree: true    // Observe descendants as well
        // attributes: false, // Usually not needed unless specific attributes change view state
        // attributeFilter: ['style', 'class'], // Example if observing attributes
    };

    observer = new MutationObserver(mutationCallback);

    try {
        // Observe the entire document body for broad coverage
        observer.observe(document.body, observerOptions);
        console.log("CS: MutationObserver started successfully.");
    } catch (e) {
        console.error("CS: CRITICAL - Failed to start MutationObserver.", e);
        // Consider alternative initialization or notifying the user/background script
    }
}

/**
 * Performs an initial scan for email content already present on page load.
 */
function runInitialScan() {
    console.log("CS: Running initial scan for existing email views...");
    try {
        // Combine selectors for potentially open email views in Gmail/Outlook
        // Target the *content* elements directly if possible, or their immediate containers.
        const initialSelectors = [
            // Gmail Specific (more precise)
            '.nH.hx:not([style*="display: none"]) .ii.gt', // Visible message body
            '.nH.hx:not([style*="display: none"]) .a3s.aiL', // Another common visible message body class

            // Outlook Specific (more precise)
            'div[data-testid="readingPaneContainer"]:not([style*="display: none"]) div[aria-label="Message body"]', // Visible reading pane body
            'div[role="document"]:not([style*="display: none"]) div[aria-label="Message body"]', // Document view body

            // Broader fallbacks (might catch list items if not careful, rely on processEmailView checks)
             '.Bs.nH.io.adp', // Gmail container
             'div[autoid^="_lvv_c"]' // Outlook container
        ].join(', '); // Combine selectors

        const potentialViews = document.querySelectorAll(initialSelectors);
        console.log(`CS: Found ${potentialViews.length} potential views in initial scan.`);

        potentialViews.forEach(node => {
            if (isConnected(node)) {
                // Use the *non-debounced* version for initial scan for faster feedback
                processEmailView(node);
            }
        });
        console.log("CS: Initial scan finished processing potential views.");

    } catch (e) {
        console.error("CS: Error during initial scan execution:", e);
    }
}

/**
 * Main initialization function for the content script.
 */
function initialize() {
    console.log(`CS: Initializing Phishing Guard Pro content script v${chrome.runtime.getManifest().version}...`);

    startObserver(); // Start observing DOM changes

    // Run the initial scan after the page is likely stable
    if (document.readyState === 'complete') {
        // If already complete, run after a short delay
        setTimeout(runInitialScan, 1500);
    } else {
        // Otherwise, wait for the window load event
        window.addEventListener('load', () => setTimeout(runInitialScan, 1500), { once: true });
    }

    console.log("CS: Initialization sequence complete.");
}

// --- Start Execution ---
initialize();