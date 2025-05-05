console.log("Phishing Guard Content Script Loaded.");

// --- Constants ---
const WARNING_BANNER_ID = 'phishing-guard-warning-banner';
const CHECKED_EMAIL_ATTR = 'data-phishing-guard-checked'; // Mark emails that have been processed
const EMAIL_BODY_CHECK_DELAY_MS = 1500; // Delay before checking email body after DOM changes

// --- State ---
let emailCheckTimeout = null; // Timeout ID for debouncing email checks
let currentVisibleEmailElement = null; // Track the currently viewed email container

// --- Helper Functions ---

function findEmailContainer(targetElement) {
    // Find the main container element for an open email view.
    // This requires inspecting the DOM structure of Gmail, Outlook, etc.
    // These selectors are EXAMPLES and WILL LIKELY NEED ADJUSTMENT.

    // Gmail Example (might change with updates)
    let container = targetElement.closest('.nH.bkK, .nH.if'); // Common containers for email threads/views
    if (container) return container;

    // Outlook Web Example (might change with updates)
    container = targetElement.closest('[role="main"] .IzmLX'); // Container usually holding email content area
    if (container) return container;
    container = targetElement.closest('.wide-content-host'); // Another potential container
    if (container) return container;


    // Yahoo Mail Example (Inspect needed)
    container = targetElement.closest('.some-yahoo-email-container-selector');
    if (container) return container;

    console.log("Content Script: Could not find specific email container for target:", targetElement);
    // Fallback: Look for broader containers, might be less accurate
    container = targetElement.closest('[role="document"], [role="main"], .email-view');
    return container;
}

function extractEmailDetails(emailElement) {
    // Extract sender and content from the identified email container.
    // Again, these selectors are EXAMPLES.

    let sender = null;
    let content = '';
    const emailAddressRegex = /([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/g;

    // Gmail Examples:
    let senderElement = emailElement.querySelector('.gD[email]');
    if (senderElement) sender = senderElement.getAttribute('email');
    // Alternative sender element
    if (!sender) {
         senderElement = emailElement.querySelector('.go'); // Contains sender name/email
         if(senderElement && senderElement.textContent) {
              const matches = senderElement.textContent.match(emailAddressRegex);
              if(matches) sender = matches[matches.length -1]; // Take the last found email
         }
    }
    // Gmail Body
    const bodyElement = emailElement.querySelector('.a3s.aiL, .ii.gt'); // Common body wrappers
    if (bodyElement) content = bodyElement.innerText; // Get text content

    // Outlook Web Examples:
     if (!sender) {
          // Outlook sender often in a specific div structure
          senderElement = emailElement.querySelector('[role="heading"] + div span'); // Find span near heading
          if (senderElement?.textContent) {
               const matches = senderElement.textContent.match(emailAddressRegex);
               if (matches) sender = matches[0]; // Usually just one
          }
          // Alternative: Look for specific class names if available
          if (!sender) {
              senderElement = emailElement.querySelector('.lMFJL span, .pEcEi span'); // Classes observed in Outlook headers
              if (senderElement?.textContent) {
                  const matches = senderElement.textContent.match(emailAddressRegex);
                  if (matches) sender = matches[0];
              }
          }
     }
     // Outlook Body
     if (!content) {
          const outlookBody = emailElement.querySelector('.rps_*, .PlainText, .ZoomReadable, .elementToProof'); // Common body classes/areas
          if (outlookBody) content = outlookBody.innerText;
          // If body is complex (e.g., nested divs), might need more specific traversal
          if(!content) {
              const mainContentArea = emailElement.querySelector('[role="main"] .IzmLX, [role="main"] .BkRhG'); // Find main content area
              if(mainContentArea) content = mainContentArea.innerText;
          }
     }


    // Yahoo Mail Examples: (Inspect required)
    if (!sender) {
        senderElement = emailElement.querySelector('.yahoo-sender-selector');
        if (senderElement?.textContent) {
            const matches = senderElement.textContent.match(emailAddressRegex);
            if (matches) sender = matches[0];
        }
    }
    if (!content) {
        const yahooBody = emailElement.querySelector('.yahoo-body-selector');
        if (yahooBody) content = yahooBody.innerText;
    }

    // Basic cleanup
    content = content.replace(/\s+/g, ' ').trim(); // Normalize whitespace

    console.log(`Content Script: Extracted - Sender: ${sender}, Content Length: ${content.length}`);
    return { senderEmail: sender, emailContent: content };
}

function showWarningBanner(emailElement, reason, keywords = []) {
    if (!emailElement) return;

    // Remove existing banner first
    removeWarningBanner(emailElement);

    console.log("Content Script: Showing warning banner for:", emailElement);

    const banner = document.createElement('div');
    banner.id = WARNING_BANNER_ID;
    banner.className = 'phishing-guard-warning-banner-content'; // Use class from content.css

    let message = `⚠️ **Cảnh báo Lừa đảo:** ${reason}`;
    if (keywords.length > 0) {
        message += `<br><small>Các từ khóa đáng ngờ được tìm thấy: ${keywords.slice(0, 5).join(', ')}${keywords.length > 5 ? '...' : ''}</small>`;
    }

    banner.innerHTML = message;

    // Find the best place to insert the banner (e.g., before the email body)
    // This is highly dependent on the mail client's structure.
    let insertLocation = emailElement.querySelector('.adn.ads, .aCi, .Bs.nH.iY, .YD.aeF, .gs, .nH.if .ha, .conductorContent'); // Try various potential locations in Gmail/Outlook
    if (!insertLocation) {
        insertLocation = emailElement.firstChild; // Fallback: insert at the beginning
    }

    if (insertLocation) {
         // Insert *before* the found location or as the first child
         if (insertLocation === emailElement.firstChild) {
              emailElement.prepend(banner);
         } else {
              insertLocation.parentNode.insertBefore(banner, insertLocation);
         }
        console.log("Content Script: Warning banner inserted.");
    } else {
        console.error("Content Script: Could not find suitable location to insert warning banner.");
        emailElement.prepend(banner); // Fallback insert
    }
}

function removeWarningBanner(emailElement) {
    if (!emailElement) return;
    const existingBanner = emailElement.querySelector(`#${WARNING_BANNER_ID}`);
    if (existingBanner) {
        existingBanner.remove();
        console.log("Content Script: Removed existing warning banner.");
    }
}

async function checkEmail(emailElement) {
    if (!emailElement || emailElement.hasAttribute(CHECKED_EMAIL_ATTR)) {
        return; // Already checked or invalid element
    }

    // Mark as checked to prevent re-processing immediately
    emailElement.setAttribute(CHECKED_EMAIL_ATTR, 'true');
    console.log("Content Script: Checking email element:", emailElement);

    const { senderEmail, emailContent } = extractEmailDetails(emailElement);

    if (!senderEmail && !emailContent) {
        console.log("Content Script: Could not extract sender or content. Skipping check.");
        // Maybe remove attribute if extraction failed?
        emailElement.removeAttribute(CHECKED_EMAIL_ATTR);
        return;
    }

    // Remove any previous banner before sending request
    removeWarningBanner(emailElement);

    try {
        console.log(`Content Script: Sending 'checkEmailDetails' to background - Sender: ${senderEmail}, Content Length: ${emailContent?.length}`);
        const response = await chrome.runtime.sendMessage({
            action: 'checkEmailDetails',
            senderEmail: senderEmail,
            emailContent: emailContent // Send extracted content
        });

        console.log("Content Script: Received response from background:", response);

        if (chrome.runtime.lastError) {
            console.error("Content Script: Error sending message to background:", chrome.runtime.lastError);
            // Optionally display an error message?
            removeWarningBanner(emailElement); // Ensure no stale banner
        } else if (response && response.isPhishing) {
            let reason = response.senderReason || 'Nội dung hoặc người gửi đáng ngờ.';
            if(response.contentScan?.hasSuspiciousKeywords && response.senderStatus !== 'blocked') {
                 reason = `Nội dung chứa từ khóa đáng ngờ.`; // Prioritize content warning if sender was ok/invalid
            } else if (response.senderStatus === 'blocked') {
                 reason = `Người gửi (${senderEmail}) nằm trong danh sách chặn.`; // Prioritize sender warning
            }
            showWarningBanner(emailElement, reason, response.contentScan?.keywordsFound || []);
        } else if (response && !response.isPhishing) {
             // Email is considered safe, ensure no warning is shown
             console.log(`Content Script: Email from ${senderEmail} determined safe. Reason: ${response.senderReason || 'N/A'}. Content Scan: ${response.contentScan?.hasSuspiciousKeywords}`);
             removeWarningBanner(emailElement);
        } else if (response && response.status === 'error') {
             console.warn("Content Script: Background script reported an error during check:", response.reason);
             // Decide if to show a less severe warning or nothing
             showWarningBanner(emailElement, `Lưu ý: Không thể hoàn tất kiểm tra (${response.reason})`, []);
             removeWarningBanner(emailElement); // Safer to show nothing on error
        } else {
             // No action needed if safe
             removeWarningBanner(emailElement);
        }

    } catch (error) {
        console.error("Content Script: Exception during email check:", error);
        // Ensure banner is removed on error
        removeWarningBanner(emailElement);
    } finally {
         // Optionally remove the checked attribute after a delay to allow re-checks if needed?
         setTimeout(() => emailElement.removeAttribute(CHECKED_EMAIL_ATTR), 5000);
    }
}

// --- Event Listeners & Observers ---

// Use MutationObserver to detect when emails are opened/rendered in the DOM.
// This is more reliable than click listeners in complex web apps.
const observer = new MutationObserver(mutations => {
    let emailToCheck = null;

    for (const mutation of mutations) {
         // Check added nodes for potential email containers
        for (const node of mutation.addedNodes) {
            if (node.nodeType === Node.ELEMENT_NODE) {
                 // Check if the added node itself is an email container
                 const container = findEmailContainer(node);
                 if (container && !container.hasAttribute(CHECKED_EMAIL_ATTR)) {
                     emailToCheck = container;
                     break; // Found one
                 }
                 // Check if children of the added node contain an email container
                 const childContainer = node.querySelector('.nH.bkK, .nH.if, [role="main"] .IzmLX, .wide-content-host'); // Add selectors here
                 if(childContainer && !childContainer.hasAttribute(CHECKED_EMAIL_ATTR)) {
                      emailToCheck = childContainer;
                      break;
                 }
            }
        }
         if (emailToCheck) break;

         // Also check if the *target* of the mutation (or its parent) looks like an email container
         // This helps catch updates within an already loaded email view
         if (!emailToCheck && mutation.target && mutation.target.nodeType === Node.ELEMENT_NODE) {
             const targetContainer = findEmailContainer(mutation.target);
             if (targetContainer && !targetContainer.hasAttribute(CHECKED_EMAIL_ATTR)) {
                  // Check if the mutation likely indicates the email content became visible/changed
                  // Example: check for changes in style attribute, class list, or specific child nodes
                 if (mutation.type === 'attributes' || mutation.type === 'childList') {
                      emailToCheck = targetContainer;
                      break;
                 }
             }
         }
         if (emailToCheck) break;
    }


    if (emailToCheck && emailToCheck !== currentVisibleEmailElement) {
        // Debounce the check to avoid rapid firing during rendering
        clearTimeout(emailCheckTimeout);
        currentVisibleEmailElement = emailToCheck; // Store the element we intend to check
        console.log("Content Script: Detected potential email view change. Debouncing check for:", currentVisibleEmailElement);

        emailCheckTimeout = setTimeout(() => {
            if (currentVisibleEmailElement) { // Check if still relevant
                 // Double check if it's still in the DOM before checking
                 if (document.body.contains(currentVisibleEmailElement)) {
                      checkEmail(currentVisibleEmailElement);
                 } else {
                      console.log("Content Script: Email element removed from DOM before check could run.");
                      currentVisibleEmailElement = null; // Reset
                 }
            }
        }, EMAIL_BODY_CHECK_DELAY_MS); // Wait a bit for content to settle
    } else if (!emailToCheck) {
         // Maybe clear currentVisibleEmailElement if no email seems active?
         // currentVisibleEmailElement = null;
    }
});

// Start observing the document body for changes
observer.observe(document.body, {
    childList: true,  // Watch for nodes being added or removed
    subtree: true,    // Watch the entire DOM tree under the target
    attributes: true, // Watch for attribute changes (e.g., style, class affecting visibility)
    attributeFilter: ['style', 'class'] // Optional: only observe specific attributes
});

console.log("Phishing Guard Content Script Observer Started.");

// Initial check in case an email is already open when the script loads
// Use a small delay to let the page fully render
setTimeout(() => {
     console.log("Content Script: Performing initial check for open emails...");
     const potentialContainers = document.querySelectorAll('.nH.bkK, .nH.if, [role="main"] .IzmLX, .wide-content-host'); // Add more selectors
     potentialContainers.forEach(container => {
          // Check if the container seems visible/active
          if (container.offsetParent !== null && !container.hasAttribute(CHECKED_EMAIL_ATTR)) { // Check if visible
               checkEmail(container);
          }
     });
}, 2000);