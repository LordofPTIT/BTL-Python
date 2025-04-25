const statusElement = document.getElementById('current-site-status');
const urlElement = document.getElementById('current-site-url');
const reportButton = document.getElementById('report-site-button');
// const whitelistButton = document.getElementById('whitelist-site-button'); // Uncomment if implementing whitelist
const apiIndicator = document.getElementById('api-indicator');
const apiText = document.getElementById('api-text');

let currentUrl = null;
let currentDomain = null;

// Function to update UI based on URL status
function updateUi(url, domain, isPhishing, reason) {
    currentUrl = url;
    currentDomain = domain;

    if (!url) {
        statusElement.textContent = 'Không có trang hợp lệ';
        statusElement.className = 'unknown';
        urlElement.textContent = 'Mở một trang web để kiểm tra.';
        reportButton.disabled = true;
        // whitelistButton.disabled = true;
        return;
    }

    urlElement.textContent = url.length > 50 ? url.substring(0, 47) + '...' : url; // Truncate long URLs

    if (isPhishing) {
        statusElement.textContent = 'CẢNH BÁO LỪA ĐẢO!';
        statusElement.className = 'phishing';
        reportButton.textContent = 'Đã bị chặn/báo cáo';
        reportButton.disabled = true; // Already known phishing
        // whitelistButton.disabled = false; // Allow whitelisting
        // whitelistButton.textContent = 'Bỏ chặn trang này (Tin tưởng)';
    } else {
        statusElement.textContent = 'Trang web có vẻ an toàn';
        statusElement.className = 'safe';
        reportButton.disabled = false;
        reportButton.textContent = 'Báo cáo trang này là lừa đảo';
        // whitelistButton.disabled = true;
        // whitelistButton.textContent = 'Thêm vào danh sách an toàn';
    }
}

// Get current tab URL and check its status
chrome.runtime.sendMessage({ action: 'getCurrentTabUrl' }, (response) => {
    if (response && response.url) {
        const url = response.url;
        try {
             const domain = new URL(url).hostname.replace(/^www\./, '');
             // Ask background script to check this domain
             chrome.runtime.sendMessage({ action: 'checkDomain', value: domain }, (checkResponse) => {
                 if (chrome.runtime.lastError) {
                      console.error("Popup: Error receiving checkDomain response:", chrome.runtime.lastError);
                      updateUi(url, domain, false, "Lỗi kiểm tra"); // Assume safe on error
                      return;
                 }
                 if (checkResponse) {
                    updateUi(url, domain, checkResponse.isPhishing, checkResponse.reason);
                 } else {
                      updateUi(url, domain, false, "Phản hồi không hợp lệ");
                 }

             });
        } catch(e) {
             console.warn("Popup: Invalid URL in current tab:", url);
             updateUi(null, null, false, null); // Handle invalid URL
        }

    } else {
         updateUi(null, null, false, null); // No valid URL
         if (response && response.error) {
             console.error("Popup: Error getting current tab URL:", response.error);
         }
    }
});


// Report button listener
reportButton.addEventListener('click', () => {
    if (currentDomain) {
        reportButton.disabled = true;
        reportButton.textContent = 'Đang gửi báo cáo...';
        chrome.runtime.sendMessage({ action: 'reportItem', type: 'domain', value: currentDomain }, (response) => {
             // Update UI based on report success? Or rely on notification?
             // For now, just re-enable slightly differently or keep disabled shortly
            if(response && response.success){
                 reportButton.textContent = 'Đã báo cáo!';
                 // Keep it disabled briefly or permanently for this session
                 setTimeout(() => { if(statusElement.className !== 'phishing') reportButton.disabled = false; reportButton.textContent = 'Báo cáo trang này là lừa đảo';}, 3000); // Re-enable after 3s if not phishing
            } else {
                 reportButton.textContent = 'Lỗi báo cáo. Thử lại?';
                 reportButton.disabled = false; // Allow retry
            }

        });
    }
});

// Whitelist button listener (Optional)
// whitelistButton.addEventListener('click', () => {
//     if (currentDomain) {
//         whitelistButton.disabled = true;
//         whitelistButton.textContent = 'Đang xử lý...';
//         chrome.runtime.sendMessage({ action: 'whitelistItem', type: 'domain', value: currentDomain }, (response) => {
//             // Update UI after whitelisting
//              whitelistButton.textContent = 'Đã thêm vào danh sách an toàn';
//         });
//     }
// });


// Check API Status
chrome.runtime.sendMessage({ action: 'getApiStatus' }, (response) => {
  if (response && response.reachable) {
    apiIndicator.className = 'online';
    apiText.textContent = 'API Online';
  } else {
    apiIndicator.className = 'offline';
    apiText.textContent = 'API Offline';
     if (chrome.runtime.lastError) {
         console.error("Popup: Error receiving API status:", chrome.runtime.lastError);
          apiText.textContent = 'Lỗi API';
     }
  }
});