document.addEventListener('DOMContentLoaded', () => {
    const statusElement = document.getElementById('current-site-status');
    const urlElement = document.getElementById('current-site-url');
    const reasonElement = document.getElementById('current-site-reason');
    const reportButton = document.getElementById('report-site-button');
    const whitelistButton = document.getElementById('whitelist-site-button');
    const apiIndicator = document.getElementById('api-indicator');
    const apiText = document.getElementById('api-text');
    const optionsLink = document.getElementById('options-link');

    let currentUrl = null;
    let currentDomain = null;
    let currentStatus = { isPhishing: null, reason: null };

    optionsLink.addEventListener('click', (e) => {
        e.preventDefault();
        chrome.runtime.openOptionsPage();
    });


    function updateUi() {
        urlElement.textContent = currentUrl ? (currentUrl.length > 60 ? currentUrl.substring(0, 57) + '...' : currentUrl) : 'Không có URL hợp lệ.';
        reasonElement.textContent = '';

        if (!currentUrl || !currentDomain) {
            statusElement.textContent = 'Không áp dụng';
            statusElement.className = 'unknown';
            reportButton.disabled = true;
            whitelistButton.disabled = true;
            urlElement.textContent = 'Mở một trang web (http/https).';
            return;
        }

        if (currentStatus.isPhishing === null) {
             statusElement.textContent = 'Đang kiểm tra...';
             statusElement.className = 'checking';
             reportButton.disabled = true;
             whitelistButton.disabled = true;
        } else if (currentStatus.isPhishing === true) {
            statusElement.textContent = 'CẢNH BÁO LỪA ĐẢO!';
            statusElement.className = 'phishing';
            reasonElement.textContent = `Lý do: ${currentStatus.reason || 'Nằm trong danh sách chặn'}`;
            reportButton.textContent = 'Đã bị chặn/báo cáo';
            reportButton.disabled = true;
            whitelistButton.textContent = 'Whitelist trang này (Tin tưởng)';
            whitelistButton.disabled = false;
        } else {
             statusElement.textContent = 'Trang có vẻ an toàn';
             statusElement.className = 'safe';
             reasonElement.textContent = `Lý do kiểm tra: ${currentStatus.reason || 'Không nằm trong danh sách chặn'}`;
             if (currentStatus.reason && currentStatus.reason.toLowerCase().includes('whitelist')) {

                 whitelistButton.textContent = 'Đã trong Whitelist';
                 whitelistButton.disabled = true;
                 reportButton.disabled = true;
             } else {
                 whitelistButton.textContent = 'Whitelist trang này';
                 whitelistButton.disabled = false;
             }
             reportButton.textContent = 'Báo cáo trang này là lừa đảo';
             reportButton.disabled = false;
        }
    }


    function refreshCurrentTabStatus() {
         currentStatus = { isPhishing: null, reason: null };
         updateUi();

         chrome.runtime.sendMessage({ action: 'getCurrentTabInfo' }, (response) => {
            if (chrome.runtime.lastError) {
                console.error("Popup: Error getCurrentTabInfo:", chrome.runtime.lastError.message);
                currentUrl = null; currentDomain = null; updateUi(); return;
            }
            if (response && response.url && response.domain) {
                currentUrl = response.url;
                currentDomain = response.domain;

                chrome.runtime.sendMessage({ action: 'checkDomain', value: currentDomain }, (checkResponse) => {
                    if (chrome.runtime.lastError) {
                        console.error("Popup: Error checkDomain response:", chrome.runtime.lastError.message);
                        currentStatus = { isPhishing: false, reason: "Lỗi kiểm tra" }; updateUi(); return;
                    }
                    if (checkResponse && typeof checkResponse.isPhishing !== 'undefined') {
                       currentStatus = checkResponse;
                    } else {
                       currentStatus = { isPhishing: false, reason: "Phản hồi không hợp lệ" };
                    }
                    updateUi();
                });
            } else {
                currentUrl = response?.url || null;
                currentDomain = null;
                updateUi();
            }
        });
    }



    reportButton.addEventListener('click', () => {
        if (currentDomain) {
            reportButton.disabled = true; whitelistButton.disabled = true;
            reportButton.textContent = 'Đang báo cáo...';
            chrome.runtime.sendMessage({ action: 'reportItem', type: 'domain', value: currentDomain, context: `Popup report from URL: ${currentUrl}` }, (response) => {
                if (chrome.runtime.lastError || !response?.success) {
                     console.error("Popup: Report failed:", chrome.runtime.lastError?.message || "API Error");
                     reportButton.textContent = 'Lỗi! Thử lại?';
                     reportButton.disabled = false; whitelistButton.disabled = false;
                } else {
                     reportButton.textContent = 'Đã báo cáo!';

                     setTimeout(refreshCurrentTabStatus, 500);
                }
            });
        }
    });

    whitelistButton.addEventListener('click', () => {
        if (currentDomain) {
            whitelistButton.disabled = true; reportButton.disabled = true;
            whitelistButton.textContent = 'Đang xử lý...';

            chrome.runtime.sendMessage({ action: 'whitelistItem', type: 'domain', value: currentDomain }, (response) => {
                 if (chrome.runtime.lastError || !response?.success) {
                      console.error("Popup: Whitelist failed:", chrome.runtime.lastError?.message || response?.message);
                      whitelistButton.textContent = 'Lỗi! Thử lại?';
                      whitelistButton.disabled = false; reportButton.disabled = currentStatus.isPhishing === true;
                 } else {
                      whitelistButton.textContent = 'Đã Whitelist!';

                       setTimeout(refreshCurrentTabStatus, 500);
                 }
            });
        }
    });


    chrome.runtime.sendMessage({ action: 'getApiStatus' }, (response) => {
      if (chrome.runtime.lastError) {
           apiIndicator.className = 'offline'; apiText.textContent = 'Lỗi kiểm tra API'; return;
      }
      if (response && response.reachable) {
        apiIndicator.className = 'online'; apiText.textContent = 'API Online';
      } else {
        apiIndicator.className = 'offline'; apiText.textContent = 'API Offline';
      }
    });


    refreshCurrentTabStatus();

});