// This script is injected into pages identified as potentially malicious by background.js

(function() {
    const POPUP_ID = 'phishing-guard-domain-warning-popup';
    let warningData = null; // To store data received from background

    function createPopup(type, item, fullUrl, reason) {
        if (document.getElementById(POPUP_ID)) return; // Popup already exists

        const popup = document.createElement('div');
        popup.id = POPUP_ID;
        // Apply styles via JS to avoid needing separate CSS for this simple case, or link to shared CSS
        Object.assign(popup.style, {
            position: 'fixed', top: '0', left: '0', width: '100%', height: '100%',
            backgroundColor: 'rgba(0,0,0,0.7)', zIndex: '2147483646',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontFamily: 'Arial, sans-serif'
        });

        const contentBox = document.createElement('div');
        Object.assign(contentBox.style, {
            backgroundColor: '#ffeeba', color: '#856404', padding: '30px',
            borderRadius: '8px', textAlign: 'center', maxWidth: '500px',
            boxShadow: '0 5px 15px rgba(0,0,0,0.3)'
        });

        const title = document.createElement('h2');
        title.textContent = '⚠️ Cảnh Báo An Ninh!';
        title.style.color = '#d9534f';
        contentBox.appendChild(title);

        const message = document.createElement('p');
        message.innerHTML = `Trang web bạn đang cố truy cập (<strong>${item}</strong>) bị nghi ngờ là không an toàn hoặc nằm trong danh sách chặn. <br>Lý do: ${reason || 'Không có lý do cụ thể.'}<br><br>Tiếp tục truy cập có thể tiềm ẩn rủi ro.`;
        message.style.marginBottom = '20px';
        message.style.fontSize = '15px';
        contentBox.appendChild(message);

        const buttonContainer = document.createElement('div');

        const proceedButton = document.createElement('button');
        proceedButton.textContent = 'Tiếp tục truy cập (Rủi ro)';
        Object.assign(proceedButton.style, {
            backgroundColor: '#f0ad4e', color: 'white', border: 'none',
            padding: '10px 15px', margin: '5px', borderRadius: '5px', cursor: 'pointer'
        });
        proceedButton.onclick = () => {
            // Send message to background to temporarily allow this domain for the session
            chrome.runtime.sendMessage({ action: 'addTemporaryAllowDomain', domain: item }, (response) => {
                if (response && response.success) {
                    popup.remove();
                    // Optionally, reload the page if the request was truly blocked and needs to be re-attempted.
                    // However, since we are not blocking, just removing popup is enough.
                    // window.location.reload(); // If original request was fully blocked by a redirect
                } else {
                    alert('Không thể bỏ qua cảnh báo tạm thời. Lỗi: ' + (response?.error || 'Không rõ'));
                }
            });
            popup.remove(); // Remove popup immediately for better UX
        };
        buttonContainer.appendChild(proceedButton);

        const backButton = document.createElement('button');
        backButton.textContent = 'Quay lại trang an toàn';
        Object.assign(backButton.style, {
            backgroundColor: '#5cb85c', color: 'white', border: 'none',
            padding: '10px 15px', margin: '5px', borderRadius: '5px', cursor: 'pointer'
        });
        backButton.onclick = () => {
            // Try to go back, if not possible, redirect to a safe page like about:blank or extension's newtab
            if (window.history.length > 1) {
                window.history.back();
            } else {
                window.location.replace('about:blank');
            }
            popup.remove();
        };
        buttonContainer.appendChild(backButton);
        contentBox.appendChild(buttonContainer);
        popup.appendChild(contentBox);
        document.body.appendChild(popup);
    }

    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        if (message.action === 'showPhishingWarningPopup' && message.type === 'domain') {
            warningData = message; // Store for later use if needed
            createPopup(message.type, message.blockedItem, message.fullUrl, message.reason);
            sendResponse({ status: "domain warning popup shown" });
        }
        return true; // Indicate async response potential if needed for other messages
    });

})();