(function() {
    const POPUP_ID = 'phishing-guard-domain-warning-popup';
    let warningData = null;

    function createPopup(type, item, fullUrl, reason) {
        if (document.getElementById(POPUP_ID)) return;

        const popup = document.createElement('div');
        popup.id = POPUP_ID;
        Object.assign(popup.style, {
            position: 'fixed', top: '0', left: '0', width: '100%', height: '100%',
            backgroundColor: 'rgba(0,0,0,0.7)', zIndex: '2147483646',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontFamily: 'Arial, sans-serif'
        });

        const contentBox = document.createElement('div');
        Object.assign(contentBox.style, {
            backgroundColor: '#fff', color: '#d9534f', padding: '32px',
            borderRadius: '12px', textAlign: 'center', maxWidth: '420px', width: '420px',
            boxShadow: '0 4px 24px rgba(0,0,0,0.13)'
        });

        const title = document.createElement('h2');
        title.textContent = 'CẢNH BÁO AN NINH NGHIÊM TRỌNG!';
        title.style.color = '#d9534f';
        contentBox.appendChild(title);

        const message = document.createElement('p');
        message.innerHTML = `Trang web bạn đang cố truy cập (<strong>${item}</strong>) bị nghi ngờ không an toàn hoặc nằm trong danh sách chặn.<br>Lý do: ${reason || 'Không có lý do cụ thể.'}`;
        message.style.marginBottom = '18px';
        message.style.fontSize = '15px';
        message.style.color = '#333';
        contentBox.appendChild(message);

        const buttonContainer = document.createElement('div');
        buttonContainer.style.display = 'flex';
        buttonContainer.style.flexDirection = 'column';
        buttonContainer.style.gap = '12px';
        buttonContainer.style.margin = '18px 0 0 0';

        const backButton = document.createElement('button');
        backButton.textContent = 'Quay lại trang an toàn';
        backButton.style.background = '#5cb85c';
        backButton.style.color = '#fff';
        backButton.style.border = 'none';
        backButton.style.borderRadius = '6px';
        backButton.style.padding = '10px 0';
        backButton.style.fontWeight = '600';
        backButton.style.fontSize = '1rem';
        backButton.style.cursor = 'pointer';
        backButton.onclick = () => {
            if (window.history.length > 1) {
                window.history.back();
            } else {
                window.location.replace('about:blank');
            }
            popup.remove();
        };
        buttonContainer.appendChild(backButton);

        const allowButton = document.createElement('button');
        allowButton.textContent = 'Cho phép tạm thời & Tiếp tục truy cập';
        allowButton.style.background = '#f0ad4e';
        allowButton.style.color = '#fff';
        allowButton.style.border = 'none';
        allowButton.style.borderRadius = '6px';
        allowButton.style.padding = '10px 0';
        allowButton.style.fontWeight = '600';
        allowButton.style.fontSize = '1rem';
        allowButton.style.cursor = 'pointer';
        allowButton.onclick = () => {
            chrome.runtime.sendMessage({ action: 'addTemporaryAllowDomain', domain: item }, (response) => {
                popup.remove();
            });
        };
        buttonContainer.appendChild(allowButton);

        const safeButton = document.createElement('button');
        safeButton.textContent = 'Báo cáo là an toàn';
        safeButton.style.background = '#0275d8';
        safeButton.style.color = '#fff';
        safeButton.style.border = 'none';
        safeButton.style.borderRadius = '6px';
        safeButton.style.padding = '10px 0';
        safeButton.style.fontWeight = '600';
        safeButton.style.fontSize = '1rem';
        safeButton.style.cursor = 'pointer';
        safeButton.onclick = () => {
            chrome.runtime.sendMessage({ action: 'markAsSafeAndReport', domainToMarkSafe: item, data: { report_type: 'false_positive_domain', value: item, source_url: item, context: 'Reported as safe from warning popup.' } }, function(response) {
                popup.remove();
            });
        };
        buttonContainer.appendChild(safeButton);

        contentBox.appendChild(buttonContainer);
        popup.appendChild(contentBox);
        document.body.appendChild(popup);
    }

    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
        if (message.action === 'showPhishingWarningPopup' && message.type === 'domain') {
            try {
                warningData = message;
                createPopup(message.type, message.blockedItem, message.fullUrl, message.reason);
                sendResponse({ status: "domain warning popup shown" });
            } catch (e) {
                // Nếu không thể hiển thị popup, fallback mở warning.html
                const warningPageUrl = chrome.runtime.getURL('warning/warning.html') +
                    `?url=${encodeURIComponent(message.fullUrl)}` +
                    `&listName=${encodeURIComponent('Local Blocklist')}` +
                    `&reason=${encodeURIComponent(message.reason)}`;
                window.open(warningPageUrl, '_blank');
            }
        } else {
            console.log('[Phishing Guard] Message không phù hợp:', message);
        }
        return true;
    });

})();