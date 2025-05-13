document.addEventListener('DOMContentLoaded', async function() {
    const apiStatus = document.getElementById('apiStatus');
    const reportEmailInput = document.getElementById('reportEmailInput');
    const reportEmailButton = document.getElementById('reportEmailButton');
    const reportEmailResult = document.getElementById('reportEmailResult');
    const reportDomainInput = document.getElementById('reportDomainInput');
    const reportDomainButton = document.getElementById('reportDomainButton');
    const reportDomainResult = document.getElementById('reportDomainResult');

    function setApiStatus(online) {
        if (online) {
            apiStatus.className = 'api-status online';
            apiStatus.textContent = 'API Online';
        } else {
            apiStatus.className = 'api-status offline';
            apiStatus.textContent = 'API Offline';
        }
    }

    try {
        const response = await chrome.runtime.sendMessage({ action: 'getApiStatus' });
        setApiStatus(response.reachable);
    } catch (error) {
        setApiStatus(false);
    }

    // Xử lý báo cáo email
    reportEmailButton.addEventListener('click', async function() {
        const email = reportEmailInput.value.trim().toLowerCase();
        if (!email) {
            reportEmailResult.textContent = 'Vui lòng nhập email cần báo cáo';
            return;
        }

        try {
            const response = await chrome.runtime.sendMessage({
                action: 'reportToBackend',
                data: {
                    type: 'email',
                    value: email,
                    context: 'Reported from popup'
                }
            });

            if (response.success) {
                reportEmailResult.textContent = 'Đã báo cáo email thành công!';
                reportEmailInput.value = '';
                chrome.runtime.sendMessage({ action: 'updateBlocklists' });
            } else {
                reportEmailResult.textContent = `Lỗi: ${response.error || 'Không thể báo cáo email'}`;
            }
        } catch (error) {
            reportEmailResult.textContent = `Lỗi: ${error.message}`;
        }
    });

    // Xử lý báo cáo domain
    reportDomainButton.addEventListener('click', async function() {
        const domain = reportDomainInput.value.trim().toLowerCase();
        if (!domain) {
            reportDomainResult.textContent = 'Vui lòng nhập domain cần báo cáo';
            return;
        }

        try {
            const response = await chrome.runtime.sendMessage({
                action: 'reportToBackend',
                data: {
                    type: 'domain',
                    value: domain,
                    context: 'Reported from popup'
                }
            });

            if (response.success) {
                reportDomainResult.textContent = 'Đã báo cáo domain thành công!';
                reportDomainInput.value = '';
                // Đồng bộ blocklist local ngay sau khi báo cáo thành công
                chrome.runtime.sendMessage({ action: 'updateBlocklists' });
            } else {
                reportDomainResult.textContent = `Lỗi: ${response.error || 'Không thể báo cáo domain'}`;
            }
        } catch (error) {
            reportDomainResult.textContent = `Lỗi: ${error.message}`;
        }
    });
});