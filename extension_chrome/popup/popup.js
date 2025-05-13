document.addEventListener('DOMContentLoaded', async function() {
    const apiIndicator = document.getElementById('api-indicator');
    const apiText = document.getElementById('api-text');
    const optionsLink = document.getElementById('options-link');
    const reportEmailInput = document.getElementById('reportEmailInput');
    const reportEmailButton = document.getElementById('reportEmailButton');
    const reportEmailResult = document.getElementById('reportEmailResult');
    const reportDomainInput = document.getElementById('reportDomainInput');
    const reportDomainButton = document.getElementById('reportDomainButton');
    const reportDomainResult = document.getElementById('reportDomainResult');

    optionsLink.addEventListener('click', (e) => {
        e.preventDefault();
        chrome.runtime.openOptionsPage();
    });

    function setApiStatus(online) {
        if (online) {
            apiIndicator.className = 'online';
            apiText.textContent = 'API Online';
        } else {
            apiIndicator.className = 'offline';
            apiText.textContent = 'API Offline';
        }
    }

    try {
        const response = await chrome.runtime.sendMessage({ action: 'getApiStatus' });
        setApiStatus(response.reachable);
    } catch (error) {
        console.error('Error checking API status:', error);
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
                    report_type: 'suspicious_email',
                    value: email,
                    context: 'Reported from popup'
                }
            });

            if (response.success) {
                reportEmailResult.textContent = 'Đã báo cáo email thành công!';
                reportEmailInput.value = '';
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
                    report_type: 'suspicious_domain',
                    value: domain,
                    context: 'Reported from popup'
                }
            });

            if (response.success) {
                reportDomainResult.textContent = 'Đã báo cáo domain thành công!';
                reportDomainInput.value = '';
            } else {
                reportDomainResult.textContent = `Lỗi: ${response.error || 'Không thể báo cáo domain'}`;
            }
        } catch (error) {
            reportDomainResult.textContent = `Lỗi: ${error.message}`;
        }
    });
});