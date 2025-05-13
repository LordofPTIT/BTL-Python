document.addEventListener('DOMContentLoaded', () => {
    const apiIndicator = document.getElementById('api-indicator');
    const apiText = document.getElementById('api-text');
    const optionsLink = document.getElementById('options-link');
    const reportEmailInput = document.getElementById('report-email-input');
    const reportEmailBtn = document.getElementById('report-email-btn');
    const reportEmailResult = document.getElementById('report-email-result');
    const reportDomainInput = document.getElementById('report-domain-input');
    const reportDomainBtn = document.getElementById('report-domain-btn');
    const reportDomainResult = document.getElementById('report-domain-result');

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

    chrome.runtime.sendMessage({ action: 'getApiStatus' }, (response) => {
        if (chrome.runtime.lastError) {
            setApiStatus(false);
            return;
        }
        setApiStatus(response && response.reachable);
    });

    reportEmailBtn.addEventListener('click', () => {
        const email = reportEmailInput.value.trim().toLowerCase();
        reportEmailResult.textContent = '';
        if (!email || !/^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(email)) {
            reportEmailResult.textContent = 'Email không hợp lệ.';
            reportEmailResult.style.color = '#cf222e';
            return;
        }
        reportEmailBtn.disabled = true;
        chrome.runtime.sendMessage({
            action: 'reportItem',
            type: 'email',
            value: email,
            context: 'Popup report email'
        }, (response) => {
            reportEmailBtn.disabled = false;
            if (chrome.runtime.lastError || !response?.success) {
                reportEmailResult.textContent = 'Lỗi cập nhật. Vui lòng thử lại.';
                reportEmailResult.style.color = '#cf222e';
            } else {
                reportEmailResult.textContent = 'Đã cập nhật email vào danh sách chặn!';
                reportEmailResult.style.color = '#2da44e';
                reportEmailInput.value = '';
            }
        });
    });

    reportDomainBtn.addEventListener('click', () => {
        const domain = reportDomainInput.value.trim().toLowerCase();
        reportDomainResult.textContent = '';
        if (!domain || !/^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/.test(domain)) {
            reportDomainResult.textContent = 'Domain không hợp lệ.';
            reportDomainResult.style.color = '#cf222e';
            return;
        }
        reportDomainBtn.disabled = true;
        chrome.runtime.sendMessage({
            action: 'reportItem',
            type: 'domain',
            value: domain,
            context: 'Popup report domain'
        }, (response) => {
            reportDomainBtn.disabled = false;
            if (chrome.runtime.lastError || !response?.success) {
                reportDomainResult.textContent = 'Lỗi cập nhật. Vui lòng thử lại.';
                reportDomainResult.style.color = '#cf222e';
            } else {
                reportDomainResult.textContent = 'Đã cập nhật domain vào danh sách chặn!';
                reportDomainResult.style.color = '#2da44e';
                reportDomainInput.value = '';
            }
        });
    });
});