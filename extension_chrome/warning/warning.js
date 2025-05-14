document.addEventListener('DOMContentLoaded', function () {
    const params = new URLSearchParams(window.location.search);
    const blockedUrl = params.get('url');
    const listName = params.get('listName');
    const reason = params.get('reason');
    const tabIdParam = params.get('tabId');
    const prevSafeUrl = params.get('prevSafeUrl') || '';

    if (!blockedUrl) {
        document.body.innerHTML = '<div style="color:#d9534f;text-align:center;margin-top:60px;font-size:1.2rem;">Không có URL để cảnh báo!</div>';
        return;
    }

    document.getElementById('blocked-url').textContent = blockedUrl || 'Không có URL';
    document.getElementById('list-name').textContent = listName || 'Không rõ nguồn gốc';
    document.getElementById('reason-text').textContent = reason || 'Không có lý do cụ thể.';

    const goBackButton = document.getElementById('go-back');
    const reportFalsePositiveButton = document.getElementById('report-false-positive');
    const proceedAnywayButton = document.getElementById('proceed-anyway');

    goBackButton.addEventListener('click', function () {
        if (tabIdParam && chrome && chrome.tabs) {
            try {
                chrome.tabs.update(Number(tabIdParam), { url: 'https://www.google.com/' }, function() {
                    window.close();
                });
            } catch (e) {
                window.close();
            }
        } else {
            window.close();
        }
    });

    function showStatusMessage(msg, isSuccess = true) {
        const statusDiv = document.getElementById('status-message');
        statusDiv.textContent = msg;
        statusDiv.style.color = isSuccess ? '#218838' : '#d9534f';
        if (isSuccess) {
            setTimeout(() => { statusDiv.textContent = ''; }, 1500);
        }
    }

    reportFalsePositiveButton.addEventListener('click', function() {
        if (blockedUrl) {
            const domain = new URL(blockedUrl).hostname.replace(/^www\./, '');
            chrome.runtime.sendMessage({ 
                action: "addToPermanentWhitelist", 
                domain: domain
            }, function(response) {
                showStatusMessage('Đã đánh dấu là an toàn!', true);
                setTimeout(() => {
                    window.close();
                }, 1200);
            });
        } else {
            showStatusMessage('Không có URL để báo cáo.', false);
        }
    });

    proceedAnywayButton.addEventListener('click', function () {
        window.close();
    });
});