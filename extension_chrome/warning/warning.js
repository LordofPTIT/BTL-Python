document.addEventListener('DOMContentLoaded', function () {
    const params = new URLSearchParams(window.location.search);
    const blockedUrl = params.get('url');
    const listName = params.get('listName');
    const reason = params.get('reason');
    const tabIdParam = params.get('tabId');
    const prevSafeUrl = params.get('prevSafeUrl') || '';

    document.getElementById('blocked-url').textContent = blockedUrl || 'Không có URL';
    document.getElementById('list-name').textContent = listName || 'Không rõ nguồn gốc';
    document.getElementById('reason-text').textContent = reason || 'Không có lý do cụ thể.';

    const goBackButton = document.getElementById('go-back');
    const reportFalsePositiveButton = document.getElementById('report-false-positive');
    const proceedAnywayButton = document.getElementById('proceed-anyway');

    goBackButton.addEventListener('click', function () {
        if (window.history.length > 1) {
            window.history.go(-1);
        } else if (prevSafeUrl && (prevSafeUrl.startsWith('http:') || prevSafeUrl.startsWith('https:'))) {
            window.location.href = prevSafeUrl;
        } else {
            window.location.href = 'about:blank';
        }
    });

    reportFalsePositiveButton.addEventListener('click', function() {
        if (blockedUrl) {
            let itemType = "domain";
            let domainToMarkSafe = blockedUrl;
            try {
                const urlObj = new URL(blockedUrl);
                domainToMarkSafe = urlObj.hostname.toLowerCase().replace(/^www\./, '');
            } catch(e) {
                domainToMarkSafe = blockedUrl;
            }
            chrome.runtime.sendMessage({
                action: "markAsSafeAndReport",
                domainToMarkSafe: domainToMarkSafe,
                data: {
                    report_type: `false_positive_domain`,
                    value: blockedUrl.toLowerCase(),
                    source_url: blockedUrl,
                    context: `Reported as safe from warning page by user.`
                }
            }, function(response) {
                if (response && response.success) {
                    window.location.href = blockedUrl;
                } else {
                    alert("Không thể báo cáo an toàn. Vui lòng thử lại.");
                }
            });
        } else {
            alert("Không có URL để báo cáo.");
        }
    });

    proceedAnywayButton.addEventListener('click', function () {
        if (blockedUrl) {
            chrome.runtime.sendMessage({ action: "addToSessionWhitelist", url: blockedUrl }, function(response) {
                if (response && response.success) {
                    window.location.href = blockedUrl;
                } else {
                    alert("Không thể cho phép tạm thời. Vui lòng thử lại.");
                }
            });
        } else {
            alert("Không có URL để tiếp tục.");
        }
    });
});