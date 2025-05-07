document.addEventListener('DOMContentLoaded', function () {
    const params = new URLSearchParams(window.location.search);
    const blockedUrl = params.get('url');
    const listName = params.get('listName');
    const reason = params.get('reason');
    const tabIdParam = params.get('tabId');
    const prevSafeUrl = params.get('prevSafeUrl') || 'chrome://newtab';

    document.getElementById('blocked-url').textContent = blockedUrl || 'Không có URL';
    document.getElementById('list-name').textContent = listName || 'Không rõ nguồn gốc';
    document.getElementById('reason-text').textContent = reason || 'Không có lý do cụ thể.';

    const goBackButton = document.getElementById('go-back');
    const reportFalsePositiveButton = document.getElementById('report-false-positive');
    const proceedAnywayButton = document.getElementById('proceed-anyway');

    goBackButton.addEventListener('click', function () {
        if (prevSafeUrl && (prevSafeUrl.startsWith('http:') || prevSafeUrl.startsWith('https:') || prevSafeUrl === 'chrome://newtab' || prevSafeUrl === 'about:blank')) {
            window.location.href = prevSafeUrl;
        } else if (tabIdParam && parseInt(tabIdParam)) {
            const tabIdInt = parseInt(tabIdParam);
            chrome.tabs.goBack(tabIdInt, () => {
                if (chrome.runtime.lastError) {
                    console.warn("Failed to go back using chrome.tabs.goBack, opening newtab:", chrome.runtime.lastError.message);
                    window.location.href = 'chrome://newtab';
                }
            });
        } else if (window.history.length > 1) {
            window.history.back();
        } else {
            window.location.href = 'chrome://newtab';
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
                console.warn("Could not parse blockedUrl as URL to extract domain for allowlist, using full URL string as fallback (less effective).");
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
                    alert(`Đã ghi nhận "${domainToMarkSafe}" là an toàn và gửi báo cáo. Trang sẽ không bị chặn nữa. Bạn có thể cần tải lại trang đích.`);
                    window.location.href = blockedUrl;
                    reportFalsePositiveButton.textContent = "Đã báo cáo an toàn";
                    reportFalsePositiveButton.disabled = true;
                    proceedAnywayButton.textContent = "Tiếp tục truy cập (Đã cho phép)";
                } else {
                    alert(`Gửi yêu cầu không thành công. Lỗi: ${response ? (response.error || (response.reportSuccess === false ? "Lỗi báo cáo backend" : "Lỗi cập nhật allowlist")) : 'Unknown error'}`);
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