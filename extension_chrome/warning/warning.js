document.addEventListener('DOMContentLoaded', function () {
    const params = new URLSearchParams(window.location.search);
    const blockedUrl = params.get('url');
    const listName = params.get('listName');
    const reason = params.get('reason');

    document.getElementById('blocked-url').textContent = blockedUrl || 'Không có URL';
    document.getElementById('list-name').textContent = listName || 'Không rõ nguồn gốc';
    document.getElementById('reason-text').textContent = reason || 'Không có lý do cụ thể.';

    const proceedButton = document.getElementById('proceed-anyway');
    const backButton = document.getElementById('go-back');
    const reportFalsePositiveButton = document.getElementById('report-false-positive');

    if (blockedUrl) {
        proceedButton.addEventListener('click', function () {
            chrome.storage.local.get('whitelistedUrls', function (data) {
                let whitelistedUrls = data.whitelistedUrls || [];
                if (!whitelistedUrls.includes(blockedUrl)) {
                    whitelistedUrls.push(blockedUrl); // Simple temporary whitelist for this session
                    chrome.storage.local.set({ whitelistedUrls: whitelistedUrls }, function() {
                        window.location.href = blockedUrl;
                    });
                } else {
                     window.location.href = blockedUrl;
                }
            });
        });
    } else {
        proceedButton.disabled = true;
    }

    backButton.addEventListener('click', function () {
        window.history.back();
        // As a fallback if history.back() doesn't work (e.g., new tab)
        setTimeout(() => {
             chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
                if (tabs[0] && tabs[0].id) {
                    chrome.tabs.goBack(tabs[0].id, () => {
                        // If goBack fails (no history), close the tab or redirect to a safe page
                        if (chrome.runtime.lastError) {
                            window.location.href = "about:blank"; // Or chrome.tabs.remove(tabs[0].id);
                        }
                    });
                } else {
                     window.location.href = "about:blank";
                }
            });
        }, 100);
    });

    if (reportFalsePositiveButton) {
        reportFalsePositiveButton.addEventListener('click', function() {
            if (blockedUrl) {
                const reportPageUrl = chrome.runtime.getURL('report/report.html') +
                                      `?type=false_positive&value=${encodeURIComponent(blockedUrl)}&source_url=${encodeURIComponent(window.location.href)}`;
                window.open(reportPageUrl, '_blank');
            }
        });
    }
});