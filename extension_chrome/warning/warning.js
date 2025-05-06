document.addEventListener('DOMContentLoaded', function () {
    const params = new URLSearchParams(window.location.search);
    const blockedUrl = params.get('url');
    const listName = params.get('listName');
    const reason = params.get('reason');
    const tabId = params.get('tabId'); // Lấy tabId nếu có

    document.getElementById('blocked-url').textContent = blockedUrl || 'Không có URL';
    document.getElementById('list-name').textContent = listName || 'Không rõ nguồn gốc';
    document.getElementById('reason-text').textContent = reason || 'Không có lý do cụ thể.';

    const goBackButton = document.getElementById('go-back');
    const reportFalsePositiveButton = document.getElementById('report-false-positive');
    const proceedAnywayButton = document.getElementById('proceed-anyway');

    goBackButton.addEventListener('click', function () {
        if (window.history.length > 1) {
            window.history.back();
        } else {
            // Nếu không có lịch sử, đóng tab hoặc mở trang an toàn
            // chrome.tabs.getCurrent(tab => { chrome.tabs.remove(tab.id); }); // Đóng tab hiện tại
            window.location.href = 'chrome://newtab'; // Hoặc mở tab mới an toàn
        }
    });

    reportFalsePositiveButton.addEventListener('click', function() {
        if (blockedUrl) {
            let itemType = "domain"; // Mặc định là domain cho URL bị chặn
            // Cố gắng xác định nếu là email (ít khả khi URL bị chặn là email thuần túy)
            const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
            if (emailRegex.test(blockedUrl)) {
                itemType = "email";
            }

            chrome.runtime.sendMessage({
                action: "reportToBackend",
                data: {
                    report_type: `false_positive_${itemType}`,
                    value: blockedUrl.toLowerCase(),
                    source_url: blockedUrl,
                    context: `Reported as safe from warning page by user.`
                }
            }, function(response) {
                if (response && response.success) {
                    alert(`Đã gửi báo cáo trang "${blockedUrl}" là an toàn. Cảm ơn bạn! Thay đổi có thể mất một chút thời gian để cập nhật.`);
                    // Có thể tự động điều hướng người dùng hoặc cho họ lựa chọn
                    // window.location.href = blockedUrl;
                } else {
                    alert(`Gửi báo cáo không thành công. Lỗi: ${response ? response.error : 'Unknown error'}`);
                }
            });
        } else {
            alert("Không có URL để báo cáo.");
        }
    });

    proceedAnywayButton.addEventListener('click', function () {
        if (blockedUrl) {
            // Gửi thông điệp tới background script để thêm vào session whitelist
            chrome.runtime.sendMessage({
                action: "addToSessionWhitelist",
                url: blockedUrl
            }, function(response) {
                if (response && response.success) {
                    // Sau khi được background xác nhận, tiến hành điều hướng
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