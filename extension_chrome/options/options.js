const apiUrlInput = document.getElementById('api-url');
const updateIntervalInput = document.getElementById('update-interval');
const saveButton = document.getElementById('save-button');
const statusMessage = document.getElementById('status-message');
const testConnectionButton = document.getElementById('test-connection');
const testStatus = document.getElementById('test-status');

const CACHE_KEYS = {
    API_BASE_URL: 'apiBaseUrl',
    CACHE_UPDATE_INTERVAL: 'cacheUpdateIntervalMinutes'
};
// CHANGE: Reflect the new local default
const DEFAULT_API_URL = 'http://127.0.0.1:5001/api';
const DEFAULT_INTERVAL = 60;

// Load saved settings on page load
async function loadSettings() {
    try {
        const data = await chrome.storage.sync.get([CACHE_KEYS.API_BASE_URL, CACHE_KEYS.CACHE_UPDATE_INTERVAL]);
        apiUrlInput.value = data[CACHE_KEYS.API_BASE_URL] || DEFAULT_API_URL;
        updateIntervalInput.value = data[CACHE_KEYS.CACHE_UPDATE_INTERVAL] || DEFAULT_INTERVAL;
        console.log('Options: Settings loaded.', data);
    } catch (error) {
        console.error('Options: Error loading settings:', error);
        statusMessage.textContent = 'Lỗi tải cài đặt.';
        statusMessage.className = 'status error';
        // Set defaults if loading fails
        apiUrlInput.value = DEFAULT_API_URL;
        updateIntervalInput.value = DEFAULT_INTERVAL;
    }
}

// Save settings
async function saveSettings() {
    const apiUrl = apiUrlInput.value.trim().replace(/\/$/, ''); // Remove trailing slash
    const interval = parseInt(updateIntervalInput.value, 10);

    if (!apiUrl || !apiUrl.startsWith('http')) {
         statusMessage.textContent = 'Lỗi: Vui lòng nhập URL API hợp lệ (bắt đầu bằng http hoặc https).';
         statusMessage.className = 'status error';
         return;
    }

    if (isNaN(interval) || interval < 5 || interval > 1440) {
        statusMessage.textContent = 'Lỗi: Khoảng thời gian cập nhật phải từ 5 đến 1440 phút.';
        statusMessage.className = 'status error';
        return;
    }

    try {
        await chrome.storage.sync.set({
            [CACHE_KEYS.API_BASE_URL]: apiUrl,
            [CACHE_KEYS.CACHE_UPDATE_INTERVAL]: interval
        });
        statusMessage.textContent = 'Cài đặt đã được lưu thành công!';
        statusMessage.className = 'status success';
        console.log('Options: Settings saved.', { apiUrl, interval });

        // Notify background script about the changes
        chrome.runtime.sendMessage({ action: 'settingsUpdated' }, (response) => {
             if (chrome.runtime.lastError) {
                  console.warn("Options: Could not send settings update message to background.", chrome.runtime.lastError.message);
             } else {
                  console.log("Options: Sent settings update notification to background.");
             }
        });


        setTimeout(() => { statusMessage.textContent = ''; statusMessage.className = 'status'; }, 3000);
    } catch (error) {
        console.error('Options: Error saving settings:', error);
        statusMessage.textContent = `Lỗi lưu cài đặt: ${error.message}`;
        statusMessage.className = 'status error';
    }
}

// Test API Connection
async function testApiConnection() {
    const apiUrl = apiUrlInput.value.trim().replace(/\/$/, '');
    if (!apiUrl || !apiUrl.startsWith('http')) {
        testStatus.textContent = 'Lỗi: URL API không hợp lệ.';
        testStatus.className = 'status error';
        return;
    }

    testStatus.textContent = 'Đang kiểm tra kết nối...';
    testStatus.className = 'status info';
    testConnectionButton.disabled = true;

    // Use the /api/status endpoint which should be defined in app.py
    const statusUrl = `${apiUrl}/status`;

    try {
        const response = await fetch(statusUrl, { method: 'GET', mode: 'cors' }); // mode: 'cors' is important

        if (!response.ok) {
            throw new Error(`Lỗi HTTP ${response.status}: ${response.statusText}`);
        }

        const data = await response.json();

        if (data && data.status === 'ok') {
            testStatus.textContent = `Kết nối thành công! (DB: ${data.database_status || 'unknown'})`;
            testStatus.className = 'status success';
        } else {
             testStatus.textContent = `Kết nối thành công nhưng phản hồi API không mong đợi.`;
             testStatus.className = 'status warning';
             console.warn("Options: API Status response unexpected:", data);
        }

    } catch (error) {
        console.error('Options: API connection test failed:', error);
        testStatus.textContent = `Kết nối thất bại: ${error.message}. Máy chủ backend có đang chạy không?`;
        testStatus.className = 'status error';
    } finally {
        testConnectionButton.disabled = false;
    }
}


// Event Listeners
document.addEventListener('DOMContentLoaded', loadSettings);
saveButton.addEventListener('click', saveSettings);
testConnectionButton.addEventListener('click', testApiConnection);