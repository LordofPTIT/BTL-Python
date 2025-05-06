const apiUrlInput = document.getElementById('api-url');
const updateIntervalInput = document.getElementById('update-interval');
const saveButton = document.getElementById('save-button');
const statusMessage = document.getElementById('status-message');
const testConnectionButton = document.getElementById('test-connection');
const testStatus = document.getElementById('test-status');

const CACHE_KEYS_OPTIONS = { // Renamed to avoid conflict if this script is ever merged
    API_BASE_URL: 'apiBaseUrl',
    CACHE_UPDATE_INTERVAL: 'cacheUpdateIntervalMinutes'
};
const DEFAULT_API_URL_OPTIONS = 'http://127.0.0.1:5001/api';
const DEFAULT_INTERVAL_OPTIONS = 60;

async function loadSettingsOptions() {
    try {
        const data = await chrome.storage.sync.get([CACHE_KEYS_OPTIONS.API_BASE_URL, CACHE_KEYS_OPTIONS.CACHE_UPDATE_INTERVAL]);
        apiUrlInput.value = data[CACHE_KEYS_OPTIONS.API_BASE_URL] || DEFAULT_API_URL_OPTIONS;
        updateIntervalInput.value = data[CACHE_KEYS_OPTIONS.CACHE_UPDATE_INTERVAL] || DEFAULT_INTERVAL_OPTIONS;
    } catch (error) {
        statusMessage.textContent = 'Lỗi tải cài đặt.'; statusMessage.className = 'status error';
        apiUrlInput.value = DEFAULT_API_URL_OPTIONS; updateIntervalInput.value = DEFAULT_INTERVAL_OPTIONS;
    }
}

async function saveSettingsOptions() {
    const apiUrl = apiUrlInput.value.trim().replace(/\/$/, '');
    const interval = parseInt(updateIntervalInput.value, 10);

    if (!apiUrl || !apiUrl.startsWith('http')) {
         statusMessage.textContent = 'Lỗi: URL API không hợp lệ.'; statusMessage.className = 'status error'; return;
    }
    if (isNaN(interval) || interval < 5 || interval > 1440) {
        statusMessage.textContent = 'Lỗi: Khoảng thời gian cập nhật phải từ 5-1440 phút.'; statusMessage.className = 'status error'; return;
    }

    try {
        await chrome.storage.sync.set({
            [CACHE_KEYS_OPTIONS.API_BASE_URL]: apiUrl,
            [CACHE_KEYS_OPTIONS.CACHE_UPDATE_INTERVAL]: interval
        });
        statusMessage.textContent = 'Cài đặt đã lưu!'; statusMessage.className = 'status success';
        if (chrome.runtime && chrome.runtime.sendMessage) {
            chrome.runtime.sendMessage({ action: 'settingsUpdated' }, response => {
                if (chrome.runtime.lastError) console.warn("Options: BG script not receiving settings update:", chrome.runtime.lastError.message);
            });
        }
        setTimeout(() => { statusMessage.textContent = ''; statusMessage.className = 'status'; }, 3000);
    } catch (error) {
        statusMessage.textContent = `Lỗi lưu cài đặt: ${error.message}`; statusMessage.className = 'status error';
    }
}

async function testApiConnectionOptions() {
    const apiUrl = apiUrlInput.value.trim().replace(/\/$/, '');
    if (!apiUrl || !apiUrl.startsWith('http')) {
        testStatus.textContent = 'Lỗi: URL API không hợp lệ.'; testStatus.className = 'status error'; return;
    }
    testStatus.textContent = 'Đang kiểm tra...'; testStatus.className = 'status info';
    testConnectionButton.disabled = true;
    const statusUrl = `${apiUrl}/status`;

    try {
        const response = await fetch(statusUrl, { method: 'GET', mode: 'cors' });
        if (!response.ok) throw new Error(`Lỗi HTTP ${response.status}: ${response.statusText}`);
        const data = await response.json();
        if (data && data.status === 'ok') {
            testStatus.textContent = `Kết nối OK! (DB: ${data.database_status || 'N/A'}, URI: ${data.database_uri_used || 'N/A'})`;
            testStatus.className = 'status success';
        } else {
             testStatus.textContent = `Phản hồi API không mong đợi.`; testStatus.className = 'status warning';
        }
    } catch (error) {
        testStatus.textContent = `Kết nối thất bại: ${error.message}. Máy chủ backend có đang chạy?`;
        testStatus.className = 'status error';
    } finally {
        testConnectionButton.disabled = false;
    }
}

document.addEventListener('DOMContentLoaded', loadSettingsOptions);
saveButton.addEventListener('click', saveSettingsOptions);
testConnectionButton.addEventListener('click', testApiConnectionOptions);