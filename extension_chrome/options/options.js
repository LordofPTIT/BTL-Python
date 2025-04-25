const apiUrlInput = document.getElementById('api-url');
const cacheExpiryInput = document.getElementById('cache-expiry');
const saveButton = document.getElementById('save-button');
const statusElement = document.getElementById('save-status');

// Load current settings when the page opens
document.addEventListener('DOMContentLoaded', () => {
    chrome.storage.sync.get(['apiUrl', 'cacheExpiryMinutes'], (settings) => {
        if (settings.apiUrl) {
            apiUrlInput.value = settings.apiUrl;
        }
         if (settings.cacheExpiryMinutes) {
            cacheExpiryInput.value = settings.cacheExpiryMinutes;
        }
        // Load defaults if nothing is set (optional, could be handled by background)
        // else {
             // apiUrlInput.placeholder = 'DEFAULT_API_URL'; // Set placeholder to default
        // }
    });
});

// Save settings when the button is clicked
saveButton.addEventListener('click', () => {
    const apiUrl = apiUrlInput.value.trim();
    const cacheExpiry = parseInt(cacheExpiryInput.value, 10);

    // Basic validation
    let isValid = true;
    statusElement.textContent = '';
    statusElement.className = '';

    if (!apiUrl || !apiUrl.startsWith('http')) {
         // Consider more robust URL validation
         statusElement.textContent = 'Lỗi: Vui lòng nhập URL API hợp lệ.';
         statusElement.className = 'error';
         isValid = false;
    }
     if (isNaN(cacheExpiry) || cacheExpiry < 5 || cacheExpiry > 1440) { // Example range
          statusElement.textContent = 'Lỗi: Thời gian làm mới cache phải từ 5 đến 1440 phút.';
         statusElement.className = 'error';
          isValid = false;
     }


    if (isValid) {
        chrome.storage.sync.set({
            apiUrl: apiUrl,
            cacheExpiryMinutes: cacheExpiry
        }, () => {
            if (chrome.runtime.lastError) {
                 statusElement.textContent = 'Lỗi khi lưu: ' + chrome.runtime.lastError.message;
                 statusElement.className = 'error';
            } else {
                statusElement.textContent = 'Đã lưu cài đặt!';
                statusElement.className = 'success';
                setTimeout(() => { statusElement.textContent = ''; statusElement.className = ''; }, 3000); // Clear status after 3s
                 // Optional: Notify background script about settings change if needed immediately
                 // chrome.runtime.sendMessage({ action: 'settingsUpdated' });
            }
        });
    }
});