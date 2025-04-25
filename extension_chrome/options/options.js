document.addEventListener('DOMContentLoaded', () => {
    const apiUrlInput = document.getElementById('api-url');
    const cacheExpiryInput = document.getElementById('cache-expiry');
    const whitelistItemsTextarea = document.getElementById('whitelist-items'); // Added
    const saveButton = document.getElementById('save-button');
    const statusElement = document.getElementById('save-status');

    const DEFAULT_CACHE = 60;
    const MIN_CACHE = 5;
    const MAX_CACHE = 1440;

    // --- Load Settings ---
    function loadSettings() {
        // Get settings from chrome.storage.sync
        chrome.storage.sync.get(['apiUrl', 'cacheExpiryMinutes', 'whitelistItems'], (settings) => {
            if (chrome.runtime.lastError) {
                console.error("Options: Error loading settings:", chrome.runtime.lastError);
                statusElement.textContent = 'Lỗi tải cài đặt.';
                statusElement.className = 'error';
                return;
            }

            // API URL: Use saved value or try to get default from background (less reliable) or hardcode
            // For simplicity, we'll just use the saved value or empty string. Background default is handled there.
            apiUrlInput.value = settings.apiUrl || '';

            // Cache Expiry
            cacheExpiryInput.value = settings.cacheExpiryMinutes || DEFAULT_CACHE;

             // Whitelist Items (stored as an array, display as newline-separated string)
             whitelistItemsTextarea.value = (settings.whitelistItems || []).join('\n');

            console.log('Options: Settings loaded', settings);
        });
    }

    // --- Save Settings ---
    function saveSettings() {
        statusElement.textContent = 'Đang lưu...';
        statusElement.className = '';

        const apiUrl = apiUrlInput.value.trim();
        let cacheExpiry = parseInt(cacheExpiryInput.value, 10);
         // Whitelist: split by newline, trim, filter empty lines, keep unique
         const whitelistItems = [
             ...new Set(
                 whitelistItemsTextarea.value
                     .split('\n')
                     .map(item => item.trim().toLowerCase()) // Normalize
                     .filter(Boolean) // Remove empty lines
             )
         ];


        // --- Validation ---
        let isValid = true;
        let errors = [];

        // Validate API URL (must be HTTPS for production)
        if (!apiUrl) {
             errors.push('Địa chỉ API không được để trống.');
             isValid = false;
        } else if (!apiUrl.startsWith('https://')) {
             // Allow http only for localhost during development? More complex. Force HTTPS for now.
             errors.push('Địa chỉ API phải bắt đầu bằng https://.');
             isValid = false;
        } else {
             try { new URL(apiUrl); } catch (_) { errors.push('Địa chỉ API không hợp lệ.'); isValid = false; }
        }

        // Validate Cache Expiry
        if (isNaN(cacheExpiry) || cacheExpiry < MIN_CACHE || cacheExpiry > MAX_CACHE) {
            errors.push(`Tần suất làm mới cache phải từ ${MIN_CACHE} đến ${MAX_CACHE} phút.`);
            cacheExpiry = DEFAULT_CACHE; // Reset to default if invalid
            cacheExpiryInput.value = DEFAULT_CACHE;
            isValid = false; // Consider if invalid cache time should prevent saving other settings
        }

         // Validate Whitelist items (basic format check if needed)
         // For now, just save the cleaned list


        // --- Save if Valid ---
        if (isValid) {
            chrome.storage.sync.set({
                apiUrl: apiUrl,
                cacheExpiryMinutes: cacheExpiry,
                whitelistItems: whitelistItems // Save the cleaned array
            }, () => {
                if (chrome.runtime.lastError) {
                    console.error("Options: Error saving settings:", chrome.runtime.lastError);
                    statusElement.textContent = 'Lỗi lưu cài đặt: ' + chrome.runtime.lastError.message;
                    statusElement.className = 'error';
                } else {
                    console.log('Options: Settings saved successfully.');
                    statusElement.textContent = 'Đã lưu cài đặt!';
                    statusElement.className = 'success';
                    // Notify background script that settings have changed
                    chrome.runtime.sendMessage({ action: 'settingsUpdated' }, (response) => {
                        if (chrome.runtime.lastError) {
                            console.warn("Options: Could not notify background of settings update.", chrome.runtime.lastError.message);
                        } else {
                            console.log("Options: Background notified of settings update.");
                        }
                    });
                    setTimeout(() => { statusElement.textContent = ''; statusElement.className = ''; }, 3000);
                }
            });
        } else {
            statusElement.textContent = 'Lỗi: ' + errors.join(' ');
            statusElement.className = 'error';
        }
    }

    // --- Event Listeners ---
    saveButton.addEventListener('click', saveSettings);

    // --- Initial Load ---
    loadSettings();
});