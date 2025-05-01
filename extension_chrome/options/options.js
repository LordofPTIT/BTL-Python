document.addEventListener('DOMContentLoaded', () => {
    const apiUrlInput = document.getElementById('api-url');
    const cacheExpiryInput = document.getElementById('cache-expiry');
    const whitelistItemsTextarea = document.getElementById('whitelist-items');
    const saveButton = document.getElementById('save-button');
    const statusElement = document.getElementById('save-status');

    const DEFAULT_CACHE = 60;
    const MIN_CACHE = 5;
    const MAX_CACHE = 1440;


    function loadSettings() {

        chrome.storage.sync.get(['apiUrl', 'cacheExpiryMinutes', 'whitelistItems'], (settings) => {
            if (chrome.runtime.lastError) {
                console.error("Options: Error loading settings:", chrome.runtime.lastError);
                statusElement.textContent = 'Lỗi tải cài đặt.';
                statusElement.className = 'error';
                return;
            }


            apiUrlInput.value = settings.apiUrl || '';


            cacheExpiryInput.value = settings.cacheExpiryMinutes || DEFAULT_CACHE;


             whitelistItemsTextarea.value = (settings.whitelistItems || []).join('\n');

            console.log('Options: Settings loaded', settings);
        });
    }


    function saveSettings() {
        statusElement.textContent = 'Đang lưu...';
        statusElement.className = '';

        const apiUrl = apiUrlInput.value.trim();
        let cacheExpiry = parseInt(cacheExpiryInput.value, 10);

         const whitelistItems = [
             ...new Set(
                 whitelistItemsTextarea.value
                     .split('\n')
                     .map(item => item.trim().toLowerCase())
                     .filter(Boolean)
             )
         ];



        let isValid = true;
        let errors = [];


        if (!apiUrl) {
             errors.push('Địa chỉ API không được để trống.');
             isValid = false;
        } else if (!apiUrl.startsWith('https://')) {

             errors.push('Địa chỉ API phải bắt đầu bằng https://.');
             isValid = false;
        } else {
             try { new URL(apiUrl); } catch (_) { errors.push('Địa chỉ API không hợp lệ.'); isValid = false; }
        }


        if (isNaN(cacheExpiry) || cacheExpiry < MIN_CACHE || cacheExpiry > MAX_CACHE) {
            errors.push(`Tần suất làm mới cache phải từ ${MIN_CACHE} đến ${MAX_CACHE} phút.`);
            cacheExpiry = DEFAULT_CACHE;
            cacheExpiryInput.value = DEFAULT_CACHE;
            isValid = false;
        }


        if (isValid) {
            chrome.storage.sync.set({
                apiUrl: apiUrl,
                cacheExpiryMinutes: cacheExpiry,
                whitelistItems: whitelistItems
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


    saveButton.addEventListener('click', saveSettings);


    loadSettings();
});