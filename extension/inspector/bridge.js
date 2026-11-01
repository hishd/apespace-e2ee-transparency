// Runs next to hook.js in the extension's isolated world. Every second the hook
// publishes the media keys it knows; this forwards them to the background, which
// searches every HTTP request of this tab (page, workers) for them, and hands the
// results back to the hook's panel.

document.addEventListener('e2ee-inspector:keys', e => {
    chrome.runtime.sendMessage({ type: 'leak-status', keys: JSON.parse(e.detail) }, status => {
        if (!chrome.runtime.lastError && status) {
            document.dispatchEvent(new CustomEvent('e2ee-inspector:http', { detail: JSON.stringify(status) }));
        }
    });
});
