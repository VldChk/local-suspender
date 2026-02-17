function isSafeNavigationUrl(url) {
  if (!url || typeof url !== 'string') return false;
  try {
    const parsed = new URL(url);
    return ['http:', 'https:', 'file:', 'ftp:'].includes(parsed.protocol);
  } catch { return false; }
}

function isSafeFaviconUrl(url) {
  if (!url || typeof url !== 'string') return false;
  try {
    const parsed = new URL(url);
    return ['http:', 'https:', 'data:', 'chrome:', 'chrome-extension:'].includes(parsed.protocol);
  } catch { return false; }
}

const params = new URLSearchParams(window.location.search);
const token = params.get('token');
const urlParam = params.get('url');
const titleParam = params.get('title');
const faviconParam = params.get('favicon');

const detailsEl = document.getElementById('details');
const hintEl = document.getElementById('hint');
const wakeButton = document.getElementById('wake');

let tabId = null;
let tabInfo = null;
let backgroundLocked = false;

// Immediately render available info from URL params
if (titleParam) {
  document.title = titleParam;
  detailsEl.textContent = titleParam;
}
if (urlParam) {
  hintEl.textContent = `Original URL: ${urlParam}`;
}
// Try to apply grayscale to the tab icon
if (faviconParam) {
  updateFavicon(faviconParam);
}


function updateFavicon(url) {
  if (!isSafeFaviconUrl(url)) return;
  const link = document.querySelector("link[rel~='icon']") || document.createElement('link');
  link.type = 'image/x-icon';
  link.rel = 'icon';
  link.href = url;
  document.getElementsByTagName('head')[0].appendChild(link);

  const logoEl = document.getElementById('siteLogo');
  if (logoEl) {
    logoEl.src = url;
  }

  getGrayscaleFavicon(url).then(grayUrl => {
    if (grayUrl) {
      link.href = grayUrl;
    }
  }).catch(err => console.warn('Failed to generate grayscale favicon', err));
}

function getGrayscaleFavicon(url) {
  return new Promise((resolve) => {
    const img = new Image();
    img.crossOrigin = 'Anonymous';
    img.onload = () => {
      try {
        const canvas = document.createElement('canvas');
        const size = 32; // Standard favicon size
        canvas.width = size;
        canvas.height = size;
        const ctx = canvas.getContext('2d');
        ctx.filter = 'grayscale(100%) opacity(0.6)';
        ctx.drawImage(img, 0, 0, size, size);
        resolve(canvas.toDataURL('image/png'));
      } catch (e) {
        resolve(null);
      }
    };
    img.onerror = () => resolve(null);
    img.src = url;
  });
}

function sendMessage(type, payload = {}) {
  return chrome.runtime.sendMessage({ type, ...payload }).catch(err => {
    console.warn('Message failed:', type, err);
    return null;
  });
}

async function init() {
  if (!token) {
    detailsEl.textContent = 'Missing suspension metadata.';
    wakeButton.disabled = true;
    return;
  }

  chrome.tabs.getCurrent(async tab => {
    tabId = tab?.id ?? null;
    await loadInfo();
  });
}

async function loadInfo() {
  const payload = { token };
  if (typeof tabId === 'number') {
    payload.tabId = tabId;
  }

  try {
    const response = await sendMessage('SUSPENDED_VIEW_INFO', payload);

    if (response && response.locked) {
      backgroundLocked = true;
      const targetUrl = tabInfo?.url || urlParam;
      if (targetUrl && isSafeNavigationUrl(targetUrl)) {
        wakeButton.disabled = false;
        wakeButton.textContent = 'Open original URL';
        if (response.reason === 'corrupt-state') {
          detailsEl.textContent = 'State is corrupted. Reset from options, or open the original URL now.';
        } else {
          detailsEl.textContent = 'Suspension log is locked. Unlock in options, or open the original URL now.';
        }
      } else {
        detailsEl.textContent = response.reason === 'corrupt-state'
          ? 'State is corrupted. Reset encryption from options to recover.'
          : 'Suspension log is encrypted. Unlock it from the options page to resume this tab.';
        wakeButton.disabled = true;
      }
      return;
    }

    if (response && response.found && response.info) {
      backgroundLocked = false;
      tabInfo = response.info;
      detailsEl.textContent = `${tabInfo.title || tabInfo.url}`;
      hintEl.textContent = `Original URL: ${tabInfo.url}`;
      document.title = tabInfo.title || 'Tab suspended';

      const faviconSource = tabInfo.favIconUrl;
      if (faviconSource) {
        updateFavicon(faviconSource);
      }
      return;
    }
  } catch (err) {
    console.warn('Failed to fetch info from background', err);
  }

  // Fallback to URL params if background request failed or returned no info
  if (urlParam) {
    tabInfo = {
      url: urlParam,
      title: titleParam || urlParam,
    };
    // UI is already set from params at the top, but ensure consistency
    detailsEl.textContent = tabInfo.title;
    hintEl.textContent = `Original URL: ${tabInfo.url}`;
  } else {
    detailsEl.textContent = 'Suspension metadata missing.';
    wakeButton.disabled = true;
  }
}

wakeButton.addEventListener('click', async () => {
  wakeButton.disabled = true;
  wakeButton.textContent = 'Unsuspending...';
  const targetUrl = tabInfo?.url || urlParam;

  if (backgroundLocked) {
    if (targetUrl && isSafeNavigationUrl(targetUrl)) {
      window.location.href = targetUrl;
      return;
    }
    wakeButton.disabled = false;
    wakeButton.textContent = 'Retry unsuspend';
    detailsEl.textContent = 'Unlock from options before retrying.';
    return;
  }

  // Try to unsuspend via background script first
  if (typeof tabId === 'number') {
    try {
      const response = await sendMessage('UNSUSPEND_TOKEN', { token, tabId });
      if (response && response.ok) {
        detailsEl.textContent = 'Waking up...';
        return;
      }
      if (response?.error === 'expired') {
        wakeButton.disabled = false;
        wakeButton.textContent = 'Open original URL';
        detailsEl.textContent = 'This suspended link expired. Opening original URL instead.';
      } else if (response?.error === 'used') {
        wakeButton.disabled = false;
        wakeButton.textContent = 'Open original URL';
        detailsEl.textContent = 'This suspended link was already used. Opening original URL instead.';
      } else if (response?.error === 'invalid-token') {
        wakeButton.disabled = false;
        wakeButton.textContent = 'Open original URL';
        detailsEl.textContent = 'Unable to validate this suspended tab. Opening original URL instead.';
      }
    } catch (err) {
      console.warn('Background unsuspend failed', err);
    }
  }

  // Fallback: navigate current tab to original URL
  if (targetUrl && isSafeNavigationUrl(targetUrl)) {
    window.location.href = targetUrl;
  } else {
    wakeButton.disabled = false;
    wakeButton.textContent = 'Retry unsuspend';
    detailsEl.textContent = targetUrl
      ? 'Cannot navigate to this URL for safety reasons.'
      : 'Failed to unsuspend automatically. Try reloading the tab.';
  }
});

init();
