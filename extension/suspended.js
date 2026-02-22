function isSafeNavigationUrl(url) {
  if (!url || typeof url !== 'string') return false;
  try {
    const parsed = new URL(url);
    return ['http:', 'https:', 'file:', 'ftp:'].includes(parsed.protocol);
  } catch { return false; }
}

function isLocalFaviconUrl(url) {
  if (!url || typeof url !== 'string') return false;
  try {
    const parsed = new URL(url);
    return ['data:', 'chrome-extension:'].includes(parsed.protocol);
  } catch {
    return false;
  }
}

function hashFnv1a(input) {
  let hash = 0x811c9dc5;
  for (let i = 0; i < input.length; i += 1) {
    hash ^= input.charCodeAt(i);
    hash = Math.imul(hash, 0x01000193) >>> 0;
  }
  return hash >>> 0;
}

function mixSeed(seed) {
  let h = seed >>> 0;
  h ^= h >>> 16;
  h = Math.imul(h, 0x85ebca6b) >>> 0;
  h ^= h >>> 13;
  h = Math.imul(h, 0xc2b2ae35) >>> 0;
  h ^= h >>> 16;
  return h >>> 0;
}

function makePrng(seed) {
  let state = (seed >>> 0) || 1;
  return function nextRand() {
    state ^= state << 13;
    state >>>= 0;
    state ^= state >>> 17;
    state >>>= 0;
    state ^= state << 5;
    state >>>= 0;
    return state >>> 0;
  };
}

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function toHsl(h, s, l) {
  return `hsl(${h} ${s}% ${l}%)`;
}

function buildPalette(seed) {
  const bgHue = seed % 360;
  const bgSat = 25 + ((seed >>> 5) % 20);
  const bgLight = 18 + ((seed >>> 9) % 14);

  const fgHue = (bgHue + 100 + ((seed >>> 13) % 120)) % 360;
  const fgSat = 65 + ((seed >>> 17) % 20);
  let fgLight = 72 + ((seed >>> 21) % 16);

  const minDelta = 45;
  if (fgLight - bgLight < minDelta) {
    fgLight = clamp(bgLight + minDelta, 70, 92);
  }

  return {
    background: toHsl(bgHue, bgSat, bgLight),
    foreground: toHsl(fgHue, fgSat, fgLight),
  };
}

function buildMirroredCells(seed) {
  const nextRand = makePrng(seed);
  const cells = [];
  let count = 0;

  for (let y = 0; y < 5; y += 1) {
    for (let x = 0; x < 3; x += 1) {
      const on = ((nextRand() >>> 16) & 1) === 1;
      if (!on) {
        continue;
      }
      const mirrorX = 4 - x;
      cells.push([x, y]);
      count += 1;
      if (mirrorX !== x) {
        cells.push([mirrorX, y]);
        count += 1;
      }
    }
  }

  return { cells, count };
}

const MIN_CELL_COUNT = 6;
const MAX_CELL_COUNT = 19;
const MAX_DENSITY_ATTEMPTS = 4;

function normalizeCellDensity(seed) {
  let currentSeed = seed;
  for (let attempt = 0; attempt < MAX_DENSITY_ATTEMPTS; attempt += 1) {
    const result = buildMirroredCells(currentSeed);
    if (result.count >= MIN_CELL_COUNT && result.count <= MAX_CELL_COUNT) {
      return result.cells;
    }
    currentSeed = mixSeed(currentSeed ^ (attempt + 1));
  }
  const fallback = buildMirroredCells(mixSeed(seed ^ 0xdeadbeef));
  if (fallback.count >= MIN_CELL_COUNT && fallback.count <= MAX_CELL_COUNT) {
    return fallback.cells;
  }
  return [[2, 0], [1, 1], [3, 1], [0, 2], [4, 2], [1, 3], [3, 3], [2, 4]];
}

function buildIconSvg(patternSeed, colorSeed) {
  const cells = normalizeCellDensity(patternSeed);
  const palette = buildPalette(colorSeed);

  let cellRects = '';
  for (const [x, y] of cells) {
    const px = 2 + (x * 3);
    const py = 2 + (y * 3);
    cellRects += `<rect x='${px}' y='${py}' width='2' height='2' rx='0.4' fill='${palette.foreground}'/>`;
  }

  return `<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 16 16'><rect width='16' height='16' rx='2' fill='${palette.background}'/>${cellRects}</svg>`;
}

const fallbackIconCache = new Map();
const MAX_FALLBACK_ICON_CACHE_SIZE = 64;

function buildTokenFallbackIconDataUrl(sourceToken) {
  const raw = sourceToken || 'local-suspender-fallback';
  const tokenInput = raw.length > 256 ? raw.slice(0, 256) : raw;
  const cached = fallbackIconCache.get(tokenInput);
  if (cached) {
    return cached;
  }

  const hash = hashFnv1a(tokenInput);
  const svg = buildIconSvg(hash, mixSeed(hash));
  const dataUrl = `data:image/svg+xml,${encodeURIComponent(svg)}`;

  fallbackIconCache.set(tokenInput, dataUrl);
  if (fallbackIconCache.size > MAX_FALLBACK_ICON_CACHE_SIZE) {
    const oldestKey = fallbackIconCache.keys().next().value;
    fallbackIconCache.delete(oldestKey);
  }

  return dataUrl;
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

function applySuspendedFavicon(url) {
  if (!isLocalFaviconUrl(url)) {
    return;
  }
  let link = document.querySelector("link[rel~='icon']");
  if (!link) {
    link = document.createElement('link');
    link.type = 'image/x-icon';
    link.rel = 'icon';
    document.head.appendChild(link);
  }
  link.href = url;

  const logoEl = document.getElementById('siteLogo');
  if (logoEl) {
    logoEl.src = url;
  }
}

function applyInitialFavicon() {
  if (isLocalFaviconUrl(faviconParam)) {
    applySuspendedFavicon(faviconParam);
    return;
  }
  if (token) {
    applySuspendedFavicon(buildTokenFallbackIconDataUrl(token));
  }
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
      if (isLocalFaviconUrl(faviconSource)) {
        applySuspendedFavicon(faviconSource);
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

// Immediately render available info from URL params
if (titleParam) {
  document.title = titleParam;
  detailsEl.textContent = titleParam;
}
if (urlParam) {
  hintEl.textContent = `Original URL: ${urlParam}`;
}
applyInitialFavicon();

init();
