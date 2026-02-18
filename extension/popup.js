const statusEl = document.getElementById('status');
const tabsListEl = document.getElementById('tabs');
const tabsHeaderEl = document.getElementById('tabsHeader');
const tabsCountEl = document.getElementById('tabsCount');
const suspendedContextEl = document.getElementById('suspendedContext');
const actionsGroupEl = document.getElementById('actionsGroup');
const unsuspendCurrentBtn = document.getElementById('unsuspendCurrent');
const neverSuspendSiteBtn = document.getElementById('neverSuspendSite');
const unsuspendAllBtn = document.getElementById('unsuspendAll');

let currentSuspendedTabId = null;
let currentSuspendedUrl = null;
let lastRenderedStateHash = '';
let refreshTimer = null;

function scheduleRefresh(message) {
  if (refreshTimer) {
    clearTimeout(refreshTimer);
  }
  refreshTimer = setTimeout(() => {
    refreshTimer = null;
    refreshState(message);
  }, 150);
}

async function sendMessage(type, payload = {}) {
  try {
    return await chrome.runtime.sendMessage({ type, ...payload });
  } catch (err) {
    console.warn('Message failed:', type, err);
    return null;
  }
}

function interpretActionResult(response) {
  if (!response || typeof response !== 'object') {
    return { ok: false, skipped: null, locked: false, reason: null, error: 'unknown' };
  }
  return {
    ok: response.ok === true,
    skipped: typeof response.skipped === 'string' ? response.skipped : null,
    locked: response.locked === true || response.skipped === 'locked' || response.error === 'locked',
    reason: typeof response.reason === 'string' ? response.reason : null,
    error: typeof response.error === 'string' ? response.error : null,
  };
}

function getActionFailureMessage(defaultMessage, interpreted) {
  if (interpreted.locked || interpreted.reason === 'corrupt-state') {
    return interpreted.reason === 'corrupt-state'
      ? 'State is corrupted. Reset encryption from options.'
      : 'State locked. Unlock from options to continue.';
  }
  return defaultMessage;
}

function presentActionFailure(defaultMessage, interpreted) {
  const message = getActionFailureMessage(defaultMessage, interpreted);
  if (interpreted.locked || interpreted.reason === 'corrupt-state') {
    scheduleRefresh(message);
    return;
  }
  statusEl.textContent = message;
}

// --- Event Listeners ---

document.getElementById('suspendCurrent').addEventListener('click', async () => {
  try {
    const interpreted = interpretActionResult(await sendMessage('SUSPEND_CURRENT'));
    if (interpreted.skipped === 'incognito') {
      scheduleRefresh('Skipped: incognito tabs are never suspended.');
      return;
    }
    if (interpreted.skipped === 'unsafe-url') {
      scheduleRefresh('Skipped: this tab URL cannot be suspended.');
      return;
    }
    if (interpreted.skipped === 'policy-excluded') {
      scheduleRefresh('Skipped: no suspendable current tab in this window.');
      return;
    }
    if (interpreted.ok === true) {
      scheduleRefresh('Suspended current tab.');
      return;
    }
    presentActionFailure('Failed to suspend tab.', interpreted);
  } catch (err) {
    statusEl.textContent = 'Failed to suspend tab.';
  }
});

document.getElementById('suspendInactive').addEventListener('click', async () => {
  try {
    const interpreted = interpretActionResult(await sendMessage('SUSPEND_INACTIVE'));
    if (interpreted.ok === true) {
      scheduleRefresh('Suspended inactive tabs.');
      return;
    }
    presentActionFailure('Failed to suspend inactive tabs.', interpreted);
  } catch (err) {
    statusEl.textContent = 'Failed to suspend inactive tabs.';
  }
});

document.getElementById('unsuspendAll').addEventListener('click', async () => {
  try {
    const interpreted = interpretActionResult(await sendMessage('RESUME_ALL'));
    if (interpreted.ok === true) {
      scheduleRefresh('Unsuspended all tabs.');
      return;
    }
    presentActionFailure('Failed to unsuspend tabs.', interpreted);
  } catch (err) {
    statusEl.textContent = 'Failed to unsuspend tabs.';
  }
});

document.getElementById('openOptions').addEventListener('click', (e) => {
  e.preventDefault();
  chrome.runtime.openOptionsPage();
});

tabsHeaderEl.addEventListener('click', () => {
  const icon = tabsHeaderEl.querySelector('.toggle-icon');
  tabsListEl.classList.toggle('hidden');
  icon.textContent = tabsListEl.classList.contains('hidden') ? '+' : '-';
});

tabsListEl.addEventListener('click', async (event) => {
  const row = event.target.closest('li.tab-item');
  if (!row || !tabsListEl.contains(row)) {
    return;
  }
  const tabId = Number(row.dataset.tabId);
  if (!Number.isInteger(tabId)) {
    return;
  }
  const windowId = Number(row.dataset.windowId);
  const safeWindowId = Number.isInteger(windowId) && windowId > 0 ? windowId : null;
  const unsuspendBtn = event.target.closest('button[data-action="unsuspend"]');
  if (unsuspendBtn) {
    event.stopPropagation();
    await handleUnsuspend(tabId, safeWindowId);
    return;
  }
  await focusTab(tabId, safeWindowId, row);
});

if (unsuspendCurrentBtn) {
  unsuspendCurrentBtn.addEventListener('click', async () => {
    if (currentSuspendedTabId) {
      const interpreted = interpretActionResult(
        await sendMessage('RESUME_TAB', { tabId: currentSuspendedTabId })
      );
      if (interpreted.ok !== true) {
        presentActionFailure('Failed to unsuspend tab.', interpreted);
        return;
      }
      window.close();
    }
  });
}

if (neverSuspendSiteBtn) {
  neverSuspendSiteBtn.addEventListener('click', async () => {
    if (currentSuspendedUrl) {
      const settings = await sendMessage('GET_SETTINGS');
      if (!settings || typeof settings !== 'object') {
        statusEl.textContent = 'Unable to load settings right now.';
        return;
      }
      let domain;
      try {
        const urlObj = new URL(currentSuspendedUrl);
        domain = urlObj.hostname.replace(/^www\./, '');
      } catch {
        statusEl.textContent = 'Cannot whitelist: invalid URL.';
        return;
      }

      const newWhitelist = Array.from(new Set([...(settings.whitelist || []), domain]));
      const payload = { ...settings, whitelist: newWhitelist };
      const saveResult = await sendMessage('SAVE_SETTINGS', { payload });
      if (!saveResult) {
        statusEl.textContent = 'Failed to save whitelist changes.';
        return;
      }
      scheduleRefresh(`Added "${domain}" to whitelist and unsuspended.`);
      tabsHeaderEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
      const confirmation = document.createElement('div');
      confirmation.className = 'status-message';
      confirmation.textContent = `Whitelisted: ${domain}`;
      statusEl.parentElement?.insertBefore(confirmation, statusEl.nextSibling);
      setTimeout(() => confirmation.remove(), 2000);
      // Auto-unsuspend is handled by background on SAVE_SETTINGS
      setTimeout(() => window.close(), 1000);
    }
  });
}

// --- Helpers ---

function formatTimestamp(ts) {
  if (!ts) return '';
  const date = new Date(ts);
  return date.toLocaleTimeString();
}

function computeEntriesHash(entries) {
  let hash = `${entries.length}|`;
  for (const [tabId, info] of entries) {
    hash += `${tabId}:${info.suspendedAt || 0}:${info.method || ''}:${info.url || ''}|`;
  }
  return hash;
}

async function focusTab(tabId, windowId, row) {
  try {
    await chrome.tabs.update(tabId, { active: true });
    if (windowId) {
      await chrome.windows.update(windowId, { focused: true });
    }
  } catch (err) {
    statusEl.textContent = 'Tab no longer exists. Removing from list.';
    row?.remove();
  }
}

async function handleUnsuspend(tabId, windowId) {
  try {
    const interpreted = interpretActionResult(await sendMessage('RESUME_TAB', { tabId }));
    if (interpreted.ok !== true) {
      presentActionFailure('Failed to unsuspend tab.', interpreted);
      return;
    }
    await chrome.tabs.update(tabId, { active: true });
    if (windowId) {
      await chrome.windows.update(windowId, { focused: true });
    }
    scheduleRefresh('Unsuspended tab.');
  } catch (err) {
    statusEl.textContent = 'Failed to unsuspend tab.';
  }
}

function renderTabList(entries) {
  const fragment = document.createDocumentFragment();
  for (const [tabId, info] of entries) {
    const li = document.createElement('li');
    li.className = 'tab-item';
    li.dataset.tabId = tabId;
    if (Number.isInteger(info.windowId)) {
      li.dataset.windowId = String(info.windowId);
    }

    const contentDiv = document.createElement('div');
    contentDiv.className = 'tab-content';
    contentDiv.title = 'Click to switch to this tab';

    const titleSpan = document.createElement('span');
    titleSpan.className = 'tab-title';
    titleSpan.textContent = info.title || info.url;

    const metaSpan = document.createElement('span');
    metaSpan.className = 'tab-meta';
    metaSpan.textContent = formatTimestamp(info.suspendedAt);

    contentDiv.appendChild(titleSpan);
    contentDiv.appendChild(metaSpan);

    const actionsDiv = document.createElement('div');
    actionsDiv.className = 'tab-actions';

    const unsuspendBtn = document.createElement('button');
    unsuspendBtn.className = 'btn-sm';
    unsuspendBtn.dataset.action = 'unsuspend';
    unsuspendBtn.textContent = 'Unsuspend';

    actionsDiv.appendChild(unsuspendBtn);
    li.appendChild(contentDiv);
    li.appendChild(actionsDiv);
    fragment.appendChild(li);
  }
  tabsListEl.replaceChildren(fragment);
}

async function checkActiveTabContext() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) return;

    // Check if it's a suspended page
    if (tab.url && tab.url.startsWith(chrome.runtime.getURL('suspended.html'))) {
      const urlObj = new URL(tab.url);
      const originalUrl = urlObj.searchParams.get('url');
      if (originalUrl) {
        currentSuspendedTabId = tab.id;
        currentSuspendedUrl = originalUrl;
        suspendedContextEl.classList.remove('hidden');
        actionsGroupEl?.classList.add('hidden');
        unsuspendAllBtn?.classList.add('hidden');

        // Disable suspend buttons since it's already suspended
        document.getElementById('suspendCurrent').disabled = true;
        document.getElementById('suspendInactive').disabled = true;
        return;
      }
    }
    suspendedContextEl.classList.add('hidden');
    actionsGroupEl?.classList.remove('hidden');
    unsuspendAllBtn?.classList.remove('hidden');
    document.getElementById('suspendCurrent').disabled = false;
    document.getElementById('suspendInactive').disabled = false;
  } catch (err) {
    console.warn('Failed to query active tab context', err);
  }
}

async function refreshState(message) {
  const response = await sendMessage('GET_STATE');
  statusEl.textContent = message || '';

  if (!response) {
    tabsListEl.replaceChildren();
    lastRenderedStateHash = '';
    statusEl.textContent = 'Unable to reach background service.';
    return;
  }

  if (response.locked) {
    tabsListEl.replaceChildren();
    lastRenderedStateHash = '';
    statusEl.textContent = response.reason === 'corrupt-state'
      ? 'State is corrupted. Reset encryption from options.'
      : 'State locked. Unlock from options to view suspended tabs.';
    return;
  }

  const entries = Object.entries(response.state?.suspendedTabs || {}).sort(
    (a, b) => (b[1].suspendedAt || 0) - (a[1].suspendedAt || 0)
  );

  tabsCountEl.textContent = `${entries.length} suspended tabs`;
  tabsHeaderEl.querySelector('.toggle-icon').textContent = tabsListEl.classList.contains('hidden') ? '+' : '-';

  if (!entries.length) {
    lastRenderedStateHash = 'empty';
    tabsListEl.replaceChildren();
    const li = document.createElement('li');
    li.textContent = 'No suspended tabs.';
    tabsListEl.appendChild(li);
    return;
  }
  const nextHash = computeEntriesHash(entries);
  if (nextHash === lastRenderedStateHash) {
    return;
  }
  lastRenderedStateHash = nextHash;
  renderTabList(entries);
}

// --- Init ---

(async () => {
  try {
    await checkActiveTabContext();
    await refreshState();
  } catch (err) {
    console.warn('Popup initialization failed', err);
    statusEl.textContent = 'Failed to initialize. Try reopening the popup.';
  }
})();
