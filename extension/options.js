const form = document.getElementById('settingsForm');
const statusEl = document.getElementById('status');
const autoMinutesEl = document.getElementById('autoMinutes');
const excludeActiveEl = document.getElementById('excludeActive');
const excludePinnedEl = document.getElementById('excludePinned');
const excludeAudibleEl = document.getElementById('excludeAudible');
const whitelistEl = document.getElementById('whitelist');
const unsuspendMethodEl = document.getElementById('unsuspendMethod');
const passphraseEl = document.getElementById('passphrase');
const cloudBackupEl = document.getElementById('cloudBackup');
const embedOriginalUrlEl = document.getElementById('embedOriginalUrl');
const unlockPassphraseEl = document.getElementById('unlockPassphrase');
const unlockBtn = document.getElementById('unlockBtn');
const lockedPanel = document.getElementById('lockedPanel');
const unlockedPanel = document.getElementById('unlockedPanel');
const resetEncryptionBtn = document.getElementById('resetEncryptionBtn');
const encryptionHintEl = document.getElementById('encryptionHint');
const snapshotListEl = document.getElementById('snapshotList');
const retryImportBtn = document.getElementById('retryImportBtn');
const cloudWarningEl = document.getElementById('cloudWarning');

import { defaultSettings } from './settings.js';

function isSafeDisplayUrl(url) {
  if (!url || typeof url !== 'string') return false;
  try {
    const parsed = new URL(url);
    return ['http:', 'https:', 'file:', 'ftp:', 'chrome:', 'chrome-extension:'].includes(parsed.protocol);
  } catch { return false; }
}

function isSafeFaviconUrl(url) {
  if (!url || typeof url !== 'string') return false;
  try {
    const parsed = new URL(url);
    return ['http:', 'https:', 'data:', 'chrome:', 'chrome-extension:'].includes(parsed.protocol);
  } catch { return false; }
}

function setContent(parent, tag, className, text) {
  const el = document.createElement(tag);
  el.className = className;
  el.textContent = text;
  parent.replaceChildren(el);
}

const fallbackSettings = { ...defaultSettings };

let currentSettings = { ...fallbackSettings };
const pendingSnapshotTimers = new Set();

async function sendMessage(type, payload = {}) {
  try {
    return await chrome.runtime.sendMessage({ type, ...payload });
  } catch (err) {
    console.warn('Message failed', type, err);
    throw err;
  }
}

async function loadSettings() {
  try {
    const response = await sendMessage('GET_SETTINGS');
    currentSettings = {
      ...fallbackSettings,
      ...(response || {}),
      encryption: {
        ...fallbackSettings.encryption,
        ...(response?.encryption || {}),
      },
    };
  } catch (err) {
    currentSettings = { ...fallbackSettings };
    showStatus('Background process not yet ready. Using defaults.', true);
  }
  autoMinutesEl.value = currentSettings.autoSuspendMinutes;
  excludeActiveEl.checked = currentSettings.excludeActive;
  excludePinnedEl.checked = currentSettings.excludePinned;
  excludeAudibleEl.checked = currentSettings.excludeAudible;
  unsuspendMethodEl.value = currentSettings.unsuspendMethod;
  whitelistEl.value = (currentSettings.whitelist || []).join('\n');
  cloudBackupEl.checked = !!currentSettings.encryption.cloudBackupEnabled;
  embedOriginalUrlEl.checked = currentSettings.embedOriginalUrl !== false;
  await refreshEncryptionStatus();
}

function applyEncryptionStatus(status) {
  const statusDiv = document.getElementById('encryptionStatus');
  const setBtn = document.getElementById('setPassphraseBtn');
  const removeBtn = document.getElementById('removePassphraseBtn');

  cloudBackupEl.checked = !!status.cloudBackupEnabled;
  if (cloudWarningEl) {
    cloudWarningEl.classList.add('hidden');
    cloudWarningEl.classList.remove('hint-warning');
  }
  if (retryImportBtn) {
    retryImportBtn.classList.add('hidden');
  }

  // Reset dynamic state classes
  resetEncryptionBtn.classList.remove('reset-highlight');

  if (status.locked) {
    if (status.reason === 'corrupt-key') {
      statusDiv.textContent = 'Status: Error - Encryption key corrupted';
      statusDiv.className = 'status-indicator status-error';
      lockedPanel.classList.remove('hidden');
      unlockedPanel.classList.add('hidden');
      encryptionHintEl.textContent = 'The encryption key is corrupted or invalid. You must reset encryption to continue.';
      resetEncryptionBtn.classList.add('reset-highlight');
      if (retryImportBtn) {
        retryImportBtn.classList.remove('hidden');
      }
    } else {
      statusDiv.textContent = 'Status: Locked - passkey required';
      statusDiv.className = 'status-indicator status-locked';
      lockedPanel.classList.remove('hidden');
      unlockedPanel.classList.add('hidden');
      encryptionHintEl.textContent = 'Enter your passkey to unlock your data.';
    }
    setBtn.disabled = true;
    removeBtn.disabled = true;
    setContent(snapshotListEl, 'li', 'empty-state', 'Unlock to view session history.');
    return;
  }

  lockedPanel.classList.add('hidden');
  unlockedPanel.classList.remove('hidden');
  setBtn.disabled = false;
  removeBtn.disabled = false;

  if (status.usingPasskey) {
    statusDiv.textContent = 'Status: Protected by Passkey';
    statusDiv.className = 'status-indicator status-ok';
    passphraseEl.placeholder = 'Enter new passkey to change';
    setBtn.textContent = 'Change Passkey';
    removeBtn.classList.remove('hidden');
    if (status.cloudBackupEnabled && status.syncEligible) {
      encryptionHintEl.textContent = 'Your passkey-wrapped data key is backed up to Chrome Sync.';
    } else {
      encryptionHintEl.textContent = 'Your data key is wrapped with your passkey and stored locally.';
    }
  } else {
    statusDiv.textContent = status.cloudBackupEnabled
      ? 'Status: Local-only key (cloud backup requires passkey)'
      : 'Status: Key stored locally only';
    statusDiv.className = 'status-indicator status-neutral';
    passphraseEl.placeholder = 'Set a passkey (optional)';
    setBtn.textContent = 'Set Passkey';
    removeBtn.classList.add('hidden');
    encryptionHintEl.textContent = status.cloudBackupEnabled
      ? 'Set a passkey first to enable cloud backup; the key currently stays local-only.'
      : 'Your data is encrypted locally; the key stays on this device.';
    if (status.cloudBackupEnabled && !status.usingPasskey && cloudWarningEl) {
      cloudWarningEl.textContent = 'Cloud backup requires a passkey. Set one, then enable cloud backup.';
      cloudWarningEl.classList.add('hint-warning');
      cloudWarningEl.classList.remove('hidden');
    }
  }

  loadSnapshots();
}

async function refreshEncryptionStatus() {
  try {
    const status = await sendMessage('GET_ENCRYPTION_STATUS');
    applyEncryptionStatus(status || {});
  } catch (err) {
    console.warn('Failed to load encryption status', err);
    applyEncryptionStatus({
      locked: false,
      usingPasskey: false,
      cloudBackupEnabled: currentSettings.encryption.cloudBackupEnabled,
      syncEligible: false,
      syncBlockedReason: null,
    });
  }
}

// --- Session History ---

async function loadSnapshots() {
  try {
    const response = await sendMessage('GET_SNAPSHOTS');
    if (response.locked) {
      setContent(snapshotListEl, 'li', 'empty-state', 'Unlock to view session history.');
      return;
    }
    renderSnapshots(response.snapshots || []);
  } catch (err) {
    console.warn('Failed to load snapshots', err);
    setContent(snapshotListEl, 'li', 'empty-state', 'Failed to load history.');
  }
}


function renderSnapshots(snapshots) {
  for (const timerId of pendingSnapshotTimers) {
    clearTimeout(timerId);
  }
  pendingSnapshotTimers.clear();
  snapshotListEl.replaceChildren();
  if (!snapshots.length) {
    setContent(snapshotListEl, 'li', 'empty-state', 'No snapshots found.');
    return;
  }

  snapshots.forEach(snapshot => {
    const li = document.createElement('li');
    li.className = 'snapshot-item';

    // Single source of truth for expanded/collapsed
    let expanded = false;

    const header = document.createElement('div');
    header.className = 'snapshot-header';

    const toggle = document.createElement('button');
    toggle.className = 'btn-xs toggle-icon';
    toggle.type = 'button';
    toggle.textContent = '+';
    toggle.setAttribute('aria-expanded', 'false');

    const timestamp = typeof snapshot.timestamp === 'number' ? snapshot.timestamp : Date.now();
    const date = new Date(timestamp);
    const dateStr = formatSnapshotTimestamp(date);
    const tabCount = typeof snapshot.tabCount === 'number' ? snapshot.tabCount : 0;

    const title = document.createElement('span');
    title.className = 'snapshot-title';
    title.textContent = `(${dateStr}) ${tabCount} suspended tabs`;

    const actions = document.createElement('div');
    actions.className = 'snapshot-actions';

    const openBtn = document.createElement('button');
    openBtn.className = 'btn-xs';
    openBtn.textContent = 'Open all';
    openBtn.onclick = (e) => {
      e.stopPropagation();
      openSnapshot(snapshot.id, false);
    };

    const openUnsuspendBtn = document.createElement('button');
    openUnsuspendBtn.className = 'btn-xs';
    openUnsuspendBtn.textContent = 'Open all + unsuspend';
    openUnsuspendBtn.onclick = (e) => {
      e.stopPropagation();
      openSnapshot(snapshot.id, true);
    };

    actions.appendChild(openBtn);
    actions.appendChild(openUnsuspendBtn);

    header.appendChild(toggle);
    header.appendChild(title);
    header.appendChild(actions);

    const details = document.createElement('div');
    details.className = 'snapshot-details hidden';
    setContent(details, 'p', 'loading', 'Loading details...');

    li.appendChild(header);
    li.appendChild(details);
    snapshotListEl.appendChild(li);

    let detailsLoaded = false;
    let detailsLoading = false;
    let detailsGeneration = 0;
    let loadingTimeout;

    const loadDetails = async () => {
      if (detailsLoading) {
        return;
      }
      detailsLoading = true;
      detailsLoaded = false;
      const thisGeneration = ++detailsGeneration;

      try {
        setContent(details, 'p', 'loading', 'Loading details...');
        loadingTimeout = setTimeout(() => {
          pendingSnapshotTimers.delete(loadingTimeout);
          if (!detailsLoaded && thisGeneration === detailsGeneration) {
            setContent(details, 'p', 'loading', 'Still loading\u2026');
          }
        }, 2000);
        pendingSnapshotTimers.add(loadingTimeout);

        const responsePromise = sendMessage('GET_SNAPSHOT_DETAILS', { snapshotId: snapshot.id });
        const response = await Promise.race([
          responsePromise,
          new Promise(resolve => setTimeout(() => resolve({ timeout: true }), 10000))
        ]);

        if (thisGeneration !== detailsGeneration) {
          return;
        }

        if (response?.timeout) {
          const timeoutP = document.createElement('p');
          timeoutP.className = 'error';
          timeoutP.textContent = 'Timed out. ';
          const retryBtn = document.createElement('button');
          retryBtn.className = 'btn-xs retry-details';
          retryBtn.textContent = 'Retry';
          timeoutP.appendChild(retryBtn);
          details.replaceChildren(timeoutP);
          retryBtn.addEventListener('click', (event) => {
            event.stopPropagation();
            loadDetails();
          });
          return;
        }

        if (response?.locked) {
          setContent(details, 'p', 'error', 'Unlock encryption to view this snapshot.');
        } else if (response && response.ok && response.tabs) {
          renderSnapshotDetails(details, response.tabs);
          detailsLoaded = true;
        } else if (response?.error) {
          const errorP = document.createElement('p');
          errorP.className = 'error';
          errorP.textContent = `Failed to load details: ${response.error}`;
          details.replaceChildren(errorP);
          const retryBtn = document.createElement('button');
          retryBtn.className = 'btn-xs retry-details';
          retryBtn.textContent = 'Retry';
          retryBtn.addEventListener('click', (event) => {
            event.stopPropagation();
            loadDetails();
          });
          details.appendChild(retryBtn);
        } else {
          setContent(details, 'p', 'error', 'Failed to load details.');
        }
      } catch (err) {
        if (thisGeneration !== detailsGeneration) return;
        console.warn('Failed to fetch snapshot details', err);
        setContent(details, 'p', 'error', 'Error loading details.');
        const retryBtn = document.createElement('button');
        retryBtn.className = 'btn-xs retry-details';
        retryBtn.textContent = 'Retry';
        retryBtn.addEventListener('click', (event) => {
          event.stopPropagation();
          loadDetails();
        });
        details.appendChild(retryBtn);
      } finally {
        clearTimeout(loadingTimeout);
        pendingSnapshotTimers.delete(loadingTimeout);
        if (thisGeneration === detailsGeneration) {
          detailsLoading = false;
        }
      }
    };

    toggle.onclick = async (e) => {
      e.stopPropagation();
      expanded = !expanded;
      details.classList.toggle('hidden', !expanded);
      toggle.textContent = expanded ? '-' : '+';
      toggle.setAttribute('aria-expanded', expanded);

      if (expanded && !detailsLoaded) {
        await loadDetails();
      }
    };
  });
}

function renderSnapshotDetails(container, tabsMap) {
  container.replaceChildren();
  const ul = document.createElement('ul');
  ul.className = 'snapshot-tab-list';

  const tabs = Object.values(tabsMap);
  if (tabs.length === 0) {
    setContent(container, 'p', 'empty', 'No tabs in this snapshot.');
    return;
  }

  tabs.forEach(tab => {
    const li = document.createElement('li');
    li.className = 'snapshot-tab-item';

    const link = document.createElement('a');
    link.href = isSafeDisplayUrl(tab.url) ? tab.url : '#';
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    link.textContent = tab.title || tab.url;
    link.className = 'snapshot-tab-link';

    if (tab.favIconUrl && isSafeFaviconUrl(tab.favIconUrl)) {
      const icon = document.createElement('img');
      icon.src = tab.favIconUrl;
      icon.className = 'snapshot-tab-icon';
      icon.onerror = () => { icon.classList.add('hidden'); };
      li.appendChild(icon);
    }

    li.appendChild(link);
    ul.appendChild(li);
  });

  container.appendChild(ul);
}

function formatSnapshotTimestamp(date) {
  const pad = n => `${n}`.padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`;
}

async function openSnapshot(snapshotId, unsuspend) {
  try {
    const response = await sendMessage('OPEN_SNAPSHOT', { snapshotId, unsuspend });
    if (response?.locked) {
      showStatus('Unlock encryption to open snapshots.', true);
      return;
    }
    if (response?.ok) {
      const verb = unsuspend ? 'unsuspended' : 'suspended';
      showStatus(`Opened ${response.opened || 0} tabs from snapshot (${verb}).`);
    } else {
      showStatus('Failed to open snapshot.', true);
    }
  } catch (err) {
    console.warn('Failed to open snapshot', err);
    showStatus('Failed to open snapshot.', true);
  }
}


function collectSettingsFromForm() {
  return {
    autoSuspendMinutes: Math.max(1, Math.min(1440, Math.round(Number(autoMinutesEl.value) || 30))),
    excludeActive: excludeActiveEl.checked,
    excludePinned: excludePinnedEl.checked,
    excludeAudible: excludeAudibleEl.checked,
    unsuspendMethod: unsuspendMethodEl.value,
    embedOriginalUrl: embedOriginalUrlEl.checked,
    whitelist: whitelistEl.value
      .split('\n')
      .map(line => line.trim())
      .filter(Boolean),
    encryption: {
      enabled: true,
      iterations: currentSettings?.encryption?.iterations || 600000,
      cloudBackupEnabled: cloudBackupEl.checked,
    },
  };
}

function showStatus(message, isError = false) {
  statusEl.textContent = message;
  statusEl.classList.toggle('status-msg-error', isError);
  statusEl.classList.toggle('status-msg-ok', !isError);
}

form.addEventListener('submit', async event => {
  event.preventDefault();
  const nextSettings = collectSettingsFromForm();

  try {
    await sendMessage('SAVE_SETTINGS', { payload: nextSettings });
    showStatus('Settings saved.');
    await loadSettings();
  } catch (err) {
    showStatus('Failed to save settings.', true);
  }
});

document.getElementById('setPassphraseBtn').addEventListener('click', async () => {
  const passphrase = passphraseEl.value.trim();
  if (!passphrase) {
    showStatus('Please enter a passphrase first.', true);
    return;
  }

  if (!confirm('Setting a passphrase will wrap your key. Make sure you remember it!')) {
    return;
  }

  try {
    const response = await sendMessage('SET_PASSKEY', { passkey: passphrase });
    if (response?.ok) {
      passphraseEl.value = '';
      await refreshEncryptionStatus();
      showStatus('Passphrase set successfully.');
    } else {
      showStatus('Failed to set passphrase.', true);
    }
  } catch (err) {
    showStatus('Error setting passphrase.', true);
  }
});

document.getElementById('removePassphraseBtn').addEventListener('click', async () => {
  if (!confirm('Are you sure? This will remove the passkey and keep the data key local-only.')) {
    return;
  }

  try {
    const response = await sendMessage('REMOVE_PASSKEY');
    if (response?.ok) {
      passphraseEl.value = '';
      await refreshEncryptionStatus();
      showStatus('Passphrase removed.');
    } else {
      showStatus('Failed to remove passphrase.', true);
    }
  } catch (err) {
    showStatus('Error removing passphrase.', true);
  }
});

unlockBtn.addEventListener('click', async () => {
  const passphrase = unlockPassphraseEl.value.trim();
  if (!passphrase) {
    showStatus('Please enter your passkey to unlock.', true);
    return;
  }
  try {
    const response = await sendMessage('UNLOCK_WITH_PASSKEY', { passkey: passphrase });
    if (response?.ok) {
      unlockPassphraseEl.value = '';
      await refreshEncryptionStatus();
      showStatus('Unlocked successfully.');
    } else if (response?.error === 'corrupt-state') {
      showStatus('State data is corrupted. Reset encryption to continue.', true);
    } else {
      showStatus('Incorrect passkey.', true);
    }
  } catch (err) {
    showStatus('Failed to unlock.', true);
  }
});

if (retryImportBtn) {
  retryImportBtn.addEventListener('click', async () => {
    try {
      const result = await sendMessage('RETRY_IMPORT_KEY');
      if (result?.ok) {
        await refreshEncryptionStatus();
        showStatus('Key import retried successfully.');
      } else {
        showStatus('Retry failed. You may need to reset encryption.', true);
      }
    } catch (err) {
      showStatus('Retry failed.', true);
    }
  });
}

cloudBackupEl.addEventListener('change', async () => {
  const previousValue = !cloudBackupEl.checked;
  try {
    const result = await sendMessage('SET_CLOUD_BACKUP', { enabled: cloudBackupEl.checked });
    if (!result?.ok) {
      cloudBackupEl.checked = previousValue;
      if (result?.error === 'passkey-required') {
        showStatus('Set a passkey before enabling cloud backup.', true);
      } else {
        showStatus('Failed to update cloud backup.', true);
      }
      await refreshEncryptionStatus();
      return;
    }
    await refreshEncryptionStatus();
    showStatus('Cloud backup preference saved.');
  } catch (err) {
    console.error('Failed to toggle cloud backup', err);
    cloudBackupEl.checked = previousValue;
    showStatus('Failed to update cloud backup.', true);
  }
});

resetEncryptionBtn.addEventListener('click', async () => {
  if (!confirm('This will erase encrypted session data and snapshots and generate a new key. Continue?')) {
    return;
  }
  try {
    const response = await sendMessage('RESET_ENCRYPTION');
    if (response?.ok) {
      await loadSettings();
      showStatus('Encryption reset. Using fresh key.');
    } else {
      showStatus('Failed to reset encryption.', true);
    }
  } catch (err) {
    console.error('Failed to reset encryption', err);
    showStatus('Failed to reset encryption.', true);
  }
});

// --- Logging ---

const downloadLogsBtn = document.getElementById('downloadLogs');
const clearLogsBtn = document.getElementById('clearLogs');

downloadLogsBtn.addEventListener('click', async () => {
  try {
    const stored = await chrome.storage.local.get('logs');
    const logs = stored.logs || [];
    if (logs.length === 0) {
      showStatus('No logs to download.');
      return;
    }

    const text = logs.map(entry => {
      const dataStr = entry.data ? `\nData: ${JSON.stringify(entry.data, null, 2)}` : '';
      return `[${entry.timestamp}] [${entry.level.toUpperCase()}] ${entry.message}${dataStr}`;
    }).join('\n\n');

    const blob = new Blob([text], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `local-suspender-logs-${new Date().toISOString().replace(/[:.]/g, '-')}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  } catch (err) {
    console.error('Failed to download logs', err);
    showStatus('Failed to download logs.', true);
  }
});

clearLogsBtn.addEventListener('click', async () => {
  if (!confirm('Are you sure you want to clear all logs?')) {
    return;
  }
  try {
    await chrome.storage.local.remove('logs');
    showStatus('Logs cleared.');
  } catch (err) {
    console.error('Failed to clear logs', err);
    showStatus('Failed to clear logs.', true);
  }
});

loadSettings();
