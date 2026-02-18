import Logger from './logger.js';
import {
  initializeEncryption,
  getCryptoKey,
  isEncryptionLocked,
  getEncryptionLockReason,
  unlockWithPasskey as decryptWithPasskey,
  setPasskey as persistPasskey,
  removePasskey as clearPasskey,
  setCloudBackupEnabled as updateCloudBackup,
  clearSessionKey,
  clearKeyRecords,
  generateAndPersistDataKey,
  getEncryptionStatusPayload,
  loadKeyRecord,
  retryImportPlaintextKey,
} from './encryption.js';
import { ensureSettings, saveSettings as persistSettings, defaultSettings, SETTINGS_KEY } from './settings.js';
import { sessionGet, sessionSet, sessionRemove } from './session.js';
import { encodeStateV2, decodeStateAny } from './state-codec.js';
import { processUnsuspendTokenMessage } from './unsuspend-token-flow.js';

const STATE_KEY = 'suspenderState';
const SESSION_LAST_ACTIVE_KEY = 'lastActive';
const LEGACY_SESSION_PENDING_STATE_KEY = 'pendingSuspenderState';
const SNAPSHOT_RETENTION_DAYS = 7;
const SNAPSHOT_MAX = 20;
const TOKEN_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const SNAPSHOT_PERIOD_MINUTES = 180;
const AUTO_SUSPEND_BATCH_LIMIT = 5;
const ALARM_PERIOD_DIVISOR = 3;
const MAX_ALARM_PERIOD_MINUTES = 60;
const STATE_VALIDATION_THROTTLE_MS = 60 * 1000;
const LAST_ACTIVE_FLUSH_DELAY_MS = 3000;
const SNAPSHOT_DETAILS_CACHE_LIMIT = 10;

let cachedState = null;
let lastActiveCache = {};
let initError = null;
let stateCorruptionReason = null;
let validationTimer = null;
let validationRunning = false;
let nextValidationAllowedAt = 0;
let whitelistRegexCacheKey = '';
let whitelistRegexCache = [];
let lastActiveDirty = false;
let lastActiveFlushTimer = null;
const snapshotDetailsCache = new Map();

// Lock hierarchy (acquire in this order to avoid deadlock):
//   snapshotLock → stateLock
//   reconciliationLock is independent; saveState waits for it but never holds stateLock while waiting.
//   Note: stateLock holders may wait on reconciliationLock (via saveState/validateState) — no deadlock risk.
let stateLock = Promise.resolve();

async function withStateLock(fn) {
  const prev = stateLock;
  let release;
  stateLock = new Promise(r => { release = r; });
  try {
    await prev;
    return await fn();
  } finally {
    release();
  }
}

function hasCryptoKey() {
  return !!getCryptoKey();
}

function encryptionIsLocked() {
  return isEncryptionLocked();
}

function encryptionReason() {
  return getEncryptionLockReason();
}

function stateIsLocked() {
  return encryptionIsLocked() || !hasCryptoKey();
}

function markStateCorrupt(reason = 'corrupt-state') {
  stateCorruptionReason = reason;
}

function clearStateCorruption() {
  stateCorruptionReason = null;
}

function stateIsCorrupt() {
  return !!stateCorruptionReason;
}

function stateLockReason() {
  if (stateIsCorrupt()) {
    return stateCorruptionReason;
  }
  return encryptionReason();
}

function stateWriteBlockedReason() {
  if (stateIsCorrupt()) {
    return stateLockReason() || 'corrupt-state';
  }
  if (stateIsLocked()) {
    return stateLockReason() || 'locked';
  }
  return null;
}

function stateIsWritable() {
  return !stateWriteBlockedReason();
}

function lockedMutationResponse({ skip = false } = {}) {
  const reason = stateWriteBlockedReason() || 'locked';
  if (skip) {
    return { ok: true, skipped: 'locked', reason };
  }
  return { ok: false, locked: true, reason };
}

async function clearLegacyPendingState() {
  await sessionRemove(LEGACY_SESSION_PENDING_STATE_KEY);
}

function cloneSuspendedTabsMap(tabsMap) {
  const clone = {};
  for (const [tabId, entry] of Object.entries(tabsMap || {})) {
    clone[tabId] = { ...entry };
  }
  return clone;
}

function clearSnapshotDetailsCache() {
  snapshotDetailsCache.clear();
}

function readSnapshotDetailsCache(snapshotId) {
  if (!snapshotDetailsCache.has(snapshotId)) {
    return null;
  }
  const cached = snapshotDetailsCache.get(snapshotId);
  snapshotDetailsCache.delete(snapshotId);
  snapshotDetailsCache.set(snapshotId, cached);
  return cloneSuspendedTabsMap(cached);
}

function setSnapshotDetailsCache(snapshotId, tabsMap) {
  snapshotDetailsCache.set(snapshotId, cloneSuspendedTabsMap(tabsMap));
  while (snapshotDetailsCache.size > SNAPSHOT_DETAILS_CACHE_LIMIT) {
    const oldestKey = snapshotDetailsCache.keys().next().value;
    snapshotDetailsCache.delete(oldestKey);
  }
}

async function runStateValidationNow(trigger = 'scheduled') {
  if (validationRunning) {
    return;
  }
  if (validationTimer) {
    clearTimeout(validationTimer);
    validationTimer = null;
  }
  validationRunning = true;
  try {
    await withStateLock(async () => {
      const state = await loadState();
      if (!state || stateIsLocked() || stateIsCorrupt()) {
        return;
      }
      await validateState(state);
    });
  } catch (err) {
    Logger.warn('State validation failed', { trigger, err: err?.message || String(err) });
  } finally {
    validationRunning = false;
    nextValidationAllowedAt = Date.now() + STATE_VALIDATION_THROTTLE_MS;
  }
}

function maybeScheduleValidation(trigger = 'get-state') {
  if (validationRunning || validationTimer) {
    return;
  }
  const delay = Math.max(0, nextValidationAllowedAt - Date.now());
  validationTimer = setTimeout(() => {
    validationTimer = null;
    void runStateValidationNow(trigger);
  }, delay);
}

function buildWhitelistCacheKey(whitelist) {
  if (!Array.isArray(whitelist) || whitelist.length === 0) {
    return '';
  }
  return whitelist.map(item => String(item)).join('\n');
}

function getWhitelistRegexes(whitelist) {
  const nextKey = buildWhitelistCacheKey(whitelist);
  if (nextKey === whitelistRegexCacheKey) {
    return whitelistRegexCache;
  }
  whitelistRegexCacheKey = nextKey;
  whitelistRegexCache = [];
  for (const pattern of whitelist || []) {
    try {
      whitelistRegexCache.push(wildcardToRegExp(pattern));
    } catch (err) {
      Logger.warn('Invalid whitelist pattern', pattern, err);
    }
  }
  return whitelistRegexCache;
}

function markLastActiveDirty() {
  lastActiveDirty = true;
  if (lastActiveFlushTimer) {
    return;
  }
  lastActiveFlushTimer = setTimeout(() => {
    lastActiveFlushTimer = null;
    void flushLastActiveCache();
  }, LAST_ACTIVE_FLUSH_DELAY_MS);
}

async function flushLastActiveCache() {
  if (lastActiveFlushTimer) {
    clearTimeout(lastActiveFlushTimer);
    lastActiveFlushTimer = null;
  }
  if (!lastActiveDirty) {
    return;
  }
  const snapshot = { ...lastActiveCache };
  lastActiveDirty = false;
  try {
    await sessionSet(SESSION_LAST_ACTIVE_KEY, snapshot);
  } catch (err) {
    lastActiveDirty = true;
    Logger.warn('Failed to persist last-active cache', err);
    markLastActiveDirty();
  }
}

// --- Snapshot Service ---

const SnapshotService = {
  async createSnapshot() {
    const previousLock = snapshotLock;
    let release;
    snapshotLock = new Promise(resolve => { release = resolve; });

    try {
      await previousLock; // serialize

      const state = await withStateLock(async () => {
        const loaded = await loadState();
        // Validate state against actual open tabs to ensure we only snapshot truly suspended tabs.
        await validateState(loaded);
        return loaded;
      });

      if (!state || !state.suspendedTabs || Object.keys(state.suspendedTabs).length === 0) {
        return;
      }
      const encodedState = encodeStateV2(state);

      // We only create snapshots if we have the key to encrypt them (if encryption is on)
      const settings = await ensureSettings();
      if (settings.encryption.enabled && (encryptionIsLocked() || !hasCryptoKey())) {
        Logger.warn('Skipping snapshot: Encryption enabled but key not available');
        return;
      }

      let snapshotData;
      if (settings.encryption.enabled) {
        snapshotData = await encryptPayload(encodedState);
      } else {
        snapshotData = { plain: encodedState };
      }

      const snapshot = {
        id: crypto.randomUUID(),
        timestamp: Date.now(),
        tabCount: Object.keys(state.suspendedTabs).length,
        data: snapshotData
      };

      const stored = await chrome.storage.local.get('backups');
      const existing = stored.backups || [];
      const backups = pruneSnapshots([...existing, snapshot]);

      await chrome.storage.local.set({ backups });
      clearSnapshotDetailsCache();
      Logger.info('Snapshot created', { id: snapshot.id, tabCount: snapshot.tabCount });
    } catch (err) {
      Logger.error('Failed to create snapshot', err);
    } finally {
      release?.();
    }
  },

  async getSnapshots() {
    const previousLock = snapshotLock;
    let release;
    snapshotLock = new Promise(resolve => { release = resolve; });
    try {
      await previousLock;
      const stored = await chrome.storage.local.get('backups');
      const pruned = pruneSnapshots(stored.backups || []);
      if (pruned.length !== (stored.backups || []).length) {
        await chrome.storage.local.set({ backups: pruned });
        clearSnapshotDetailsCache();
      }
      return pruned.map(b => ({
        id: b.id,
        timestamp: b.timestamp,
        tabCount: b.tabCount
      }));
    } finally {
      release?.();
    }
  },

  async restoreSnapshot(snapshotId) {
    await withStateLock(async () => {
      const stored = await chrome.storage.local.get('backups');
      const backups = stored.backups || [];
      const snapshot = backups.find(b => b.id === snapshotId);

      if (!snapshot) {
        throw new Error('Snapshot not found');
      }

      let restoredState;
      if (snapshot.data.ct && (encryptionIsLocked() || !hasCryptoKey())) {
        throw new Error('Encryption key required to restore this snapshot');
      }
      restoredState = await getSnapshotData(snapshot);

      cachedState = restoredState;
      await validateState(cachedState);
      await saveState(cachedState);
      clearSnapshotDetailsCache();
      Logger.info('Snapshot restored', { id: snapshotId });
    });
    return true;
  }
};

function pruneSnapshots(list) {
  if (!Array.isArray(list)) return [];
  const cutoff = Date.now() - SNAPSHOT_RETENTION_DAYS * 24 * 60 * 60 * 1000;
  const filtered = list.filter(item => typeof item.timestamp === 'number' && item.timestamp >= cutoff);
  filtered.sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0));
  return filtered.slice(0, SNAPSHOT_MAX);
}

async function getSnapshotById(snapshotId) {
  const stored = await chrome.storage.local.get('backups');
  let backups = stored.backups || [];
  backups = pruneSnapshots(backups);
  const snapshot = backups.find(b => b.id === snapshotId);
  if (backups.length !== (stored.backups || []).length) {
    await chrome.storage.local.set({ backups });
    clearSnapshotDetailsCache();
  }
  return snapshot || null;
}

async function getSnapshotData(snapshot) {
  if (!snapshot || !snapshot.data) {
    throw new Error('Snapshot missing data');
  }
  if (snapshot.data.ct) {
    const state = await decryptPayload(snapshot.data);
    return decodeStateAny(state);
  }
  if (snapshot.data.plain) {
    return decodeStateAny(snapshot.data.plain);
  }
  throw new Error('Invalid snapshot format');
}

async function openSnapshotTabs(snapshotId, { unsuspend = false } = {}) {
  if (!unsuspend && !stateIsWritable()) {
    return lockedMutationResponse();
  }
  const snapshot = await getSnapshotById(snapshotId);
  if (!snapshot) {
    return { ok: false, error: 'not-found' };
  }
  const needsKey = !!snapshot.data?.ct;
  if (needsKey && (encryptionIsLocked() || !hasCryptoKey())) {
    return { ok: false, locked: true };
  }
  const state = await getSnapshotData(snapshot);
  const entries = Object.values(state?.suspendedTabs || {});
  if (!entries.length) {
    return { ok: true, opened: 0 };
  }

  const seenUrls = new Set();
  const existingUrls = new Set();
  if (!unsuspend) {
    await withStateLock(async () => {
      const currentState = await loadState();
      for (const entry of Object.values(currentState?.suspendedTabs || {})) {
        if (entry?.url) {
          existingUrls.add(entry.url);
        }
      }
    });
  }

  const filteredEntries = [];
  for (const entry of entries) {
    const parsedEntry = {
      url: entry?.url,
      title: entry?.title,
      favIconUrl: entry?.favIconUrl,
    };
    if (!isSafeUrl(parsedEntry.url)) continue;
    if (!unsuspend) {
      const urlKey = parsedEntry.url;
      if (existingUrls.has(urlKey) || seenUrls.has(urlKey)) {
        continue; // Avoid duplicates in state and tabs
      }
      seenUrls.add(urlKey);
    }
    filteredEntries.push(parsedEntry);
  }

  if (!filteredEntries.length) {
    return { ok: true, opened: 0 };
  }

  const win = await chrome.windows.create({ url: 'about:blank', focused: true });
  const windowId = win.id;
  const tabs = win.tabs || [];
  let firstTabId = tabs[0]?.id || null;
  let firstTabUsed = false;
  let opened = 0;
  const settings = await ensureSettings();
  const embedOriginalUrl = settings.embedOriginalUrl !== false;
  const pendingStateEntries = [];

  for (const entry of filteredEntries) {
    let urlToOpen;
    let isSuspended = false;
    let token = null;

    if (unsuspend) {
      urlToOpen = entry.url;
    } else {
      // Construct suspended URL directly.
      token = crypto.randomUUID();
      const suspendedUrl = new URL(chrome.runtime.getURL('suspended.html'));
      suspendedUrl.searchParams.set('token', token);
      if (embedOriginalUrl) {
        suspendedUrl.searchParams.set('url', entry.url);
        if (entry.title) suspendedUrl.searchParams.set('title', entry.title);
        if (entry.favIconUrl) suspendedUrl.searchParams.set('favicon', entry.favIconUrl);
      }

      urlToOpen = suspendedUrl.toString();
      isSuspended = true;
    }

    let tab;
    if (opened === 0 && firstTabId) {
      tab = await chrome.tabs.update(firstTabId, { url: urlToOpen, active: true });
      firstTabUsed = true;
    } else {
      tab = await chrome.tabs.create({ windowId, url: urlToOpen, active: false });
    }
    opened += 1;

    if (isSuspended) {
      const now = Date.now();
      pendingStateEntries.push({
        tabId: tab.id,
        metadata: {
          url: entry.url,
          title: entry.title,
          favIconUrl: entry.favIconUrl,
          windowId,
          suspendedAt: now,
          method: 'page',
          reason: 'restored-from-snapshot',
          token,
          tokenIssuedAt: now,
          tokenUsed: false,
        },
      });
      existingUrls.add(entry.url);
    }
  }

  if (!unsuspend && pendingStateEntries.length) {
    await withStateLock(async () => {
      const currentState = await loadState();
      const currentUrls = new Set(Object.values(currentState?.suspendedTabs || {}).map(item => item.url));
      for (const entry of pendingStateEntries) {
        if (currentUrls.has(entry.metadata.url)) {
          continue;
        }
        currentState.suspendedTabs[entry.tabId] = entry.metadata;
        currentUrls.add(entry.metadata.url);
      }
      await saveState(currentState);
    });
  }

  if (opened > 0 && firstTabId && !firstTabUsed) {
    await chrome.tabs.remove(firstTabId).catch(() => null);
  }

  return { ok: true, opened };
}

// --- Initialization ---

// Create a promise that resolves when initialization is complete.
// This ensures that event handlers can wait for settings/state to be loaded.
  let readyResolve;
  const ready = new Promise(resolve => {
    readyResolve = resolve;
  });

let snapshotLock = Promise.resolve();

async function init() {
  try {
    await ensureSettings();
    await loadLastActive();
    await clearLegacyPendingState();

    await initializeEncryption();

    // Only schedule if not already scheduled
    const alarm = await chrome.alarms.get('autoSuspend');
    if (!alarm) {
      await scheduleAutoSuspendAlarm();
    }

    const snapshotAlarm = await chrome.alarms.get('snapshotTimer');
    if (!snapshotAlarm) {
      await chrome.alarms.create('snapshotTimer', { periodInMinutes: SNAPSHOT_PERIOD_MINUTES });
    }

    const validateAlarm = await chrome.alarms.get('stateValidator');
    if (!validateAlarm) {
      await scheduleStateValidationAlarm();
    }
  } catch (err) {
    Logger.error('Initialization failed', err);
    initError = err;
  } finally {
    readyResolve();
  }
}

// Start initialization immediately
init();

// --- Event Listeners (Registered Synchronously) ---

chrome.runtime.onInstalled.addListener(handleInstalled);
chrome.runtime.onStartup.addListener(handleStartup);
chrome.runtime.onMessage.addListener(handleMessage);
chrome.tabs.onActivated.addListener(handleTabActivated);
chrome.windows.onFocusChanged.addListener(handleWindowFocusChanged);
chrome.tabs.onRemoved.addListener(handleTabRemoved);
chrome.tabs.onUpdated.addListener(handleTabUpdated);
chrome.alarms.onAlarm.addListener(handleAlarm);
chrome.idle.onStateChanged.addListener(handleIdleStateChange);
chrome.storage.onChanged.addListener(handleStorageChanged);

// --- Event Handlers ---

async function handleInstalled(details) {
  // onInstalled is a special case where we might want to force a reset
  if (details.reason === 'install') {
    await ready;
    await chrome.storage.local.set({ [SETTINGS_KEY]: defaultSettings });
    await saveState({ suspendedTabs: {} });
    await scheduleAutoSuspendAlarm(); // Force schedule on install
    await chrome.alarms.create('snapshotTimer', { periodInMinutes: SNAPSHOT_PERIOD_MINUTES });
    try {
      await chrome.runtime.openOptionsPage();
    } catch (err) {
      Logger.warn('Failed to open options page on install', err);
    }
  } else if (details.reason === 'update') {
    await ready; // Wait for init to ensure we have settings
    await scheduleAutoSuspendAlarm(); // Ensure alarm is correct after update
    await chrome.alarms.create('snapshotTimer', { periodInMinutes: SNAPSHOT_PERIOD_MINUTES });
  }
}

async function handleStartup() {
  await ready;
  await clearLegacyPendingState();
}

function handleStorageChanged(changes, areaName) {
  if (areaName === 'local' && changes[STATE_KEY]) {
    cachedState = null;
    clearStateCorruption();
  }
}

async function saveSettings(nextSettings) {
  const merged = {
    ...defaultSettings,
    ...nextSettings,
    encryption: {
      ...defaultSettings.encryption,
      ...(nextSettings.encryption || {}),
      enabled: true,
      cloudBackupEnabled: nextSettings.encryption?.cloudBackupEnabled ?? defaultSettings.encryption.cloudBackupEnabled,
    },
  };
  if (merged.encryption.cloudBackupEnabled) {
    const record = await loadKeyRecord(true);
    if (!record?.usingPasskey) {
      merged.encryption.cloudBackupEnabled = false;
      Logger.warn('Cloud backup requires passkey-wrapped key; forcing local-only setting');
    }
  }
  await persistSettings(merged);
  await scheduleAutoSuspendAlarm(); // Reschedule when settings change
}

async function loadState() {
  if (stateIsLocked()) {
    cachedState = cachedState || { suspendedTabs: {} };
    return cachedState;
  }
  if (cachedState) {
    return cachedState;
  }
  const stored = await chrome.storage.local.get(STATE_KEY);
  const payload = stored[STATE_KEY];
  if (payload && payload.ct) {
    try {
      const decryptedState = await decryptPayload(payload);
      cachedState = decodeStateAny(decryptedState);
      clearStateCorruption();
    } catch (err) {
      Logger.warn('Failed to decrypt state', err);
      markStateCorrupt('corrupt-state');
      cachedState = cachedState || { suspendedTabs: {} };
    }
  } else if (payload && payload.plain) {
    clearStateCorruption();
    cachedState = decodeStateAny(payload.plain);
  } else {
    clearStateCorruption();
    cachedState = { suspendedTabs: {} };
  }
  return cachedState;
}

let reconciliationLock = Promise.resolve();

// Core save logic without reconciliation lock — used by both saveState and reconcilePendingStateAfterUnlock
async function saveStateInternal(state) {
  const blockedReason = stateWriteBlockedReason();
  if (blockedReason) {
    throw new Error(blockedReason);
  }
  const encodedState = encodeStateV2(state);
  const settings = await ensureSettings();
  if (settings.encryption.enabled) {
    const encrypted = await encryptPayload(encodedState);
    await chrome.storage.local.set({ [STATE_KEY]: encrypted });
  } else {
    await chrome.storage.local.set({ [STATE_KEY]: { plain: encodedState } });
  }
}

async function saveState(state) {
  await reconciliationLock;
  cachedState = state;
  await saveStateInternal(state);
}

function isSafeUrl(url) {
  if (!url || typeof url !== 'string') return false;
  try {
    const parsed = new URL(url);
    return ['http:', 'https:', 'file:', 'ftp:'].includes(parsed.protocol);
  } catch {
    return false;
  }
}

function wildcardToRegExp(pattern) {
  // Normalize pattern: remove protocol, www, trailing slash
  let p = pattern.trim().toLowerCase();
  p = p.replace(/^(https?:\/\/)?(www\.)?/, '');
  if (p.endsWith('/')) {
    p = p.slice(0, -1);
  }

  // Escape regex characters except *
  const escaped = p.replace(/[.+^${}()|[\]\\]/g, '\\$&');

  // Convert * to .*
  // If pattern ends with *, it matches prefix.
  // If pattern starts with *, it matches suffix.
  // If no *, we match exact domain or path prefix.

  let regexString = escaped.replace(/\*/g, '.*?');

  // If it's just a domain like "leetcode.com", we want to match "leetcode.com" AND "leetcode.com/problems" AND "sub.leetcode.com"
  // But we don't want "myleetcode.com"

  // Simple heuristic: if no slash, assume domain match
  if (!p.includes('/')) {
    // Match exact domain or subdomain
    // regex: (^|\.)leetcode\.com(\/|$)
    regexString = `(^|\\.)${regexString}(\\/|$)`;
  } else {
    // Path match, anchor start
    regexString = `^${regexString}`;
  }

  return new RegExp(regexString);
}

function matchesWhitelist(url, whitelist) {
  if (!url) return false;
  if (!Array.isArray(whitelist) || whitelist.length === 0) {
    return false;
  }

  // Normalize URL for matching: lower-case host/path, strip protocol and www
  let normalized = '';
  try {
    const u = new URL(url);
    const host = (u.hostname || '').toLowerCase().replace(/^www\./, '');
    const path = (u.pathname || '').toLowerCase();
    normalized = `${host}${path}`;
  } catch (err) {
    // Fallback: strip protocol/www manually
    normalized = url.toLowerCase().replace(/^(https?:\/\/)?(www\.)?/, '');
  }

  const regexes = getWhitelistRegexes(whitelist);
  for (const regex of regexes) {
    if (regex.test(normalized)) {
      return true;
    }
  }
  return false;
}

async function unsuspendWhitelistedTabs(whitelist) {
  if (!stateIsWritable()) {
    return;
  }
  await withStateLock(async () => {
    if (!stateIsWritable()) {
      return;
    }
    const state = await loadState();
    if (!state || !state.suspendedTabs) return;

    const entries = Object.entries(state.suspendedTabs);
    for (const [tabIdStr, entry] of entries) {
      if (matchesWhitelist(entry.url, whitelist)) {
        const tabId = Number(tabIdStr);
        Logger.info('Auto-unsuspending whitelisted tab', { tabId, url: entry.url });
        await resumeSuspendedTab(tabId, entry, { focus: false, reloadIfDiscarded: true });
        delete state.suspendedTabs[tabId];
      }
    }
    await saveState(state);
  });
}

async function validateState(state) {
  if (!state || !state.suspendedTabs) return;

  const tabIds = Object.keys(state.suspendedTabs).map(Number);
  if (tabIds.length === 0) return;

  // Batch query tabs once to avoid N calls
  const allTabs = await chrome.tabs.query({});
  const tabMap = new Map(allTabs.map(t => [t.id, t]));
  const suspendedPagePrefix = chrome.runtime.getURL('suspended.html');

  let changed = false;
  for (const tabId of tabIds) {
    const entry = state.suspendedTabs[tabId];
    const tab = tabMap.get(tabId);

    if (!tab) {
      delete state.suspendedTabs[tabId];
      changed = true;
      continue;
    }

    // Never keep incognito entries
    if (tab.incognito) {
      delete state.suspendedTabs[tabId];
      changed = true;
      continue;
    }

    // Prune entries with unsafe URLs (javascript:, data:, etc.)
    if (!isSafeUrl(entry.url)) {
      delete state.suspendedTabs[tabId];
      changed = true;
      continue;
    }

    if (entry.method === 'discard') {
      if (!tab.discarded) {
        delete state.suspendedTabs[tabId];
        changed = true;
      }
    } else if (entry.method === 'page') {
      if (!tab.url.startsWith(suspendedPagePrefix)) {
        delete state.suspendedTabs[tabId];
        changed = true;
      }
    } else {
      // Unknown method — prune
      delete state.suspendedTabs[tabId];
      changed = true;
    }
  }

  if (changed) {
    await saveState(state);
  }
}

async function handleTabActivated(activeInfo) {
  await ready;
  await markTabActive(activeInfo.tabId);
  const settings = await ensureSettings();
  if (settings.unsuspendMethod === 'activate') {
    const tab = await chrome.tabs.get(activeInfo.tabId).catch(() => null);
    if (tab) {
      await maybeAutoUnsuspend(tab);
    }
  }
}

async function handleWindowFocusChanged(windowId) {
  await ready;
  if (windowId === chrome.windows.WINDOW_ID_NONE) {
    return;
  }
  const [tab] = await chrome.tabs.query({ active: true, windowId });
  if (tab) {
    await markTabActive(tab.id);
    if ((await ensureSettings()).unsuspendMethod === 'activate') {
      await maybeAutoUnsuspend(tab);
    }
  }
}

async function handleTabRemoved(tabId) {
  await ready;
  delete lastActiveCache[tabId];
  markLastActiveDirty();
  if (!stateIsWritable()) {
    return;
  }
  try {
    await withStateLock(async () => {
      if (!stateIsWritable()) {
        return;
      }
      const state = await loadState();
      if (state && state.suspendedTabs && state.suspendedTabs[tabId]) {
        delete state.suspendedTabs[tabId];
        await saveState(state);
      }
    });
  } catch (err) {
    Logger.warn('handleTabRemoved: state save failed', err);
  }
}

async function handleTabUpdated(tabId, changeInfo, tab) {
  await ready;
  if (changeInfo.status === 'loading') {
    await markTabActive(tabId);
  }
  if (!stateIsWritable()) {
    return;
  }
  try {
    await withStateLock(async () => {
      if (!stateIsWritable()) {
        return;
      }
      const state = await loadState();
      if (!state) return;
      let modified = false;

      if ('discarded' in changeInfo) {
        if (changeInfo.discarded) {
          const settings = await ensureSettings();
          if (!tab.incognito && (await shouldSuspendTab(tab, settings, Date.now()))) {
            state.suspendedTabs[tabId] = {
              url: tab.url,
              title: tab.title,
              windowId: tab.windowId,
              suspendedAt: Date.now(),
              method: 'discard',
            };
            modified = true;
          }
        } else if (state.suspendedTabs[tabId]?.method === 'discard') {
          delete state.suspendedTabs[tabId];
          modified = true;
        }
      }

      if (tab.url && !tab.url.startsWith('chrome-extension://')) {
        if (state.suspendedTabs[tabId]?.method === 'page') {
          if (!tab.url.startsWith(chrome.runtime.getURL('suspended.html'))) {
            delete state.suspendedTabs[tabId];
            modified = true;
          }
        }
      }

      if (modified) {
        await saveState(state);
      }
    });
  } catch (err) {
    Logger.warn('handleTabUpdated: state save failed', err);
  }
}

async function handleAlarm(alarm) {
  await ready;
  if (alarm.name === 'autoSuspend') {
    await autoSuspendTick();
  } else if (alarm.name === 'snapshotTimer') {
    await SnapshotService.createSnapshot();
  } else if (alarm.name === 'stateValidator') {
    await runStateValidationNow('alarm');
  }
}

async function handleIdleStateChange(newState) {
  await ready;
  if (newState === 'locked' || newState === 'idle') {
    await autoSuspendTick();
  }
}

async function markTabActive(tabId) {
  if (!tabId || tabId === chrome.tabs.TAB_ID_NONE) {
    return;
  }
  lastActiveCache[tabId] = Date.now();
  markLastActiveDirty();
}

async function loadLastActive() {
  const stored = await sessionGet(SESSION_LAST_ACTIVE_KEY);
  lastActiveCache = stored[SESSION_LAST_ACTIVE_KEY] || {};
  if (lastActiveFlushTimer) {
    clearTimeout(lastActiveFlushTimer);
    lastActiveFlushTimer = null;
  }
  lastActiveDirty = false;
}

async function autoSuspendTick() {
  await flushLastActiveCache();
  if (!stateIsWritable()) {
    return;
  }
  const settings = await ensureSettings();
  const tabs = await chrome.tabs.query({ windowType: 'normal' });
  const now = Date.now();

  // Prune orphaned lastActiveCache entries for closed tabs
  const validTabIds = new Set(tabs.map(t => t.id));
  let pruned = false;
  for (const tabId of Object.keys(lastActiveCache)) {
    if (!validTabIds.has(Number(tabId))) {
      delete lastActiveCache[tabId];
      pruned = true;
    }
  }
  if (pruned) {
    markLastActiveDirty();
  }

  const candidates = [];
  for (const tab of tabs) {
    if (await shouldSuspendTab(tab, settings, now)) {
      candidates.push(tab);
    }
  }

  const limit = AUTO_SUSPEND_BATCH_LIMIT;
  let index = 0;
  const statePatches = [];
  const worker = async () => {
    while (index < candidates.length) {
      const current = candidates[index++];
      try {
        const result = await suspendTab(current, 'auto', { deferStateWrite: true });
        if (result?.ok && result.patch) {
          statePatches.push(result.patch);
        }
      } catch (err) {
        if (!err.message.includes('No tab with id')) {
          Logger.warn('Failed to auto-suspend tab', { tabId: current.id, err });
        }
      }
    }
  };

  const workers = Array.from({ length: Math.min(limit, candidates.length) }, () => worker());
  await Promise.all(workers);
  if (statePatches.length > 0) {
    await withStateLock(async () => {
      const state = await loadState();
      if (!state) {
        return;
      }
      const allTabs = await chrome.tabs.query({});
      const tabMap = new Map(allTabs.map(tab => [tab.id, tab]));
      const suspendedPagePrefix = chrome.runtime.getURL('suspended.html');
      let modified = false;
      for (const patch of statePatches) {
        if (!patch?.tabId || !patch?.metadata) {
          continue;
        }
        const tab = tabMap.get(patch.tabId);
        if (!tab) {
          continue;
        }
        if (patch.metadata.method === 'discard' && !tab.discarded) {
          continue;
        }
        if (patch.metadata.method === 'page' && !tab.url?.startsWith(suspendedPagePrefix)) {
          continue;
        }
        state.suspendedTabs[patch.tabId] = patch.metadata;
        modified = true;
      }
      if (modified) {
        await saveState(state);
      }
    });
  }
  await flushLastActiveCache();
}

function getSuspendSafetySkipReason(tab) {
  if (!tab || !tab.id) {
    return 'policy-excluded';
  }
  if (tab.incognito) {
    return 'incognito';
  }
  if (!tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('chrome-extension://')) {
    return 'unsafe-url';
  }
  if (!isSafeUrl(tab.url)) {
    return 'unsafe-url';
  }
  return null;
}

function shouldSuspendByAutoPolicy(tab, settings, now) {
  if (settings.excludeActive && tab.active) {
    return false;
  }
  if (settings.excludePinned && tab.pinned) {
    return false;
  }
  if (settings.excludeAudible && tab.audible) {
    return false;
  }
  if (settings.whitelist.length && matchesWhitelist(tab.url, settings.whitelist)) {
    return false;
  }
  const lastActive = lastActiveCache[tab.id] || tab.lastAccessed || now;
  const threshold = settings.autoSuspendMinutes * 60 * 1000;
  if (!threshold || threshold <= 0) {
    return false;
  }
  return now - lastActive >= threshold;
}

async function shouldSuspendTab(tab, settings, now) {
  return getSuspendSafetySkipReason(tab) === null && shouldSuspendByAutoPolicy(tab, settings, now);
}

function buildSuspensionMetadata(tab, reason, method, extras = {}) {
  return {
    url: tab.url,
    title: tab.title,
    windowId: tab.windowId,
    suspendedAt: Date.now(),
    method,
    reason,
    favIconUrl: tab.favIconUrl,
    ...extras,
  };
}

async function suspendTab(tab, reason, { deferStateWrite = false } = {}) {
  const blockedReason = stateWriteBlockedReason();
  if (blockedReason) {
    return { ok: false, locked: true, reason: blockedReason };
  }
  const settings = await ensureSettings();
  if (settings.unsuspendMethod === 'manual') {
    return suspendViaPage(tab, reason, { deferStateWrite });
  }
  return suspendViaDiscard(tab, reason, { deferStateWrite });
}

async function suspendViaDiscard(tab, reason, { deferStateWrite = false } = {}) {
  if (tab.discarded) {
    return { ok: false };
  }
  try {
    await chrome.tabs.discard(tab.id);
    const updated = await chrome.tabs.get(tab.id);
    if (!updated.discarded) {
      throw new Error('Tab was not discarded');
    }

    // Re-check shortly after to detect silent reloads
    await new Promise(resolve => setTimeout(resolve, 1000));
    const rechecked = await chrome.tabs.get(tab.id).catch(() => null);
    if (!rechecked || !rechecked.discarded) {
      Logger.warn('Discard did not persist; falling back to page suspension', { tabId: tab.id, url: tab.url });
      return suspendViaPage(tab, reason, { deferStateWrite });
    }

    const metadata = buildSuspensionMetadata(tab, reason, 'discard');
    if (deferStateWrite) {
      return {
        ok: true,
        patch: {
          tabId: tab.id,
          metadata,
        },
      };
    }

    await withStateLock(async () => {
      const state = await loadState();
      if (state) {
        state.suspendedTabs[tab.id] = metadata;
        await saveState(state);
      }
    });
    return { ok: true };
  } catch (err) {
    Logger.warn('Failed to discard tab, falling back to parked page suspension', err);
    return suspendViaPage(tab, reason, { deferStateWrite });
  }
}

async function suspendViaPage(tab, reason, { deferStateWrite = false } = {}) {
  const settings = await ensureSettings();
  const embedOriginalUrl = settings.embedOriginalUrl !== false;

  const token = crypto.randomUUID();
  const now = Date.now();
  const metadata = buildSuspensionMetadata(tab, reason, 'page', {
    token,
    tokenIssuedAt: now,
    tokenUsed: false,
  });
  const suspendedUrl = new URL(chrome.runtime.getURL('suspended.html'));
  suspendedUrl.searchParams.set('token', token);
  if (embedOriginalUrl) {
    suspendedUrl.searchParams.set('url', tab.url);
    if (tab.title) {
      suspendedUrl.searchParams.set('title', tab.title);
    }
    if (tab.favIconUrl) {
      suspendedUrl.searchParams.set('favicon', tab.favIconUrl);
    }
  }

  try {
    await chrome.tabs.update(tab.id, { url: suspendedUrl.toString() });
    if (deferStateWrite) {
      return {
        ok: true,
        patch: {
          tabId: tab.id,
          metadata,
        },
      };
    }
    await withStateLock(async () => {
      const state = await loadState();
      if (!state) {
        Logger.warn('State locked; cannot record suspension');
        return;
      }
      state.suspendedTabs[tab.id] = metadata;
      await saveState(state);
    });
    return { ok: true };
  } catch (err) {
    Logger.warn('Failed to navigate tab to parked page', err);
    return { ok: false };
  }
}

async function maybeAutoUnsuspend(tab) {
  if (!stateIsWritable()) {
    return;
  }
  await withStateLock(async () => {
    if (!stateIsWritable()) {
      return;
    }
    const state = await loadState();
    if (!state || !state.suspendedTabs[tab.id]) {
      return;
    }
    const metadata = state.suspendedTabs[tab.id];
    if ((await ensureSettings()).unsuspendMethod !== 'activate') {
      return;
    }
    const resumed = await resumeSuspendedTab(tab.id, metadata, { focus: false });
    if (resumed) {
      delete state.suspendedTabs[tab.id];
      await saveState(state);
    }
  });
}

async function scheduleAutoSuspendAlarm() {
  const settings = await ensureSettings();
  const threshold = Math.max(1, Math.round(settings.autoSuspendMinutes));
  const period = Math.min(MAX_ALARM_PERIOD_MINUTES, Math.max(1, Math.round(threshold / ALARM_PERIOD_DIVISOR)));
  await chrome.alarms.clear('autoSuspend');
  await chrome.alarms.create('autoSuspend', {
    delayInMinutes: period,
    periodInMinutes: period,
  });
}

async function scheduleStateValidationAlarm() {
  // Run every 15 minutes to keep state clean
  await chrome.alarms.clear('stateValidator');
  await chrome.alarms.create('stateValidator', {
    periodInMinutes: 15,
  });
}

async function resumeSuspendedTab(tabId, metadata, { focus = true, reloadIfDiscarded = false } = {}) {
  if (!metadata) {
    return false;
  }
  try {
    if (metadata.method === 'discard') {
      if (focus) {
        await chrome.tabs.update(tabId, { active: true });
      } else if (reloadIfDiscarded) {
        await chrome.tabs.reload(tabId);
      }
      // Chrome will reload discarded tabs automatically on activation.
      return true;
    }
    const updateInfo = { url: metadata.url };
    if (focus) {
      updateInfo.active = true;
    }
    await chrome.tabs.update(tabId, updateInfo);
    return true;
  } catch (err) {
    Logger.warn('Failed to resume suspended tab', err);
    return false;
  }
}

function bytesToBase64Url(bytes) {
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const chunk = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode(...chunk);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function encodedBytesToUint8(value) {
  if (Array.isArray(value)) {
    return new Uint8Array(value);
  }
  if (typeof value !== 'string' || !value) {
    throw new Error('Invalid payload encoding');
  }
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/');
  const padLength = (4 - (base64.length % 4)) % 4;
  const binary = atob(base64 + '='.repeat(padLength));
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function encryptPayload(data) {
  const key = getCryptoKey();
  if (!key) {
    throw new Error('Encryption key not available');
  }
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(JSON.stringify(data));
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, encoded);
  return {
    iv: bytesToBase64Url(iv),
    ct: bytesToBase64Url(new Uint8Array(cipher)),
  };
}

async function decryptPayload(payload) {
  const key = getCryptoKey();
  if (!key) {
    throw new Error('Encryption key not available');
  }
  const iv = encodedBytesToUint8(payload.iv);
  const ct = encodedBytesToUint8(payload.ct);
  const plainBuffer = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  const text = new TextDecoder().decode(plainBuffer);
  return JSON.parse(text);
}

async function reconcilePendingStateAfterUnlock() {
  // Create a lock promise that resolves when this function completes
  let releaseLock;
  const lockPromise = new Promise(resolve => { releaseLock = resolve; });
  // Chain it to the existing lock to ensure sequential execution if multiple unlocks happen (unlikely but safe)
  const previousLock = reconciliationLock;
  reconciliationLock = lockPromise;

  try {
    await previousLock; // Wait for any previous operation

    const stored = await chrome.storage.local.get(STATE_KEY);
    const payload = stored[STATE_KEY];
    let merged = { suspendedTabs: {} };

    if (payload && payload.ct) {
      try {
        const decrypted = decodeStateAny(await decryptPayload(payload));
        clearStateCorruption();
        merged = decrypted;
      } catch (err) {
        Logger.warn('Failed to decrypt stored state after unlock', err);
        markStateCorrupt('corrupt-state');
        cachedState = cachedState || { suspendedTabs: {} };
        return;
      }
    } else if (payload && payload.plain) {
      clearStateCorruption();
      merged = decodeStateAny(payload.plain);
    } else {
      clearStateCorruption();
    }

    cachedState = merged;
    try {
      await saveStateInternal(merged);
    } catch (saveErr) {
      Logger.error('Failed to re-encrypt state after unlock', saveErr);
      markStateCorrupt('corrupt-state');
    }

  } finally {
    releaseLock();
  }
}

async function unlockAndReconcile(passkey) {
  const result = await decryptWithPasskey(passkey);
  if (result?.ok) {
    await reconcilePendingStateAfterUnlock();
    if (stateIsCorrupt()) {
      return { ok: false, error: 'corrupt-state' };
    }
  }
  return result;
}

async function resetEncryption() {
  await clearSessionKey();
  await clearKeyRecords();
  clearStateCorruption();
  clearSnapshotDetailsCache();
  cachedState = null;
  await chrome.storage.local.remove([STATE_KEY, 'backups']);
  await clearLegacyPendingState();

  const settings = await ensureSettings();
  await generateAndPersistDataKey(settings.encryption.cloudBackupEnabled);
  cachedState = { suspendedTabs: {} };
  await saveState(cachedState);
  return { ok: true };
}

function handleMessage(message, sender, sendResponse) {
  (async () => {
    try {
    // Wait for init before handling messages that might depend on settings/state
    await ready;

    if (initError) {
      sendResponse({ ok: false, error: 'initialization-failed' });
      return;
    }

    switch (message.type) {
      case 'GET_SETTINGS': {
        const settings = await ensureSettings();
        sendResponse(settings);
        break;
      }
      case 'GET_ENCRYPTION_STATUS': {
        const settings = await ensureSettings();
        const record = await loadKeyRecord(settings.encryption.cloudBackupEnabled);
        const payload = getEncryptionStatusPayload(settings, record);
        sendResponse(payload);
        break;
      }
      case 'SAVE_SETTINGS': {
        const { payload } = message;
        await saveSettings(payload);

        // Check if we need to auto-unsuspend tabs based on new whitelist
        if (payload.whitelist && payload.whitelist.length > 0) {
          unsuspendWhitelistedTabs(payload.whitelist).catch(err => {
            Logger.error('Failed to auto-unsuspend whitelisted tabs', err);
          });
        }

        sendResponse({ ok: true });
        break;
      }
      case 'UNLOCK_WITH_PASSKEY': {
        const result = await unlockAndReconcile(message.passkey);
        sendResponse(result);
        break;
      }
      case 'RETRY_IMPORT_KEY': {
        const result = await retryImportPlaintextKey();
        if (result?.ok) {
          await reconcilePendingStateAfterUnlock();
        }
        sendResponse(result);
        break;
      }
      case 'SET_PASSKEY': {
        const result = await persistPasskey(message.passkey);
        sendResponse(result);
        break;
      }
      case 'REMOVE_PASSKEY': {
        const result = await clearPasskey();
        sendResponse(result);
        break;
      }
      case 'SET_CLOUD_BACKUP': {
        const result = await updateCloudBackup(message.enabled);
        sendResponse(result);
        break;
      }
      case 'RESET_ENCRYPTION': {
        const result = await resetEncryption();
        sendResponse(result);
        break;
      }
      case 'SUSPEND_CURRENT': {
        if (!stateIsWritable()) {
          sendResponse(lockedMutationResponse({ skip: true }));
          break;
        }
        const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
        if (!tab) {
          // No active tab available in current window.
          sendResponse({ ok: true, skipped: 'policy-excluded' });
          break;
        }
        // Manual current-tab suspension enforces only safety checks:
        // - incognito => skipped: 'incognito'
        // - unsafe/internal URL => skipped: 'unsafe-url'
        // Auto policy rules (active/pinned/audible/whitelist/inactive threshold) do not apply here.
        const safetySkip = getSuspendSafetySkipReason(tab);
        if (safetySkip) {
          sendResponse({ ok: true, skipped: safetySkip });
          break;
        }
        const result = await suspendTab(tab, 'manual');
        if (result?.locked) {
          sendResponse(lockedMutationResponse({ skip: true }));
          break;
        }
        sendResponse({ ok: true });
        break;
      }
      case 'SUSPEND_INACTIVE': {
        if (!stateIsWritable()) {
          sendResponse(lockedMutationResponse({ skip: true }));
          break;
        }
        const tabs = await chrome.tabs.query({ windowType: 'normal' });
        const settings = await ensureSettings();
        const patches = [];
        for (const tab of tabs) {
          if (tab.active) continue;
          if (await shouldSuspendTab(tab, settings, Date.now())) {
            try {
              const result = await suspendTab(tab, 'manual', { deferStateWrite: true });
              if (result?.ok && result.patch) {
                patches.push(result.patch);
              }
            } catch (err) {
              if (!err.message?.includes('No tab with id')) {
                Logger.warn('Failed to suspend inactive tab', { tabId: tab.id, err });
              }
            }
          }
        }
        if (patches.length > 0) {
          await withStateLock(async () => {
            const state = await loadState();
            if (!state) return;
            const allTabs = await chrome.tabs.query({});
            const tabMap = new Map(allTabs.map(t => [t.id, t]));
            const prefix = chrome.runtime.getURL('suspended.html');
            for (const patch of patches) {
              if (!patch?.tabId || !patch?.metadata) continue;
              const t = tabMap.get(patch.tabId);
              if (!t) continue;
              if (patch.metadata.method === 'discard' && !t.discarded) continue;
              if (patch.metadata.method === 'page' && !t.url?.startsWith(prefix)) continue;
              state.suspendedTabs[patch.tabId] = patch.metadata;
            }
            await saveState(state);
          });
        }
        sendResponse({ ok: true });
        break;
      }
      case 'RESUME_TAB': {
        if (!stateIsWritable()) {
          sendResponse(lockedMutationResponse());
          break;
        }
        if (typeof message.tabId === 'number' && Number.isInteger(message.tabId)) {
          await withStateLock(async () => {
            if (!stateIsWritable()) {
              return;
            }
            const state = await loadState();
            const entry = state?.suspendedTabs?.[message.tabId];
            if (entry) {
              const resumed = await resumeSuspendedTab(message.tabId, entry, { focus: true });
              if (resumed) {
                delete state.suspendedTabs[message.tabId];
                await saveState(state);
              }
            } else {
              try {
                await chrome.tabs.update(message.tabId, { active: true });
              } catch (err) {
                Logger.warn('Failed to activate tab during resume fallback', err);
              }
            }
          });
        }
        sendResponse({ ok: true });
        break;
      }
      case 'RESUME_ALL': {
        if (!stateIsWritable()) {
          sendResponse(lockedMutationResponse());
          break;
        }
        await withStateLock(async () => {
          if (!stateIsWritable()) {
            return;
          }
          const state = await loadState();
          if (!state || !state.suspendedTabs) {
            return;
          }
          const entries = Object.entries(state.suspendedTabs);
          for (const [tabIdStr, entry] of entries) {
            const tabId = Number(tabIdStr);
            const resumed = await resumeSuspendedTab(tabId, entry, { focus: false, reloadIfDiscarded: true });
            if (resumed) {
              delete state.suspendedTabs[tabId];
            }
          }
          await saveState(state);
        });
        sendResponse({ ok: true });
        break;
      }
      case 'GET_STATE': {
        const state = await withStateLock(async () => loadState());
        if (stateIsCorrupt()) {
          sendResponse({ ok: false, locked: true, reason: stateLockReason() });
          break;
        }
        if (stateIsLocked()) {
          sendResponse({ ok: false, locked: true, reason: stateLockReason() });
          break;
        }
        maybeScheduleValidation('get-state');
        sendResponse({ ok: true, locked: false, state });
        break;
      }
      case 'SUSPENDED_VIEW_INFO': {
        const state = await withStateLock(() => loadState());
        if (!state || stateIsLocked() || stateIsCorrupt()) {
          sendResponse({ ok: false, locked: true, reason: stateLockReason() });
          break;
        }
        const { token } = message;
        let entry;
        const maybeId = Number(message.tabId);
        if (Number.isInteger(maybeId)) {
          const tabEntry = state.suspendedTabs?.[maybeId];
          if (tabEntry?.token === token) {
            entry = tabEntry;
          }
        }
        if (!entry && token) {
          entry = Object.values(state.suspendedTabs || {}).find(item => item.token === token);
        }
        if (!entry) {
          sendResponse({ found: false });
          break;
        }
        sendResponse({ found: true, info: entry });
        break;
      }
      case 'UNSUSPEND_TOKEN': {
        const tabId = Number(message.tabId);
        if (!Number.isInteger(tabId)) {
          sendResponse({ ok: false });
          break;
        }
        const tokenResult = await processUnsuspendTokenMessage({
          tabId,
          token: message.token,
          tokenTtlMs: TOKEN_TTL_MS,
          stateIsWritable,
          lockedMutationResponse,
          withStateLock,
          loadState,
          saveState,
          resumeSuspendedTab,
        });
        sendResponse(tokenResult);
        break;
      }
      case 'GET_SNAPSHOTS': {
        if (encryptionIsLocked() || !hasCryptoKey()) {
          sendResponse({ ok: false, locked: true, reason: encryptionReason() });
          break;
        }
        const snapshots = await SnapshotService.getSnapshots();
        sendResponse({ snapshots });
        break;
      }
      case 'GET_SNAPSHOT_DETAILS': {
        if (encryptionIsLocked() || !hasCryptoKey()) {
          sendResponse({ ok: false, locked: true, reason: encryptionReason() });
          break;
        }
        try {
          const cachedTabs = readSnapshotDetailsCache(message.snapshotId);
          if (cachedTabs) {
            sendResponse({ ok: true, tabs: cachedTabs });
            break;
          }
          const snapshot = await getSnapshotById(message.snapshotId);
          if (!snapshot) {
            sendResponse({ ok: false, error: 'not-found' });
            break;
          }
          const state = await getSnapshotData(snapshot);
          setSnapshotDetailsCache(snapshot.id, state.suspendedTabs || {});
          sendResponse({ ok: true, tabs: state.suspendedTabs || {} });
        } catch (err) {
          Logger.error('Failed to get snapshot details', err);
          sendResponse({ ok: false, error: err.message });
        }
        break;
      }
      case 'RESTORE_SNAPSHOT': {
        if (encryptionIsLocked() || !hasCryptoKey()) {
          sendResponse({ ok: false, locked: true, reason: encryptionReason() });
          break;
        }
        try {
          await SnapshotService.restoreSnapshot(message.snapshotId);
          sendResponse({ ok: true });
        } catch (err) {
          Logger.error('Restore failed', err);
          sendResponse({ ok: false, error: err.message });
        }
        break;
      }
      case 'OPEN_SNAPSHOT': {
        try {
          const result = await openSnapshotTabs(message.snapshotId, { unsuspend: !!message.unsuspend });
          sendResponse(result);
        } catch (err) {
          Logger.error('Open snapshot failed', err);
          sendResponse({ ok: false, error: err.message });
        }
        break;
      }
      default:
        sendResponse({ ok: false, error: 'Unknown message' });
    }
    } catch (err) {
      Logger.error('Uncaught error in message handler', {
        type: message.type, error: err?.message
      });
      try {
        sendResponse({ ok: false, error: 'internal-error' });
      } catch (_) { /* sendResponse already called */ }
    }
  })();
  return true;
}
