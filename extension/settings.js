export const SETTINGS_KEY = 'settings';

export const defaultSettings = {
  autoSuspendMinutes: 30,
  excludePinned: true,
  excludeAudible: true,
  excludeActive: true,
  whitelist: [],
  unsuspendMethod: 'activate', // 'activate' | 'manual'
  embedOriginalUrl: true, // Whether to include original URL in suspended page for recovery
  encryption: {
    enabled: true,
    iterations: 600000,
  },
};

let cachedSettings = null;

// ABSOLUTELY-LOCAL: allowlist, not spread. A settings blob written by the upstream
// build carries extra key-escrow flags; spreading would preserve them, leaving
// live-looking remote-backup state in storage for an auditor to trip over.
// Naming the fields we accept drops everything else on first read.
function normalizeEncryption(source) {
  return {
    enabled: true,
    iterations: source?.iterations ?? defaultSettings.encryption.iterations,
  };
}

export async function ensureSettings() {
  if (cachedSettings) {
    return cachedSettings;
  }
  const stored = await chrome.storage.local.get(SETTINGS_KEY);
  if (!stored[SETTINGS_KEY]) {
    cachedSettings = { ...defaultSettings };
  } else {
    cachedSettings = {
      ...defaultSettings,
      ...stored[SETTINGS_KEY],
      encryption: normalizeEncryption(stored[SETTINGS_KEY].encryption),
    };
  }
  await chrome.storage.local.set({ [SETTINGS_KEY]: cachedSettings });
  return cachedSettings;
}

export async function saveSettings(nextSettings) {
  cachedSettings = {
    ...defaultSettings,
    ...nextSettings,
    encryption: normalizeEncryption(nextSettings.encryption),
  };
  await chrome.storage.local.set({ [SETTINGS_KEY]: cachedSettings });
}
