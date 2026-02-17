const MAX_LOGS = 1000;
const FLUSH_INTERVAL_MS = 2000;
const FLUSH_BATCH_SIZE = 20;

let pendingLogs = [];
let flushTimer = null;
let flushInFlight = null;

function scheduleFlush(immediate = false) {
  if (immediate) {
    if (flushTimer) {
      clearTimeout(flushTimer);
      flushTimer = null;
    }
    void flushLogs();
    return;
  }
  if (flushTimer) {
    return;
  }
  flushTimer = setTimeout(() => {
    flushTimer = null;
    void flushLogs();
  }, FLUSH_INTERVAL_MS);
}

async function flushLogs() {
  if (flushInFlight) {
    await flushInFlight;
    return;
  }
  if (!pendingLogs.length) {
    return;
  }
  const batch = pendingLogs;
  pendingLogs = [];

  flushInFlight = (async () => {
    try {
      const stored = await chrome.storage.local.get('logs');
      const logs = stored.logs || [];
      logs.push(...batch);
      if (logs.length > MAX_LOGS) {
        logs.splice(0, logs.length - MAX_LOGS);
      }
      await chrome.storage.local.set({ logs });
    } catch (err) {
      // Requeue on failure so logs are not silently dropped.
      pendingLogs = [...batch, ...pendingLogs];
      console.error('Failed to save log', err);
    } finally {
      flushInFlight = null;
      if (pendingLogs.length) {
        scheduleFlush(false);
      }
    }
  })();

  await flushInFlight;
}

const Logger = {
  async log(level, message, data = null) {
    const entry = {
      timestamp: new Date().toISOString(),
      level,
      message,
      data: data instanceof Error ? { message: data.message, stack: data.stack } : data,
    };
    console[level](message, data || '');
    pendingLogs.push(entry);
    if (level === 'error' || pendingLogs.length >= FLUSH_BATCH_SIZE) {
      scheduleFlush(true);
      return;
    }
    scheduleFlush(false);
  },
  info(message, data) { this.log('info', message, data); },
  warn(message, data) { this.log('warn', message, data); },
  error(message, data) { this.log('error', message, data); }
};

export default Logger;
