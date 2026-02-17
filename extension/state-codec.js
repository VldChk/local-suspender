const METHOD_DISCARD = 0;
const METHOD_PAGE = 1;

function toFiniteNumber(value, fallback = 0) {
  const num = Number(value);
  return Number.isFinite(num) ? num : fallback;
}

function decodeMethod(value, fallback = 'page') {
  if (value === METHOD_DISCARD || value === 'discard') {
    return 'discard';
  }
  if (value === METHOD_PAGE || value === 'page') {
    return 'page';
  }
  return fallback;
}

function normalizeEntry(entry) {
  if (!entry || typeof entry !== 'object' || typeof entry.url !== 'string' || !entry.url) {
    return null;
  }
  const method = decodeMethod(
    entry.method,
    entry.token || entry.tokenIssuedAt ? 'page' : 'discard'
  );
  const normalized = {
    url: entry.url,
    title: typeof entry.title === 'string' ? entry.title : '',
    windowId: toFiniteNumber(entry.windowId, 0),
    suspendedAt: toFiniteNumber(entry.suspendedAt, 0),
    method,
    reason: typeof entry.reason === 'string' ? entry.reason : '',
    favIconUrl: typeof entry.favIconUrl === 'string' ? entry.favIconUrl : '',
  };
  if (method === 'page') {
    normalized.token = typeof entry.token === 'string' ? entry.token : '';
    normalized.tokenIssuedAt = toFiniteNumber(entry.tokenIssuedAt, normalized.suspendedAt);
    normalized.tokenUsed = !!entry.tokenUsed;
  }
  return normalized;
}

function decodeLegacyState(raw) {
  const suspendedTabs = {};
  const source = raw?.suspendedTabs;
  if (!source || typeof source !== 'object') {
    return { suspendedTabs };
  }
  for (const [tabId, entry] of Object.entries(source)) {
    const normalized = normalizeEntry(entry);
    if (!normalized) continue;
    suspendedTabs[tabId] = normalized;
  }
  return { suspendedTabs };
}

function decodeCompactState(raw) {
  const suspendedTabs = {};
  const tuples = Array.isArray(raw?.tabs) ? raw.tabs : [];
  for (const tuple of tuples) {
    if (!Array.isArray(tuple) || tuple.length < 11) {
      continue;
    }
    const tabId = toFiniteNumber(tuple[0], NaN);
    if (!Number.isInteger(tabId) || tabId <= 0) {
      continue;
    }
    const method = decodeMethod(tuple[5]);
    const entry = {
      url: typeof tuple[1] === 'string' ? tuple[1] : '',
      title: typeof tuple[2] === 'string' ? tuple[2] : '',
      windowId: toFiniteNumber(tuple[3], 0),
      suspendedAt: toFiniteNumber(tuple[4], 0),
      method,
      reason: typeof tuple[6] === 'string' ? tuple[6] : '',
      favIconUrl: typeof tuple[10] === 'string' ? tuple[10] : '',
    };
    if (!entry.url) {
      continue;
    }
    if (method === 'page') {
      entry.token = typeof tuple[7] === 'string' ? tuple[7] : '';
      entry.tokenIssuedAt = toFiniteNumber(tuple[8], entry.suspendedAt);
      entry.tokenUsed = tuple[9] === 1 || tuple[9] === true;
    }
    suspendedTabs[tabId] = entry;
  }
  return { suspendedTabs };
}

export function decodeStateAny(raw) {
  if (!raw || typeof raw !== 'object') {
    return { suspendedTabs: {} };
  }
  if (raw.v === 2) {
    return decodeCompactState(raw);
  }
  return decodeLegacyState(raw);
}

function encodeTuple(tabId, entry) {
  const method = decodeMethod(entry.method);
  return [
    Number(tabId),
    typeof entry.url === 'string' ? entry.url : '',
    typeof entry.title === 'string' ? entry.title : '',
    toFiniteNumber(entry.windowId, 0),
    toFiniteNumber(entry.suspendedAt, 0),
    method === 'discard' ? METHOD_DISCARD : METHOD_PAGE,
    typeof entry.reason === 'string' ? entry.reason : '',
    method === 'page' && typeof entry.token === 'string' ? entry.token : '',
    method === 'page' ? toFiniteNumber(entry.tokenIssuedAt, entry.suspendedAt) : 0,
    method === 'page' && entry.tokenUsed ? 1 : 0,
    typeof entry.favIconUrl === 'string' ? entry.favIconUrl : '',
  ];
}

export function encodeStateV2(state) {
  const tabs = [];
  const entries = Object.entries(state?.suspendedTabs || {});
  entries.sort((a, b) => Number(a[0]) - Number(b[0]));
  for (const [tabId, entry] of entries) {
    const normalized = normalizeEntry(entry);
    if (!normalized) {
      continue;
    }
    tabs.push(encodeTuple(tabId, normalized));
  }
  return { v: 2, tabs };
}
