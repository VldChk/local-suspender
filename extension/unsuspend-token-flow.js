export async function processUnsuspendTokenMessage({
  tabId,
  token,
  tokenTtlMs,
  stateIsWritable,
  lockedMutationResponse,
  withStateLock,
  loadState,
  saveState,
  resumeSuspendedTab,
  now = () => Date.now(),
}) {
  if (!stateIsWritable()) {
    return lockedMutationResponse();
  }

  const prepareResult = await withStateLock(async () => {
    if (!stateIsWritable()) {
      return lockedMutationResponse();
    }
    const state = await loadState();
    if (!state) {
      return lockedMutationResponse();
    }

    const entry = state.suspendedTabs?.[tabId];
    if (!entry || entry.token !== token) {
      return { ok: false, error: 'invalid-token' };
    }
    if (entry.tokenUsed) {
      return { ok: false, error: 'used' };
    }

    const issuedAt = entry.tokenIssuedAt || entry.suspendedAt;
    if (tokenTtlMs && issuedAt && now() - issuedAt > tokenTtlMs) {
      return { ok: false, error: 'expired' };
    }

    // Reserve the token before resume to block concurrent attempts.
    entry.tokenUsed = true;
    await saveState(state);

    return { ok: true, entry: { ...entry } };
  });

  if (!prepareResult?.ok) {
    return prepareResult;
  }

  const resumed = await resumeSuspendedTab(tabId, prepareResult.entry, { focus: true });
  if (!resumed) {
    await withStateLock(async () => {
      if (!stateIsWritable()) {
        return;
      }
      const state = await loadState();
      if (!state) {
        return;
      }
      const entry = state.suspendedTabs?.[tabId];
      if (entry && entry.token === token && entry.tokenUsed) {
        // Retry-friendly rollback: failed resume should allow another wake attempt.
        entry.tokenUsed = false;
        await saveState(state);
      }
    });
    return { ok: false, error: 'resume-failed' };
  }

  const finalizeResult = await withStateLock(async () => {
    if (!stateIsWritable()) {
      return lockedMutationResponse();
    }
    const state = await loadState();
    if (!state) {
      return lockedMutationResponse();
    }
    const entry = state.suspendedTabs?.[tabId];
    if (!entry || entry.token !== token) {
      return { ok: false, error: 'invalid-token' };
    }
    delete state.suspendedTabs[tabId];
    await saveState(state);
    return { ok: true };
  });

  return finalizeResult;
}
