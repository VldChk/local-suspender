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

    // Strict one-shot policy: consume the token before attempting resume.
    // This remains consumed even if resume fails, preventing token replay.
    entry.tokenUsed = true;
    await saveState(state);

    return { ok: true, entry: { ...entry } };
  });

  if (!prepareResult?.ok) {
    return prepareResult;
  }

  const resumed = await resumeSuspendedTab(tabId, prepareResult.entry, { focus: true });
  if (!resumed) {
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
    delete state.suspendedTabs?.[tabId];
    await saveState(state);
    return { ok: true };
  });

  return finalizeResult;
}
