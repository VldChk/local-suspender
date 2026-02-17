import test from 'node:test';
import assert from 'node:assert/strict';
import { processUnsuspendTokenMessage } from './unsuspend-token-flow.js';

function createHarness({
  initialState,
  writable = true,
  resumeResult = true,
  now = 2_000,
} = {}) {
  const state = structuredClone(initialState);
  let saveCount = 0;

  return {
    state,
    get saveCount() {
      return saveCount;
    },
    async invoke({ tabId = 1, token = 'token-1', tokenTtlMs = 100_000 } = {}) {
      return processUnsuspendTokenMessage({
        tabId,
        token,
        tokenTtlMs,
        stateIsWritable: () => writable,
        lockedMutationResponse: () => ({ ok: false, locked: true }),
        withStateLock: async fn => fn(),
        loadState: async () => state,
        saveState: async () => {
          saveCount += 1;
        },
        resumeSuspendedTab: async () => resumeResult,
        now: () => now,
      });
    },
  };
}

test('UNSUSPEND_TOKEN consumes token and deletes suspended entry on first successful use', async () => {
  const harness = createHarness({
    initialState: {
      suspendedTabs: {
        1: { token: 'token-1', tokenUsed: false, tokenIssuedAt: 1_000 },
      },
    },
    resumeResult: true,
  });

  const result = await harness.invoke();

  assert.deepEqual(result, { ok: true });
  assert.equal(harness.state.suspendedTabs[1], undefined);
  assert.equal(harness.saveCount, 2);
});

test('UNSUSPEND_TOKEN rejects second use as used', async () => {
  const harness = createHarness({
    initialState: {
      suspendedTabs: {
        1: { token: 'token-1', tokenUsed: false, tokenIssuedAt: 1_000 },
      },
    },
    resumeResult: false,
  });

  const firstAttempt = await harness.invoke();
  const secondAttempt = await harness.invoke();

  assert.deepEqual(firstAttempt, { ok: false, error: 'resume-failed' });
  assert.deepEqual(secondAttempt, { ok: false, error: 'used' });
  assert.equal(harness.state.suspendedTabs[1].tokenUsed, true);
  assert.equal(harness.saveCount, 1);
});

test('UNSUSPEND_TOKEN keeps token consumed when resume fails (strict one-shot rollback policy)', async () => {
  const harness = createHarness({
    initialState: {
      suspendedTabs: {
        1: { token: 'token-1', tokenUsed: false, tokenIssuedAt: 1_000 },
      },
    },
    resumeResult: false,
  });

  const result = await harness.invoke();

  assert.deepEqual(result, { ok: false, error: 'resume-failed' });
  assert.equal(harness.state.suspendedTabs[1].tokenUsed, true);
  assert.equal(harness.state.suspendedTabs[1].token, 'token-1');
  assert.equal(harness.saveCount, 1);
});
