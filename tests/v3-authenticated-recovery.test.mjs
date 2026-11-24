import { test } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { Buffer } from 'node:buffer';
globalThis.crypto = webcrypto;
globalThis.btoa = value => Buffer.from(value, 'binary').toString('base64');
globalThis.atob = value => Buffer.from(value, 'base64').toString('binary');
const { createRecoverableIdentity } = await import('../tase-recoverable-identity.mjs');
const { recoverForAuthenticatedSession } = await import('../tase-authenticated-recovery.mjs');
const userId = 'aabbccdd-1111-2222-3333-444455556666';
const password = 'a long test password for recovery';

test('recovery requires matching authenticated account and a verified device grant', async () => {
  const identity = await createRecoverableIdentity({ userId, password });
  const expectedPublicKeys = {
    encryption_public_jwk: identity.encryption_public_jwk,
    signing_public_jwk: identity.signing_public_jwk
  };
  const args = {
    userId, password, backup: identity.backup, expectedPublicKeys,
    supa: { auth: { getUser: async () => ({ data: { user: { id: userId } }, error: null }) } }
  };
  await assert.rejects(recoverForAuthenticatedSession(args), /authorization service is required/);
  await assert.rejects(recoverForAuthenticatedSession({
    ...args, supa: { auth: { getUser: async () => ({ data: { user: { id: 'other' } } }) } },
    authorizeRestoredDevice: async () => ({ authorized: true })
  }), /does not match/);
  await assert.rejects(recoverForAuthenticatedSession({
    ...args, authorizeRestoredDevice: async () => ({ authorized: false })
  }), /not confirmed/);
  const result = await recoverForAuthenticatedSession({
    ...args, authorizeRestoredDevice: async () => ({ authorized: true })
  });
  assert.equal(result.keys.enc.privateKey.extractable, false);
});
