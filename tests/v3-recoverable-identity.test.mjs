import { test } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { Buffer } from 'node:buffer';

globalThis.crypto = webcrypto;
globalThis.btoa = value => Buffer.from(value, 'binary').toString('base64');
globalThis.atob = value => Buffer.from(value, 'base64').toString('binary');
const { createRecoverableIdentity, restoreRecoverableIdentity } = await import('../tase-recoverable-identity.mjs');
const userId = 'aabbccdd-1111-2222-3333-444455556666';
const password = 'a long test password for recovery';

test('recoverable identity roundtrip yields non-extractable signing and encryption keys', async () => {
  const created = await createRecoverableIdentity({ userId, password });
  const expectedPublicKeys = {
    encryption_public_jwk: created.encryption_public_jwk,
    signing_public_jwk: created.signing_public_jwk
  };
  assert.equal(created.keys.enc.privateKey.extractable, false);
  assert.equal(created.keys.sign.privateKey.extractable, false);
  const restored = await restoreRecoverableIdentity({
    userId, password, backup: created.backup, expectedPublicKeys
  });
  assert.equal(restored.enc.privateKey.extractable, false);
  assert.equal(restored.sign.privateKey.extractable, false);
  await assert.rejects(restoreRecoverableIdentity({
    userId, password: 'wrong password', backup: created.backup, expectedPublicKeys
  }));
  await assert.rejects(restoreRecoverableIdentity({
    userId, password, backup: created.backup,
    expectedPublicKeys: { ...expectedPublicKeys, signing_public_jwk: created.encryption_public_jwk }
  }));
});
