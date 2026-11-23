import { test } from 'node:test';
import assert from 'node:assert/strict';
import { webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { Buffer } from 'node:buffer';

const source = readFileSync(new URL('../tase-password-backup.mjs', import.meta.url), 'utf8');
const originalCrypto = globalThis.crypto;
const originalBtoa = globalThis.btoa;
const originalAtob = globalThis.atob;
globalThis.crypto = webcrypto;
globalThis.btoa = value => Buffer.from(value, 'binary').toString('base64');
globalThis.atob = value => Buffer.from(value, 'base64').toString('binary');
const { wrapIdentityMaterial, unwrapIdentityMaterial } = await import('../tase-password-backup.mjs');
const userId = 'aabbccdd-1111-2222-3333-444455556666';
const otherId = 'aabbccdd-1111-2222-3333-444455556667';
const password = 'a long test password for recovery';

test('password-wrapped identity roundtrip and no plaintext fields', async () => {
  const material = { signing: { kty: 'EC', d: 'PRIVATE-TEST-ONLY' } };
  const backup = await wrapIdentityMaterial({ userId, password, material });
  assert.equal(backup.version, 1);
  assert.ok(!JSON.stringify(backup).includes('PRIVATE-TEST-ONLY'));
  assert.deepEqual(await unwrapIdentityMaterial({ userId, password, backup }), material);
  await assert.rejects(unwrapIdentityMaterial({ userId, password: 'incorrect password', backup }));
  await assert.rejects(unwrapIdentityMaterial({ userId: otherId, password, backup }));
});

test('rejects malformed and downgraded backup parameters', async () => {
  const backup = await wrapIdentityMaterial({ userId, password, material: { example: true } });
  await assert.rejects(unwrapIdentityMaterial({ userId, password, backup: { ...backup, iterations: 1 } }));
  await assert.rejects(unwrapIdentityMaterial({ userId, password, backup: { ...backup, version: 0 } }));
  await assert.rejects(unwrapIdentityMaterial({ userId, password, backup: { ...backup, iv: 'AA==' } }));
});

test('password helper does not perform network requests or enroll a device', () => {
  assert.doesNotMatch(source, /fetch\s*\(|\.from\s*\(|\.functions\.invoke\s*\(/);
  assert.doesNotMatch(source, /localStorage|sessionStorage/);
});
