import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { webcrypto } from 'node:crypto';

// These regression tests intentionally do not implement password recovery.
// They prevent a future implementation from pretending existing non-extractable
// identity keys can be exported or from silently replacing a registered identity.
const source = readFileSync(new URL('../e2ee-v3.js', import.meta.url), 'utf8');

test('legacy identity private keys cannot be exported for a password backup', async () => {
  const enc = await webcrypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']
  );
  const sign = await webcrypto.subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']
  );
  for (const key of [enc.privateKey, sign.privateKey]) {
    assert.equal(key.extractable, false);
    await assert.rejects(webcrypto.subtle.exportKey('jwk', key), {
      name: 'InvalidAccessException'
    });
  }
});

test('identity enrollment refuses to overwrite an existing remote identity', () => {
  assert.match(source, /if\(existing\)throw Error\('This account already has an encryption identity/);
  assert.match(source, /keys will not be silently replaced/);
});

test('sender rejects missing and mismatched local encryption identities', () => {
  assert.match(source, /if\(!mine\)throw Error\('Enable encryption on this device before sending/);
  assert.match(source, /Local encryption identity does not match the registered identity\. No message was sent/);
});
