import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readEncryptedIdentityBackup, storeEncryptedIdentityBackupOnce } from '../tase-backup-storage.mjs';
const userId = 'aabbccdd-1111-2222-3333-444455556666';
const backup = { version: 1, kdf: 'PBKDF2-SHA256', iterations: 600000,
  salt: 'salt', iv: 'iv', ciphertext: 'ciphertext' };
test('storage refuses a session for another user', async () => {
  const supa = { auth: { getUser: async () => ({ data: { user: { id: 'wrong' } } }) },
    from: () => { throw Error('Must not query table'); } };
  await assert.rejects(readEncryptedIdentityBackup(supa, userId), /authentication failed/);
  await assert.rejects(storeEncryptedIdentityBackupOnce(supa, userId, backup), /authentication failed/);
});
test('storage uses insert, not upsert or update', async () => {
  let inserted = null;
  const supa = { auth: { getUser: async () => ({ data: { user: { id: userId } } }) },
    from: name => {
      assert.equal(name, 'tichor_e2ee_identity_backups');
      return { insert: async row => { inserted = row; return { error: null }; } };
    } };
  await storeEncryptedIdentityBackupOnce(supa, userId, backup);
  assert.equal(inserted.user_id, userId);
  assert.equal(inserted.ciphertext, backup.ciphertext);
});
test('storage refuses duplicate record without replacing ciphertext', async () => {
  const supa = { auth: { getUser: async () => ({ data: { user: { id: userId } } }) },
    from: () => ({ insert: async () => ({ error: { message: 'duplicate key' } }) }) };
  await assert.rejects(storeEncryptedIdentityBackupOnce(supa, userId, backup), /not stored/);
});
