// TichorConnect V3 staging-only encrypted identity backup storage.
// Caller must authenticate and verify the account before invoking.
// Backups contain ciphertext only; do not pass private keys or passwords.
const TABLE = 'tichor_e2ee_identity_backups';
const fields = 'user_id,backup_version,kdf,iterations,salt,iv,ciphertext';
export async function readEncryptedIdentityBackup(supa, userId) {
  if (!supa?.auth?.getUser || !supa?.from) throw Error('Authenticated client required');
  const { data: auth, error: authError } = await supa.auth.getUser();
  if (authError || auth?.user?.id !== userId) throw Error('Backup account authentication failed');
  const { data, error } = await supa.from(TABLE).select(fields)
    .eq('user_id', userId).eq('backup_version', 1).maybeSingle();
  if (error) throw Error('Unable to read encrypted identity backup: ' + error.message);
  if (!data) return null;
  if (data.user_id !== userId) throw Error('Backup owner mismatch');
  return {
    version: data.backup_version, kdf: data.kdf, iterations: data.iterations,
    salt: data.salt, iv: data.iv, ciphertext: data.ciphertext
  };
}
export async function storeEncryptedIdentityBackupOnce(supa, userId, backup) {
  if (!supa?.auth?.getUser || !supa?.from) throw Error('Authenticated client required');
  const { data: auth, error: authError } = await supa.auth.getUser();
  if (authError || auth?.user?.id !== userId) throw Error('Backup account authentication failed');
  if (!backup || backup.version !== 1 || backup.kdf !== 'PBKDF2-SHA256' ||
      backup.iterations !== 600000 || typeof backup.salt !== 'string' ||
      typeof backup.iv !== 'string' || typeof backup.ciphertext !== 'string')
    throw Error('Unsupported encrypted identity backup');
  const row = {
    user_id: userId, backup_version: backup.version, kdf: backup.kdf,
    iterations: backup.iterations, salt: backup.salt, iv: backup.iv,
    ciphertext: backup.ciphertext
  };
  // Insert-only: duplicate records must fail, never overwrite the old backup.
  const { error } = await supa.from(TABLE).insert(row);
  if (error) throw Error('Encrypted backup was not stored: ' + error.message);
  return true;
}
