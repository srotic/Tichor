// TichorConnect V3 password-wrapped key material (development only).
// This module does NOT authorize devices, publish rosters, or change existing identities.
// Call only after an authenticated recovery ceremony; never send password or plaintext
// private key material to Supabase. PBKDF2 is a browser-compatible baseline, NOT a
// substitute for a memory-hard KDF / offline-guessing resistance in production.
const cryptoAPI = globalThis.crypto?.subtle;
const encoder = new TextEncoder();
const decoder = new TextDecoder();
const ITERATIONS = 600_000;
const SALT_LENGTH = 32;
const IV_LENGTH = 12;
const MAX_BACKUP_BYTES = 16_384;
const CONTEXT = 'TichorConnect V3 E2EE identity backup v1';
const encode64 = bytes => {
  let str = '';
  for (const byte of bytes) str += String.fromCharCode(byte);
  return btoa(str);
};
const decode64 = value => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]+={0,2}$/.test(value) || value.length > 40_000)
    throw Error('Invalid backup encoding');
  return Uint8Array.from(atob(value), c => c.charCodeAt(0));
};
async function derive(password, salt) {
  if (!cryptoAPI) throw Error('Secure browser cryptography required');
  if (typeof password !== 'string' || password.length < 12)
    throw Error('A password of at least 12 characters is required for encrypted recovery');
  const material = await cryptoAPI.importKey('raw', encoder.encode(password), 'PBKDF2', false, ['deriveKey']);
  return cryptoAPI.deriveKey(
    { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS },
    material, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}
function aad(userId) {
  if (typeof userId !== 'string' || !/^[a-f0-9-]{36}$/i.test(userId))
    throw Error('Valid account ID required');
  return encoder.encode(CONTEXT + ':' + userId);
}
// Key material must be generated/exported *before* it becomes non-extractable.
// Existing non-extractable identity keys cannot be migrated by this helper.
export async function wrapIdentityMaterial({ userId, password, material }) {
  if (!material || typeof material !== 'object' || Array.isArray(material))
    throw Error('Identity material is required');
  const raw = encoder.encode(JSON.stringify(material));
  if (raw.byteLength > MAX_BACKUP_BYTES) throw Error('Identity material exceeds backup size limit');
  const salt = crypto.getRandomValues(new Uint8Array(SALT_LENGTH));
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH));
  const key = await derive(password, salt);
  const ct = await cryptoAPI.encrypt({ name: 'AES-GCM', iv, additionalData: aad(userId) }, key, raw);
  return { version: 1, kdf: 'PBKDF2-SHA256', iterations: ITERATIONS, salt: encode64(salt), iv: encode64(iv), ciphertext: encode64(new Uint8Array(ct)) };
}
export async function unwrapIdentityMaterial({ userId, password, backup }) {
  if (!backup || backup.version !== 1 || backup.kdf !== 'PBKDF2-SHA256' || backup.iterations !== ITERATIONS)
    throw Error('Unsupported encrypted identity backup');
  const salt = decode64(backup.salt), iv = decode64(backup.iv), ct = decode64(backup.ciphertext);
  if (salt.byteLength !== SALT_LENGTH || iv.byteLength !== IV_LENGTH ||
      ct.byteLength < 17 || ct.byteLength > MAX_BACKUP_BYTES + 16)
    throw Error('Malformed encrypted identity backup');
  const key = await derive(password, salt);
  let raw;
  try {
    raw = await cryptoAPI.decrypt({ name: 'AES-GCM', iv, additionalData: aad(userId) }, key, ct);
  } catch {
    throw Error('Backup decryption failed; password, account, or backup may be incorrect');
  }
  const material = JSON.parse(decoder.decode(raw));
  if (!material || typeof material !== 'object' || Array.isArray(material))
    throw Error('Invalid recovered identity material');
  return material;
}
