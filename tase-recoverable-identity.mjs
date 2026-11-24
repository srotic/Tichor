// Development-only bridge between password-wrapped backups and non-extractable
// local identity keys. Not a device authorization or account recovery ceremony.
// The caller must validate the published identity and server authorization before
// using recovered keys. Never persist plaintext JWKs or return them to the server.
import { wrapIdentityMaterial, unwrapIdentityMaterial } from './tase-password-backup.mjs';
const subtle = globalThis.crypto?.subtle;
const encAlg = { name: 'ECDH', namedCurve: 'P-256' };
const signAlg = { name: 'ECDSA', namedCurve: 'P-256' };
function requireCrypto() {
  if (!subtle) throw Error('Secure browser cryptography required');
}
function publicFields(jwk) {
  if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256' ||
      typeof jwk.x !== 'string' || typeof jwk.y !== 'string')
    throw Error('Invalid P-256 identity key');
  return JSON.stringify([jwk.kty, jwk.crv, jwk.x, jwk.y]);
}
async function importPair(privateJwk, publicJwk, algorithm, usages) {
  if (privateJwk?.kty !== 'EC' || privateJwk?.crv !== 'P-256' ||
      typeof privateJwk?.d !== 'string' || privateJwk.d.length === 0 ||
      publicFields(privateJwk) !== publicFields(publicJwk))
    throw Error('Recovered private/public key mismatch');
  const privateKey = await subtle.importKey('jwk', privateJwk, algorithm, false, usages);
  const publicKey = await subtle.importKey('jwk', publicJwk, algorithm, true,
    algorithm.name === 'ECDH' ? [] : ['verify']);
  return { privateKey, publicKey };
}
async function signChallenge(pair) {
  const challenge = crypto.getRandomValues(new Uint8Array(32));
  const signature = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, challenge);
  if (!await subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pair.publicKey, signature, challenge))
    throw Error('Recovered signing key does not match its public key');
}
async function deriveChallenge(pair) {
  const ephemeral = await subtle.generateKey(encAlg, false, ['deriveBits']);
  const a = await subtle.deriveBits({ name: 'ECDH', public: ephemeral.publicKey }, pair.privateKey, 256);
  const b = await subtle.deriveBits({ name: 'ECDH', public: pair.publicKey }, ephemeral.privateKey, 256);
  if (new Uint8Array(a).some((value, i) => value !== new Uint8Array(b)[i]))
    throw Error('Recovered encryption key does not match its public key');
}
export async function createRecoverableIdentity({ userId, password }) {
  requireCrypto();
  const enc = await subtle.generateKey(encAlg, true, ['deriveBits']);
  const sign = await subtle.generateKey(signAlg, true, ['sign', 'verify']);
  const encryption_public_jwk = await subtle.exportKey('jwk', enc.publicKey);
  const signing_public_jwk = await subtle.exportKey('jwk', sign.publicKey);
  const material = {
    encryption_private_jwk: await subtle.exportKey('jwk', enc.privateKey),
    signing_private_jwk: await subtle.exportKey('jwk', sign.privateKey),
    encryption_public_jwk, signing_public_jwk
  };
  const backup = await wrapIdentityMaterial({ userId, password, material });
  const keys = {
    enc: await importPair(material.encryption_private_jwk, encryption_public_jwk, encAlg, ['deriveBits']),
    sign: await importPair(material.signing_private_jwk, signing_public_jwk, signAlg, ['sign'])
  };
  await signChallenge(keys.sign);
  await deriveChallenge(keys.enc);
  return { backup, keys, encryption_public_jwk, signing_public_jwk };
}
export async function restoreRecoverableIdentity({ userId, password, backup, expectedPublicKeys }) {
  requireCrypto();
  if (!expectedPublicKeys?.encryption_public_jwk || !expectedPublicKeys?.signing_public_jwk)
    throw Error('Trusted published identity required before recovery');
  const material = await unwrapIdentityMaterial({ userId, password, backup });
  if (publicFields(material.encryption_public_jwk) !== publicFields(expectedPublicKeys.encryption_public_jwk) ||
      publicFields(material.signing_public_jwk) !== publicFields(expectedPublicKeys.signing_public_jwk))
    throw Error('Recovered identity does not match the trusted published identity');
  const keys = {
    enc: await importPair(material.encryption_private_jwk, material.encryption_public_jwk, encAlg, ['deriveBits']),
    sign: await importPair(material.signing_private_jwk, material.signing_public_jwk, signAlg, ['sign'])
  };
  await signChallenge(keys.sign);
  await deriveChallenge(keys.enc);
  return keys;
}
