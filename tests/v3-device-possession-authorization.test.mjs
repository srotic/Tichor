import {test} from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {Buffer} from 'node:buffer';

// Node.js 22 exposes globalThis.crypto as a read-only WebCrypto implementation.
assert.ok(globalThis.crypto?.subtle, 'Node.js WebCrypto must be available');
const source=readFileSync(new URL('../e2ee-device-registry.js',import.meta.url),'utf8');
// The browser file is a classic .js module in a repository without a Node
// package type. Import its exact source as an ESM data URL to execute it.
const {proveLocalDeviceKeyPossession,assertCurrentDeviceAuthorization}=
 await import('data:text/javascript;base64,'+Buffer.from(source).toString('base64'));
const account='11111111-1111-4111-8111-111111111111';
const device='22222222-2222-4222-8222-222222222222';
const now=Date.now();
const registered={user_id:account,device_id:device,state:'active'};
const grant={user_id:account,device_id:device,expires_at_ms:now+60000};
const keys=async(extractable=false)=>webcrypto.subtle.generateKey(
 {name:'ECDSA',namedCurve:'P-256'},extractable,['sign','verify']);

test('valid non-extractable device key proves possession',async()=>{
 const pair=await keys();
 const publicJwk=await webcrypto.subtle.exportKey('jwk',pair.publicKey);
 assert.equal(await proveLocalDeviceKeyPossession(pair.privateKey,publicJwk),true);
});
test('mismatched public key cannot verify a private-key signature',async()=>{
 const a=await keys(),b=await keys();
 await assert.rejects(proveLocalDeviceKeyPossession(a.privateKey,
  await webcrypto.subtle.exportKey('jwk',b.publicKey)),/possession check failed/);
});
test('extractable signing keys are rejected',async()=>{
 const pair=await keys(true);
 await assert.rejects(proveLocalDeviceKeyPossession(pair.privateKey,
  await webcrypto.subtle.exportKey('jwk',pair.publicKey)),/non-extractable/);
});
test('valid active device with unexpired grant is accepted',()=>{
 assert.equal(assertCurrentDeviceAuthorization(registered,grant,account,device,now),true);
});
test('expired or missing grants fail closed',()=>{
 for(const invalid of [{...grant,expires_at_ms:now},{...grant,expires_at_ms:now-1},null]){
  assert.throws(()=>assertCurrentDeviceAuthorization(registered,invalid,account,device,now),/missing or expired/);
 }
});
test('revoked and pending devices fail closed even with valid grants',()=>{
 for(const state of ['revoked','pending']){
  assert.throws(()=>assertCurrentDeviceAuthorization({...registered,state},grant,account,device,now),/not active or has been revoked/);
 }
});
test('authorization bound to another device or account is rejected',()=>{
 assert.throws(()=>assertCurrentDeviceAuthorization(registered,{...grant,device_id:account},account,device,now),/missing or expired/);
 assert.throws(()=>assertCurrentDeviceAuthorization({...registered,user_id:device},grant,account,device,now),/not active or has been revoked/);
});
