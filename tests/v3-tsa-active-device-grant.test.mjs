import {test} from 'node:test';
import assert from 'node:assert/strict';
import {signActiveDeviceGrant,verifyActiveDeviceGrant} from '../tsa-active-device-grant.mjs';
const account='11111111-1111-4111-8111-111111111111';
const device='22222222-2222-4222-8222-222222222222';
const nonce='33333333-3333-4333-8333-333333333333';
const now=1700000000000;
async function fixture(){
 const root=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
 const sign=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
 const enc=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
 const args={account,device,nonce,issuedAt:now,expiresAt:now+3600000,
  encryptionKey:await crypto.subtle.exportKey('jwk',enc.publicKey),
  signingKey:await crypto.subtle.exportKey('jwk',sign.publicKey)};
 return {root,args,packet:await signActiveDeviceGrant(args,root.privateKey),pub:await crypto.subtle.exportKey('jwk',root.publicKey)};
}
test('original root authenticates device keys, nonce and one-hour activation grant',async()=>{
 const f=await fixture();
 assert.equal((await verifyActiveDeviceGrant(f.packet,f.pub,now)).state,'root-signed-active-grant-verified-not-delivery');
 await assert.rejects(verifyActiveDeviceGrant(f.packet,f.pub,now+3600000),/Stale/);
});
test('invalid signatures, key substitution, and changed nonce fail closed',async()=>{
 const f=await fixture();
 const changed=structuredClone(f.packet);changed.grant.nonce='44444444-4444-4444-8444-444444444444';
 await assert.rejects(verifyActiveDeviceGrant(changed,f.pub,now),/Invalid original root authorization signature/);
 const attacker=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
 await assert.rejects(verifyActiveDeviceGrant(f.packet,await crypto.subtle.exportKey('jwk',attacker.publicKey),now),/Invalid original root authorization signature/);
 const substituted=structuredClone(f.packet);substituted.grant.encryptionKey.x=substituted.grant.signingKey.x;
 await assert.rejects(verifyActiveDeviceGrant(substituted,f.pub,now),/Invalid original root authorization signature|Invalid TSA activation public key/);
});
