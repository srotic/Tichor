import test from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {signPersistentTrust,verifyPersistentTrust} from '../tsa-persistent-device-trust.mjs';
if(!globalThis.crypto)globalThis.crypto=webcrypto;
test('persistent trust binds account, device, revision and both keys',async()=>{
 const root=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
 const enc=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']);
 const signing=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
 const input={account:crypto.randomUUID(),device:crypto.randomUUID(),revision:1,encryptionKey:await crypto.subtle.exportKey('jwk',enc.publicKey),signingKey:await crypto.subtle.exportKey('jwk',signing.publicKey)};
 const pub=await crypto.subtle.exportKey('jwk',root.publicKey);
 const packet=await signPersistentTrust(input,root.privateKey);
 assert.equal((await verifyPersistentTrust(packet,pub,input)).device,input.device);
 for(const change of [{account:crypto.randomUUID()},{device:crypto.randomUUID()},{revision:2},{signingKey:input.encryptionKey}]){
  await assert.rejects(verifyPersistentTrust(packet,pub,{...input,...change}));
 }
 const bad=structuredClone(packet);bad.signature[0]^=1;
 await assert.rejects(verifyPersistentTrust(bad,pub,input));
 assert.equal('expiresAt' in packet.trust,false);
});
