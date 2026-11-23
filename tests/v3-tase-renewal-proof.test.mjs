import {test} from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {renewalPayload,signRenewalChallenge} from '../tase-renewal-proof.mjs';
const account='11111111-1111-4111-8111-111111111111';
const device='22222222-2222-4222-8222-222222222222';
test('renewal proof binds account, device and challenge to a domain-separated signature',async()=>{
 const keys=await webcrypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
 const now=Date.now();
 const request={account,device,challenge:'unique-server-challenge',expiresAt:now+60000};
 const result=await signRenewalChallenge(keys.privateKey,request,now);
 const message=new TextEncoder().encode(renewalPayload(request));
 assert.equal(await webcrypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},keys.publicKey,new Uint8Array(result.signature),message),true);
 assert.equal(await webcrypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},keys.publicKey,new Uint8Array(result.signature),new TextEncoder().encode(renewalPayload({...request,device:account}))),false);
});
test('expired and distant challenges are rejected',async()=>{
 const keys=await webcrypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
 const now=Date.now();
 for(const expiresAt of [now-1,now,now+300001])
  await assert.rejects(signRenewalChallenge(keys.privateKey,{account,device,challenge:'x',expiresAt},now),/expired or invalid/);
});
test('extractable keys cannot authorize renewal',async()=>{
 const keys=await webcrypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']);
 await assert.rejects(signRenewalChallenge(keys.privateKey,{account,device,challenge:'x',expiresAt:Date.now()+60000}),/non-extractable/);
});
