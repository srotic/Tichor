import {test} from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {renewalPayload,signRenewalChallenge} from '../tase-renewal-proof.mjs';
const account='11111111-1111-4111-8111-111111111111',device='22222222-2222-4222-8222-222222222222';
test('a challenge signature verifies only for the exact account, device, challenge and expiry',async()=>{
 const pair=await webcrypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
 const request={account,device,challenge:'33333333-3333-4333-8333-333333333333',expiresAt:Date.now()+30000};
 const proof=await signRenewalChallenge(pair.privateKey,request);
 const verify=async(x)=>webcrypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},pair.publicKey,new Uint8Array(proof.signature),new TextEncoder().encode(renewalPayload(x)));
 assert.equal(await verify(request),true);
 for(const changed of [{...request,account:device},{...request,device:account},{...request,challenge:account},{...request,expiresAt:request.expiresAt+1}])
  assert.equal(await verify(changed),false);
});
test('a different signing key cannot impersonate an authorized device',async()=>{
 const a=await webcrypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
 const b=await webcrypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
 const request={account,device,challenge:'33333333-3333-4333-8333-333333333333',expiresAt:Date.now()+30000};
 const proof=await signRenewalChallenge(a.privateKey,request);
 assert.equal(await webcrypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},b.publicKey,new Uint8Array(proof.signature),new TextEncoder().encode(renewalPayload(request))),false);
});
