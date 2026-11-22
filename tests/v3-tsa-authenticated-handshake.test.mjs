import {test} from 'node:test';
import assert from 'node:assert/strict';
import {initiateTsaHandshake,answerTsaHandshake,verifyTsaHandshake,deriveInitiatorTsaSession,deriveResponderTsaSession} from '../tsa-authenticated-handshake.mjs';
const initiatorAccount='11111111-1111-4111-8111-111111111111';
const initiatorDevice='22222222-2222-4222-8222-222222222222';
const responderAccount='33333333-3333-4333-8333-333333333333';
const responderDevice='44444444-4444-4444-8444-444444444444';
const now=1700000000000;
async function fixture(){
 const a=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
 const b=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
 const first=await initiateTsaHandshake({initiatorAccount,initiatorDevice,responderAccount,responderDevice,signingKey:a.privateKey,now});
 const second=await answerTsaHandshake({request:first.request,signature:first.signature,initiatorSigningPublic:await crypto.subtle.exportKey('jwk',a.publicKey),expectedResponderAccount:responderAccount,expectedResponderDevice:responderDevice,responderSigningKey:b.privateKey,now});
 return {a,b,first,second,async verify(override={}){return verifyTsaHandshake({
  request:first.request,signature:first.signature,response:second.response,responseSignature:second.responseSignature,
  initiatorSigningPublic:await crypto.subtle.exportKey('jwk',a.publicKey),
  responderSigningPublic:await crypto.subtle.exportKey('jwk',b.publicKey),
  expectedInitiatorAccount:initiatorAccount,expectedInitiatorDevice:initiatorDevice,
  expectedResponderAccount:responderAccount,expectedResponderDevice:responderDevice,now,...override
 });}};
}
test('both signed transcripts bind original and responding device identities',async()=>{
 const f=await fixture();
 const result=await f.verify();
 assert.equal(result.state,'authenticated-transcript-only-no-delivery');
 assert.equal(result.initiatorDevice,initiatorDevice);
 assert.equal(result.responderDevice,responderDevice);
});
test('handshake rejects replay after expiry, wrong device, substituted key and tampering',async()=>{
 const f=await fixture();
 await assert.rejects(f.verify({now:now+120000}),/expired/);
 await assert.rejects(f.verify({expectedResponderDevice:initiatorDevice}),/identity mismatch/);
 const attacker=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
 await assert.rejects(f.verify({responderSigningPublic:await crypto.subtle.exportKey('jwk',attacker.publicKey)}),/Unauthenticated TSA responder/);
 const tampered=structuredClone(f.second.response);
 tampered.request.nonce='55555555-5555-4555-8555-555555555555';
 await assert.rejects(f.verify({response:tampered}),/Unauthenticated TSA responder/);
 await assert.rejects(answerTsaHandshake({request:f.first.request,signature:f.first.signature,
  initiatorSigningPublic:await crypto.subtle.exportKey('jwk',attacker.publicKey),
  expectedResponderAccount:responderAccount,expectedResponderDevice:responderDevice,
  responderSigningKey:f.b.privateKey,now}),/Unauthenticated TSA initiator/);
});

test('both verified handshake parties derive the same ephemeral encryption key',async()=>{
 const f=await fixture();
 const base={request:f.first.request,signature:f.first.signature,response:f.second.response,
  responseSignature:f.second.responseSignature,
  initiatorSigningPublic:await crypto.subtle.exportKey('jwk',f.a.publicKey),
  responderSigningPublic:await crypto.subtle.exportKey('jwk',f.b.publicKey),
  expectedInitiatorAccount:initiatorAccount,expectedInitiatorDevice:initiatorDevice,
  expectedResponderAccount:responderAccount,expectedResponderDevice:responderDevice,now};
 const initiator=await deriveInitiatorTsaSession({...base,privateEphemeral:f.first.privateEphemeral});
 const responder=await deriveResponderTsaSession({...base,privateEphemeral:f.second.privateEphemeral});
 assert.equal(initiator.state,'ephemeral-session-prototype-not-delivery-authorized');
 assert.equal(initiator.key.extractable,false);assert.equal(responder.key.extractable,false);
 const iv=crypto.getRandomValues(new Uint8Array(12));
 const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv},initiator.key,new TextEncoder().encode('shared secret'));
 const plain=await crypto.subtle.decrypt({name:'AES-GCM',iv},responder.key,ct);
 assert.equal(new TextDecoder().decode(plain),'shared secret');
 const wrong=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
 const unrelated=await deriveResponderTsaSession({...base,privateEphemeral:wrong.privateKey});
 await assert.rejects(crypto.subtle.decrypt({name:'AES-GCM',iv},unrelated.key,ct));
});
