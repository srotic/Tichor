import {test} from 'node:test';
import assert from 'node:assert/strict';
import {encryptDeviceCopies} from '../tsa-multidevice-envelope.mjs';
import {decryptDeviceCopyOnce,createIndexedDbTsaReplayStore} from '../tsa-replay-receipts.mjs';

const sender='11111111-1111-4111-8111-111111111111';
const recipient='22222222-2222-4222-8222-222222222222';
const senderDevice='33333333-3333-4333-8333-333333333333';
const recipientDevice='44444444-4444-4444-8444-444444444444';
const messageId='55555555-5555-4555-8555-555555555555';
async function fixture(){
 const signing=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
 const first=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
 const second=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
 const packet=await encryptDeviceCopies({
  sender,recipient,messageId,text:'authenticated ciphertext',signingKey:signing.privateKey,
  targets:[
   {account:sender,device:senderDevice,authorized:true,encryptionKey:await crypto.subtle.exportKey('jwk',first.publicKey)},
   {account:recipient,device:recipientDevice,authorized:true,encryptionKey:await crypto.subtle.exportKey('jwk',second.publicKey)}
  ]
 });
 return {packet,args:{recipientAccount:recipient,deviceId:recipientDevice,privateKey:second.privateKey,senderPublicKey:await crypto.subtle.exportKey('jwk',signing.publicKey)}};
}
function store(){
 const seen=new Set();
 return {async claim(key){if(seen.has(key))return false;seen.add(key);return true;},seen};
}
test('authenticated message is accepted once and duplicate replay is rejected',async()=>{
 const f=await fixture(),receipts=store();
 assert.equal(await decryptDeviceCopyOnce({packet:f.packet,...f.args},receipts),'authenticated ciphertext');
 await assert.rejects(decryptDeviceCopyOnce({packet:f.packet,...f.args},receipts),/Duplicate TSA message/);
 assert.equal(receipts.seen.size,1);
});
test('invalid ciphertext never consumes the message receipt',async()=>{
 const f=await fixture(),receipts=store();
 const changed=structuredClone(f.packet);changed.copies[1].ct='AAAA'+changed.copies[1].ct.slice(4);
 await assert.rejects(decryptDeviceCopyOnce({packet:changed,...f.args},receipts),/signature invalid/);
 assert.equal(receipts.seen.size,0);
 assert.equal(await decryptDeviceCopyOnce({packet:f.packet,...f.args},receipts),'authenticated ciphertext');
});
test('unavailable durable receipt storage prevents plaintext disclosure',async()=>{
 const f=await fixture();
 await assert.rejects(decryptDeviceCopyOnce({packet:f.packet,...f.args},{claim:async()=>{throw Error('store unavailable')}}),/store unavailable/);
 assert.throws(()=>createIndexedDbTsaReplayStore(null),/Persistent replay protection unavailable/);
});
