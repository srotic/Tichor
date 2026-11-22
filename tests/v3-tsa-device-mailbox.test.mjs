import {test} from 'node:test';
import assert from 'node:assert/strict';
import {encryptDeviceCopies} from '../tsa-multidevice-envelope.mjs';
import {prepareDeviceEnvelopeRows,previewEncryptedMailboxBatch,previewVerifiedEncryptedMailboxBatch,publishEncryptedMailboxBatch,receiveEncryptedMailbox} from '../tsa-device-mailbox.mjs';

const sender='11111111-1111-4111-8111-111111111111',recipient='22222222-2222-4222-8222-222222222222';
const devices=['33333333-3333-4333-8333-333333333333','44444444-4444-4444-8444-444444444444'];
const messageId='55555555-5555-4555-8555-555555555555';
async function packet(){
 const signature=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
 const targets=await Promise.all(devices.map(async(device,index)=>({
  account:index===0?sender:recipient,device,authorized:true,
  encryptionKey:await crypto.subtle.exportKey('jwk',(await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits'])).publicKey)
 })));
 return encryptDeviceCopies({sender,recipient,messageId,text:'text ciphertext only',targets,signingKey:signature.privateKey});
}
test('mailbox fanout rows contain only signed ciphertext and device routing identifiers',async()=>{
 const encrypted=await packet();
 const rows=prepareDeviceEnvelopeRows({packet:encrypted});
 assert.equal(rows.length,2);
 assert.deepEqual(rows.map(x=>x.recipient_id),[sender,recipient]);
 assert.ok(rows.every(x=>x.envelope===encrypted));
 assert.ok(!JSON.stringify(rows).includes('text ciphertext only'));
 assert.equal((await previewEncryptedMailboxBatch(encrypted)).state,'ciphertext-batch-preview-not-sent');
});
test('plaintext, malformed destinations and premature authorization activation fail',async()=>{
 const encrypted=await packet();
 assert.throws(()=>prepareDeviceEnvelopeRows({packet:{v:1,protocol:'TSA-experimental-multi-device-text',from:sender,to:recipient,messageId,copies:[],signature:'x'}}),/Invalid TSA ciphertext/);
 assert.throws(()=>prepareDeviceEnvelopeRows({packet:encrypted,deliveryAuthorized:true}),/not permitted/);
 const wrong=structuredClone(encrypted);wrong.copies[1].account='77777777-7777-4777-8777-777777777777';
 assert.throws(()=>prepareDeviceEnvelopeRows({packet:wrong}),/Unrecognized/);
 await assert.rejects(publishEncryptedMailboxBatch(),/disabled/);
 await assert.rejects(receiveEncryptedMailbox(),/disabled/);
});

test('local fanout preflight authenticates ciphertext but never enables delivery',async()=>{
 const signer=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
 const senderKey=await crypto.subtle.exportKey('jwk',signer.publicKey);
 const owner=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
 const peer=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
 const targets=[
  {account:sender,device:devices[0],authorized:true,encryptionKey:await crypto.subtle.exportKey('jwk',owner.publicKey)},
  {account:recipient,device:devices[1],authorized:true,encryptionKey:await crypto.subtle.exportKey('jwk',peer.publicKey)}
 ];
 const encrypted=await encryptDeviceCopies({sender,recipient,messageId,text:'secret preflight',targets,signingKey:signer.privateKey});
 const localDevice={recipientAccount:recipient,deviceId:devices[1],privateKey:peer.privateKey,senderPublicKey:senderKey};
 assert.deepEqual(await previewVerifiedEncryptedMailboxBatch({packet:encrypted,localDevice}),{
  state:'locally-verified-ciphertext-preview-not-sent',rowCount:2,deliveryAuthorized:false
 });
 const tampered=structuredClone(encrypted);tampered.copies[1].ct=(tampered.copies[1].ct[0]==='A'?'B':'A')+tampered.copies[1].ct.slice(1);
 await assert.rejects(previewVerifiedEncryptedMailboxBatch({packet:tampered,localDevice}),/signature invalid/);
 const impostor=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
 await assert.rejects(previewVerifiedEncryptedMailboxBatch({packet:encrypted,localDevice:{...localDevice,senderPublicKey:await crypto.subtle.exportKey('jwk',impostor.publicKey)}}),/signature invalid/);
 await assert.rejects(previewVerifiedEncryptedMailboxBatch({packet:encrypted,localDevice:{...localDevice,deviceId:devices[0]}}),/No ciphertext for this device/);
 const unaffected=await previewVerifiedEncryptedMailboxBatch({packet:encrypted,localDevice:{...localDevice,packet:tampered}});
 assert.equal(unaffected.deliveryAuthorized,false);
 await assert.rejects(publishEncryptedMailboxBatch(),/disabled/);
});
