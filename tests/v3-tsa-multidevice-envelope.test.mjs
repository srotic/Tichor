import {test} from 'node:test';
import assert from 'node:assert/strict';
import {encryptDeviceCopies,decryptDeviceCopy} from '../tsa-multidevice-envelope.mjs';
const sender='11111111-1111-4111-8111-111111111111', recipient='22222222-2222-4222-8222-222222222222';
const ids=['33333333-3333-4333-8333-333333333333','44444444-4444-4444-8444-444444444444','55555555-5555-4555-8555-555555555555'];
const mid='66666666-6666-4666-8666-666666666666';
async function fixture(){
 const signature=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
 const devices=await Promise.all(ids.map(async(id,index)=>({id,account:index===0?sender:recipient,keys:await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits'])})));
 const targets=await Promise.all(devices.map(async d=>({account:d.account,device:d.id,encryptionKey:await crypto.subtle.exportKey('jwk',d.keys.publicKey),authorized:true})));
 return {signature,devices,targets,senderPublicKey:await crypto.subtle.exportKey('jwk',signature.publicKey)};
}
test('one signed ciphertext envelope decrypts independently on sender and two recipient devices',async()=>{
 const f=await fixture();
 const packet=await encryptDeviceCopies({sender,recipient,messageId:mid,text:'encrypted on all authorized devices',targets:f.targets,signingKey:f.signature.privateKey,createdAt:1700000000000});
 assert.equal(packet.copies.length,3);
 assert.equal(new Set(packet.copies.map(x=>x.ct)).size,3);
 assert.ok(!JSON.stringify(packet).includes('encrypted on all authorized devices'));
 for(const d of f.devices){
  const plaintext=await decryptDeviceCopy({packet,recipientAccount:d.account,deviceId:d.id,privateKey:d.keys.privateKey,senderPublicKey:f.senderPublicKey});
  assert.equal(plaintext,'encrypted on all authorized devices');
 }
});
test('revoked, missing, duplicated and unexpected devices cannot become targets',async()=>{
 const f=await fixture();
 for(const changes of [
  [{...f.targets[0],authorized:false},...f.targets.slice(1)],
  [f.targets[0],{...f.targets[1],revoked:true},f.targets[2]],
  [f.targets[0],f.targets[1],f.targets[1]],
  [f.targets[0],{...f.targets[1],account:'77777777-7777-4777-8777-777777777777'},f.targets[2]]
 ]){
  await assert.rejects(encryptDeviceCopies({sender,recipient,messageId:mid,text:'blocked',targets:changes,signingKey:f.signature.privateKey}),/authorization|Duplicate|destination/);
 }
});
test('tampered ciphertext or recipient metadata fails authenticated decryption',async()=>{
 const f=await fixture();
 const packet=await encryptDeviceCopies({sender,recipient,messageId:mid,text:'private!',targets:f.targets,signingKey:f.signature.privateKey});
 const first=f.devices[1];
 const args={recipientAccount:first.account,deviceId:first.id,privateKey:first.keys.privateKey,senderPublicKey:f.senderPublicKey};
 const tampered=structuredClone(packet);tampered.copies[1].ct='AAAA'+tampered.copies[1].ct.slice(4);
 await assert.rejects(decryptDeviceCopy({packet:tampered,...args}),/signature invalid/);
 const swapped=structuredClone(packet);swapped.copies[1].device=f.devices[2].id;
 await assert.rejects(decryptDeviceCopy({packet:swapped,...args}),/Duplicate|signature invalid/);
 const other=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
 await assert.rejects(decryptDeviceCopy({packet,...args,senderPublicKey:await crypto.subtle.exportKey('jwk',other.publicKey)}),/signature invalid/);
});
