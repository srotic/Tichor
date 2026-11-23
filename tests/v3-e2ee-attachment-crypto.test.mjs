import {test} from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {encryptAttachment,decryptAttachment} from '../e2ee-attachment-crypto.mjs';
test('binary audio, document, image and video bytes round-trip',async()=>{
 for(const mime of ['audio/ogg','application/pdf','image/jpeg','video/mp4']){
  const input=webcrypto.getRandomValues(new Uint8Array(257));
  const encrypted=await encryptAttachment(input,{mime,name:'private.bin'});
  assert.notDeepEqual(encrypted.ciphertext,input);
  assert.deepEqual((await decryptAttachment(encrypted)).data,input);
 }
});
test('tampering with ciphertext, metadata, or key is rejected',async()=>{
 const encrypted=await encryptAttachment(new Uint8Array([1,2,3]),{name:'x'});
 const corrupted=new Uint8Array(encrypted.ciphertext);corrupted[0]^=1;
 await assert.rejects(decryptAttachment({...encrypted,ciphertext:corrupted}));
 await assert.rejects(decryptAttachment({...encrypted,metadata:encrypted.metadata.replace('"x"','"y"')}));
 const wrongKey=new Uint8Array(encrypted.key);wrongKey[0]^=1;
 await assert.rejects(decryptAttachment({...encrypted,key:wrongKey}));
});
test('zero-length and oversized attachments are rejected',async()=>{
 await assert.rejects(encryptAttachment(new Uint8Array()));
 await assert.rejects(encryptAttachment(new Uint8Array(100*1024*1024+1)));
});
