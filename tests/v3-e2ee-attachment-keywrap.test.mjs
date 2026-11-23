import {test} from 'node:test';
import assert from 'node:assert/strict';
import {webcrypto} from 'node:crypto';
import {wrapAttachmentKey,unwrapAttachmentKey} from '../e2ee-attachment-keywrap.mjs';
test('wrap attachment key to each distinct approved device, reject unauthorized device',async()=>{
 const a=await webcrypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
 const b=await webcrypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
 const pubA=await webcrypto.subtle.exportKey('jwk',a.publicKey);
 const pubB=await webcrypto.subtle.exportKey('jwk',b.publicKey);
 const key=webcrypto.getRandomValues(new Uint8Array(32));
 const envelope=await wrapAttachmentKey(key,{account:'alice',attachmentId:'file1',verifiedDevices:[{device:'one',state:'active',encryptionKey:pubA},{device:'two',state:'active',encryptionKey:pubB}]});
 assert.deepEqual(await unwrapAttachmentKey(envelope,{account:'alice',device:'one',privateKey:a.privateKey}),key);
 assert.deepEqual(await unwrapAttachmentKey(envelope,{account:'alice',device:'two',privateKey:b.privateKey}),key);
 await assert.rejects(unwrapAttachmentKey(envelope,{account:'alice',device:'one',privateKey:b.privateKey}));
 await assert.rejects(unwrapAttachmentKey(envelope,{account:'bob',device:'one',privateKey:a.privateKey}));
 await assert.rejects(unwrapAttachmentKey(envelope,{account:'alice',device:'three',privateKey:a.privateKey}));
 await assert.rejects(wrapAttachmentKey(key,{account:'alice',attachmentId:'file1',verifiedDevices:[{device:'one',state:'pending',encryptionKey:pubA}]}));
});
