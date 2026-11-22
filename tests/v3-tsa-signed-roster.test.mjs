import {test} from 'node:test';
import assert from 'node:assert/strict';
import {makeTsaRosterBody,signTsaRoster,verifyTsaRoster,previewTsaRosterCoverage} from '../tsa-signed-roster.mjs';
const from='11111111-1111-4111-8111-111111111111',to='22222222-2222-4222-8222-222222222222';
const first='33333333-3333-4333-8333-333333333333',second='44444444-4444-4444-8444-444444444444',third='55555555-5555-4555-8555-555555555555';
const at=1700000000000;
async function fixture(){
 const roots=await Promise.all([0,1].map(()=>crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify'])));
 const keys=await Promise.all([0,1,2].map(async()=>({
  encryptionKey:await crypto.subtle.exportKey('jwk',(await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits'])).publicKey),
  signingKey:await crypto.subtle.exportKey('jwk',(await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify'])).publicKey)
 })));
 const sender=await signTsaRoster(makeTsaRosterBody({account:from,revision:1,issuedAt:at,expiresAt:at+120000,devices:[{device:first,state:'active',...keys[0]}]}),roots[0].privateKey);
 const recipient=await signTsaRoster(makeTsaRosterBody({account:to,revision:2,issuedAt:at,expiresAt:at+120000,devices:[{device:third,state:'active',...keys[2]},{device:second,state:'active',...keys[1]}]}),roots[1].privateKey);
 const [senderRoot,recipientRoot]=await Promise.all(roots.map(r=>crypto.subtle.exportKey('jwk',r.publicKey)));
 const packet={v:1,protocol:'TSA-experimental-multi-device-text',from,to,copies:[
  {account:from,device:first},{account:to,device:second},{account:to,device:third}
 ]};
 return {roots,sender,recipient,senderRoot,recipientRoot,packet};
}
test('signed roster coverage validates every destination and never enables delivery',async()=>{
 const f=await fixture();
 assert.deepEqual(await previewTsaRosterCoverage({packet:f.packet,senderRoster:f.sender,recipientRoster:f.recipient,senderRoot:f.senderRoot,recipientRoot:f.recipientRoot,now:at+1000}),{
  state:'signed-roster-coverage-preview-not-sent',deviceCount:3,senderRevision:1,recipientRevision:2,deliveryAuthorized:false
 });
});
test('signed roster rejects key substitution, expiry, revocation and missing devices',async()=>{
 const f=await fixture();
 const altered=structuredClone(f.recipient);altered.roster.devices.pop();
 await assert.rejects(verifyTsaRoster(altered,f.recipientRoot,at+1000),/roster invalid/);
 await assert.rejects(verifyTsaRoster(f.recipient,f.senderRoot,at+1000),/roster invalid/);
 await assert.rejects(verifyTsaRoster(f.recipient,f.recipientRoot,at+120000),/stale/);
 const missing=structuredClone(f.packet);missing.copies.pop();
 await assert.rejects(previewTsaRosterCoverage({packet:missing,senderRoster:f.sender,recipientRoster:f.recipient,senderRoot:f.senderRoot,recipientRoot:f.recipientRoot,now:at+1000}),/incomplete/);
 const injected=structuredClone(f.packet);injected.copies[1].device='66666666-6666-4666-8666-666666666666';
 await assert.rejects(previewTsaRosterCoverage({packet:injected,senderRoster:f.sender,recipientRoster:f.recipient,senderRoot:f.senderRoot,recipientRoot:f.recipientRoot,now:at+1000}),/unapproved/);
 const duplicate=structuredClone(f.packet);duplicate.copies[2]=duplicate.copies[1];
 await assert.rejects(previewTsaRosterCoverage({packet:duplicate,senderRoster:f.sender,recipientRoster:f.recipient,senderRoot:f.senderRoot,recipientRoot:f.recipientRoot,now:at+1000}),/duplicate/);
 const revoked=structuredClone(f.recipient);revoked.roster.devices[0].state='revoked';
 await assert.rejects(verifyTsaRoster(revoked,f.recipientRoot,at+1000),/inactive/);
});
