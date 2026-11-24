import {test} from 'node:test';
import assert from 'node:assert/strict';
import {buildSignedTsaMailboxRequest} from '../tsa-mailbox-client.mjs';
import {encryptDeviceCopies} from '../tsa-multidevice-envelope.mjs';

const account='11111111-1111-4111-8111-111111111111';
const peer='22222222-2222-4222-8222-222222222222';
const device='33333333-3333-4333-8333-333333333333';
const peerDevice='44444444-4444-4444-8444-444444444444';
const now=1700000000000;
async function setup(){
 const signer=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
 const targets=[];
 for(const [acct,dev] of [[account,device],[peer,peerDevice]]){
  const key=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
  targets.push({account:acct,device:dev,authorized:true,encryptionKey:await crypto.subtle.exportKey('jwk',key.publicKey)});
 }
 const packet=await encryptDeviceCopies({sender:account,recipient:peer,messageId:'55555555-5555-4555-8555-555555555555',text:'ciphertext only',
  targets,signingKey:signer.privateKey,createdAt:now});
 return {signer,packet};
}
async function verifyRequest(req,publicKey){
 const body={domain:'Tichor TSA mailbox request v1',action:req.action,account:req.account,device:req.device,nonce:req.nonce,
  issuedAt:req.issuedAt,digest:req.digest};
 const key=await crypto.subtle.importKey('jwk',await crypto.subtle.exportKey('jwk',publicKey),{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
 const binary=Uint8Array.from(atob(req.signature.replace(/-/g,'+').replace(/_/g,'/')+'=='),c=>c.charCodeAt(0));
 return crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key,binary,new TextEncoder().encode(JSON.stringify(body)));
}
test('staging mailbox request signs exact ciphertext hash with a non-extractable device key',async()=>{
 const {signer,packet}=await setup();
 const args={account,device,action:'publish',signingKey:signer.privateKey,packet,issuedAt:now,nonce:'66666666-6666-4666-8666-666666666666'};
 const request=await buildSignedTsaMailboxRequest(args);
 assert.equal(request.packet_text,JSON.stringify(packet));
 assert.equal(await verifyRequest(request,signer.publicKey),true);
 const changed={...request,digest:'not-the-real-packet-hash'};
 assert.equal(await verifyRequest(changed,signer.publicKey),false);
 assert.equal(request.packet_text.includes('ciphertext only'),false);
});
test('receive request signs device identity and does not contain ciphertext',async()=>{
 const {signer}=await setup();
 const request=await buildSignedTsaMailboxRequest({account,device,action:'receive',signingKey:signer.privateKey,
  issuedAt:now,nonce:'77777777-7777-4777-8777-777777777777'});
 assert.equal(request.digest,null);
 assert.equal('packet_text' in request,false);
 assert.equal(await verifyRequest(request,signer.publicKey),true);
 await assert.rejects(buildSignedTsaMailboxRequest({account,device,action:'receive',signingKey:signer.privateKey,packet:{},issuedAt:now}),/Unexpected packet/);
 await assert.rejects(buildSignedTsaMailboxRequest({account,device,action:'publish',signingKey:signer.privateKey,packet:{},issuedAt:now}),/Invalid TSA ciphertext/);
});
test('staging secure mailbox is mandatory for direct text and has no plaintext fallback',async()=>{
 const fs=await import('node:fs');
 const chat=fs.readFileSync(new URL('../chat.html',import.meta.url),'utf8');
 assert.match(chat,/import \{encryptAndPublishTsaTextStaging,receiveTsaVerifiedTextStaging\} from ".\/tsa-mailbox-client\.mjs"/);
 assert.match(chat,/id="tcTsaSecureMode"/);
 assert.match(chat,/const tcTsaSelected=\(\)=>Boolean/);
 assert.match(chat,/tsaToggle.checked=true;tsaToggle.disabled=true/);
 assert.match(chat,/if\(secureMailbox\)\{/);
 assert.match(chat,/if\(!secureMailbox\)/);
 assert.match(chat,/Encryption is mandatory/);
 assert.match(chat,/Encrypted message stored/);
 assert.match(chat,/No plaintext fallback/);
 assert.match(chat,/await encryptAndPublishTsaTextStaging\(client/);
 assert.match(chat,/if\(result.state!=='stored-staging-ciphertext'\)/);
 assert.match(chat,/return;\s*\}\s*finally\s*\{pending\.remove\(\);\}\s*\}\s*throw Error\('Encrypted mailbox delivery did not complete/);
 assert.doesNotMatch(chat.slice(chat.indexOf("$('sendForm').onsubmit="),chat.indexOf("$('refresh').onclick=load")),/from\('chat_messages'\)\.insert\(/);
});

test('experimental mailbox defaults collapsed, preserving chat viewport and immutable receipt timestamps',async()=>{
 const fs=await import('node:fs');
 const html=fs.readFileSync(new URL('../chat.html',import.meta.url),'utf8');
 assert.match(html,/<details id="tcTsaMailboxPanel"/);
 assert.match(html,/<summary[^>]*>🔒 Experimental multi-device secure mailbox/);
 assert.match(html,/id="tcTsaInbox"[^>]*max-height:180px/);
 assert.match(html,/\.update\(\{read_at:new Date\(\)\.toISOString\(\)\}\)/);
 assert.doesNotMatch(html,/\.update\(\{read_at:new Date\(\)\.toISOString\(\),delivered_at:/);
});

test('mandatory secure mode survives peer reload without permitting plaintext',async()=>{
 const fs=await import('node:fs');
 const html=fs.readFileSync(new URL('../chat.html',import.meta.url),'utf8');
 assert.match(html,/tichor-v3-tsa-secure-opt-in:/);
 assert.match(html,/tcTsaSecureMode'\)\.checked=true/);
 assert.match(html,/tcTsaSecureMode'\)\.disabled=true/);
 const send=html.slice(html.indexOf("$('sendForm').onsubmit="),html.indexOf("$('refresh').onclick=load"));
 assert.doesNotMatch(send,/await tcMaintainTsaRoster\(sender\)/);
 assert.match(send,/tcLoadTsaRoster\(sender\)/);
 assert.match(send,/tcLoadTsaRoster\(target\)/);
 const directory=html.slice(html.indexOf('async function tcLoadTsaRoster('),html.indexOf('async function tcReadTsaInbox('));
 assert.doesNotMatch(directory,/taseEnrollFirstDevice\(/);
 assert.match(directory,/localDeviceFingerprint\(supa,own\)/);
 assert.match(directory,/action:\s*['"]directory['"]/);
 assert.match(directory,/persistent-directory/);
 assert.match(directory,/if\(error\|\|data\?\.kind/);
 assert.match(directory,/if\(user\?\.id!==own\)/);
 assert.match(html,/await taseEnrollFirstDevice\(/);
 assert.match(html,/if\(!secureMailbox\)/);
});
test('short-lived device rosters are reused while valid and cannot renew without authorization',async()=>{
 const {renewOwnTsaRosterIfNeeded}=await import('../tsa-roster-directory.mjs');
 const account='11111111-1111-4111-8111-111111111111';
 const now=1700000000000;
 const client={
  auth:{getUser:async()=>({data:{user:{id:account}},error:null})},
  from:table=>{
   assert.equal(table,'tsa_signed_device_rosters');
   return {select:()=>({eq:()=>({maybeSingle:async()=>({
    data:{roster:{expiresAt:now+130000}},error:null
   })})})};
  }
 };
 assert.deepEqual(await renewOwnTsaRosterIfNeeded(client,account,{now}),{
  state:'signed-roster-current',expiresAt:now+130000,renewed:false
 });
 await assert.rejects(renewOwnTsaRosterIfNeeded(client,account,{now,renewBeforeMs:200000}),/Invalid TSA renewal window/);
});
