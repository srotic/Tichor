const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const read=name=>fs.readFileSync(path.join(root,name),'utf8');
test('V3 does not misrepresent the currently unencrypted message transport',()=>{
 const html=read('chat.html');
 assert.match(html,/id="tichorE2EEStatus"/);
 assert.match(html,/Security status: Not end-to-end encrypted/);
 assert.match(html,/Do not share sensitive information/);
 assert.match(html,/supa\.from\('chat_messages'\)\.insert/);
 assert.match(html,/supa\.from\('tichor_group_messages'\)\.insert/);
});
test('Four-phase release gates explicitly block unreviewed E2EE claims',()=>{
 const plan=read('docs/e2ee-release-gates.md');
 assert.match(plan,/Status: DESIGN \/ NOT DEPLOYED/);
 for(const phase of ['Phase 1','Phase 2','Phase 3','Phase 4'])
   assert.match(plan,new RegExp(phase));
 assert.match(plan,/independent security assessment signs off/);
 assert.match(plan,/never silently fall back to plaintext/);
 assert.match(plan,/Global E2EE required \| \*\*Disabled\*\*/);
});

test('TSA recipient discovery remains explicitly non-authorizing and requires verified account fingerprint',()=>{
 const source=read('e2ee-v3.js');
 assert.match(source,/discoverRecipientCertificatePreviews\(supa,sender,recipient,confirmedRootFingerprint\)/);
 assert.match(source,/requireContactRootPin/);
 assert.match(source,/confirmRecipientRootForTSA/);
 assert.match(source,/Recipient root identity mismatch\. Discovery blocked/);
 assert.match(source,/verifyEligibilityCertificate/);
 assert.match(source,/verified-certificate-preview-not-authorized/);
 assert.doesNotMatch(source,/state:'verified-certificate-preview-authorized'/);
});

test('TSA device revocation verifies certificate withdrawal and never enables pending-device transport',()=>{
 const registry=read('e2ee-device-registry.js');
 const spec=read('docs/tsa-revocation-milestone.md');
 assert.match(registry,/update\(\{state:'revoked'\}\)/);
 assert.match(registry,/from\('tichor_e2ee_recipient_directory'\)/);
 assert.match(registry,/Revocation could not be confirmed in the recipient directory/);
 assert.match(spec,/tichor_e2ee_device_preview_withdrawal/);
 assert.match(spec,/not a production E2EE activation/i);
});

test('TSA contact fingerprint pin is explicit, account-scoped, immutable and fail-closed',async()=>{
 const {confirmContactRootPin,readContactRootPin,requireContactRootPin}=await import('../tsa-contact-root-pin.mjs');
 const account='11111111-1111-4111-8111-111111111111';
 const contact='22222222-2222-4222-8222-222222222222';
 const other='33333333-3333-4333-8333-333333333333';
 const fp='ab'.repeat(32), changed='cd'.repeat(32);
 const map=new Map();
 const store={getItem:k=>map.has(k)?map.get(k):null,setItem:(k,v)=>map.set(k,v)};
 assert.equal(readContactRootPin(store,account,contact),null);
 assert.throws(()=>requireContactRootPin(store,account,contact,fp),/not independently verified/);
 assert.throws(()=>confirmContactRootPin(store,account,contact,changed,fp),/verification failed/);
 assert.equal(map.size,0);
 assert.equal(confirmContactRootPin(store,account,contact,fp.toUpperCase(),fp),fp);
 assert.equal(requireContactRootPin(store,account,contact,fp),fp);
 assert.equal(map.size,1);
 assert.throws(()=>requireContactRootPin(store,account,contact,changed),/changed/);
 assert.throws(()=>confirmContactRootPin(store,account,contact,changed,changed),/identity changed/);
 assert.equal(readContactRootPin(store,account,contact),fp);
 assert.equal(readContactRootPin(store,account,other),null);
 assert.equal(readContactRootPin(store,other,contact),null);
 assert.throws(()=>confirmContactRootPin(store,account,account,fp,fp),/different account/);
 assert.throws(()=>confirmContactRootPin(store,'invalid',contact,fp,fp),/identifier/);
});

test('TSA multi-device envelope is staging-only and cannot claim production E2EE',()=>{
 const primitive=read('tsa-multidevice-envelope.mjs');
 const html=read('chat.html');
 assert.match(primitive,/NOT a Signal Double Ratchet/);
 assert.match(primitive,/authorized/);
 assert.match(primitive,/revoked/);
 assert.match(primitive,/encryptDeviceCopies/);
 assert.match(primitive,/decryptDeviceCopy/);
 assert.doesNotMatch(html,/tsa-multidevice-envelope\.mjs/);
});

test('Verified original-device direct text encrypts automatically and refuses plaintext downgrade',()=>{
 const html=read('chat.html');
 assert.match(html,/id="tcVerifyContactRoot"/);
 assert.match(html,/confirmContactRootPin\(localStorage,account,target,typed,info\.fingerprint\)/);
 assert.match(html,/tcVerifiedRootPinned=\(\)=>/);
 assert.match(html,/tcE2EESelected=\(\)=>Boolean\(user&&peer&&\(tcVerifiedRootPinned\(\)/);
 assert.match(html,/toggle\.disabled=pinned/);
 assert.match(html,/requireContactRootPin\(localStorage,sender,target,info\.fingerprint\)/);
 assert.match(html,/encrypted\?await encryptDirectText\(client,sender,target,body\):body/);
 assert.match(html,/if\(encrypted&&!isEncrypted\(outgoingBody\)\)/);
 assert.match(html,/if\(encrypted&&file\)throw Error/);
 assert.match(html,/Other devices, attachments, calls and groups remain outside this protection/);
 assert.doesNotMatch(html,/import.*tsa-multidevice-envelope\.mjs/);
});
