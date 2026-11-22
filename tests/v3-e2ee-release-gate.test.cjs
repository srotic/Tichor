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
 assert.match(source,/Recipient root fingerprint must be independently confirmed/);
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
