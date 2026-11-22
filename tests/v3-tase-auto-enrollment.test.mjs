import {test} from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {taseCanBootstrap,taseEnrollFirstDevice} from '../tase-auto-enrollment.mjs';

test('TASE first-device bootstrap requires verified account, original identity and empty device registry',()=>{
 assert.equal(taseCanBootstrap({authenticated:true,verified:true,deviceCount:0,hasOriginalIdentity:true}),true);
 for(const c of [
  {authenticated:false,verified:true,deviceCount:0,hasOriginalIdentity:true},
  {authenticated:true,verified:false,deviceCount:0,hasOriginalIdentity:true},
  {authenticated:true,verified:true,deviceCount:1,hasOriginalIdentity:true},
  {authenticated:true,verified:true,deviceCount:0,hasOriginalIdentity:false},
  {authenticated:true,verified:true,deviceCount:-1,hasOriginalIdentity:true}
 ])assert.equal(taseCanBootstrap(c),false);
});
test('TASE rejects unsupported browsers without registering keys or devices',async()=>{
 await assert.rejects(taseEnrollFirstDevice(null,'11111111-1111-4111-8111-111111111111'),/secure browser/);
});
test('TASE only runs after signed-in account session, and never self-approves additional devices',()=>{
 const enroll=readFileSync(new URL('../tase-auto-enrollment.mjs',import.meta.url),'utf8');
 const chat=readFileSync(new URL('../chat.html',import.meta.url),'utf8');
 assert.match(enroll,/email_confirmed_at\|\|user\?\.phone_confirmed_at/);
 assert.match(enroll,/existing\.length/);
 assert.match(enroll,/updated\.length!==1/);
 assert.match(enroll,/local\.fingerprint!==fingerprint/);
 assert.match(enroll,/saveEnrollmentPreview\(client,account,updated\[0\],fingerprint\)/);
 assert.match(enroll,/activateConfirmedDevice\(client,account,registered\.id\)/);
 assert.match(enroll,/loadApprovedLocalDevice\(client,account\)/);
 assert.match(enroll,/pending-device-approval-required/);
 assert.match(enroll,/secure-recovery-required/);
 assert.doesNotMatch(enroll,/\.update\(\{state:'active'\}\)/);
 assert.match(chat,/taseEnrollFirstDevice\(supa,onboardingAccount/);
 assert.match(chat,/id="tcTaseLinkShortcut"/);
 assert.match(chat,/Approve it on the original trusted device before sending|another trusted device must approve/i);
 assert.match(chat,/normal messages are not end-to-end encrypted/i);
});

test('existing trusted browser is recognized before new root keys and expired grants fail closed',()=>{
 const enroll=readFileSync(new URL('../tase-auto-enrollment.mjs',import.meta.url),'utf8');
 const before=enroll.indexOf('const existing=await listDeviceRequests(client,account);');
 const after=enroll.indexOf('const root=await ensureIdentity(client,account);');
 assert.ok(before>=0&&after>before,'existing devices must be checked before attempting root identity creation');
 assert.match(enroll,/await loadApprovedLocalDevice\(client,account\)/);
 assert.match(enroll,/authorization-renewal-required/);
 assert.match(enroll,/waiting-for-original-device-approval/);
});
test('advanced encryption controls stay collapsed and one-time browser linking remains accessible',()=>{
 const chat=readFileSync(new URL('../chat.html',import.meta.url),'utf8');
 assert.match(chat,/<details id="tcEncryptionAdvanced"/);
 assert.match(chat,/<button type="button" id="tcTaseLinkShortcut" hidden/);
 assert.match(chat,/\$\('tcTaseLinkShortcut'\)\.onclick=/);
 assert.match(chat,/linkButton\.hidden=!\(needsApproval\|\|needsRecovery\)/);
 assert.match(chat,/result\.state==='authorization-renewal-required'/);
 assert.match(chat,/Existing encryption keys will not be replaced/i);
 assert.match(chat,/Encrypted messaging still requires verified contacts/);
 assert.match(chat,/No plaintext fallback/);
});

test('TASE automates pending device registration but never grants a new browser trust',()=>{
 const enroll=readFileSync(new URL('../tase-auto-enrollment.mjs',import.meta.url),'utf8');
 const chat=readFileSync(new URL('../chat.html',import.meta.url),'utf8');
 const existingAt=enroll.indexOf('if(existing.length){');
 const requestAt=enroll.indexOf('const request=await requestDevice(client,account);',existingAt);
 assert.ok(existingAt>=0&&requestAt>existingAt);
 assert.match(enroll,/requireFreshLinkEvidence\(client,account,local\.id\)/);
 assert.match(enroll,/refreshed\.id!==local\.id/);
 assert.match(enroll,/matched\?\.state==='revoked'/);
 assert.match(enroll,/!existing\.some\(d=>d\.state==='active'\)/);
 assert.match(enroll,/state:'pending-device-approval-required'/);
 assert.match(enroll,/state:'secure-recovery-required'/);
 assert.doesNotMatch(enroll,/\.update\(\{state:'active'\}\)/);
 assert.match(chat,/Review pending device approval/);
 assert.match(chat,/Review secure recovery options/);
 assert.match(chat,/tcManageDevice\(false\)/);
});
