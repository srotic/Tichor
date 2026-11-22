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
 assert.match(enroll,/existing-device-approval-required/);
 assert.doesNotMatch(enroll,/\.update\(\{state:'active'\}\)/);
 assert.match(chat,/taseEnrollFirstDevice\(supa,onboardingAccount/);
 assert.match(chat,/Secure device linking or recovery is required/);
 assert.match(chat,/normal messages are not end-to-end encrypted/i);
});
