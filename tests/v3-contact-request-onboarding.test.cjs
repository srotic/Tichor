const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const chat=fs.readFileSync(path.join(__dirname,'..','chat.html'),'utf8');
test('V3 contact setup has an accessible username creation flow',()=>{
 for(const id of ['tichorContactSetup','tichorQuickUsername','tichorQuickSaveUsername','tichorQuickUsernameStatus','tichorMyContactHandle','tichorContactRequestStatus','recipient','openConversation'])
  assert.match(chat,new RegExp('id="'+id+'"'));
 assert.match(chat,/function tichorContactIdentityStatus/);
 assert.match(chat,/async function loadProfile/);
 assert.match(chat,/tichor_profiles'\)\.upsert\(\{user_id:user\.id,username\}/);
});
test('V3 does not mistake generic RPC message for a confirmed contact request',()=>{
 assert.match(chat,/tichor_request_contact/);
 assert.match(chat,/tichor_request_usernames/);
 assert.match(chat,/No new pending request was saved/);
 assert.match(chat,/Contact request not sent:/);
 assert.match(chat,/matched\?\.status==='pending'/);
 assert.match(chat,/onConflict:'user_id'/);
});

test('Accepting a request refreshes reciprocal saved contacts without another request',()=>{
 assert.match(chat,/tichor_respond_contact/);
 assert.match(chat,/Both accounts now have each other in Contacts/);
 assert.match(chat,/already connected to you/);
 assert.match(chat,/tichor_contact_allowed/);
});
