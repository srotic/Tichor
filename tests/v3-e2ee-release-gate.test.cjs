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
