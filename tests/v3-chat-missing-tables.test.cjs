const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const read=p=>fs.readFileSync(path.join(root,p),'utf8');
test('V3 chat requires both hidden-message and attachment tables',()=>{
 const chat=read('chat.html'),sql=read('supabase/migrations/20261121_v3_restore_hidden_messages_attachments.sql');
 assert.match(chat,/from\('tichor_hidden_messages'\)/);
 assert.match(chat,/from\('tichor_attachments'\)/);
 for(const t of ['tichor_hidden_messages','tichor_attachments']){
  assert.match(sql,new RegExp('create table if not exists public\\.'+t));
  assert.match(sql,new RegExp('alter table public\\.'+t+' enable row level security'));
 }
 assert.match(sql,/storage\.buckets/);
 assert.match(sql,/public=false/);
 assert.match(sql,/notify pgrst, 'reload schema'/);
});
test('V3 hidden records are owner-scoped and attachment metadata participant-scoped',()=>{
 const sql=read('supabase/migrations/20261121_v3_restore_hidden_messages_attachments.sql');
 assert.match(sql,/user_id = \(select auth\.uid\(\)\)/);
 assert.match(sql,/sender_id=\(select auth\.uid\(\)\)/);
 assert.match(sql,/recipient_id=\(select auth\.uid\(\)\)/);
 assert.match(sql,/revoke all on public\.tichor_hidden_messages from public, anon/);
 assert.match(sql,/revoke all on public\.tichor_attachments from public,anon/);
 assert.match(sql,/V3 sender upload attachment/);
 assert.match(sql,/V3 participants read attachment/);
});
