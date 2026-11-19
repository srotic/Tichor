// TichorConnect V3: live two-account RLS smoke test, opt-in only.
// Run with dedicated test accounts (never personal accounts):
// SUPABASE_URL=... SUPABASE_ANON_KEY=... TEST_A_EMAIL=... TEST_A_PASSWORD=... TEST_B_EMAIL=... TEST_B_PASSWORD=... node --test tests/v3-supabase-rls.live.test.cjs
const {test}=require('node:test');
const assert=require('node:assert/strict');
const env=process.env;
const required=['SUPABASE_URL','SUPABASE_ANON_KEY','TEST_A_EMAIL','TEST_A_PASSWORD','TEST_B_EMAIL','TEST_B_PASSWORD'];
const configured=required.every(k=>Boolean(env[k]));
const base=(env.SUPABASE_URL||'').replace(/\/$/,'');
const key=env.SUPABASE_ANON_KEY;
async function api(path,token,method='GET',body){
 const response=await fetch(base+path,{method,headers:{apikey:key,Authorization:'Bearer '+token,...(body===undefined?{}:{'Content-Type':'application/json'}),Prefer:'return=representation'},body:body===undefined?undefined:JSON.stringify(body)});
 const raw=await response.text();let data;try{data=raw?JSON.parse(raw):null}catch{data=raw}
 return {status:response.status,ok:response.ok,data};
}
async function signIn(email,password){
 const result=await api('/auth/v1/token?grant_type=password',key,'POST',{email,password});
 assert.equal(result.status,200,'Test account login must succeed: '+JSON.stringify(result.data));
 assert.ok(result.data.access_token&&result.data.user?.id);
 return {token:result.data.access_token,id:result.data.user.id};
}
test('Supabase tichor_tasks owner isolation: read, update, delete, insert', {skip:!configured&&'Dedicated test-account environment variables are required',timeout:30000},async()=>{
 assert.notEqual(env.TEST_A_EMAIL,env.TEST_B_EMAIL,'Use distinct test accounts');
 const a=await signIn(env.TEST_A_EMAIL,env.TEST_A_PASSWORD);
 const b=await signIn(env.TEST_B_EMAIL,env.TEST_B_PASSWORD);
 assert.notEqual(a.id,b.id,'Test users must have different UUIDs');
 const id=crypto.randomUUID();
 try{
  const created=await api('/rest/v1/tichor_tasks',a.token,'POST',{id,user_id:a.id,description:'V3 RLS test '+id,completed:false});
  assert.ok(created.ok,'A must be able to insert its own task: '+JSON.stringify(created.data));
  const own=await api('/rest/v1/tichor_tasks?id=eq.'+id+'&select=id,user_id,description',a.token);
  assert.equal(own.status,200);assert.equal(own.data.length,1);
  const foreign=await api('/rest/v1/tichor_tasks?id=eq.'+id+'&select=id,user_id,description',b.token);
  assert.equal(foreign.status,200);assert.equal(foreign.data.length,0,'B must not read A task');
  const update=await api('/rest/v1/tichor_tasks?id=eq.'+id,b.token,'PATCH',{description:'Unauthorized change'});
  assert.ok(update.ok===false||Array.isArray(update.data)&&update.data.length===0,'B must not update A task');
  const remove=await api('/rest/v1/tichor_tasks?id=eq.'+id,b.token,'DELETE');
  assert.ok(remove.ok===false||Array.isArray(remove.data)&&remove.data.length===0,'B must not delete A task');
  const forged=await api('/rest/v1/tichor_tasks',b.token,'POST',{id:crypto.randomUUID(),user_id:a.id,description:'Forged owner',completed:false});
  assert.equal(forged.ok,false,'B must not create a task owned by A');
  const unchanged=await api('/rest/v1/tichor_tasks?id=eq.'+id+'&select=description',a.token);
  assert.equal(unchanged.data.length,1,'A task must survive B delete attempt');
  assert.equal(unchanged.data[0].description,'V3 RLS test '+id,'A task must survive B update attempt');
 }finally{
  await api('/rest/v1/tichor_tasks?id=eq.'+id+'&user_id=eq.'+a.id,a.token,'DELETE');
 }
});
