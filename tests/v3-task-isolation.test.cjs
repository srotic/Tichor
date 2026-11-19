// TichorConnect 3.0: dependency-free regression checks for browser task isolation.
// Run: node --test tests/v3-task-isolation.test.cjs
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const source = fs.readFileSync(require('node:path').join(__dirname, '../chat.html'), 'utf8');
function extract(start, end) {
  const a = source.indexOf(start);
  const b = source.indexOf(end, a + start.length);
  assert.ok(a >= 0 && b > a, 'Task implementation markers must exist');
  return source.slice(a, b);
}
const taskLoadSource = extract('const taskLoad=()=>{', 'const taskSave=');
function simulateTaskLoad(owner, initial) {
  const storage = new Map(Object.entries(initial).map(([k,v])=>[k,typeof v==='string'?v:JSON.stringify(v)]));
  const localStorage = {
    getItem: key => storage.get(key) ?? null,
    setItem: (key,value) => storage.set(key,String(value)),
    removeItem: key => storage.delete(key),
    key: i => [...storage.keys()][i] ?? null,
    get length(){return storage.size}
  };
  const ctx = vm.createContext({localStorage, owner});
  vm.runInContext(`
    const taskOwner=owner;
    const taskKeyFor=id=>'tichor-tasks-v2:'+(id||'guest');
    const taskPendingKey=id=>'tichor-tasks-pending-v2:'+(id||'guest');
    const taskRead=(key,fallback=[])=>{try{const v=JSON.parse(localStorage.getItem(key)||'null');return Array.isArray(v)?v:fallback}catch{return fallback}};
    const taskValid=t=>t&&typeof t.id==='string'&&typeof t.text==='string'&&t.text.trim();
    const taskNormalize=t=>({id:t.id,text:t.text,due:t.due||'',done:!!t.done});
    let taskCache=[],taskPending=[];
    ${taskLoadSource}
    taskLoad();
    globalThis.result=JSON.stringify({tasks:taskCache,pending:taskPending});
  `,ctx,{timeout:1000});
  return {result:JSON.parse(ctx.result),storage};
}
const task=(id,text)=>({id,text,due:'',done:false});
test('account B never inherits account A, guest, or legacy tasks',()=>{
  const state={
    'tichor-tasks-v2:A':[task('a','Private A')],
    'tichor-tasks-v2:B':[task('b','Private B')],
    'tichor-tasks-v2:guest':[task('g','Guest')],
    'tichor-tasks-v1:someone-else':[task('old','Legacy private')]
  };
  const a=simulateTaskLoad('A',state).result.tasks;
  const b=simulateTaskLoad('B',state).result.tasks;
  assert.deepEqual(a.map(x=>x.id),['a']);
  assert.deepEqual(b.map(x=>x.id),['b']);
});
test('guest and legacy records are preserved, not silently migrated or erased',()=>{
  const legacy=[task('old','Legacy')];
  const guest=[task('g','Guest')];
  const {result,storage}=simulateTaskLoad('B',{'tichor-tasks-v1:local':legacy,'tichor-tasks-v2:guest':guest});
  assert.deepEqual(result.tasks,[]);
  assert.deepEqual(JSON.parse(storage.get('tichor-tasks-v1:local')),legacy);
  assert.deepEqual(JSON.parse(storage.get('tichor-tasks-v2:guest')),guest);
});
test('pending changes are isolated by account',()=>{
  const state={
    'tichor-tasks-pending-v2:A':[{id:'a',op:'upsert',task:task('a','A')}],
    'tichor-tasks-pending-v2:B':[{id:'b',op:'delete',task:null}],
    'tichor-tasks-pending-v2:guest':[{id:'g',op:'upsert',task:task('g','Guest')}]
  };
  const {result}=simulateTaskLoad('B',state);
  assert.deepEqual(result.pending.map(x=>x.id),['b']);
});
test('malformed cache does not crash task loading',()=>{
  const {result}=simulateTaskLoad('A',{'tichor-tasks-v2:A':'{bad json'});
  assert.deepEqual(result.tasks,[]);
});
test('task synchronization remains account-filtered and exposes sync status',()=>{
  const sync=extract('const taskSync=async()=>{','taskLoad();renderTasks();');
  assert.match(sync,/\.eq\('user_id',owner\)/);
  assert.match(sync,/taskIdentity\(\)!==owner/);
  assert.match(sync,/taskPending\.length/);
  assert.match(sync,/Tasks synced to your account/);
});

test('previously synchronized tasks are not re-uploaded after remote deletion',()=>{
  const sync=extract('const taskSync=async()=>{','taskLoad();renderTasks();');
  assert.match(sync,/const seen=taskRead\(taskSeenKey\(owner\)\)/);
  assert.match(sync,/!seenIds\.has\(t\.id\)/);
  assert.match(sync,/taskWrite\(taskSeenKey\(owner\)/);
  const remoteIds=new Set(['still-remote']);
  const seenIds=new Set(['deleted-elsewhere','still-remote']);
  const cache=[task('deleted-elsewhere','Old'),task('new-offline','New')];
  const missing=cache.filter(t=>!remoteIds.has(t.id)&&!seenIds.has(t.id));
  assert.deepEqual(missing.map(t=>t.id),['new-offline']);
});
