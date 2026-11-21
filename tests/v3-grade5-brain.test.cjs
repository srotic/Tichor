const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const read=p=>fs.readFileSync(path.join(root,p),'utf8');
const bank=()=>new Function('window',read('grade5-brain-bank.js')+';return window.TICHOR_GRADE5_BRAIN_BANK')({});
test('Grade 5 Brain Games contains eight categories and 64 challenge rounds',()=>{
 const games=bank();
 assert.equal(games.length,8);
 assert.equal(new Set(games.map(g=>g.title)).size,8);
 assert.equal(games[7].title,'Memory Matrix');
 assert.equal(games[7].questions.length,0);
 for(const game of games.slice(0,7)){
  assert.equal(game.questions.length,8);
  for(const q of game.questions){
   assert.equal(q.length,4);
   assert.ok(q[0].length>15);
   assert.ok(q[3].length>15);
   assert.equal(q[2].length,4);
   assert.equal(new Set(q[2]).size,4);
   assert.ok(q[2].includes(q[1]));
  }
 }
 const app=read('grade5-brain-games.js');
 assert.match(app,/function memoryRound/);
 assert.match(app,/state\.round===7/);
 assert.match(app,/4000/);
 assert.match(app,/localStorage\.setItem/);
 assert.doesNotThrow(()=>new Function(app));
});
test('Grade 5 Brain Games is linked and loads its question bank first',()=>{
 const page=read('grade5-brain-games.html');
 assert.ok(page.indexOf('grade5-brain-bank.js')<page.indexOf('grade5-brain-games.js'));
 for(const id of ['cards','workspace','question','visual','choices','feedback','next','hear','mute','history'])assert.match(page,new RegExp('id="'+id+'"'));
 assert.match(read('grade5.html'),/href="grade5-brain-games\.html"/);
});
