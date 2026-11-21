const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const read=f=>fs.readFileSync(path.join(root,f),'utf8');
test('Kindergarten brain games include eight games and forty rounds',()=>{
 const src=read('kindergarten-brain-games.js');
 assert.doesNotThrow(()=>new Function(src));
 const start=src.indexOf('const games='),end=src.indexOf('if(bank.length!==8');
 assert.ok(start>=0&&end>start);
 const code=src.slice(start,end);
 const data=new Function(code+';return {games,bank};')();
 assert.equal(data.games.length,8);
 assert.equal(data.bank.length,8);
 assert.equal(data.games[0].kind,'memory');
 assert.equal(data.bank[0].length,0);
 for(const [i,rounds] of data.bank.entries()){
  if(i===0)continue;
  assert.equal(rounds.length,5,'Five rounds in quiz game '+i);
  for(const q of rounds){
   assert.equal(q.options.length,4,'Exactly four choices');
   assert.equal(new Set(q.options).size,4,'Unique answers');
   assert.ok(q.options.includes(q.correct),'Correct answer available');
   assert.ok(q.why.length>10,'Useful explanation');
  }
 }
 assert.match(src,/state\.pairs===3/);
 assert.match(src,/speechSynthesis/);
 assert.match(src,/AudioContext/);
 assert.match(src,/localStorage\.setItem/);
});
test('Brain games page contains accessible controls and link in Discovery Lab',()=>{
 const html=read('kindergarten-brain-games.html'),discovery=read('discovery-lab.html');
 assert.match(html,/kindergarten-brain-games\.js/);
 for(const id of ['game-cards','play-workspace','memory-grid','choices','feedback','mute','speak','next','star-total'])assert.match(html,new RegExp('id="'+id+'"'));
 assert.match(discovery,/href="kindergarten-brain-games\.html"/);
});
