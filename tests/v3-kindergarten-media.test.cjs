const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const read=file=>fs.readFileSync(path.join(root,file),'utf8');
test('Kindergarten Math has 12 complete animated lessons with checkpoint answers',()=>{
 const source=read('kindergarten-math-media.js');
 const match=source.match(/const source=(\[[^;]+\]);\s*let active=/);
 assert.ok(match,'Narration dataset should be in the media player');
 const lessons=JSON.parse(match[1]);
 assert.equal(lessons.length,12);
 for(const [i,item] of lessons.entries()){
  assert.equal(item.length,7,'Each lesson must have title, emoji, four narrations, four scenes, prompt, answer and choices');
  assert.equal(item[2].length,4,'Each lesson must have four narrated scenes');
  assert.equal(item[3].length,4,'Each lesson must have four visual scenes');
  assert.equal(item[6].length,4,'Each checkpoint must have four choices');
  assert.equal(new Set(item[6]).size,4,'Checkpoint choices must be distinct');
  assert.ok(item[6].includes(item[5]),'The correct answer must be selectable: '+i);
  assert.ok(item[2].every(x=>x.trim().length>10),'Narrations must be nonempty');
 }
 assert.match(source,/speechSynthesis/);
 assert.match(source,/AudioContext/);
 assert.match(source,/prefers-reduced-motion/);
});
test('Kindergarten Math has exactly 96 valid practice questions',()=>{
 const src=read('kindergarten-math-app.js');
 const prefix=src.slice(0,src.indexOf('let history=[]'));
 const evaluator=new Function('window','document',prefix.replace('(()=>{','return (()=>{')+'return BANK;})();');
 const bank=evaluator({},{});
 assert.equal(bank.length,12);
 for(const [i,lesson] of bank.entries()){
  assert.equal(lesson.length,8,'Eight questions required in session '+(i+1));
  for(const item of lesson){
   assert.equal(item.choices.length,4,'Four choices required');
   assert.equal(new Set(item.choices).size,4,'No duplicate choices');
   assert.ok(item.choices.includes(item.correct),'Correct choice must exist');
  }
 }
 assert.match(src,/KINDER_MEDIA\.start/);
 assert.match(src,/Go straight to practice/);
});
test('Kindergarten Math page loads narration and animation before practice',()=>{
 const html=read('kindergarten-math.html');
 assert.ok(html.indexOf('kindergarten-math-media.js') < html.indexOf('kindergarten-math-app.js'));
 for(const id of ['video-lesson','video-picture','video-caption','video-next','video-choices','video-play','video-mute','video-skip','workspace'])assert.match(html,new RegExp('id="'+id+'"'));
 assert.match(html,/tc-enter/);
 assert.match(html,/prefers-reduced-motion/);
});
