const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const read=name=>fs.readFileSync(path.join(root,name),'utf8');
const bank=()=>new Function('window',read('grade1-math-bank.js')+';return window.GRADE1_MATH_BANK;')({});
test('Grade 1 includes twelve narrated lessons and 96 valid questions',()=>{
 const data=bank();
 assert.equal(data.length,12);
 assert.equal(data.reduce((count,l)=>count+l.questions.length,0),96);
 assert.equal(new Set(data.map(x=>x.title)).size,12);
 data.forEach((lesson,index)=>{
  assert.equal(lesson.scenes.length,4,'Four teaching scenes in lesson '+index);
  assert.ok(lesson.scenes.every(x=>x.line.length>10&&x.display.length>0));
  assert.equal(lesson.questions.length,8);
  for(const question of [...lesson.questions,lesson.checkpoint]){
   assert.equal(question.choices.length,4);
   assert.equal(new Set(question.choices).size,4);
   assert.ok(question.choices.includes(question.correct),lesson.title+' correct answer missing');
  }
 });
});
test('Grade 1 HTML loads data before the narrator and practice engine',()=>{
 const html=read('grade1-math.html');
 const scripts=['grade1-math-bank.js','grade1-math-media.js','grade1-math-app.js'];
 const positions=scripts.map(file=>html.indexOf(file));
 assert.ok(positions.every(x=>x>=0));
 assert.deepEqual(positions,[...positions].sort((a,b)=>a-b));
 for(const id of ['video-lesson','video-caption','video-choices','video-next','video-mute','video-skip','workspace'])assert.match(html,new RegExp('id="'+id+'"'));
 assert.match(html,/prefers-reduced-motion/);
});
test('Grade 1 has narration, sound feedback and local score tracking',()=>{
 const media=read('grade1-math-media.js'),app=read('grade1-math-app.js');
 assert.doesNotThrow(()=>new Function(media));
 assert.doesNotThrow(()=>new Function(app));
 assert.match(media,/speechSynthesis/);
 assert.match(media,/AudioContext/);
 assert.match(media,/GRADE1_MEDIA/);
 assert.match(app,/GRADE1_MEDIA\.start/);
 assert.match(app,/localStorage\.setItem/);
 assert.match(app,/Go straight to practice/);
});
