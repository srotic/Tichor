'use strict';
(()=> {
 const base=(window.TICHOR_CARS_BANK||[]).map(p=>({...p,q:p.q.map(q=>q.length===8?[q[0],q.slice(1,5),q[5],q[6],q[7]]:q)}));
 const EXAMS=[base,...Array.from({length:9},(_,i)=>window.TICHOR_CARS_EXAMS?.[i+1]||[])];
 const BANK=EXAMS.flat();
 const $=id=>document.getElementById(id);
 if(EXAMS.length!==10||EXAMS.some(group=>!Array.isArray(group)||group.length!==9||group.reduce((n,p)=>n+p.q.length,0)!==53)||new Set(BANK.map(p=>p.title)).size!==90){
  $('status').textContent='Question bank could not load. Refresh the page.';return;
 }
 const STORE='tichor-cars-practice-v1',ROTATE='tichor-cars-rotation-v1';
 let history=[];try{history=JSON.parse(localStorage.getItem(STORE)||'[]');if(!Array.isArray(history))history=[]}catch{history=[]}
 const exam={items:[],answers:[],flags:new Set(),index:0,timed:true,tutor:false,seconds:0,started:0,interval:null,submitted:false,scope:'one',examNumber:1};
 $('passage-count').textContent=BANK.length;$('question-count').textContent=BANK.reduce((n,p)=>n+p.q.length,0);
 for(let n=1;n<=10;n++)$('exam-select').add(new Option('Exam '+n+' · 9 passages / 53 questions',String(n)));
 const best=()=>{$('best').textContent=history.length?Math.max(...history.map(x=>x.accuracy))+'%':'—'};best();
 function view(id){
  document.querySelectorAll('.screen').forEach(s=>s.classList.toggle('active',s.id===id));
  document.querySelectorAll('.tab').forEach(b=>b.setAttribute('aria-selected',String(b.dataset.view===id)));
  if(id==='review')renderHistory();
 }
 document.querySelectorAll('.tab').forEach(b=>b.addEventListener('click',()=>view(b.dataset.view)));
 const pad=n=>String(n).padStart(2,'0');
 function updateClock(){
  if(!exam.items.length||exam.submitted)return;
  const elapsed=Math.floor((Date.now()-exam.started)/1000);
  const remaining=exam.timed?Math.max(0,exam.seconds-elapsed):elapsed;
  $('clock').textContent=(exam.timed?'Remaining ':'Elapsed ')+pad(Math.floor(remaining/60))+':'+pad(remaining%60);
  if(exam.timed&&remaining===0)finish(true);
 }
 function pickPassages(scope,examNumber){
  const bank=EXAMS[examNumber-1];
  if(scope==='full')return bank.map((p,i)=>({p,index:(examNumber-1)*9+i}));
  const size=scope==='three'?3:1;
  const rotationKey=ROTATE+':exam:'+examNumber;
  let pointer=0;try{pointer=Number(localStorage.getItem(rotationKey)||'0')||0}catch{}
  const result=Array.from({length:size},(_,i)=>({p:bank[(pointer+i)%bank.length],index:(examNumber-1)*9+(pointer+i)%bank.length}));
  try{localStorage.setItem(rotationKey,String((pointer+size)%bank.length))}catch{}
  return result;
 }
 function start(){
  if(exam.items.length&&!exam.submitted&&!confirm('Discard the current practice session and begin again?'))return;
  if(exam.interval)clearInterval(exam.interval);
  const scope=$('scope').value;const examNumber=Number($('exam-select').value)||1;const selected=pickPassages(scope,examNumber);
  exam.examNumber=examNumber;
  document.getElementById('passage-body').dataset.passageKey='';
  exam.scope=scope;exam.timed=$('clockmode').value==='timed';exam.tutor=$('feedback').value==='tutor';
  exam.items=selected.flatMap(({p,index})=>p.q.map((q,j)=>({p,passageIndex:index,localIndex:j,q})));
  exam.answers=Array(exam.items.length).fill(null);exam.flags=new Set();exam.index=0;exam.submitted=false;exam.seconds=scope==='full'?90*60:scope==='three'?30*60:10*60;exam.started=Date.now();
  $('exam-workspace').classList.remove('hide');$('result').classList.add('hide');$('status').textContent='Exam '+examNumber+' · '+(scope==='full'?'Full section':selected.length+' passage'+(selected.length>1?'s':''))+' · '+exam.items.length+' questions';
  view('exam');render();updateClock();if(exam.timed)exam.interval=setInterval(updateClock,1000);else exam.interval=setInterval(updateClock,1000);
  window.scrollTo({top:0,behavior:'instant'});
 }
 $('begin').addEventListener('click',start);
 $('return-setup').addEventListener('click',()=>view('welcome'));
 function render(){
  if(!exam.items.length)return;
  const entry=exam.items[exam.index],{p,q}=entry;
  const passageNumber=exam.items.slice(0,exam.index+1).filter((e,i,all)=>i===0||all[i-1].p!==e.p).length;
  const displayed=$('passage-body');const oldKey=displayed.dataset.passageKey;
  if(oldKey!==String(entry.passageIndex)){
   $('passage-title').textContent=p.title;
   $('passage-meta').textContent='PASSAGE '+passageNumber+' · '+p.discipline+' · '+p.text.trim().split(/\s+/).length+' words';
   displayed.replaceChildren();
   for(const para of p.text.trim().split(/\n\s*\n/)){const el=document.createElement('p');el.textContent=para;displayed.append(el)}
   displayed.dataset.passageKey=String(entry.passageIndex);
   document.querySelector('.reading-pane').scrollTop=0;
  }
  $('q-position').textContent='Question '+(exam.index+1)+' of '+exam.items.length;
  $('q-type').textContent={'Comprehension':'Foundations of Comprehension','Within the Text':'Reasoning Within the Text','Beyond the Text':'Reasoning Beyond the Text'}[q[3]]||q[3];
  $('question').textContent=q[0];
  $('flag').setAttribute('aria-pressed',String(exam.flags.has(exam.index)));
  $('flag').textContent=exam.flags.has(exam.index)?'⚑ Flagged':'⚑ Flag for review';
  const picked=exam.answers[exam.index],reveal=exam.submitted||(exam.tutor&&picked!==null);
  const holder=$('answers');holder.replaceChildren();
  for(let i=0;i<q[1].length;i++){
   const b=document.createElement('button');b.type='button';b.className='answer';b.textContent='ABCD'[i]+'. '+q[1][i];b.setAttribute('aria-pressed',String(picked===i));
   if(picked===i)b.classList.add('selected');
   if(reveal&&i===q[2])b.classList.add('correct');
   if(reveal&&picked===i&&i!==q[2])b.classList.add('wrong');
   b.disabled=reveal;
   b.addEventListener('click',()=>{exam.answers[exam.index]=i;render()});holder.append(b);
  }
  $('explanation').classList.toggle('hide',!reveal);
  $('explanation').textContent=reveal?((picked===q[2]?'Correct. ':'Correct answer: '+('ABCD'[q[2]])+'. ')+q[4]):'';
  $('prev').disabled=exam.index===0;
  $('next').textContent=exam.index===exam.items.length-1?'Review / submit':'Next →';
  $('progress').style.width=Math.round(exam.answers.filter(x=>x!==null).length/exam.items.length*100)+'%';
  $('answered-count').textContent=exam.answers.filter(x=>x!==null).length+' of '+exam.items.length+' answered';
  const nav=$('navigator');nav.replaceChildren();
  for(let i=0;i<exam.items.length;i++){
   const b=document.createElement('button');b.type='button';b.textContent=i+1;b.className=(i===exam.index?'current ':'')+(exam.answers[i]!==null?'answered ':'')+(exam.flags.has(i)?'flagged':'');b.title='Question '+(i+1)+(exam.flags.has(i)?' (flagged)':'');b.setAttribute('aria-label',b.title);b.onclick=()=>{exam.index=i;render()};nav.append(b);
  }
 }
 $('prev').onclick=()=>{if(exam.index>0){exam.index--;render()}};
 $('next').onclick=()=>{if(exam.index<exam.items.length-1){exam.index++;render()}else if(exam.submitted){exam.index=0;render()}else attemptSubmit()};
 $('flag').onclick=()=>{const i=exam.index;if(exam.flags.has(i))exam.flags.delete(i);else exam.flags.add(i);render()};
 $('submit').onclick=attemptSubmit;
 function attemptSubmit(){
  if(!exam.items.length||exam.submitted)return;
  const missing=exam.answers.filter(v=>v===null).length,flagged=exam.flags.size;
  if(!confirm('Submit this CARS practice session? '+missing+' unanswered and '+flagged+' flagged question(s).'))return;
  finish(false);
 }
 function finish(timedOut){
  if(!exam.items.length||exam.submitted)return;
  exam.submitted=true;clearInterval(exam.interval);exam.interval=null;
  const correct=exam.items.filter((e,i)=>exam.answers[i]===e.q[2]).length,total=exam.items.length,accuracy=Math.round(correct/total*100);
  const elapsed=Math.floor((Date.now()-exam.started)/1000);
  const byType={};
  exam.items.forEach((e,i)=>{const k=e.q[3];byType[k]??={right:0,total:0};byType[k].total++;if(exam.answers[i]===e.q[2])byType[k].right++});
  const record={date:new Date().toISOString(),correct,total,accuracy,elapsed,scope:exam.scope,examNumber:exam.examNumber,byType};
  history.unshift(record);history=history.slice(0,30);try{localStorage.setItem(STORE,JSON.stringify(history))}catch{};best();
  const el=$('result');el.classList.remove('hide');el.replaceChildren();
  const title=document.createElement('h2');title.textContent='Exam '+exam.examNumber+' · '+(timedOut?'Time expired — CARS results':'CARS practice results');el.append(title);
  const summary=document.createElement('p');summary.textContent=correct+' / '+total+' correct ('+accuracy+'%) · '+Math.floor(elapsed/60)+' min '+elapsed%60+' sec · '+exam.answers.filter(v=>v===null).length+' unanswered';el.append(summary);
  const details=document.createElement('div');details.className='stats-detail';
  for(const [type,stats] of Object.entries(byType)){const block=document.createElement('div');block.className='metric';const strong=document.createElement('strong');strong.textContent=stats.right+'/'+stats.total;const name=document.createElement('small');name.textContent={'Comprehension':'Comprehension','Within the Text':'Within-text reasoning','Beyond the Text':'Beyond-text reasoning'}[type]||type;block.append(strong,name);details.append(block)}el.append(details);
  const note=document.createElement('p');note.className='muted';note.textContent='Accuracy is not an official MCAT scaled score. Select any question in the navigator to review the passage and explanation.';el.append(note);
  const btn=document.createElement('button');btn.className='primary';btn.textContent='Review all answers';btn.onclick=()=>{exam.index=0;render();$('exam-workspace').scrollIntoView({block:'start',behavior:'smooth'})};el.append(btn);
  $('status').textContent='Session completed';render();el.scrollIntoView({block:'nearest',behavior:'smooth'});
 }
 function renderHistory(){
  const el=$('history');el.replaceChildren();
  if(!history.length){const p=document.createElement('p');p.textContent='No CARS practice completed yet. Finish a passage to start tracking accuracy.';el.append(p);return}
  for(const r of history){const card=document.createElement('article');const h=document.createElement('strong');h.textContent=r.correct+'/'+r.total+' correct · '+r.accuracy+'%';const desc=document.createElement('p');desc.textContent='Exam '+(r.examNumber||1)+' · '+(r.scope==='full'?'Full 9-passage section':r.scope==='three'?'3-passage set':'Single passage')+' · '+new Date(r.date).toLocaleString()+' · '+Math.floor(r.elapsed/60)+' min';card.append(h,desc);el.append(card)}
 }
 $('clear-history').onclick=()=>{if(!confirm('Clear locally stored CARS scores?'))return;history=[];try{localStorage.removeItem(STORE)}catch{};best();renderHistory()};
})();
