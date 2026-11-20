'use strict';
(()=>{
 const BANK=window.GRADE5_COMPREHENSION_BANK||[],$=id=>document.getElementById(id);
 if(!Array.isArray(BANK)||!BANK.length||BANK.some(p=>!Array.isArray(p.qs)||p.qs.length!==7)){document.body.insertAdjacentText('beforeend','The reading bank could not load. Please refresh.');return}
 const KEY='tichor-grade5-advanced-reading-v1';
 let history=[];try{const x=JSON.parse(localStorage.getItem(KEY)||'[]');if(Array.isArray(x))history=x}catch{}
 const session={items:[],answers:[],index:0,mode:'tutor',timed:false,started:0,totalSecs:0,interval:null,done:false,selection:'all'};
 const view=id=>{document.querySelectorAll('.screen').forEach(el=>el.classList.toggle('active',el.id===id));document.querySelectorAll('.tab').forEach(btn=>btn.setAttribute('aria-selected',String(btn.dataset.view===id)));if(id==='results')displayHistory()};
 document.querySelectorAll('.tab').forEach(b=>b.addEventListener('click',()=>view(b.dataset.view)));
 $('passage-total').textContent=BANK.length;$('question-total').textContent=BANK.reduce((n,p)=>n+p.qs.length,0);
 const updateHigh=()=>{$('highest').textContent=history.length?Math.max(...history.map(h=>h.percent))+'%':'—'};updateHigh();
 BANK.forEach((p,i)=>{
  const op=document.createElement('option');op.value=String(i);op.textContent='Test '+(i+1)+' · '+p.title;$('story-select').append(op);
  const card=document.createElement('article');card.className='story-card';
  const genre=document.createElement('div');genre.className='genre';genre.textContent='TEST '+(i+1)+' · '+p.genre;
  const h=document.createElement('h3');h.textContent=p.title;const para=document.createElement('p');
  para.textContent=p.text.trim().split(/\s+/).length+' words · 7 advanced questions · '+p.level;
  const btn=document.createElement('button');btn.className='secondary';btn.type='button';btn.textContent='Start this test →';
  btn.addEventListener('click',()=>{$('story-select').value=String(i);start()});
  card.append(genre,h,para,btn);$('story-library').append(card);
 });
 $('mixed').onclick=()=>{$('story-select').value='all';start()};
 $('begin').onclick=start;
 function start(){
  if(session.items.length&&!session.done&&!confirm('Discard the current reading test and start a new one?'))return;
  clearInterval(session.interval);session.interval=null;
  session.selection=$('story-select').value;session.mode=$('mode').value;session.timed=$('timer').value==='on';session.done=false;
  const selected=session.selection==='all'?BANK.map((p,i)=>({p,i})):[{p:BANK[+session.selection],i:+session.selection}];
  session.items=selected.flatMap(({p,i})=>p.qs.map(q=>({p,i,q})));session.answers=Array(session.items.length).fill(null);session.index=0;session.started=Date.now();session.totalSecs=selected.length*600;
  $('workspace').classList.remove('hidden');$('summary').classList.add('hidden');$('status').textContent=(selected.length===1?'Test '+(selected[0].i+1):'Mixed Challenge')+' · '+session.items.length+' questions';
  $('story-body').dataset.key='';view('practice');render();tick();session.interval=setInterval(tick,1000);window.scrollTo({top:0,behavior:'instant'});
 }
 const pad=n=>String(n).padStart(2,'0');
 function tick(){if(!session.items.length||session.done)return;const elapsed=Math.floor((Date.now()-session.started)/1000);const secs=session.timed?Math.max(0,session.totalSecs-elapsed):elapsed;$('clock').textContent=(session.timed?'Time left ':'Elapsed ')+pad(Math.floor(secs/60))+':'+pad(secs%60);if(session.timed&&secs===0)finish(true)}
 function render(){
  if(!session.items.length)return;const it=session.items[session.index],q=it.q,selected=session.answers[session.index],reveal=session.done||(session.mode==='tutor'&&selected!==null);
  if($('story-body').dataset.key!==String(it.i)){
   $('story-body').replaceChildren();for(const para of it.p.text.split(/\n\s*\n/)){const p=document.createElement('p');p.textContent=para;$('story-body').append(p)}
   $('story-title').textContent=it.p.title;$('genre').textContent='TEST '+(it.i+1)+' · '+it.p.genre;$('story-body').dataset.key=String(it.i);document.querySelector('.passage').scrollTop=0;
  }
  $('position').textContent='Question '+(session.index+1)+' of '+session.items.length;
  $('question').textContent=q[0];const holder=$('options');holder.replaceChildren();
  q[1].forEach((answer,i)=>{const b=document.createElement('button');b.type='button';b.className='option';b.textContent=String.fromCharCode(65+i)+'. '+answer;b.setAttribute('aria-pressed',String(selected===i));
   if(selected===i)b.classList.add('selected');if(reveal&&i===q[2])b.classList.add('correct');if(reveal&&selected===i&&i!==q[2])b.classList.add('wrong');b.disabled=reveal;
   b.onclick=()=>{session.answers[session.index]=i;render()};holder.append(b)});
  $('feedback').classList.toggle('hidden',!reveal);$('feedback').textContent=reveal?(selected===q[2]?'✓ Correct! ':'Correct answer: '+String.fromCharCode(65+q[2])+'. ')+q[3]:'';
  $('previous').disabled=session.index===0;$('next').textContent=session.index===session.items.length-1?'Review / Submit':'Next →';
  $('fill').style.width=Math.round(100*session.answers.filter(x=>x!==null).length/session.items.length)+'%';
  $('answered').textContent=session.answers.filter(x=>x!==null).length+' of '+session.items.length+' answered';
  const nav=$('navigator');nav.replaceChildren();session.items.forEach((item,i)=>{const b=document.createElement('button');b.type='button';b.className='jump'+(i===session.index?' current':'')+(session.answers[i]!==null?' done':'');b.textContent=i+1;b.title='Question '+(i+1);b.onclick=()=>{session.index=i;render()};nav.append(b)});
 }
 $('previous').onclick=()=>{if(session.index){session.index--;render()}};
 $('next').onclick=()=>{if(session.index<session.items.length-1){session.index++;render()}else if(!session.done)submit();else{session.index=0;render()}};
 $('submit').onclick=submit;
 function submit(){if(!session.items.length||session.done)return;const missing=session.answers.filter(x=>x===null).length;if(!confirm('Submit this reading test? '+missing+' question(s) unanswered.'))return;finish(false)}
 function finish(expired){
  if(session.done)return;session.done=true;clearInterval(session.interval);session.interval=null;
  const correct=session.items.filter((it,i)=>session.answers[i]===it.q[2]).length,total=session.items.length,percent=Math.round(100*correct/total),seconds=Math.floor((Date.now()-session.started)/1000);
  history.unshift({at:new Date().toISOString(),selection:session.selection,correct,total,percent,seconds});history=history.slice(0,35);try{localStorage.setItem(KEY,JSON.stringify(history))}catch{}updateHigh();
  $('summary').classList.remove('hidden');$('summary').replaceChildren();const h=document.createElement('h2');h.textContent=expired?'Time is up — Test results':'Reading test results';const p=document.createElement('p');p.textContent=correct+' / '+total+' correct ('+percent+'%) · '+Math.floor(seconds/60)+' min '+seconds%60+' sec · '+session.answers.filter(x=>x===null).length+' unanswered';const note=document.createElement('p');note.textContent='Review any question using the question navigator to see the correct answer and explanation.';const btn=document.createElement('button');btn.className='primary';btn.type='button';btn.textContent='Review answers';btn.onclick=()=>{session.index=0;render();$('workspace').scrollIntoView({behavior:'smooth',block:'start'})};$('summary').append(h,p,note,btn);
  $('status').textContent='Test complete';render();$('summary').scrollIntoView({behavior:'smooth',block:'nearest'});
 }
 function displayHistory(){
  const el=$('history');el.replaceChildren();if(!history.length){const p=document.createElement('p');p.textContent='No completed tests yet. Choose a passage to begin.';el.append(p);return}
  history.forEach(h=>{const card=document.createElement('article');const title=document.createElement('strong');title.textContent=(h.selection==='all'?'Mixed Challenge':'Test '+(Number(h.selection)+1))+' · '+h.correct+'/'+h.total+' ('+h.percent+'%)';const note=document.createElement('p');note.textContent=new Date(h.at).toLocaleString()+' · '+Math.floor(h.seconds/60)+' min';card.append(title,note);el.append(card)})
 }
 $('clear').onclick=()=>{if(confirm('Clear locally saved comprehension scores?')){history=[];try{localStorage.removeItem(KEY)}catch{}updateHigh();displayHistory()}};
})();
