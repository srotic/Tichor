'use strict';
(()=>{
const $=id=>document.getElementById(id),BANK=window.TICHOR_GRADE5_BRAIN_BANK||[],KEY='tichor-grade5-brain-v1';
if(BANK.length!==8){document.body.textContent='Games unavailable. Please refresh.';return}
let history=[];try{const saved=JSON.parse(localStorage.getItem(KEY)||'[]');if(Array.isArray(saved))history=saved}catch{}
let state={game:-1,round:0,answers:[],mistakes:0,done:false,mode:'practice',timer:null,target:'',revealed:false},muted=false,voiceEnabled=true;
function escapeHTML(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
function stopSpeech(){if('speechSynthesis'in window)try{window.speechSynthesis.cancel()}catch{}}
function speak(s){if(muted||!voiceEnabled||!('speechSynthesis'in window)||typeof SpeechSynthesisUtterance==='undefined')return;stopSpeech();try{const msg=new SpeechSynthesisUtterance(s);msg.rate=.9;msg.lang='en-CA';window.speechSynthesis.speak(msg)}catch{}}
function view(id){if(id!=='play'){clearTimeout(state.timer);stopSpeech()}document.querySelectorAll('.screen').forEach(x=>x.classList.toggle('active',x.id===id));document.querySelectorAll('[data-tab]').forEach(b=>b.setAttribute('aria-selected',String(b.dataset.tab===id)));if(id==='progress')renderHistory()}
document.querySelectorAll('[data-tab]').forEach(b=>b.onclick=()=>view(b.dataset.tab));
const title=()=>BANK[state.game]?.title||'Brain Games';
const total=()=>history.reduce((n,x)=>n+x.score,0);
function update(){ $('total-stars').textContent=total()+' ★';$('best-accuracy').textContent=history.length?Math.max(...history.map(x=>Math.round(x.score/8*100)))+'%':'—'}
BANK.forEach((g,i)=>{
 const card=document.createElement('article');card.className='game-card';
 card.innerHTML='<div class="game-icon">'+escapeHTML(g.icon)+'</div><div class="small">GAME '+(i+1)+' OF 8</div><h3>'+escapeHTML(g.title)+'</h3><p>'+escapeHTML(g.description)+'</p>';
 const btn=document.createElement('button');btn.className='primary';btn.textContent='Start game →';btn.onclick=()=>start(i);
 card.append(btn);$('cards').append(card);
});update();
function start(game){
 clearTimeout(state.timer);stopSpeech();state={game,round:0,answers:[],mistakes:0,done:false,mode:'practice',timer:null,target:'',revealed:false};
 $('game-heading').textContent=BANK[game].icon+' '+title();$('workspace').classList.remove('hidden');$('end').classList.add('hidden');view('play');render();window.scrollTo({top:0,behavior:'instant'});
}
const memorySymbols=['🦊','🚀','🌻','🍄','🎯','🐢','🌙','🎈','🎹','🍎','🦋','🚲'];
function memoryRound(round){const count=3+Math.floor(round/3);const seq=[];for(let j=0;j<count;j++)seq.push(memorySymbols[(round*3+j*5)%memorySymbols.length]);const pos=round%count;const correct=seq[pos];const distractors=memorySymbols.filter(s=>!seq.includes(s)).slice(round%3,round%3+3);return {seq,position:pos,correct,options:[correct,...distractors],count}}
function render(){
 if(state.game<0||state.done)return;
 clearTimeout(state.timer);
 const game=BANK[state.game],isMemory=state.game===7,answered=state.answers[state.round]!=null;
 $('round').textContent='Challenge '+(state.round+1)+' of 8';$('bar').style.width=(state.round/8*100)+'%';$('feedback').classList.add('hidden');$('feedback').textContent='';
 $('next').disabled=!answered;$('next').textContent=state.round===7?'See results →':'Next challenge →';
 const question=isMemory?memoryRound(state.round):game.questions[state.round];
 $('question').textContent=isMemory?'Memorize the symbols, then tell us what was hidden.':question[0];
 $('visual').replaceChildren();$('choices').replaceChildren();
 if(isMemory){
  if(!answered){
   const msg=document.createElement('strong');msg.textContent=question.seq.join('   ');msg.className='sequence';$('visual').append(msg);
   $('choices').classList.add('hidden');$('visual-label').textContent='Remember the order. The picture will disappear in four seconds.';
   state.timer=setTimeout(()=>{if(state.game===7&&state.answers[state.round]==null)showMemoryQuestion(question)},4000);
  }else{
   showMemoryQuestion(question);
   reveal(answered,question.correct, 'The missing symbol was '+question.correct+'.');
  }
  speak('Remember these pictures, in order.');
 }else{
  $('choices').classList.remove('hidden');$('visual-label').textContent='Think carefully before choosing.';
  const image=game.title==='Pattern Masters'&&state.round===5?'🔴  🟨  🔺  🔴  🟨  🔺  ❓':
   game.title==='Spatial Thinkers'&&state.round===4?'Start (2,3)   → +3 right → +1 up':null;
  if(image){const graphic=document.createElement('span');graphic.className='sequence';graphic.textContent=image;$('visual').append(graphic)}
  else {const ico=document.createElement('span');ico.className='large-icon';ico.textContent=game.icon;$('visual').append(ico)}
  createChoices(question[2],question[1],question[3]);if(answered)reveal(answered,question[1],question[3]);
  speak(question[0]);
 }
}
function showMemoryQuestion(item){
 $('question').textContent='Which symbol was in position '+(item.position+1)+'?';
 $('visual-label').textContent='One picture is hidden. Remember the order!';
 $('visual').replaceChildren();const row=document.createElement('span');row.className='sequence';row.textContent=item.seq.map((v,i)=>i===item.position?'❓':v).join('   ');$('visual').append(row);
 $('choices').classList.remove('hidden');
 createChoices(item.options,item.correct,'The hidden symbol was '+item.correct+'.');
}
function createChoices(options,correct,why){
 const chosen=options.map(String);
 // Deterministic option order that varies between rounds.
 const rotate=(state.round+state.game)%4;
 const list=chosen.slice(rotate).concat(chosen.slice(0,rotate));
 $('choices').replaceChildren();
 for(const option of list){const button=document.createElement('button');button.type='button';button.className='choice';button.textContent=option;button.onclick=()=>choose(option,correct,why,button);$('choices').append(button)}
}
function choose(value,correct,why,button){
 if(state.answers[state.round]!=null)return;
 if(value!==correct){state.mistakes++;button.disabled=true;button.classList.add('wrong');$('feedback').textContent='Try another answer. Look for a clue!';$('feedback').classList.remove('hidden');return}
 const first=state.mistakes===0;state.answers[state.round]={value,correct,first};
 $('next').disabled=false;reveal(state.answers[state.round],correct,why);speak('Correct! '+why);
}
function reveal(answer,correct,why){
 for(const button of $('choices').children){button.disabled=true;if(button.textContent===correct)button.classList.add('correct')}
 $('feedback').classList.remove('hidden');$('feedback').textContent='✓ '+(answer.first?'Excellent! ★ ':'Good thinking! ')+why;
}
$('next').onclick=()=>{if(state.answers[state.round]==null)return;if(state.round===7){finish();return}state.round++;state.mistakes=0;render()};
$('hear').onclick=()=>{if(state.game<0)return;speak($('question').textContent)};
$('mute').onclick=()=>{muted=!muted;if(muted)stopSpeech();$('mute').textContent=muted?'🔇 Sound off':'🔊 Sound on'};
function finish(){
 if(state.done)return;clearTimeout(state.timer);state.done=true;
 const score=state.answers.filter(x=>x?.first).length,entry={game:state.game,score,date:new Date().toISOString()};
 history.unshift(entry);history=history.slice(0,80);try{localStorage.setItem(KEY,JSON.stringify(history))}catch{}update();
 $('workspace').classList.add('hidden');$('end').classList.remove('hidden');$('bar').style.width='100%';
 const box=$('end');box.replaceChildren();const h=document.createElement('h2');h.textContent='🎉 Mission complete!';
 const p=document.createElement('p');p.innerHTML='<strong>'+score+' / 8 stars</strong> for first-try answers. You can practise again to sharpen your thinking.';
 const replay=document.createElement('button');replay.className='primary';replay.textContent='Play again';replay.onclick=()=>start(state.game);
 const choose=document.createElement('button');choose.className='secondary';choose.textContent='Choose another game';choose.onclick=()=>view('home');
 const actions=document.createElement('div');actions.className='actions';actions.append(replay,choose);box.append(h,p,actions);
}
function renderHistory(){
 const node=$('history');node.replaceChildren();
 if(!history.length){node.textContent='No scores yet. Try your first brain game!';return}
 for(const item of history){const block=document.createElement('article');const d=new Date(item.date);block.textContent=(BANK[item.game]?.title||'Brain Game')+' — '+item.score+'/8 stars · '+(Number.isFinite(d.getTime())?d.toLocaleString():'');node.append(block)}
}
$('clear').onclick=()=>{if(!confirm('Clear brain-game scores stored on this device?'))return;history=[];try{localStorage.removeItem(KEY)}catch{}update();renderHistory()};
})();
