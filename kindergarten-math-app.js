'use strict';
(()=>{
const $=id=>document.getElementById(id),KEY='tichor-kinder-math-stars-v1';
const lessons=[
['Count to 5','🍎','Point and count small groups of objects.'],
['Count to 10','🐻','Count larger groups carefully.'],
['Recognize Numbers','🔢','Match a group with its number.'],
['More or Fewer','⚖️','Compare groups and find more, fewer, or equal.'],
['Number Order','🚂','Find the next and missing numbers.'],
['Shapes Around Us','🔺','Recognize circles, squares, triangles, rectangles and stars.'],
['Repeating Patterns','🧩','Discover what comes next in a pattern.'],
['Sort and Match','🧺','Sort objects by their type and count matches.'],
['Make 5 and 10','🖐️','Find number partners that make five or ten.'],
['Little Additions','➕','Put small groups together.'],
['Take Away','➖','Take objects away and count what remains.'],
['Measurements & Position','📏','Compare length, size and positions.']
];
const symbols=['🍎','⭐','🐟','🧸','🍓','🐝','🍀','🚗','🌻','🦋','🟢','🍪'];
function activity(question,correct,choices,visual,explanation){return {question,correct:String(correct),choices:choices.map(String),visual,explanation}}
function numberChoices(answer,low=0,high=20){const chosen=[answer];for(let d=1;chosen.length<4&&d<=high;d++){if(answer+d<=high)chosen.push(answer+d);if(chosen.length<4&&answer-d>=low)chosen.push(answer-d)}return chosen.slice(0,4)}
function objects(n,symbol){return '<span class="object" aria-hidden="true">'+symbol.repeat(n)+'</span>'}
function arrayObjects(n,symbol){return Array.from({length:n},()=>'<span class="object" aria-hidden="true">'+symbol+'</span>').join('')}
function pattern(vals){return vals.map(v=>'<span class="object" aria-hidden="true">'+v+'</span>').join('')}
function build(topic){
 const items=[];const push=(q,a,options,visual,why)=>items.push(activity(q,a,options,visual,why));
 if(topic===0||topic===1||topic===2){const hi=topic===0?5:10;for(let k=0;k<8;k++){const n=topic===0?1+k%5:topic===1?3+k%8:1+k%10;const safe=Math.min(hi,n);const symbol=symbols[(k+topic)%symbols.length];push(topic===2?'Which number matches the objects?':'How many '+(symbol==='🍎'?'apples':'things')+' do you see?',safe,numberChoices(safe,0,10),arrayObjects(safe,symbol),'Count each object once. There are '+safe+' altogether!')}}
 else if(topic===3){for(let k=0;k<8;k++){const a=2+k%5,b=k%3===0?a:Math.max(1,a+(k%2?2:-1));let ans=a===b?'Same number':a>b?'Left group':'Right group';push(k%2===0?'Which group has MORE?':'Which group has FEWER?',k%2===0?ans:(a===b?'Same number':a<b?'Left group':'Right group'),['Left group','Right group','Same number','Cannot tell'],arrayObjects(a,'🍎')+'<span class="symbol">|</span>'+arrayObjects(b,'🍐'),'Count both groups: left has '+a+', right has '+b+'.')}}
 else if(topic===4){for(let k=0;k<8;k++){let n=1+k%8,missing=k%2? n+1:n+2;push('What number belongs in the empty box?',missing,numberChoices(missing,0,12),'<span class="num">'+n+' → '+(k%2?'❓ → '+(n+2):(n+1)+' → ❓')+'</span>','Count forward one number at a time. The missing number is '+missing+'.')}}
 else if(topic===5){const shapeNames=['circle','square','triangle','rectangle','star'];for(let k=0;k<8;k++){const name=shapeNames[k%5];const options=['Circle','Square','Triangle','Rectangle','Star'];push('What shape is this?',name.charAt(0).toUpperCase()+name.slice(1),[name.charAt(0).toUpperCase()+name.slice(1),...options.filter(x=>x.toLowerCase()!==name).slice(0,3)],name==='star'?'<span class="shape star">★</span>':'<span class="shape '+name+'"></span>','This is a '+name+'. Look at its sides and corners!')}}
 else if(topic===6){for(let k=0;k<8;k++){let pair=[['🔴','🔵'],['⭐','🌙'],['🍎','🍐'],['🟡','🟢']][k%4],p=k%2?[pair[0],pair[0],pair[1]]:[pair[0],pair[1]];let seq=Array.from({length:6},(_,i)=>p[i%p.length]);let correct=p[6%p.length];let options=[...new Set([...pair,'🟣','🍀','🌸'])].slice(0,4);if(!options.includes(correct))options[3]=correct;push('What comes next in the pattern?',correct,options,pattern([...seq,'❓']),'The same pattern repeats. The next symbol is '+correct+'.')}}
 else if(topic===7){for(let k=0;k<8;k++){let symbol=['🍎','🍊','🍋','🍇'][k%4];let other=['🍎','🍊','🍋','🍇'][(k+1)%4];let a=1+(k%4),b=2+(k%3);push('How many '+symbol+' do you see?',a,numberChoices(a,0,9),pattern([...Array(a).fill(symbol),...Array(b).fill(other)].sort((x,y)=>((x.charCodeAt(0)+k)%7)-((y.charCodeAt(0)+k)%7))),'Count only the matching objects: '+a+'.')}}
 else if(topic===8){for(let k=0;k<8;k++){let target=k%2?10:5,part=1+(k%(target-1)),answer=target-part;push('What number makes '+target+' when added to '+part+'?',answer,numberChoices(answer,0,10),'<span class="num">'+part+' + ❓ = '+target+'</span>','You need '+answer+' more to make '+target+'.')}}
 else if(topic===9){for(let k=0;k<8;k++){let a=1+k%4,b=1+(k+2)%4;push('How many are there altogether?',a+b,numberChoices(a+b,0,10),arrayObjects(a,'🐞')+'<span class="symbol">+</span>'+arrayObjects(b,'🐞'),'Add the groups: '+a+' + '+b+' = '+(a+b)+'.')}}
 else if(topic===10){for(let k=0;k<8;k++){let start=3+(k%6),remove=1+k%Math.min(3,start),answer=start-remove;push('You have '+start+' cookies and eat '+remove+'. How many remain?',answer,numberChoices(answer,0,10),arrayObjects(start,'🍪')+'<span class="symbol">− '+remove+'</span>','Start at '+start+' and count back '+remove+': '+answer+' left.')}}
 else if(topic===11){const scenarios=[
 ['Which object is LONGER?','Long pencil',['Long pencil','Short pencil','Same length','Not sure'],'✏️ ━━━━━━━━━　✏️ ━━━','The longer pencil reaches farther.'],
 ['Which object is SHORTER?','Short line',['Long line','Short line','Same length','Not sure'],'<span class="num">━━━━━━　──</span>','The short line is shorter.'],
 ['Which is HEAVIER in real life?','Elephant',['Elephant','Feather','Both same','Cannot tell'],'<span class="object">🐘　🪶</span>','An elephant is much heavier than a feather.'],
 ['Which object is TALLER?','Tree',['Tree','Flower','Same height','Not sure'],'<span class="object">🌳　🌷</span>','A tree is usually taller than a flower.'],
 ['Which object holds MORE water?','Bucket',['Cup','Bucket','Both same','Not sure'],'<span class="object">🥤　🪣</span>','A bucket usually holds more water than a cup.'],
 ['Which object is ROUND?','Ball',['Book','Ball','Pencil','Shoe'],'<span class="object">📗　⚽　✏️</span>','A ball is round.'],
 ['Which item is at the TOP?','Sun',['Sun','House','Grass','Not sure'],'<span class="num">☀️</span><span class="symbol">↓</span><span class="object">🏠</span>','The sun is shown above the house.'],
 ['Which is SMALLER?','Ant',['Elephant','Ant','Both same','Not sure'],'<span class="object">🐘　🐜</span>','An ant is smaller than an elephant.']
 ];for(const [q,a,opts,visual,why] of scenarios)push(q,a,opts,visual,why)}
 if(items.length!==8)throw Error('Each math session needs eight questions');
 for(const item of items){if(!item.choices.includes(item.correct)||new Set(item.choices).size!==4)throw Error('Invalid answer choices: '+item.question)}
 return items;
}
const BANK=lessons.map((_,i)=>build(i));
let history=[];try{const parsed=JSON.parse(localStorage.getItem(KEY)||'[]');if(Array.isArray(parsed))history=parsed}catch{}
let play={topic:-1,index:0,firstCorrect:0,tries:0,answered:[],tried:[],finished:false};
const view=id=>{if(id!=='play'&&window.KINDER_MEDIA?.active)window.KINDER_MEDIA.stop();document.querySelectorAll('.screen').forEach(x=>x.classList.toggle('active',x.id===id));document.querySelectorAll('.tab').forEach(x=>x.setAttribute('aria-selected',String(x.dataset.view===id)));if(id==='progress-view')renderHistory()};
document.querySelectorAll('.tab').forEach(button=>button.onclick=()=>view(button.dataset.view));
const totalStars=()=>history.reduce((a,h)=>a+(Number(h.stars)||0),0);const refreshStars=()=>$('stars').textContent=totalStars()+' ★';refreshStars();
lessons.forEach(([name,emoji,description],i)=>{const card=document.createElement('article');card.className='lesson';const mark=document.createElement('div');mark.className='emoji';mark.textContent=emoji;const label=document.createElement('div');label.className='label';label.textContent='SESSION '+(i+1)+' OF 12';const heading=document.createElement('h3');heading.textContent=name;const info=document.createElement('p');info.textContent=description;const b=document.createElement('button');b.className='primary';b.type='button';b.textContent='🎬 Watch & Play →';b.onclick=()=>start(i,true);
 const straight=document.createElement('button');straight.className='secondary video-launch';straight.type='button';straight.textContent='Go straight to practice';straight.onclick=()=>start(i,false);
 card.append(mark,label,heading,info,b,straight);$('lesson-grid').append(card)});
function start(topic,withLesson=true){
 if(play.topic>=0&&!play.finished&&play.answered.some(Boolean)&&!confirm('Start a different session? Your current answers will not be saved.'))return;
 window.KINDER_MEDIA?.stop();play={topic,index:0,firstCorrect:0,tries:0,answered:Array(8).fill(false),tried:Array(8).fill(false),finished:false};
 $('lesson-name').textContent=lessons[topic][1]+' '+lessons[topic][0];$('workspace').classList.remove('hidden');$('finished').classList.add('hidden');view('play');
 if(withLesson&&window.KINDER_MEDIA){window.KINDER_MEDIA.start(topic,()=>{$('workspace').classList.remove('hidden');render();announceQuestion()})}
 else{render();announceQuestion()}
 window.scrollTo({top:0,behavior:'instant'});
}
function render(){if(play.topic<0)return;const item=BANK[play.topic][play.index];$('step-label').textContent='Question '+(play.index+1)+' of 8';$('instruction').textContent=item.question;$('visual').innerHTML=item.visual;$('visual').setAttribute('aria-label',item.question+'; visual illustration');$('fill').style.width=(play.answered.filter(Boolean).length/8*100)+'%';$('answers').replaceChildren();$('feedback').classList.toggle('hidden',!play.answered[play.index]);$('feedback').textContent=play.answered[play.index]?'🌟 Great job! '+item.explanation:'';$('next').disabled=!play.answered[play.index];$('next').textContent=play.index===7?'See my stars ★':'Next →';$('back').disabled=play.index===0;
 const options=item.choices.slice();const offset=(play.index+play.topic)%4;const rotated=options.slice(offset).concat(options.slice(0,offset));for(const option of rotated){const b=document.createElement('button');b.type='button';b.className='choice';b.textContent=option;b.disabled=play.answered[play.index];if(play.answered[play.index]&&option===item.correct)b.classList.add('correct');b.onclick=()=>answer(option,b);$('answers').append(b)}
}
function announceQuestion(){if(play.topic<0||window.KINDER_MEDIA?.active)return;window.KINDER_MEDIA?.speak(BANK[play.topic][play.index].question)}
function announceResult(correct){window.KINDER_MEDIA?.tone(correct);if(correct){window.KINDER_MEDIA?.speak('Great job! '+BANK[play.topic][play.index].explanation)}else window.KINDER_MEDIA?.speak('Good try! Try another answer.')}
function answer(value,button){if(play.answered[play.index])return;const item=BANK[play.topic][play.index];if(value===item.correct){if(!play.tried[play.index])play.firstCorrect++;play.answered[play.index]=true;play.tries=0;render();announceResult(true);return}play.tries++;play.tried[play.index]=true;button.classList.add('wrong');$('feedback').classList.remove('hidden');$('feedback').textContent='Almost! Try another answer. You can do it!';button.disabled=true;announceResult(false)}
$('next').onclick=()=>{if(!play.answered[play.index])return;if(play.index<7){play.index++;play.tries=0;render();announceQuestion()}else finish()};
$('back').onclick=()=>{if(play.index>0){play.index--;play.tries=0;render();announceQuestion()}};
$('hear').onclick=()=>{if(play.topic<0)return;if(!window.KINDER_MEDIA){$('feedback').textContent='This browser does not support narration.';$('feedback').classList.remove('hidden');return}announceQuestion()};
function finish(){if(play.finished)return;window.KINDER_MEDIA?.stop();play.finished=true;window.KINDER_MEDIA?.tone(true);const stars=play.firstCorrect;history.unshift({topic:play.topic,stars,at:new Date().toISOString()});history=history.slice(0,100);try{localStorage.setItem(KEY,JSON.stringify(history))}catch{}refreshStars();$('workspace').classList.add('hidden');$('finished').classList.remove('hidden');$('fill').style.width='100%';const container=$('finished');container.replaceChildren();const heading=document.createElement('h2');heading.textContent='🎉 You did it!';const big=document.createElement('strong');big.textContent='★ '+stars+' / 8 stars';const detail=document.createElement('p');detail.textContent='You finished '+lessons[play.topic][0]+'! You earn one star for each correct first answer. You can practise again whenever you like.';const replay=document.createElement('button');replay.className='primary';replay.textContent='Play again';replay.onclick=()=>start(play.topic);const choose=document.createElement('button');choose.className='secondary';choose.textContent='Choose another session';choose.onclick=()=>view('lessons');const actions=document.createElement('div');actions.className='toolbar';actions.append(replay,choose);container.append(heading,big,detail,actions)}
function renderHistory(){const el=$('history');el.replaceChildren();if(!history.length){const p=document.createElement('p');p.textContent='No math stars yet. Start a session to earn some!';el.append(p);return}history.forEach(h=>{const card=document.createElement('article');const title=document.createElement('strong');title.textContent=(lessons[h.topic]?.[0]||'Math session')+' · '+h.stars+' ★';const date=document.createElement('p');date.className='small';date.textContent=new Date(h.at).toLocaleString();card.append(title,date);el.append(card)})}
$('clear').onclick=()=>{if(confirm('Clear all kindergarten math stars saved on this device?')){history=[];try{localStorage.removeItem(KEY)}catch{}refreshStars();renderHistory()}};
})();
