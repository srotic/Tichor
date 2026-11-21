'use strict';
(()=>{
const $=id=>document.getElementById(id),KEY='tichor-kinder-brain-games-v1';
const games=[
 {name:'Memory Match',icon:'🃏',description:'Flip cards and find picture pairs.',kind:'memory'},
 {name:'Pattern Detective',icon:'🧩',description:'Find what comes next in a repeating pattern.',kind:'quiz'},
 {name:'Odd One Out',icon:'🔍',description:'Spot the picture that does not belong.',kind:'quiz'},
 {name:'Look Closely',icon:'👀',description:'Find a special object among other objects.',kind:'quiz'},
 {name:'Put It in Order',icon:'🚂',description:'Think about what happens first, next and last.',kind:'quiz'},
 {name:'Shape Detectives',icon:'🔷',description:'Recognize and compare shapes.',kind:'quiz'},
 {name:'Little Logic',icon:'💡',description:'Choose what makes sense from clues.',kind:'quiz'},
 {name:'Listen & Follow',icon:'👂',description:'Listen to simple directions and select the right answer.',kind:'quiz'}
];
const q=(prompt,visual,correct,options,why)=>({prompt,visual,correct,options,why});
const bank=[
 [],
 [
 q('What comes next?','🔴 🔵 🔴 🔵 ❓','🔴',['🔵','🔴','🟡','🟢'],'Red and blue keep taking turns.'),
 q('Finish the pattern.','⭐ 🌙 ⭐ 🌙 ❓','⭐',['🌙','☀️','⭐','💜'],'A star follows a moon in this repeating pair.'),
 q('Which comes next?','🍎 🍎 🍌 🍎 🍎 🍌 ❓','🍎',['🍌','🍎','🍇','🍓'],'The pattern repeats two apples, then one banana.'),
 q('What should be next?','🐟 🐠 🐟 🐠 ❓','🐟',['🐬','🐟','🦀','🐠'],'The two fish pictures alternate.'),
 q('Find the next shape.','🔺 🔺 🟦 🔺 🔺 🟦 ❓','🔺',['🟦','🟣','🔺','⭐'],'Two triangles are followed by a square.')
 ],
 [
 q('Which one does NOT belong?','🍎 🍊 🍌 🚗','🚗',['🍎','🚗','🍌','🍊'],'Three are fruits. A car is not a fruit.'),
 q('Which one is different?','🐶 🐱 🐰 🥕','🥕',['🐱','🐶','🥕','🐰'],'The others are animals. A carrot is a vegetable.'),
 q('Find the odd one out.','🟦 🟦 🟦 🔺','🔺',['🔺','🟦','🔴','⭐'],'The triangle is different from the three blue squares.'),
 q('Which picture is NOT a way to travel?','🚗 🚲 🚂 🌳','🌳',['🚂','🌳','🚲','🚗'],'Cars, bicycles and trains are used for travel.'),
 q('Which object is different?','🧤 🧦 👟 🍦','🍦',['🧦','🍦','👟','🧤'],'The first three are worn. Ice cream is food.')
 ],
 [
 q('How many stars can you spot?','⭐ 🍎 ⭐ 🌸 ⭐ 🍎','3',['2','3','4','5'],'Count each star once: one, two, three.'),
 q('Which is the only blue object?','🔴 🟡 🔵 🟠','🔵',['🔴','🟡','🟠','🔵'],'The blue circle is the one we are looking for.'),
 q('How many apples do you see?','🍎 🍐 🍎 🍌 🍎','3',['2','4','3','5'],'Three pictures are apples.'),
 q('Find the picture with wings.','🐢 🐠 🦋 🐱','🦋',['🐢','🦋','🐱','🐠'],'The butterfly has wings.'),
 q('How many hearts do you see?','💜 💛 💜 ⭐ 💜','3',['1','2','3','4'],'Count only the purple hearts.')
 ],
 [
 q('What do you usually do FIRST when you wake up for school?','🌅 → ? → 🎒','Get dressed',['Go to bed','Eat dinner','Get dressed','Turn out the lights'],'Getting dressed is a morning routine before leaving.'),
 q('What happens AFTER planting a seed and giving it care?','🌱 → 🌻','A plant grows',['The seed becomes a bicycle','A plant grows','It turns into a stone','The pot disappears'],'With suitable conditions a seed can develop into a plant.'),
 q('Which is the smallest number?','8   3   6   5','3',['8','6','5','3'],'Three is smaller than five, six and eight.'),
 q('Which comes BETWEEN 2 and 4?','2 → ❓ → 4','3',['2','4','3','5'],'The counting order goes two, three, four.'),
 q('How do we order these from shortest to tallest?','🌱 🌷 🌳','Sprout, flower, tree',['Tree, flower, sprout','Sprout, flower, tree','Flower, tree, sprout','All the same'],'The sprout is shortest, then flower, then tree.')
 ],
 [
 q('Which picture shows a triangle?','🔺 🟦 🟡 ⭐','🔺',['🟦','🟡','🔺','⭐'],'A triangle has three straight sides.'),
 q('Which shape has no corners?','🟡 🟦 🔺','Circle',['Square','Triangle','Circle','Rectangle'],'A circle is round with no corners.'),
 q('How many sides does a square have?','🟦','4',['3','5','4','6'],'A square has four sides.'),
 q('Which solid object is shaped like a ball?','⚽ 🎲 🥫','Sphere',['Cube','Sphere','Cylinder','Cone'],'A ball is a sphere, a round solid object.'),
 q('Which shape has three corners?','🔺','Triangle',['Circle','Square','Rectangle','Triangle'],'A triangle has three corners.')
 ],
 [
 q('Lina has one mitten. What does she need to make a pair?','🧤 + ❓','Another mitten',['A spoon','Another mitten','A hat','A book'],'A pair of mittens has two mittens.'),
 q('It is raining outside. Which item might keep you dry?','🌧️','Umbrella',['Sunglasses','Umbrella','Ice cream','Sandals'],'An umbrella can help keep rain off.'),
 q('Three friends each want one chair. How many chairs are needed?','👧 👦 👧','3',['1','2','4','3'],'Each of the three friends needs one chair.'),
 q('You have five blocks. You give away one. How many are left?','🧱 🧱 🧱 🧱 🧱 − 1','4',['3','5','4','6'],'Five take away one equals four.'),
 q('The light is red at a crossing. What should you do?','🚦🔴','Stop and wait',['Run across','Stop and wait','Close your eyes','Walk without looking'],'Stop and follow the crossing signals and adult guidance.')
 ],
 [
 q('Listen: choose the animal that barks.','🐱 🐶 🐟 🐦','🐶',['🐦','🐶','🐟','🐱'],'A dog barks.'),
 q('Listen: touch the number FOUR.','1  2  3  4','4',['1','3','4','2'],'Four is the number after three.'),
 q('Listen: find the biggest animal in this group.','🐜 🐭 🐘','🐘',['🐜','🐘','🐭','🐝'],'An elephant is much larger than an ant or mouse.'),
 q('Listen: choose the colour of a ripe yellow banana.','🍌','Yellow',['Blue','Yellow','Purple','Pink'],'A ripe yellow banana is yellow.'),
 q('Listen: find the star.','🟦 ⭐ 🟡 🔺','⭐',['🔺','🟡','⭐','🟦'],'The star has pointed rays.')
 ]
];
if(bank.length!==8||bank.slice(1).some(g=>g.length!==5)||games.length!==8){document.body.insertAdjacentText('beforeend','Brain games data unavailable. Please reload.');return}
let scores=[];try{const data=JSON.parse(localStorage.getItem(KEY)||'[]');if(Array.isArray(data))scores=data}catch{}
let state={index:-1,round:0,stars:0,errors:0,ready:false,mode:'',pairs:0,opened:[],matched:new Set(),busy:false,finished:false};
let soundOn=true,audio=null,timeout=null;
const view=id=>{stopNarration();document.querySelectorAll('.screen').forEach(x=>x.classList.toggle('active',x.id===id));document.querySelectorAll('.tab').forEach(b=>b.setAttribute('aria-selected',String(b.dataset.view===id)));if(id==='records')history()};
document.querySelectorAll('.tab').forEach(b=>b.onclick=()=>view(b.dataset.view));
function say(text){if(!soundOn||!('speechSynthesis'in window)||typeof SpeechSynthesisUtterance==='undefined')return;stopNarration();try{const u=new SpeechSynthesisUtterance(text);u.rate=.84;u.pitch=1.12;window.speechSynthesis.speak(u)}catch{}}
function stopNarration(){if('speechSynthesis'in window)try{window.speechSynthesis.cancel()}catch{}}
function chime(good){if(!soundOn)return;try{const AC=window.AudioContext||window.webkitAudioContext;if(!AC)return;audio??=new AC();if(audio.state==='suspended')audio.resume().catch(()=>{});const freq=good?[523,659,784]:[330,264];freq.forEach((f,i)=>{const t=audio.currentTime+i*.11,o=audio.createOscillator(),g=audio.createGain();o.frequency.value=f;g.gain.setValueAtTime(.0001,t);g.gain.exponentialRampToValueAtTime(.065,t+.012);g.gain.exponentialRampToValueAtTime(.0001,t+.18);o.connect(g);g.connect(audio.destination);o.start(t);o.stop(t+.19)})}catch{}}
function scramble(a,seed){const b=a.slice();for(let i=b.length-1;i>0;i--){const j=(seed*7+i*3+5)%(i+1);[b[i],b[j]]=[b[j],b[i]]}return b}
function updateStars(){$('star-total').textContent=scores.reduce((n,x)=>n+x.stars,0)+' ★'}updateStars();
games.forEach((game,i)=>{const card=document.createElement('article');card.className='game-card';const icon=document.createElement('div');icon.className='emoji';icon.textContent=game.icon;const h=document.createElement('h3');h.textContent=game.name;const p=document.createElement('p');p.textContent=game.description;const b=document.createElement('button');b.type='button';b.className='primary';b.textContent='Play five rounds →';b.onclick=()=>start(i);card.append(icon,h,p,b);$('game-cards').append(card)});
function start(i){clearTimeout(timeout);state={index:i,round:0,stars:0,errors:0,ready:false,mode:games[i].kind,pairs:0,opened:[],matched:new Set(),busy:false,finished:false};$('summary').classList.add('hidden');$('play-workspace').classList.remove('hidden');$('game-title').textContent=games[i].icon+' '+games[i].name;view('game');render();window.scrollTo({top:0,behavior:'instant'})}
function render(){if(state.index<0||state.finished)return;clearTimeout(timeout);state.ready=false;$('next').disabled=true;$('next').textContent=state.round===4?'See my stars ★':'Next challenge →';$('round-label').textContent='Round '+(state.round+1)+' of 5';$('progress').style.width=(state.round/5*100)+'%';$('feedback').classList.add('hidden');$('feedback').textContent='';$('play-area').replaceChildren();$('choices').replaceChildren();$('memory-grid').replaceChildren();$('memory-grid').classList.add('hidden');$('choices').classList.remove('hidden');
 if(state.mode==='memory'){renderMemory();return}
 const item=bank[state.index][state.round];$('prompt').textContent=item.prompt;
 const v=document.createElement('div');v.className='sample';v.textContent=item.visual;$('play-area').append(v);
 for(const choice of scramble(item.options,state.round+state.index)){const b=document.createElement('button');b.type='button';b.className='choice';b.textContent=choice;b.onclick=()=>respond(choice,b,item);$('choices').append(b)}
 say(item.prompt);
}
function feedback(message,success){$('feedback').classList.remove('hidden');$('feedback').textContent=message;chime(success);if(success)say(message)}
function respond(choice,button,item){if(state.ready)return;if(choice!==item.correct){state.errors++;button.disabled=true;button.classList.add('wrong');feedback('Not quite. Try again—you can find it!',false);return}
 if(state.errors===0)state.stars++;state.ready=true;button.classList.add('correct');for(const b of $('choices').children)b.disabled=true;$('next').disabled=false;feedback('Great thinking! '+item.why,true)}
function renderMemory(){
 $('prompt').textContent='Find all three matching pairs! Tap two cards at a time.';$('choices').classList.add('hidden');$('memory-grid').classList.remove('hidden');
 const sets=[['🐱','🐶','🐰'],['🍎','🍇','🍌'],['⭐','🌙','☀️'],['🚗','🚲','🚂'],['🌻','🌷','🌼']];
 const cards=scramble([...sets[state.round],...sets[state.round]],state.round+2);
 state.opened=[];state.matched=new Set();state.pairs=0;state.busy=false;
 cards.forEach((picture,i)=>{const b=document.createElement('button');b.type='button';b.className='memory-tile';b.textContent='?';b.setAttribute('aria-label','Hidden card '+(i+1));b.dataset.picture=picture;b.dataset.position=String(i);b.onclick=()=>flip(b);$('memory-grid').append(b)});
 say('Remember where the pictures are. Tap two cards to find a matching pair.');
}
function flip(button){
 if(state.busy||state.ready||button.disabled||state.opened.includes(button))return;
 button.textContent=button.dataset.picture;button.classList.add('revealed');button.setAttribute('aria-label',button.dataset.picture);state.opened.push(button);
 if(state.opened.length!==2)return;
 const [a,b]=state.opened;
 if(a.dataset.picture===b.dataset.picture){
  a.classList.add('matched');b.classList.add('matched');a.disabled=b.disabled=true;state.matched.add(a.dataset.picture);state.pairs++;state.opened=[];chime(true);
  if(state.pairs===3){state.ready=true;if(state.errors<=2)state.stars++;$('next').disabled=false;feedback('You matched every pair! Wonderful memory!',true)}
 }else{
  state.errors++;state.busy=true;chime(false);timeout=setTimeout(()=>{a.textContent=b.textContent='?';a.classList.remove('revealed');b.classList.remove('revealed');a.setAttribute('aria-label','Hidden card '+(Number(a.dataset.position)+1));b.setAttribute('aria-label','Hidden card '+(Number(b.dataset.position)+1));state.opened=[];state.busy=false},1100);
 }
}
$('next').onclick=()=>{if(!state.ready)return;clearTimeout(timeout);state.errors=0;if(state.round<4){state.round++;render()}else finish()};
$('speak').onclick=()=>{if(state.index<0)return;say(state.mode==='memory'?'Find the matching pairs. Tap two cards at a time.':bank[state.index][state.round].prompt)};
$('mute').onclick=()=>{soundOn=!soundOn;if(!soundOn)stopNarration();$('mute').textContent=soundOn?'Sound on':'Sound off'};
function finish(){state.finished=true;state.ready=false;stopNarration();$('progress').style.width='100%';$('play-workspace').classList.add('hidden');const score={game:state.index,stars:state.stars,date:new Date().toISOString()};scores.unshift(score);scores=scores.slice(0,100);try{localStorage.setItem(KEY,JSON.stringify(scores))}catch{}updateStars();
 const box=$('summary');box.classList.remove('hidden');box.replaceChildren();const h=document.createElement('h2');h.textContent='🎉 Brilliant brain work!';const scoreLine=document.createElement('p');scoreLine.style.fontSize='24px';scoreLine.textContent='★ '+state.stars+' out of 5 stars';const desc=document.createElement('p');desc.textContent='You finished '+games[state.index].name+'. Keep exploring and practise again whenever you want.';const actions=document.createElement('div');actions.className='toolbar';const replay=document.createElement('button');replay.className='primary';replay.textContent='Play again';replay.onclick=()=>start(state.index);const back=document.createElement('button');back.className='secondary';back.textContent='Choose another game';back.onclick=()=>view('home');actions.append(replay,back);box.append(h,scoreLine,desc,actions);chime(true)}
function history(){const list=$('history');list.replaceChildren();if(!scores.length){const p=document.createElement('p');p.textContent='No stars earned yet. Choose a game to begin!';list.append(p);return}scores.forEach(s=>{const row=document.createElement('article');const title=document.createElement('strong');title.textContent=(games[s.game]?.name||'Brain game')+' · '+s.stars+' ★';const date=document.createElement('p');date.className='small';date.textContent=new Date(s.date).toLocaleString();row.append(title,date);list.append(row)})}
$('clear').onclick=()=>{if(!confirm('Clear saved brain-game stars on this device?'))return;scores=[];try{localStorage.removeItem(KEY)}catch{}updateStars();history()};
})();
