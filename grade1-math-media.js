'use strict';
/* Grade 1 self-contained animated video-style teaching. No external video or audio embeds.
   Browser speech is optional and can be muted. Playback requires a user gesture. */
(()=>{
const source=(window.GRADE1_MATH_BANK||[]).map(x=>[x.title,x.icon,x.scenes.map(s=>s.line),x.scenes.map(s=>s.display),x.checkpoint.question,x.checkpoint.correct,x.checkpoint.choices]);
let active=false,position=0,lesson=null,activeTopic=-1,task=null,scheduled=null,playing=false,muted=false,unlocked=false;
const $=id=>document.getElementById(id);
let audioContext=null;
const allowMotion=()=>!window.matchMedia('(prefers-reduced-motion: reduce)').matches;
function stopSpeech(){if('speechSynthesis' in window){try{window.speechSynthesis.cancel()}catch{}}}
function speak(text){stopSpeech();if(muted||!('speechSynthesis' in window)||typeof SpeechSynthesisUtterance==='undefined')return;try{const u=new SpeechSynthesisUtterance(text);u.lang='en-CA';u.rate=.87;u.pitch=1.1;u.volume=.9;window.speechSynthesis.speak(u)}catch{}}
function tone(good){if(muted)return;try{const A=window.AudioContext||window.webkitAudioContext;if(!A)return;audioContext??=new A();if(audioContext.state==='suspended')audioContext.resume().catch(()=>{});const now=audioContext.currentTime;const sequence=good?[523.25,659.25,783.99]:[330,262];sequence.forEach((frequency,i)=>{const osc=audioContext.createOscillator(),gain=audioContext.createGain(),t=now+i*.105;osc.type='sine';osc.frequency.value=frequency;gain.gain.setValueAtTime(.0001,t);gain.gain.exponentialRampToValueAtTime(.09,t+.015);gain.gain.exponentialRampToValueAtTime(.0001,t+.16);osc.connect(gain);gain.connect(audioContext.destination);osc.start(t);osc.stop(t+.17)})}catch{}}
function clear(){clearTimeout(scheduled);scheduled=null;stopSpeech()}
function sceneHtml(display,emoji,topic){
 const root=document.createElement('div');root.className='video-picture';root.setAttribute('aria-label','Animated objects illustrating the lesson');
 const add=(symbol,i)=>{const el=document.createElement('span');el.className='movie-object';el.style.setProperty('--order',String(i));el.textContent=symbol;root.append(el)};
 if(/^\d+$/.test(display)&&topic<=2){const n=Math.min(10,Number(display));for(let i=0;i<n;i++)add(emoji,i)}
 else if(/^\d+\|\d+$/.test(display)){const [a,b]=display.split('|').map(Number);for(let i=0;i<a;i++)add('🍓',i);add('│',a);for(let i=0;i<b;i++)add('🍓',a+i+1)}
 else if(['circle','square','triangle','rectangle'].includes(display)){const shape=document.createElement('div');shape.className='movie-shape '+display;shape.setAttribute('aria-label',display);root.append(shape)}
 else if(display.includes(' ')&&display.includes('🔴')){display.split(/\s+/).forEach((e,i)=>add(e,i))}
 else {const el=document.createElement('strong');el.className='movie-equation';el.textContent=display;root.append(el)}
 return root;
}
function showScene(){
 if(!active||!lesson)return;
 clear();playing=true;unlocked=false;
 $('video-checkpoint').classList.add('hidden');$('video-choices').replaceChildren();
 $('video-step').textContent='Teaching scene '+(position+1)+' of 4';
 $('video-caption').textContent=lesson[2][position];
 $('video-picture').replaceChildren(sceneHtml(lesson[3][position],lesson[1],activeTopic)); 
 $('video-next').textContent=position===3?'Try a question →':'Next scene →';
 $('video-next').disabled=false;$('video-play').textContent='⏸ Pause';
 speak(lesson[2][position]);
 scheduled=setTimeout(()=>{if(active&&playing)advance()},allowMotion()?6300:7600);
}
function advance(){clear();if(position<3){position++;showScene()}else checkpoint()}
function checkpoint(){
 if(!active)return;clear();playing=false;unlocked=false;$('video-play').textContent='▶ Replay voice';
 $('video-step').textContent='Your turn!';$('video-caption').textContent=lesson[4];
 $('video-checkpoint').classList.remove('hidden');$('video-next').textContent='Start math activities →';$('video-next').disabled=true;
 $('video-choices').replaceChildren();
 for(const value of lesson[6]){const b=document.createElement('button');b.type='button';b.className='movie-choice';b.textContent=value;b.onclick=()=>{
  if(unlocked)return;
  if(value===lesson[5]){
   unlocked=true;tone(true);b.classList.add('correct');$('video-message').textContent='🌟 Brilliant! You are ready to practise.';$('video-next').disabled=false;
   speak('Great job! Now let us practise!');
   for(const child of $('video-choices').children)child.disabled=true;
  }else{tone(false);b.classList.add('wrong');b.disabled=true;$('video-message').textContent='Good try! Look at the lesson again, and choose another answer.'}
 };$('video-choices').append(b)}
 $('video-message').textContent='Choose the best answer to continue.';speak(lesson[4]);
}
function start(topic,onFinish){
 if(!source[topic])return;clear();lesson=source[topic];activeTopic=topic;task=onFinish;position=0;active=true;playing=true;unlocked=false;
 $('video-lesson').classList.remove('hidden');$('workspace').classList.add('hidden');$('finished').classList.add('hidden');
 $('video-title').textContent=lesson[1]+' '+lesson[0];$('video-message').textContent='';
 $('video-mute').textContent=muted?'🔇 Sound off':'🔊 Sound on';showScene();
}
function stop(){clear();active=false;playing=false;lesson=null;task=null;$('video-lesson').classList.add('hidden')}
function finish(){if(!active)return;const done=task;stop();if(typeof done==='function')done()}
$('video-play').onclick=()=>{if(!active)return;if($('video-checkpoint').classList.contains('hidden')){if(playing){clear();playing=false;$('video-play').textContent='▶ Resume'}else{playing=true;showScene()}}else speak(lesson[4])};
$('video-next').onclick=()=>{if(!active)return;if(!$('video-checkpoint').classList.contains('hidden')){if(unlocked)finish()}else advance()};
$('video-replay').onclick=()=>{if(!active)return;position=0;showScene()};
$('video-skip').onclick=finish;
$('video-mute').onclick=()=>{muted=!muted;stopSpeech();$('video-mute').textContent=muted?'🔇 Sound off':'🔊 Sound on';if(!muted&&active)speak($('video-checkpoint').classList.contains('hidden')?lesson[2][position]:lesson[4])};
window.GRADE1_MEDIA={start,stop,speak,tone,get active(){return active}};
})();