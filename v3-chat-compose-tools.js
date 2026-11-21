'use strict';
/* V3 composer tools menu: route through existing file/writing handlers,
   show an in-portal emoji picker, and never clip beneath the chat composer. */
(()=>{
 let panel=null,activePlus=null,view='actions';
 const emojis='😀 😃 😄 😁 😆 😅 😂 🤣 😊 🙂 😉 😍 🥰 😘 😎 🤩 🥳 😇 🤗 🤔 😐 🙄 😢 😭 😡 😴 🤒 😷 ❤️ 🧡 💛 💚 💙 💜 🤍 💕 💖 ✨ ⭐ 🌟 🔥 🎉 🎊 👍 👎 👏 🙌 🙏 💪 👋 ✌️ 🤝 🫶 👀 🌹 🌻 🌈 ☀️ 🌙 🐶 🐱 🦋 🐝 🍎 🍕 ☕ 🎂 🎁 🚗 ✈️ 💻 📚 🎵 ✅ ❌ 💯'.split(' ');
 const $=id=>document.getElementById(id);
 function close(){
  if(panel){panel.remove();panel=null}
  if(activePlus){activePlus.setAttribute('aria-expanded','false');activePlus=null}
 }
 function locate(){
  if(!panel||!activePlus?.isConnected){close();return}
  const rect=activePlus.getBoundingClientRect(),vp=window.visualViewport;
  const dx=vp?.offsetLeft||0,dy=vp?.offsetTop||0;
  const sw=vp?.width||window.innerWidth,sh=vp?.height||window.innerHeight;
  const width=Math.min(310,sw-24);
  panel.style.width=width+'px';
  // Clamp horizontal position; prefer aligning to the plus button.
  panel.style.left=Math.round(Math.max(dx+12,Math.min(dx+sw-width-12,rect.left)))+'px';
  const height=panel.offsetHeight;
  const above=rect.top-height-12;
  const below=rect.bottom+12;
  const top=above>=dy+10?above:below+height<=dy+sh-10?below:Math.max(dy+10,dy+sh-height-10);
  panel.style.top=Math.round(top)+'px';
 }
 function insertEmoji(value){
  const field=$('body');
  if(!field)return;
  const a=Number.isInteger(field.selectionStart)?field.selectionStart:field.value.length;
  const b=Number.isInteger(field.selectionEnd)?field.selectionEnd:a;
  field.setRangeText(value,a,b,'end');
  field.dispatchEvent(new Event('input',{bubbles:true}));
  close();field.focus({preventScroll:true});
 }
 function tool(label,sub,icon,callback){
  const b=document.createElement('button');b.type='button';b.className='tc-tools-action';b.setAttribute('role','menuitem');
  const pict=document.createElement('span');pict.className='tc-tools-icon';pict.textContent=icon;pict.setAttribute('aria-hidden','true');
  const words=document.createElement('span');words.className='tc-tools-action-label';
  const title=document.createElement('span');title.textContent=label;words.append(title);
  if(sub){const hint=document.createElement('span');hint.className='tc-tools-subtitle';hint.textContent=sub;words.append(hint)}
  b.append(pict,words);b.addEventListener('click',callback);
  panel.append(b);
 }
 function filePicker(accept){
  // Synchronous invocation from a real click supports iOS file selection.
  const input=$('tichorFile');
  if(!input){close();return}
  input.accept=accept;
  close();
  input.click();
 }
 function render(){
  if(!panel)return;
  panel.replaceChildren();
  const heading=document.createElement('div');heading.className='tc-tools-heading';heading.textContent=view==='emoji'?'CHOOSE AN EMOJI':'MESSAGE TOOLS';panel.append(heading);
  if(view==='emoji'){
   tool('Back to tools','', '‹',()=>{view='actions';render();locate()});
   const grid=document.createElement('div');grid.className='tc-emoji-grid';grid.setAttribute('role','group');grid.setAttribute('aria-label','Emoji choices');
   for(const value of emojis){
    const b=document.createElement('button');b.className='tc-emoji-choice';b.type='button';b.textContent=value;b.setAttribute('aria-label','Insert '+value);b.addEventListener('click',()=>insertEmoji(value));grid.append(b);
   }
   panel.append(grid);
  }else{
   tool('Photo','Choose an image to send','🖼️',()=>filePicker('image/png,image/jpeg,image/webp'));
   tool('Document','PDF, Word, Excel or text','📎',()=>filePicker('.pdf,.doc,.docx,.xls,.xlsx,.txt,application/pdf,text/plain'));
   tool('Emojis','Insert a smiley or symbol','😊',()=>{view='emoji';render();locate()});
   tool('Writing assistant','Improve your drafted message','✨',()=>{
    close();$('tichorWritingToggle')?.click();
    $('tichorWritingPanel')?.scrollIntoView({behavior:'smooth',block:'nearest'});
   });
  }
 }
 function toggle(button){
  if(panel&&activePlus===button){close();return}
  close();activePlus=button;view='actions';
  panel=document.createElement('div');panel.className='tc-v3-tools-portal';panel.setAttribute('role','menu');panel.setAttribute('aria-label','Message tools');
  document.body.append(panel);button.setAttribute('aria-expanded','true');button.setAttribute('aria-controls','tc-v3-tools-active');
  panel.id='tc-v3-tools-active';render();locate();
 }
 // Capture before the legacy inline "+" click handler, whose scroll-clipped menu
 // is deliberately suppressed on V3 only.
 document.addEventListener('click',e=>{
  const plus=e.target.closest?.('#sendForm.tc-minimal-composer .tc-compose-plus');
  if(plus){
   e.preventDefault();e.stopImmediatePropagation();
   toggle(plus);return;
  }
  if(panel&&!panel.contains(e.target))close();
 },true);
 document.addEventListener('keydown',e=>{if(e.key==='Escape'&&panel){e.preventDefault();close()}});
 document.addEventListener('scroll',e=>{if(panel&&e.target?.id==='messages')close()},true);
 window.addEventListener('resize',()=>{if(panel)locate()});
 window.visualViewport?.addEventListener('resize',()=>{if(panel)locate()});
 window.addEventListener('pagehide',close);
 const setup=()=>{
  const original=$('tichorFile'),status=$('tichorAttachmentStatus');
  if(!original||!status||original.dataset.tcToolsSelection)return;
  original.dataset.tcToolsSelection='1';
  original.addEventListener('change',()=>{
   const file=original.files?.[0];if(!file)return;
   status.textContent='Selected '+file.name+' ('+Math.ceil(file.size/1024)+' KB). Tap Send to share.';
  });
 };
 if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',setup);else setup();
})();
