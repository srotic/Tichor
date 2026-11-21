'use strict';
/* Portaled message actions: escape the scroll-clipped chat area and clamp to screen. */
(()=>{
 let popup=null,trigger=null;
 const icons={reply:'↩',forward:'➜',copy:'⧉',edit:'✎',download:'⇩',delete:'⌫',block:'⊘',other:'•'};
 const idFor=t=>{
  const s=t.toLowerCase();
  if(s.includes('delete')||s.includes('unsend'))return 'delete';
  if(s.includes('reply'))return 'reply';
  if(s.includes('forward'))return 'forward';
  if(s.includes('copy'))return 'copy';
  if(s.includes('edit'))return 'edit';
  if(s.includes('download'))return 'download';
  if(s.includes('block'))return 'block';
  return 'other';
 };
 function dismiss(){
  if(popup){popup.remove();popup=null}
  if(trigger){trigger.setAttribute('aria-expanded','false');trigger=null}
 }
 function position(){
  if(!popup||!trigger?.isConnected){dismiss();return}
  const r=trigger.getBoundingClientRect(),viewport=window.visualViewport;
  const screenWidth=viewport?.width||window.innerWidth;
  const screenHeight=viewport?.height||window.innerHeight;
  const offsetX=viewport?.offsetLeft||0,offsetY=viewport?.offsetTop||0;
  const width=Math.min(288,screenWidth-24);
  popup.style.width=width+'px';
  const height=popup.offsetHeight;
  const left=Math.min(offsetX+screenWidth-width-12,Math.max(offsetX+12,r.right-width));
  const above=r.top-height-10,below=r.bottom+10;
  const y=above>offsetY+10?above:below+height<offsetY+screenHeight-10?below:Math.max(offsetY+10,Math.min(above,offsetY+screenHeight-height-10));
  popup.style.left=Math.round(left)+'px';
  popup.style.top=Math.round(y)+'px';
 }
 function open(summary){
  if(trigger===summary&&popup){dismiss();return}
  dismiss();
  const details=summary.closest('details.tichor-message-more');
  if(!details)return;
  details.open=false;
  const actions=[...details.children].filter(el=>el.tagName==='BUTTON');
  if(!actions.length)return;
  popup=document.createElement('div');
  popup.className='tc-chat-action-portal';
  popup.setAttribute('role','menu');
  popup.setAttribute('aria-label','Message actions');
  for(const original of actions){
   const type=idFor(original.textContent);
   const b=document.createElement('button');
   b.type='button';b.dataset.action=type;b.setAttribute('role','menuitem');
   const symbol=document.createElement('span');symbol.className='tc-chat-action-symbol';symbol.setAttribute('aria-hidden','true');symbol.textContent=icons[type];
   const label=document.createElement('span');label.textContent=original.textContent;
   b.append(symbol,label);
   b.onclick=()=>{dismiss();if(original.isConnected)original.click()};
   popup.append(b);
  }
  document.body.append(popup);trigger=summary;summary.setAttribute('aria-expanded','true');
  position();
 }
 document.addEventListener('click',e=>{
  const summary=e.target.closest?.('#messages details.tichor-message-more > summary');
  if(summary){e.preventDefault();e.stopPropagation();open(summary);return}
  if(popup&&!popup.contains(e.target))dismiss();
 },true);
 document.addEventListener('keydown',e=>{if(e.key==='Escape'&&popup){e.preventDefault();dismiss()}});
 document.addEventListener('scroll',e=>{if(popup&&e.target?.id==='messages')dismiss()},true);
 window.addEventListener('resize',()=>{if(popup)position()});
 window.visualViewport?.addEventListener('resize',()=>{if(popup)position()});
 window.addEventListener('pagehide',dismiss);
})();
