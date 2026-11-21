'use strict';
/* Practice highlighter for Tichor CARS: per-paragraph text offsets avoid
   storing fragile DOM ranges and preserve the source passage verbatim. */
(()=>{
 const STORE='tichor-cars-highlights-v1';
 const COLORS={yellow:'#ffe874',mint:'#92f1b0',pink:'#ffadcd'};
 const allowed=new Set(Object.keys(COLORS));
 let records={};try{const v=JSON.parse(localStorage.getItem(STORE)||'{}');if(v&&typeof v==='object'&&!Array.isArray(v))records=v}catch{}
 let root=null,toolbar=null,passage=null,color='yellow',pending=null,undo=null;
 const $=id=>document.getElementById(id);
 const clone=v=>JSON.parse(JSON.stringify(v));
 const isValid=r=>r&&Number.isInteger(r.s)&&Number.isInteger(r.e)&&r.s>=0&&r.e>r.s&&allowed.has(r.c);
 function normalize(spans){
  const result=[];
  for(const item of spans.filter(isValid).sort((a,b)=>a.s-b.s||a.e-b.e)){
   const last=result[result.length-1];
   if(last&&last.c===item.c&&item.s<=last.e)last.e=Math.max(last.e,item.e);
   else result.push({...item});
  }
  return result;
 }
 function editSegments(existing,start,end,nextColor){
  if(!Number.isInteger(start)||!Number.isInteger(end)||start<0||end<=start)return normalize(existing||[]);
  const output=[];
  for(const segment of (existing||[]).filter(isValid)){
   if(segment.e<=start||segment.s>=end){output.push({...segment});continue}
   if(segment.s<start)output.push({...segment,e:start});
   if(segment.e>end)output.push({...segment,s:end});
  }
  if(nextColor&&allowed.has(nextColor))output.push({s:start,e:end,c:nextColor});
  return normalize(output);
 }
 function current(){if(!records[passage]||typeof records[passage]!=='object')records[passage]={};return records[passage]}
 function persist(){try{localStorage.setItem(STORE,JSON.stringify(records))}catch{}}
 function status(t){const message=$('highlight-status');if(message)message.textContent=t}
 function chooseColor(value){if(!allowed.has(value))return;color=value;document.querySelectorAll('[data-hl-color]').forEach(button=>button.setAttribute('aria-pressed',String(button.dataset.hlColor===value)));status('Selected '+value+'. Select passage text, then click Highlight.')}
 function selectionSpans(){
  const sel=window.getSelection?.();
  if(!sel||sel.isCollapsed||!sel.rangeCount||!root)return [];
  const range=sel.getRangeAt(0);
  if(!root.contains(range.startContainer)||!root.contains(range.endContainer))return [];
  const spans=[];
  [...root.querySelectorAll('p')].forEach((p,i)=>{
   if(!range.intersectsNode(p))return;
   const max=p.textContent.length;
   let start=0,end=max;
   if(p.contains(range.startContainer)){
    const r=document.createRange();r.selectNodeContents(p);r.setEnd(range.startContainer,range.startOffset);start=r.toString().length;
   }
   if(p.contains(range.endContainer)){
    const r=document.createRange();r.selectNodeContents(p);r.setEnd(range.endContainer,range.endOffset);end=r.toString().length;
   }
   if(start<end&&start>=0&&end<=max)spans.push({i,s:start,e:end});
  });
  return spans;
 }
 function capture(){const found=selectionSpans();if(found.length)pending=found}
 function paint(){
  if(!root||passage==null)return;
  const saved=current();
  [...root.querySelectorAll('p')].forEach((p,i)=>{
   const text=p.textContent;
   const spans=normalize((Array.isArray(saved[i])?saved[i]:[]).filter(r=>isValid(r)&&r.e<=text.length));
   const frag=document.createDocumentFragment();
   let at=0;
   for(const span of spans){
    if(span.s<at)continue;
    if(span.s>at)frag.append(document.createTextNode(text.slice(at,span.s)));
    const marker=document.createElement('mark');marker.className='cars-highlight cars-highlight-'+span.c;
    marker.dataset.hlColor=span.c;marker.textContent=text.slice(span.s,span.e);
    marker.title='Highlighted '+span.c;frag.append(marker);at=span.e;
   }
   if(at<text.length)frag.append(document.createTextNode(text.slice(at)));
   p.replaceChildren(frag);
  });
 }
 function apply(nextColor){
  if(!root||passage==null)return;
  const picked=selectionSpans();
  const spans=picked.length?picked:pending;
  if(!spans?.length){status('Select a sentence or phrase in the passage first.');return}
  undo={passage,value:clone(current())};
  const data=current();
  for(const {i,s,e} of spans){
   const key=String(i);data[key]=editSegments(data[key]||[],s,e,nextColor);
   if(!data[key].length)delete data[key];
  }
  persist();pending=null;
  window.getSelection?.()?.removeAllRanges();
  paint();
  status(nextColor?'Highlight applied. You can continue reading and answering.':'Selected highlighting removed.');
 }
 function clearPassage(){
  if(passage==null)return;
  if(!Object.keys(current()).length){status('There are no highlights to clear in this passage.');return}
  if(!confirm('Clear all highlights in this passage?'))return;
  undo={passage,value:clone(current())};records[passage]={};pending=null;persist();paint();status('All highlights cleared for this passage.');
 }
 function undoLast(){
  if(!undo||undo.passage!==passage){status('Nothing to undo for this passage.');return}
  records[passage]=clone(undo.value);undo=null;persist();paint();status('Last highlighting change undone.');
 }
 function showPassage(id){
  passage=String(id);pending=null;undo=null;
  paint();status('Select text, then choose Highlight. Highlights are saved in this browser.');
 }
 function bind(){
  root=$('passage-body');toolbar=$('cars-highlight-toolbar');
  if(!root||!toolbar)return false;
  root.addEventListener('mouseup',capture);
  root.addEventListener('keyup',capture);
  root.addEventListener('touchend',()=>{setTimeout(capture,0)});
  toolbar.querySelectorAll('[data-hl-color]').forEach(b=>b.addEventListener('click',()=>chooseColor(b.dataset.hlColor)));
  $('highlight-add').addEventListener('click',()=>apply(color));
  $('highlight-remove').addEventListener('click',()=>apply(null));
  $('highlight-clear').addEventListener('click',clearPassage);
  $('highlight-undo').addEventListener('click',undoLast);
  chooseColor('yellow');return true;
 }
 window.CarsHighlighter={init:bind,showPassage,apply,editSegments,normalize};
})();
