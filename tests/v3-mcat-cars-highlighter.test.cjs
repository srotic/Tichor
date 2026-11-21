const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const read=p=>fs.readFileSync(path.join(root,p),'utf8');
test('MCAT CARS passage UI exposes selection highlighter controls',()=>{
 const html=read('mcat-cars.html');
 for(const id of ['cars-highlight-toolbar','highlight-add','highlight-remove','highlight-undo','highlight-clear','highlight-status','passage-body'])assert.match(html,new RegExp('id="'+id+'"'));
 for(const color of ['yellow','mint','pink'])assert.match(html,new RegExp('data-hl-color="'+color+'"'));
 assert.ok(html.indexOf('mcat-cars-highlighter.js')<html.indexOf('mcat-cars-app.js'));
 assert.match(html,/cars-highlight-yellow/);
 assert.match(html,/cars-highlight-mint/);
 assert.match(html,/cars-highlight-pink/);
 const app=read('mcat-cars-app.js');
 assert.match(app,/CarsHighlighter\?\.init/);
 assert.match(app,/CarsHighlighter\?\.showPassage\(entry\.passageIndex\)/);
});
test('CARS highlights merge, recolor and erase precise offsets',()=>{
 const source=read('mcat-cars-highlighter.js');
 assert.doesNotThrow(()=>new Function(source));
 const win={};
 new Function('window','document','localStorage',source)(win,{}, {getItem:()=>null});
 const {editSegments,normalize}=win.CarsHighlighter;
 assert.deepEqual(editSegments([],4,12,'yellow'),[{s:4,e:12,c:'yellow'}]);
 assert.deepEqual(editSegments([{s:4,e:12,c:'yellow'}],12,16,'yellow'),[{s:4,e:16,c:'yellow'}]);
 assert.deepEqual(editSegments([{s:4,e:16,c:'yellow'}],8,12,'pink'),[
  {s:4,e:8,c:'yellow'},{s:8,e:12,c:'pink'},{s:12,e:16,c:'yellow'}]);
 assert.deepEqual(editSegments([{s:4,e:8,c:'yellow'},{s:8,e:12,c:'pink'},{s:12,e:16,c:'yellow'}],7,13,null),[
  {s:4,e:7,c:'yellow'},{s:13,e:16,c:'yellow'}]);
 assert.deepEqual(normalize([{s:0,e:3,c:'mint'},{s:3,e:7,c:'mint'}]),[{s:0,e:7,c:'mint'}]);
});
test('Highlighter stores ranges by passage and guards text-selection scope',()=>{
 const source=read('mcat-cars-highlighter.js');
 assert.match(source,/tichor-cars-highlights-v1/);
 assert.match(source,/localStorage\.setItem/);
 assert.match(source,/root\.contains\(range\.startContainer\)/);
 assert.match(source,/root\.contains\(range\.endContainer\)/);
 assert.match(source,/getSelection/);
 assert.match(source,/dataset\.hlColor/);
 assert.match(source,/clearPassage/);
 assert.match(source,/undoLast/);
});
