const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const read=f=>fs.readFileSync(path.join(root,f),'utf8');
test('V3 + tools loads on staging without modifying production chat source',()=>{
 const build=read('scripts/build-v3-staging.cjs');
 const html=read('chat.html');
 for(const f of ['v3-chat-compose-tools.css','v3-chat-compose-tools.js']){
  assert.match(build,new RegExp(f.replace(/\./g,'\\.')));
  assert.ok(!html.includes('src="'+f+'"')&&!html.includes('href="'+f+'"'));
 }
});
test('V3 + menu has real file, emoji and writing actions and viewport placement',()=>{
 const source=read('v3-chat-compose-tools.js');
 assert.doesNotThrow(()=>new Function(source));
 assert.match(source,/\.tc-compose-plus/);
 assert.match(source,/stopImmediatePropagation\(\)/);
 assert.match(source,/document\.body\.append\(panel\)/);
 assert.match(source,/visualViewport/);
 assert.match(source,/tichorFile/);
 assert.match(source,/input\.click\(\)/);
 assert.match(source,/tichorWritingToggle/);
 assert.match(source,/field\.setRangeText/);
 assert.match(source,/dispatchEvent\(new Event\('input'/);
 assert.match(source,/Selected /);
});
test('V3 + popup remains above scroll containers and has touch targets',()=>{
 const css=read('v3-chat-compose-tools.css');
 assert.match(css,/\.tc-v3-tools-portal/);
 assert.match(css,/position:fixed!important/);
 assert.match(css,/z-index:2147483001/);
 assert.match(css,/max-height:min\(72dvh,520px\)/);
 assert.match(css,/min-height:47px/);
 assert.match(css,/\.tc-emoji-grid/);
});
