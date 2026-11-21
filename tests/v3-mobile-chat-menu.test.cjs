const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const read=name=>fs.readFileSync(path.join(root,name),'utf8');
test('V3 mobile action menu avoids clipped message overflow',()=>{
 const src=read('v3-chat-message-menu.js');
 assert.doesNotThrow(()=>new Function(src));
 for(const keyword of ['document.body.append(popup)','getBoundingClientRect()','visualViewport','aria-expanded','role','menuitem','position()','dismiss()','original.click()'])assert.ok(src.includes(keyword),keyword);
 assert.match(src,/e\.key==='Escape'/);
 assert.match(src,/e\.target\?\.id==='messages'/);
 const css=read('v3-chat-mobile-polish.css');
 assert.match(css,/\.tc-chat-action-portal\{/);
 assert.match(css,/position:fixed!important/);
 assert.match(css,/z-index:2147483000/);
 assert.match(css,/max-height:min\(65dvh,430px\)/);
 assert.match(css,/#messages \.msg\.mine/);
 assert.match(css,/#sendForm\.tc-minimal-composer/);
});
test('Only V3 staging includes chat menu and mobile theme assets',()=>{
 const build=read('scripts/build-v3-staging.cjs');
 assert.match(build,/v3-chat-mobile-polish\.css\?v=1/);
 assert.match(build,/v3-chat-message-menu\.js\?v=1/);
 const source=read('chat.html');
 assert.doesNotMatch(source,/<script src="v3-chat-message-menu\.js/);
 assert.doesNotMatch(source,/<link rel="stylesheet" href="v3-chat-mobile-polish\.css/);
});
