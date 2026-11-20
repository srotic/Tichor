const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const {execFileSync}=require('node:child_process');
const root=path.resolve(__dirname,'..');
test('staging build is isolated from production configuration',()=>{
 execFileSync(process.execPath,['scripts/build-v3-staging.cjs'],{cwd:root,stdio:'pipe'});
 const out=path.join(root,'dist','v3-staging');
 const config=fs.readFileSync(path.join(out,'public-config.js'),'utf8');
 const prod=fs.readFileSync(path.join(root,'public-config.js'),'utf8');
 const chat=fs.readFileSync(path.join(out,'chat.html'),'utf8');
 assert.notEqual(config,prod);
 assert.match(config,/dasxibyqqkthibycduzr\.supabase\.co/);
 assert.doesNotMatch(config,/gblbxcrqumiraaxknwpc/);
 assert.match(chat,/tichor-v3-staging-auth-session/);
 assert.match(chat,/data-v3-titanium/);
 assert.match(chat,/v3-titanium-glass\.css\?v=6/);
 assert.equal(fs.existsSync(path.join(out,'v3-titanium-glass.css')),true);
 assert.doesNotMatch(fs.readFileSync(path.join(root,'chat.html'),'utf8'),/v3-titanium-glass\.css/);
 assert.doesNotMatch(chat,/navigator\.serviceWorker\.register\('\.\/sw\.js'/);
 assert.equal(fs.existsSync(path.join(out,'sw.js')),false);
 const forbidden=[];
 function walk(dir){for(const entry of fs.readdirSync(dir,{withFileTypes:true})){
  const p=path.join(dir,entry.name);
  if(entry.isDirectory())walk(p);
  else if(/\.(sql|ts|tsx|map|cjs|md)$/i.test(entry.name))forbidden.push(path.relative(out,p));
 }}
 walk(out);
 assert.deepEqual(forbidden,[],'Staging must not publish source, SQL or documentation');
 assert.equal(fs.existsSync(path.join(out,'manifest.webmanifest')),false);
 assert.equal(fs.readFileSync(path.join(root,'public-config.js'),'utf8'),prod);
});
