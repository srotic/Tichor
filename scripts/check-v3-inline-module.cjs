// Check the actual inline ES module shipped by chat.html; static regexp
// tests alone cannot catch JavaScript syntax regressions in a 500kB page.
const fs=require('node:fs');
const path=require('node:path');
const {spawnSync}=require('node:child_process');
const page=fs.readFileSync(path.resolve(__dirname,'../chat.html'),'utf8');
const modules=[...page.matchAll(/<script\s+type="module"\s*>([\s\S]*?)<\/script>/g)];
if(modules.length!==1)throw Error('Expected exactly one V3 chat inline ES module');
const source=modules[0][1];
if(!source.includes('tcReadTsaInbox')||!source.includes('encryptAndPublishTsaTextStaging'))throw Error('Secure chat module was not found');
const check=spawnSync(process.execPath,['--check','--input-type=module'],{input:source,encoding:'utf8'});
if(check.status!==0)throw Error('Invalid V3 chat ES module: '+(check.stderr||check.stdout));
console.log('V3 chat inline ES module syntax valid');
