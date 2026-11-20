// Build a separate, static staging bundle without modifying source files.
// Usage: node scripts/build-v3-staging.cjs
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const out=path.join(root,'dist','v3-staging');
const ignored=new Set(['.git','.github','node_modules','dist','tests','docs','scripts','supabase']);
fs.rmSync(out,{recursive:true,force:true});
fs.mkdirSync(out,{recursive:true});
// Publish only browser-deliverable assets, not repository source or SQL.
const allowed=new Set(['.html','.css','.js','.mjs','.json','.svg','.png','.jpg','.jpeg','.gif','.webp','.ico','.woff','.woff2','.ttf','.otf','.webmanifest','.txt','.xml','.wasm','.mp3','.mp4','.webm','.pdf']);
const excludedNames=new Set(['staging-public-config.js','package.json','package-lock.json','tsconfig.json','wrangler.toml','wrangler.json','wrangler.jsonc']);
function copyStatic(src,dest,topLevel=false){
 for(const item of fs.readdirSync(src,{withFileTypes:true})){
  const name=item.name;
  if(name.startsWith('.')||excludedNames.has(name)||(topLevel&&ignored.has(name)))continue;
  const from=path.join(src,name),to=path.join(dest,name);
  if(item.isDirectory()){
   // Never publish migration files, tooling, or private directories.
   if(['supabase','migrations','sql','tests','docs','scripts','node_modules','src','types'].includes(name.toLowerCase()))continue;
   fs.mkdirSync(to,{recursive:true});copyStatic(from,to);
  }else if(item.isFile()&&allowed.has(path.extname(name).toLowerCase())){
   fs.copyFileSync(from,to);
  }
 }
}
copyStatic(root,out,true);
const stage=fs.readFileSync(path.join(root,'staging-public-config.js'),'utf8');
if(!stage.includes('SUPABASE_URL')||!stage.includes('SUPABASE_PUBLISHABLE_KEY'))throw Error('Staging configuration missing');
fs.writeFileSync(path.join(out,'public-config.js'),stage);
// Prevent staging from registering a production-style PWA service worker.
// This bundle must be served from a SEPARATE origin (not chat.tichor.com).
const chatPath=path.join(out,'chat.html');
let chat=fs.readFileSync(chatPath,'utf8');
const needle="navigator.serviceWorker.register('./sw.js',{updateViaCache:'none'})";
if(!chat.includes(needle))throw Error('Service worker registration marker changed; review before building');
chat=chat.replace(needle,"Promise.reject(new Error('Service worker disabled in V3 staging'))");
chat=chat.replace(/storageKey:'tichor-auth-session'/g,"storageKey:'tichor-v3-staging-auth-session'");
// Load the V3-only titanium/glass visual layer after existing inline styles.
if(!fs.existsSync(path.join(out,'v3-titanium-glass.css')))throw Error('V3 titanium glass stylesheet missing');
if(!chat.includes('</head>'))throw Error('Chat document head marker missing');
chat=chat.replace('</head>','<script>document.documentElement.setAttribute("data-v3-titanium","");</script><link rel="stylesheet" href="v3-titanium-glass.css?v=6"></head>');
fs.writeFileSync(chatPath,chat);
// No service worker in staging output; avoid stale browser cache and cross-app scope.
fs.rmSync(path.join(out,'sw.js'),{force:true});
fs.rmSync(path.join(out,'manifest.webmanifest'),{force:true});
// Prevent production PWA metadata from being advertised by the staging bundle.
for(const html of fs.readdirSync(out).filter(x=>x.endsWith('.html'))){
 const p=path.join(out,html);
 let content=fs.readFileSync(p,'utf8');
 content=content.replace(/<link[^>]*rel=[\"']manifest[\"'][^>]*>/gi,'');
 fs.writeFileSync(p,content);
}
const config=fs.readFileSync(path.join(out,'public-config.js'),'utf8');
if(config.includes('gblbxcrqumiraaxknwpc'))throw Error('Production Supabase URL detected in staging config');
console.log('V3 staging static bundle built at dist/v3-staging. Deploy only to a separate staging origin.');
