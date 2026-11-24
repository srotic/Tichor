// Staging-only TSA ciphertext mailbox gateway; not integrated into live chats.
// Requires caller JWT AND a fresh device-private-key ECDSA signature on every operation.
// The service-role token is never returned to clients or embedded in public JS.
import {createClient} from 'https://esm.sh/@supabase/supabase-js@2.49.8';
const origin='https://v3.tichor.com';
const E=new TextEncoder();
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const coord=/^[A-Za-z0-9_-]{43}$/;
const sig=/^[A-Za-z0-9_-]{86}$/;
const base64=x=>btoa(String.fromCharCode(...new Uint8Array(x))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const decode=x=>Uint8Array.from(atob(x.replace(/-/g,'+').replace(/_/g,'/')+'=='),c=>c.charCodeAt(0));
function id(x){if(typeof x!=='string'||!uuid.test(x))throw Error('Invalid identifier');return x;}
function publicKey(k){
 if(!k||k.kty!=='EC'||k.crv!=='P-256'||typeof k.x!=='string'||typeof k.y!=='string'||!coord.test(k.x)||!coord.test(k.y)||'d' in k)throw Error('Invalid public key');
 return {kty:'EC',crv:'P-256',x:k.x,y:k.y};
}
async function verify(body,signature,key){
 if(typeof signature!=='string'||!sig.test(signature))return false;
 const imported=await crypto.subtle.importKey('jwk',publicKey(key),{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
 return crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},imported,decode(signature),E.encode(JSON.stringify(body)));
}
const canonical=x=>JSON.stringify(x);
const sha256=async text=>base64(await crypto.subtle.digest('SHA-256',E.encode(text)));
async function registry(db,account,device){
 const {data,error}=await db.from('tichor_e2ee_devices')
 .select('user_id,device_id,state,signing_public_jwk')
 .eq('user_id',account).eq('device_id',device).maybeSingle();
 if(error||!data||data.state!=='active')throw Error('Unknown or inactive device');
 return data;
}
// Verify persistent trust against current registry and root, never client claims.
async function verifyPersistentDeviceTrust(db,account,device){
 const {data:t,error}=await db.from('tsa_persistent_device_trust').select('*').eq('user_id',account).eq('device_id',device).maybeSingle();
 if(error)throw Error('Persistent trust lookup failed');
 if(!t)return false;
 const {data:d,error:de}=await db.from('tichor_e2ee_devices').select('state,encryption_public_jwk,signing_public_jwk').eq('user_id',account).eq('device_id',device).maybeSingle();
 const {data:r,error:re}=await db.from('tichor_e2ee_identity_keys').select('signing_public_jwk').eq('user_id',account).maybeSingle();
 if(de||re||!d||!r||d.state!=='active')throw Error('Persistent trust identity unavailable');
 const same=(a,b)=>JSON.stringify(publicKey(a))===JSON.stringify(publicKey(b));
 if(!same(t.root_signing_key,r.signing_public_jwk)||!same(t.encryption_key,d.encryption_public_jwk)||!same(t.signing_key,d.signing_public_jwk))throw Error('Persistent trust key mismatch');
 if(!Number.isSafeInteger(t.revision)||t.revision<1)throw Error('Invalid trust revision');
 const body={domain:'Tichor TSA persistent device trust v1',account,device,revision:t.revision,encryptionKey:publicKey(d.encryption_public_jwk),signingKey:publicKey(d.signing_public_jwk)};
 if(!await verify(body,t.root_signature,r.signing_public_jwk))throw Error('Persistent trust signature invalid');
 return true;
}
function isCiphertextSlot(copy){
 return copy&&typeof copy==='object'&&!Array.isArray(copy) &&
 uuid.test(copy.account)&&uuid.test(copy.device)&&copy.epk&&copy.epk.kty==='EC'&&copy.epk.crv==='P-256' &&
 coord.test(copy.epk.x)&&coord.test(copy.epk.y)&&
 /^[A-Za-z0-9_-]{22}$/.test(copy.salt)&&/^[A-Za-z0-9_-]{16}$/.test(copy.iv)&&
 typeof copy.ct==='string'&&/^[A-Za-z0-9_-]{16,3000}$/.test(copy.ct);
}
Deno.serve(async req=>{
 const headers={'Content-Type':'application/json','Cache-Control':'no-store',
  'Access-Control-Allow-Origin':origin,'Vary':'Origin','Access-Control-Allow-Methods':'POST, OPTIONS',
  'Access-Control-Allow-Headers':'authorization,apikey,content-type,x-client-info,x-supabase-api-version'};
 const reply=(status,message,extra={})=>new Response(JSON.stringify({message,...extra}),{status,headers});
 if(req.headers.get('origin')&&req.headers.get('origin')!==origin)return reply(403,'Origin rejected');
 if(req.method==='OPTIONS')return new Response(null,{status:204,headers});
 if(req.method!=='POST')return reply(405,'POST required');
 try{
  const token=req.headers.get('authorization')||'';
  if(!token.startsWith('Bearer '))return reply(401,'Sign-in required');
  const url=Deno.env.get('SUPABASE_URL'),secret=Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
  if(!url||!secret)throw Error('Missing server configuration');
  const db=createClient(url,secret,{auth:{persistSession:false,autoRefreshToken:false}});
  const {data:auth,error:authError}=await db.auth.getUser(token.slice(7));
  if(authError||!auth?.user?.id)return reply(401,'Invalid session');
  // A verified JWT is necessary but insufficient: superseded sessions are denied.
  const jwtPart=token.slice(7).split('.')[1];
  if(!jwtPart)return reply(401,'Session identifier required');
  let jwtSession;
  try {jwtSession=JSON.parse(atob(jwtPart.replace(/-/g,'+').replace(/_/g,'/'))).session_id} catch {return reply(401,'Malformed session')}
  if(typeof jwtSession!=='string'||!uuid.test(jwtSession))return reply(403,'Session identifier missing');
  const {data:activeSession,error:activeError}=await db.from('tichor_active_sessions').select('session_id').eq('user_id',auth.user.id).maybeSingle();
  if(activeError||activeSession?.session_id!==jwtSession)return reply(403,'Session replaced by a newer login');

  const raw=await req.text();if(raw.length>45000)throw Error('Request too large');
  const input=JSON.parse(raw);
  if(!input||typeof input!=='object'||Array.isArray(input))throw Error('Malformed request');
  const action=input.action;
  if(action!=='publish'&&action!=='receive')throw Error('Unsupported mailbox request');
  const account=id(input.account),device=id(input.device),nonce=id(input.nonce);
  if(account!==auth.user.id)throw Error('Account mismatch');
  const issuedAt=input.issuedAt,now=Date.now();
  if(!Number.isSafeInteger(issuedAt)||issuedAt>now+30000||issuedAt<now-60000)throw Error('Stale device request');
  const row=await registry(db,account,device);
  // Reject invalid persistent trust even during legacy grant migration.
  await verifyPersistentDeviceTrust(db,account,device);
  // Bind exact request payload bytes to signing key for a device; immutable packet
  // JSON is hashed before the signature is checked.
  let digest=null,packet=null,destinations=null;
  if(action==='publish'){
   if(typeof input.packet_text!=='string'||input.packet_text.length>32768)throw Error('Invalid ciphertext size');
   packet=JSON.parse(input.packet_text);
   if(!packet||packet.v!==1||packet.protocol!=='TSA-experimental-multi-device-text'||
      packet.from!==account||packet.to===account||!uuid.test(packet.to)||!uuid.test(packet.messageId)||
      !Number.isSafeInteger(packet.createdAt)||Math.abs(now-packet.createdAt)>120000||
      !Array.isArray(packet.copies)||packet.copies.length<2||packet.copies.length>16||
      packet.copies.some(c=>!isCiphertextSlot(c))||!sig.test(packet.signature))throw Error('Invalid encrypted envelope');
   const seen=new Set();
   for(const copy of packet.copies){
    if(copy.account!==account&&copy.account!==packet.to)throw Error('Unexpected destination');
    const key=copy.account+':'+copy.device;
    if(seen.has(key))throw Error('Duplicate destination');
    seen.add(key);
   }
   const {signature:packetSignature,...signed}=packet;
   if(!await verify(signed,packetSignature,row.signing_public_jwk))throw Error('Envelope signature invalid');
   destinations=packet.copies.map(x=>({account:x.account,device:x.device}));
   digest=await sha256(input.packet_text);
  }else{
   if(input.packet_text!==undefined||input.destinations!==undefined||input.peer!==undefined)throw Error('Unexpected receive fields');
  }
  const body={domain:'Tichor TSA mailbox request v1',action,account,device,nonce,issuedAt,digest};
  if(!await verify(body,input.signature,row.signing_public_jwk))throw Error('Device possession signature invalid');
  if(action==='publish'){
   const {data,error}=await db.rpc('tsa_publish_ciphertext_session_verified',{
    a_sender:account,a_peer:packet.to,a_signing_device:device,a_message:packet.messageId,
    a_nonce:nonce,a_packet_text:input.packet_text,a_destinations:destinations,a_session:jwtSession
   });
   if(error||typeof data!=='number')throw Error('Database rejected ciphertext batch');
   return reply(200,'Ciphertext stored for all active devices',{state:'stored-staging-ciphertext',copied:data});
  }
  const {data,error}=await db.rpc('tsa_read_ciphertext_session_verified',{
   a_account:account,a_device:device,a_nonce:nonce,a_session:jwtSession,a_limit:30
  });
  if(error||!Array.isArray(data))throw Error('Database rejected device mailbox request');
  return reply(200,'Encrypted mailbox retrieved',{state:'staging-ciphertext-only',messages:data});
 }catch(err){
  console.warn('Staging mailbox request denied',String(err?.message||'unknown'));
  return reply(403,'Encrypted mailbox request rejected');
 }
});
