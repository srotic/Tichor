import {createClient} from 'https://esm.sh/@supabase/supabase-js@2.49.8';
const origin='https://v3.tichor.com';
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const E=new TextEncoder();
const headers={'Content-Type':'application/json','Cache-Control':'no-store','Access-Control-Allow-Origin':origin,'Vary':'Origin','Access-Control-Allow-Headers':'authorization,apikey,content-type,x-client-info','Access-Control-Allow-Methods':'POST,OPTIONS'};
function respond(status,body){return new Response(JSON.stringify(body),{status,headers});}
function key(j){if(j?.kty!=='EC'||j?.crv!=='P-256'||!(/^[A-Za-z0-9_-]{43}$/).test(j?.x)||!(/^[A-Za-z0-9_-]{43}$/).test(j?.y)||j?.d!==undefined)throw Error('Invalid device key');return {kty:'EC',crv:'P-256',x:j.x,y:j.y};}
Deno.serve(async(req)=>{
 if(req.headers.get('origin')&&req.headers.get('origin')!==origin)return respond(403,{error:'Forbidden origin'});
 if(req.method==='OPTIONS')return new Response(null,{status:204,headers});
 if(req.method!=='POST')return respond(405,{error:'POST required'});
 try{
  const bearer=req.headers.get('authorization')||'';
  if(!bearer.startsWith('Bearer '))return respond(401,{error:'Authentication required'});
  const url=Deno.env.get('SUPABASE_URL'),secret=Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
  if(!url||!secret)throw Error('Not configured');
  const db=createClient(url,secret,{auth:{persistSession:false,autoRefreshToken:false}});
  const {data:session,error:authError}=await db.auth.getUser(bearer.slice(7));
  if(authError||!session?.user?.id)return respond(401,{error:'Invalid session'});
  const account=session.user.id;
  const body=await req.json();
  if(!body||typeof body!=='object'||Array.isArray(body)||!uuid.test(body.device))return respond(400,{error:'Invalid request'});
  const device=body.device;
  const {data:registered,error:deviceError}=await db.from('tichor_e2ee_devices').select('state,signing_public_jwk').eq('user_id',account).eq('device_id',device).maybeSingle();
  if(deviceError||registered?.state!=='active')return respond(403,{error:'Device not active'});
  const {data:grant,error:grantError}=await db.from('tichor_e2ee_active_device_grants').select('expires_at_ms').eq('user_id',account).eq('device_id',device).maybeSingle();
  if(grantError||!grant||Number(grant.expires_at_ms)<=Date.now())return respond(403,{error:'Root authorization expired; secure reauthorization required'});
  if(body.action==='issue'){
   const {data:challenge,error}=await db.from('tichor_tase_renewal_challenges').insert({user_id:account,device_id:device}).select('challenge,expires_at').single();
   if(error||!challenge)throw Error('Challenge creation failed');
   return respond(200,{account,device,challenge:challenge.challenge,expiresAt:Math.floor(new Date(challenge.expires_at).getTime())});
  }
  if(body.action==='verify'){
   if(!uuid.test(body.challenge)||!Number.isSafeInteger(body.expiresAt)||!Array.isArray(body.signature)||body.signature.length!==64||body.signature.some(v=>!Number.isInteger(v)||v<0||v>255))
    return respond(400,{error:'Invalid proof'});
   const {data:row,error:rowError}=await db.from('tichor_tase_renewal_challenges').select('expires_at,consumed_at').eq('user_id',account).eq('device_id',device).eq('challenge',body.challenge).maybeSingle();
   if(rowError||!row||row.consumed_at||new Date(row.expires_at).getTime()!==body.expiresAt||body.expiresAt<=Date.now())return respond(403,{error:'Challenge expired or consumed'});
   const payload='TICHOR-TASE-RENEWAL-V1\n'+account+'\n'+device+'\n'+body.challenge+'\n'+body.expiresAt;
   const pub=await crypto.subtle.importKey('jwk',key(registered.signing_public_jwk),{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
   if(!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},pub,new Uint8Array(body.signature),E.encode(payload)))return respond(403,{error:'Signature rejected'});
   const {data:consumed,error:consumeError}=await db.rpc('tsa_consume_renewal_challenge',{a_user:account,a_device:device,a_challenge:body.challenge,a_expires_at_ms:body.expiresAt});
   if(consumeError||consumed!==true)return respond(403,{error:'Challenge rejected or replayed'});
   return respond(200,{state:'trusted-device-possession-verified',device,authorizationRenewed:false});
  }
  return respond(400,{error:'Unknown action'});
 }catch(e){console.warn('TASE renewal proof rejected');return respond(403,{error:'Renewal verification denied'});}
});