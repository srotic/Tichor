import {createClient} from 'https://esm.sh/@supabase/supabase-js@2.49.8';
const origin='https://v3.tichor.com';
const headers={'Content-Type':'application/json','Cache-Control':'no-store','Access-Control-Allow-Origin':origin,'Vary':'Origin','Access-Control-Allow-Headers':'authorization,apikey,content-type,x-client-info','Access-Control-Allow-Methods':'POST,OPTIONS'};
const reply=(status:number,body:unknown)=>new Response(JSON.stringify(body),{status,headers});
Deno.serve(async(req:Request)=>{
 if(req.headers.get('origin')&&req.headers.get('origin')!==origin)return reply(403,{error:'Forbidden origin'});
 if(req.method==='OPTIONS')return new Response(null,{status:204,headers});
 if(req.method!=='POST')return reply(405,{error:'POST required'});
 const token=req.headers.get('authorization')||'';
 if(!token.startsWith('Bearer '))return reply(401,{error:'Sign in required'});
 try{
  const body=await req.json();
  if(body?.action!=='reset' || body?.confirmation!=='RESET MY ENCRYPTION IDENTITY' || body?.acknowledgeLoss!==true)
   return reply(400,{error:'Explicit confirmation and loss acknowledgment required'});
  const url=Deno.env.get('SUPABASE_URL'),secret=Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
  if(!url||!secret)return reply(503,{error:'Service unavailable'});
  const db=createClient(url,secret,{auth:{persistSession:false,autoRefreshToken:false}});
  const {data,error}=await db.auth.getUser(token.slice(7));
  if(error||!data.user?.id)return reply(401,{error:'Invalid account session'});
  const account=data.user.id;
  // Require a recently authenticated session for destructive identity changes.
  const authenticatedAt=Date.parse(data.user.last_sign_in_at||'');
  if(!Number.isFinite(authenticatedAt)||Date.now()-authenticatedAt>10*60_000||authenticatedAt>Date.now()+60_000)
   return reply(403,{error:'Please sign out and sign in again before resetting encryption'});
  const {data:reset,error:resetError}=await db.rpc('tichor_e2ee_reset_identity_service',{p_user_id:account});
  if(resetError)return reply(500,{error:'Reset could not be completed; no new identity was created'});
  return reply(200,{reset:reset===true,account,requiresFreshEnrollment:true});
 }catch(_){return reply(400,{error:'Invalid reset request'});}
});
