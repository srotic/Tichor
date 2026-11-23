// Resend login alert sender. Authenticated users may trigger only their own queued alert.
// Requires RESEND_API_KEY and RESEND_FROM_EMAIL Supabase function secrets.
import {createClient} from 'https://esm.sh/@supabase/supabase-js@2.49.8';
Deno.serve(async req=>{
 const origin=req.headers.get('origin')||'';
 const headers={'Content-Type':'application/json','Cache-Control':'no-store','Access-Control-Allow-Origin':'https://v3.tichor.com','Vary':'Origin','Access-Control-Allow-Headers':'authorization,apikey,content-type,x-client-info','Access-Control-Allow-Methods':'POST,OPTIONS'};
 const respond=(status:number,message:string)=>new Response(JSON.stringify({message}),{status,headers});
 if(origin&&origin!=='https://v3.tichor.com')return respond(403,'Forbidden origin');
 if(req.method==='OPTIONS')return new Response(null,{status:204,headers});
 if(req.method!=='POST')return respond(405,'Method not allowed');
 const auth=req.headers.get('authorization')||'';
 if(!auth.startsWith('Bearer '))return respond(401,'Sign in required');
 const url=Deno.env.get('SUPABASE_URL')||'';
 const service=Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')||'';
 const apiKey=Deno.env.get('RESEND_API_KEY')||'';
 const from=Deno.env.get('RESEND_FROM_EMAIL')||'';
 if(!url||!service||!apiKey||!from)return respond(503,'Login email service not configured');
 const db=createClient(url,service,{auth:{persistSession:false,autoRefreshToken:false}});
 const {data:{user},error}=await db.auth.getUser(auth.slice(7));
 if(error||!user?.id||!user.email)return respond(401,'Invalid account session');
 const jwtPayload=JSON.parse(atob(auth.split('.')[1].replace(/-/g,'+').replace(/_/g,'/')));
 const sessionId=jwtPayload.session_id;
 if(typeof sessionId!=='string')return respond(403,'Session required');
 const {data:active}=await db.from('tichor_active_sessions').select('session_id').eq('user_id',user.id).maybeSingle();
 if(active?.session_id!==sessionId)return respond(403,'Session superseded');
 const {data:alert}=await db.from('tichor_login_alerts').select('id,created_at,delivered_at').eq('user_id',user.id).eq('session_id',sessionId).maybeSingle();
 if(!alert)return respond(200,'No new-device alert pending');
 if(alert.delivered_at)return respond(200,'Already notified');
 // Resend's idempotency key prevents duplicate delivery across retries.
 const sent=await fetch('https://api.resend.com/emails',{method:'POST',headers:{'Authorization':'Bearer '+apiKey,'Content-Type':'application/json','Idempotency-Key':'tichor-login-'+alert.id},body:JSON.stringify({
 from,to:[user.email],subject:'New device login — TichorConnect',
 text:'A new device signed in to your TichorConnect account on '+new Date(alert.created_at).toUTCString()+'. If this was you, no action is required. If not, change your password and secure your account.'
 })});
 if(!sent.ok){console.warn('Resend login notification failed',sent.status);return respond(503,'Email delivery temporarily unavailable')}
 await db.from('tichor_login_alerts').update({delivered_at:new Date().toISOString()}).eq('id',alert.id).is('delivered_at',null);
 return respond(200,'Notification queued successfully');
});
