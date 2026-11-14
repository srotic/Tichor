import { createClient } from 'npm:@supabase/supabase-js@2';
import webpush from 'npm:web-push@3.6.7';
const headers={'content-type':'application/json'};
Deno.serve(async req=>{
 if(req.method!=='POST')return new Response('Method not allowed',{status:405});
 const expected=Deno.env.get('TICHOR_WEBHOOK_SECRET');
 if(!expected||req.headers.get('x-tichor-webhook-secret')!==expected)return new Response('Unauthorized',{status:401});
 try{
  const event=await req.json();const table=event.table;const record=event.record;
  if(event.type!=='INSERT'||!record)return new Response('Ignored',{status:200});
  if(!['chat_messages','tichor_call_events','tichor_guest_messages','tichor_guest_calls'].includes(table))return new Response('Ignored',{status:200});
  if(table.endsWith('_calls')||table==='tichor_call_events'){if(record.kind!=='offer')return new Response('Ignored',{status:200})}
  const url=Deno.env.get('SUPABASE_URL')!;const key=Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
  const db=createClient(url,key,{auth:{persistSession:false}});
  let recipients:string[]=[];let destination='./chat.html';
  if(table==='chat_messages'||table==='tichor_call_events'){
   recipients=[record.recipient_id];
  }else{
   const {data:room,error:roomError}=await db.from('tichor_guest_rooms').select('expires_at').eq('id',record.room_id).single();
   if(roomError||!room||new Date(room.expires_at).getTime()<=Date.now())return new Response('Expired room',{status:200});
   const {data:members,error:membersError}=await db.from('tichor_guest_members').select('user_id').eq('room_id',record.room_id);
   if(membersError)throw membersError;
   recipients=(members||[]).map(m=>m.user_id).filter(id=>id!==record.sender_id);
   destination='./guest.html';
   // Guest invitation tokens are never stored in cleartext. Notification opens the guest page;
   // recipient may need their original invitation link to re-enter the room.
  }
  recipients=recipients.filter(id=>id&&id!==record.sender_id);
  if(!recipients.length)return new Response('No recipient',{status:200});
  const {data:subs,error}=await db.from('tichor_push_subscriptions').select('id,endpoint,p256dh,auth').in('user_id',recipients);
  if(error)throw error;
  webpush.setVapidDetails(Deno.env.get('VAPID_SUBJECT')||'mailto:admin@example.com',Deno.env.get('VAPID_PUBLIC_KEY')!,Deno.env.get('VAPID_PRIVATE_KEY')!);
  const payload=JSON.stringify({type:table==='chat_messages'||table==='tichor_guest_messages'?'message':'call',id:record.id,url:destination});
  let sent=0;for(const sub of subs||[]){try{await webpush.sendNotification({endpoint:sub.endpoint,keys:{p256dh:sub.p256dh,auth:sub.auth}},payload,{TTL:table.includes('call')?90:86400,urgency:table.includes('call')?'high':'normal'});sent++}catch(err){const status=(err as {statusCode?:number}).statusCode;if(status===404||status===410)await db.from('tichor_push_subscriptions').delete().eq('id',sub.id);else console.error('Push delivery error',status)}}
  return new Response(JSON.stringify({sent}),{headers});
 }catch(err){console.error('Tichor push handler failed',err);return new Response('Push failed',{status:500})}
});
