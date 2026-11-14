import {VAPID_PUBLIC_KEY} from './push-config.js';
function keyBytes(s){const t=atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4));return Uint8Array.from(t,c=>c.charCodeAt(0))}
export async function enableNotifications(supa,user,status){
 try{
  if(!user)throw Error('Sign in or join a guest room first');
  if(!('serviceWorker' in navigator)||!('PushManager' in window)||!('Notification' in window))throw Error('This browser does not support Web Push');
  const permission=await Notification.requestPermission();if(permission!=='granted')throw Error('Notifications not allowed. Enable them in your browser settings.');
  const registration=await navigator.serviceWorker.ready;
  let sub=await registration.pushManager.getSubscription();
  if(!sub)sub=await registration.pushManager.subscribe({userVisibleOnly:true,applicationServerKey:keyBytes(VAPID_PUBLIC_KEY)});
  const json=sub.toJSON();
  const {error}=await supa.from('tichor_push_subscriptions').upsert({user_id:user.id,endpoint:json.endpoint,p256dh:json.keys.p256dh,auth:json.keys.auth,updated_at:new Date().toISOString()},{onConflict:'endpoint'});
  if(error)throw error;
  status('Notifications enabled on this device. Incoming messages and call invitations can alert you when Tichor is closed.');
 }catch(e){status('Notification setup failed: '+e.message)}
}
export async function disableNotifications(supa,user,status){
 try{const registration=await navigator.serviceWorker.ready;const sub=await registration.pushManager.getSubscription();if(sub){const {error}=await supa.from('tichor_push_subscriptions').delete().eq('user_id',user.id).eq('endpoint',sub.endpoint);if(error)throw error;await sub.unsubscribe()}status('Notifications disabled on this device.')}catch(e){status('Could not disable notifications: '+e.message)}
}
