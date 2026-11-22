// TASE — Tichor Automatic Secure Enrollment (V3 staging only).
// Automatically bootstraps exactly the first encryption device after verified
// account sign-in. It does NOT grant trust to second browsers, and does not
// activate or claim production-grade E2EE.
import {requestDevice,listDeviceRequests,localDeviceFingerprint,loadApprovedLocalDevice} from './e2ee-device-registry.js';
import {ensureIdentity,getConfirmedRootPreview,saveEnrollmentPreview,activateConfirmedDevice} from './e2ee-v3.js';
import {requestFingerprint} from './e2ee-device-approval.mjs';
import {publishOwnTsaRoster} from './tsa-roster-directory.mjs';

const pending=new Map();
export function taseCanBootstrap({authenticated,verified,deviceCount,hasOriginalIdentity}){
 return authenticated===true&&verified===true&&hasOriginalIdentity===true&&
  Number.isSafeInteger(deviceCount)&&deviceCount===0;
}
function isVerified(user){
 // Supabase confirms email/phone after completing the configured verification
 // process. Authentication alone must not silently create a trusted device.
 return Boolean(user?.email_confirmed_at||user?.phone_confirmed_at);
}
async function activeSession(client,account){
 const {data,error}=await client.auth.getUser();
 if(error||data?.user?.id!==account)throw Error('TASE account session changed');
 if(!isVerified(data.user))throw Error('Verify your email or phone before activating encryption');
 return data.user;
}
export async function taseEnrollFirstDevice(client,account,{onStage}={}){
 if(typeof account!=='string'||!account)throw Error('TASE account required');
 if(!globalThis.isSecureContext||!crypto?.subtle||!globalThis.indexedDB||
  !globalThis.navigator?.locks?.request)throw Error('TASE requires a secure browser with local key storage and cross-tab locking');
 if(pending.has(account))return pending.get(account);
 const task=navigator.locks.request('tichor-tase-first-device:'+account,async()=>{
  const notify=(stage)=>{if(typeof onStage==='function')onStage(stage)};
  await activeSession(client,account);
  notify('checking-device-identity');
  // Check the existing registry BEFORE attempting original-root key creation:
  // a returning user on a secondary browser must not generate another root.
  const existing=await listDeviceRequests(client,account);
  if(existing.length){
   const local=await localDeviceFingerprint(client,account);
   if(local&&existing.some(d=>d.device_id===local.id&&d.state==='active')){
    try{
     await loadApprovedLocalDevice(client,account);
     return Object.freeze({state:'already-active',device:local.id});
    }catch(error){
     // Expired authorization requires verified renewal; never mark it active.
     notify('device-authorization-renewal-required');
     return Object.freeze({state:'authorization-renewal-required',device:local.id});
    }
   }
   notify('additional-device-approval-required');
   return Object.freeze({state:'existing-device-approval-required',device:null});
  }
  // Never silently replace a root identity previously registered elsewhere.
  const root=await ensureIdentity(client,account);
  const allowed=taseCanBootstrap({authenticated:true,verified:true,
   deviceCount:existing.length,hasOriginalIdentity:Boolean(root?.fingerprint)});
  if(!allowed)throw Error('TASE first-device safety check failed');
  notify('creating-first-device-keys');
  const registered=await requestDevice(client,account);
  if(registered.state!=='pending')throw Error('TASE first device is not pending');
  await activeSession(client,account);
  // Atomic first-device check at the client is not a security boundary:
  // only the original non-extractable root private key can sign this approval.
  // Additional device browsers lack that root key and are not auto-approved.
  const updated=await listDeviceRequests(client,account);
  if(updated.length!==1||updated[0].device_id!==registered.id||
    updated[0].state!=='pending')
   throw Error('TASE detected another device; first-device approval stopped');
  const fingerprint=await requestFingerprint(updated[0]);
  const local=await localDeviceFingerprint(client,account);
  if(local?.id!==registered.id||local.fingerprint!==fingerprint)
   throw Error('TASE local device keys do not match registered public keys');
  await getConfirmedRootPreview(client,account,root.fingerprint);
  notify('signing-first-device-authorization');
  const evidence=await saveEnrollmentPreview(client,account,updated[0],fingerprint);
  if(evidence!=='directory-verified-preview')throw Error('First-device evidence not verified');
  await activeSession(client,account);
  const activated=await activateConfirmedDevice(client,account,registered.id);
  if(activated.state!=='active-not-delivery-authorized')
   throw Error('First-device activation was not accepted by server');
  await loadApprovedLocalDevice(client,account);
  notify('publishing-signed-roster');
  const roster=await publishOwnTsaRoster(client,account);
  notify('first-device-ready');
  return Object.freeze({state:'first-device-active-staging',device:registered.id,
   authorizedUntil:activated.expiresAt,rosterExpiresAt:roster.expiresAt});
 });
 pending.set(account,task);
 try{return await task}finally{if(pending.get(account)===task)pending.delete(account)}
}
