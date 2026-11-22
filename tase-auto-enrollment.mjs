// TASE — Tichor Automatic Secure Enrollment (V3 staging only).
// Automatically bootstraps exactly the first encryption device after verified
// account sign-in. It does NOT grant trust to second browsers, and does not
// activate or claim production-grade E2EE.
import {requestDevice,listDeviceRequests,localDeviceFingerprint,loadApprovedLocalDevice} from './e2ee-device-registry.js';
import {ensureIdentity,getConfirmedRootPreview,saveEnrollmentPreview,activateConfirmedDevice} from './e2ee-v3.js';
import {requestFingerprint} from './e2ee-device-approval.mjs';
import {publishOwnTsaRoster} from './tsa-roster-directory.mjs';
import {requireFreshLinkEvidence} from './device-link-registry.mjs';

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
   const matched=local&&existing.find(d=>d.device_id===local.id);
   if(matched&&matched.state==='active'){
    // A returning approved browser must prove current authorization, never
    // simply trust a remembered device ID or an expired server grant.
    try{
     await loadApprovedLocalDevice(client,account);
     return Object.freeze({state:'already-active',device:local.id});
    }catch(error){
     notify('device-authorization-renewal-required');
     return Object.freeze({state:'authorization-renewal-required',device:local.id});
    }
   }
   if(matched?.state==='revoked'){
    notify('revoked-device-recovery-required');
    return Object.freeze({state:'revoked-device-recovery-required',device:local.id});
   }
   if(matched?.state==='pending'){
    // Reuse fresh signed proof. Expired nonces may be renewed ONLY with the
    // same locally held pending private key and the same immutable public keys.
    try{
     await requireFreshLinkEvidence(client,account,local.id);
    }catch{
     notify('renewing-pending-device-request');
     const refreshed=await requestDevice(client,account);
     if(refreshed.id!==local.id||refreshed.state!=='pending')
      throw Error('Pending device identity changed; no approval requested');
    }
    notify('waiting-for-original-device-approval');
    return Object.freeze({state:'pending-device-approval-required',device:local.id});
   }
   // Never bootstrap a second root from account login. If all devices are
   // revoked or pending and none is currently trusted, key recovery must
   // involve a separate, explicit cryptographic recovery process.
   if(!existing.some(d=>d.state==='active')){
    notify('secure-recovery-required');
    return Object.freeze({state:'secure-recovery-required',device:null});
   }
   if(local&&!matched){
    // Unexpected local key material cannot be silently replaced or trusted.
    notify('local-device-identity-conflict');
    return Object.freeze({state:'secure-recovery-required',device:null});
   }
   // Automatically register an UNKNOWN browser as PENDING. This neither
   // signs its authorization nor makes its keys eligible for message delivery.
   notify('registering-pending-device');
   const request=await requestDevice(client,account);
   if(request.state!=='pending')throw Error('New browser was not registered pending');
   const registry=await listDeviceRequests(client,account);
   const mine=await localDeviceFingerprint(client,account);
   if(mine?.id!==request.id||!registry.some(d=>d.device_id===request.id&&d.state==='pending'))
    throw Error('Device request identity mismatch; approval blocked');
   notify('waiting-for-original-device-approval');
   return Object.freeze({state:'pending-device-approval-required',device:request.id});
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
