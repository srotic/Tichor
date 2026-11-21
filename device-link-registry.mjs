// Registry adapter for untrusted linking requests only. Never authorizes delivery.
import {verifyDeviceRequest,verifyDeviceApproval} from './device-link-proof.mjs';
const table='tichor_e2ee_devices';
const columns='user_id,device_id,encryption_public_jwk,signing_public_jwk,state';
const equalKey=(a,b)=>!!a&&!!b&&['kty','crv','x','y'].every(k=>a[k]===b[k]);
function matches(row,r){return row?.user_id===r.account&&row.device_id===r.device&&equalKey(row.encryption_public_jwk,r.encryptionKey)&&equalKey(row.signing_public_jwk,r.signingKey)}
async function currentAccount(supa,account){
 const {data,error}=await supa.auth.getUser();
 if(error||data?.user?.id!==account)throw Error('Account session mismatch');
}
async function read(supa,account,device){
 const {data,error}=await supa.from(table).select(columns).eq('user_id',account).eq('device_id',device).maybeSingle();
 if(error)throw Error('Device registry unavailable');
 return data;
}
export async function registerPendingDevice(supa,packet,account,now=Date.now()){
 await currentAccount(supa,account);
 const r=await verifyDeviceRequest(packet,account,now);
 const existing=await read(supa,account,r.device);
 if(existing){
  if(existing.state!=='pending'||!matches(existing,r))throw Error('Device identity unavailable or revoked');
  return existing;
 }
 const {data,error}=await supa.from(table).insert({user_id:r.account,device_id:r.device,encryption_public_jwk:r.encryptionKey,signing_public_jwk:r.signingKey}).select(columns).single();
 if(error||data?.state!=='pending'||!matches(data,r))throw Error('Device registration failed');
 return data;
}
export async function revokePendingDevice(supa,account,device){
 await currentAccount(supa,account);
 const {data,error}=await supa.from(table).update({state:'revoked'}).eq('user_id',account).eq('device_id',device).eq('state','pending').select(columns).maybeSingle();
 if(error||data?.state!=='revoked')throw Error('Device revocation failed or already revoked');
 return data;
}
export async function checkPendingApproval(supa,packet,account,device,nonce,approver,trustedKey,now=Date.now()){
 await currentAccount(supa,account);
 const r=await verifyDeviceApproval(packet,account,device,nonce,approver,trustedKey,now);
 const row=await read(supa,account,device);
 if(row?.state!=='pending'||!matches(row,r))throw Error('Pending registry identity mismatch or revoked');
 // The result is intentionally NOT a grant. No trusted state or messaging integration
 // until atomic nonce consumption, proof persistence, and authenticated trust roots exist.
 return {state:'proof-checked-not-authorized',device:r.device,nonce:r.nonce};
}
