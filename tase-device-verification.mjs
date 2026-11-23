// Browser-to-server TASE possession verification. This does not mint or extend grants.
import {loadApprovedLocalDevice} from './e2ee-device-registry.js';
import {signRenewalChallenge} from './tase-renewal-proof.mjs';
const jobs=new Map();
async function invoke(client,body){
 const {data,error}=await client.functions.invoke('tsa-renew-device',{body});
 if(error||!data||typeof data!=='object')throw Error('Trusted-device verification unavailable');
 return data;
}
export async function verifyExistingTrustedDevice(client,account){
 if(!client?.auth?.getUser||!client?.functions?.invoke||typeof account!=='string'||!account)
  throw Error('Verified account and Supabase client required');
 if(jobs.has(account))return jobs.get(account);
 const task=(async()=>{
  const {data:session,error}=await client.auth.getUser();
  if(error||session?.user?.id!==account)throw Error('Account session mismatch');
  const device=await loadApprovedLocalDevice(client,account);
  const request=await invoke(client,{action:'issue',device:device.deviceId});
  if(request.account!==account||request.device!==device.deviceId)
   throw Error('Server challenge identity mismatch');
  const proof=await signRenewalChallenge(device.signingKey,request);
  const result=await invoke(client,{action:'verify',...proof});
  if(result.state!=='trusted-device-possession-verified'||result.device!==device.deviceId||
     result.authorizationRenewed!==false)
   throw Error('Unrecognized server verification result');
  return Object.freeze({state:result.state,device:device.deviceId,authorizationRenewed:false});
 })();
 jobs.set(account,task);
 try{return await task}finally{if(jobs.get(account)===task)jobs.delete(account)}
}
