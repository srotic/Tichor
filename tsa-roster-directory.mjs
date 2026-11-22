// V3 staging root-signed roster discovery. NOT a production E2EE directory.
// Active device keys are immutable in the registry. The ORIGINAL account
// encryption identity must sign the complete short-lived list, after which
// peers verify the signature against their independently pinned root identity.
import {makeTsaRosterBody,verifyTsaRoster} from './tsa-signed-roster.mjs';
import {signRootDeviceRoster} from './e2ee-v3.js';
import {loadApprovedLocalDevice} from './e2ee-device-registry.js';
const ID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
function id(x){if(typeof x!=='string'||!ID.test(x))throw Error('Invalid TSA roster account');return x;}
async function session(client,account){
 const {data,error}=await client.auth.getUser();
 if(error||data?.user?.id!==account)throw Error('TSA roster account session changed');
}
export async function readPublishedTsaRoster(client,account,rootSigningKey){
 id(account);
 const {data,error}=await client.from('tsa_signed_device_rosters')
 .select('user_id,roster,signature').eq('user_id',account).maybeSingle();
 if(error||data?.user_id!==account||!data.roster||!data.signature)
  throw Error('Contact has no current signed device roster');
 return verifyTsaRoster({roster:data.roster,signature:data.signature},rootSigningKey);
}
export async function loadSignedTsaRosterPacket(client,account,rootSigningKey){
 id(account);
 const {data,error}=await client.from('tsa_signed_device_rosters')
 .select('user_id,roster,signature').eq('user_id',account).maybeSingle();
 if(error||data?.user_id!==account)throw Error('Signed TSA device roster missing');
 await verifyTsaRoster({roster:data.roster,signature:data.signature},rootSigningKey);
 return {roster:data.roster,signature:data.signature};
}
export async function publishOwnTsaRoster(client,account){
 id(account);
 await session(client,account);
 const local=await loadApprovedLocalDevice(client,account);
 const {data:devices,error:deviceError}=await client.from('tichor_e2ee_devices')
  .select('user_id,device_id,state,encryption_public_jwk,signing_public_jwk')
  .eq('user_id',account).in('state',['active','pending']).order('device_id');
 const {data:grants,error:grantError}=await client.from('tichor_e2ee_active_device_grants')
  .select('user_id,device_id,expires_at_ms').eq('user_id',account);
 if(deviceError||grantError||!Array.isArray(devices)||!Array.isArray(grants))
  throw Error('Verified active device list unavailable');
 const now=Date.now();
 const eligible=new Map(grants.filter(g=>g.user_id===account&&Number(g.expires_at_ms)>now).map(g=>[g.device_id,g]));
 if(devices.some(d=>d.state==='pending'))throw Error('Pending device registration needs resolution before publishing a complete roster');
 const active=devices.filter(d=>d.user_id===account&&d.state==='active');
 if(active.length===0||active.length>16||active.some(d=>!eligible.has(d.device_id)))
  throw Error('An active device is missing current root-signed authorization');
 if(!active.some(d=>d.device_id===local.deviceId))
  throw Error('This browser is not listed among active devices');
 const existing=await client.from('tsa_signed_device_rosters')
  .select('roster').eq('user_id',account).maybeSingle();
 if(existing.error)throw Error('Cannot determine current roster revision');
 const revision=Math.max(0,Number(existing.data?.roster?.revision)||0)+1;
 if(!Number.isSafeInteger(revision)||revision>1e12)throw Error('Invalid next roster revision');
 const devicesToSign=active.map(d=>({
  device:d.device_id,state:'active',encryptionKey:d.encryption_public_jwk,signingKey:d.signing_public_jwk
 }));
 const body=makeTsaRosterBody({account,revision,issuedAt:now,expiresAt:now+180000,devices:devicesToSign});
 const signed=await signRootDeviceRoster(client,account,body);
 await session(client,account);
 const {data,error}=await client.from('tsa_signed_device_rosters')
  .upsert({user_id:account,roster:signed.roster,signature:signed.signature},{onConflict:'user_id'})
  .select('user_id,roster,signature').single();
 if(error||data?.user_id!==account||data?.signature!==signed.signature)
  throw Error('Root-signed roster publication rejected');
 await verifyTsaRoster({roster:data.roster,signature:data.signature},
  (await client.from('tichor_e2ee_identity_keys').select('signing_public_jwk').eq('user_id',account).single()).data?.signing_public_jwk);
 return {revision,deviceCount:body.devices.length,expiresAt:body.expiresAt};
}

// Keep the original browser's short-lived roster current without repeated
// button clicks. Never auto-enroll or grant a device. Only an already active,
// locally held ORIGINAL root-signing key can publish a new signed roster.
const renewJobs=new Map();
export async function renewOwnTsaRosterIfNeeded(client,account,{renewBeforeMs=90000,now=Date.now()}={}){
 id(account);
 if(!Number.isSafeInteger(now)||!Number.isSafeInteger(renewBeforeMs)||renewBeforeMs<30000||renewBeforeMs>150000)
  throw Error('Invalid TSA renewal window');
 await session(client,account);
 const {data,error}=await client.from('tsa_signed_device_rosters')
  .select('roster,signature').eq('user_id',account).maybeSingle();
 if(error)throw Error('Current signed roster unavailable');
 const expiry=Number(data?.roster?.expiresAt);
 if(data&&Number.isSafeInteger(expiry)&&expiry-now>renewBeforeMs)
  return Object.freeze({state:'signed-roster-current',expiresAt:expiry,renewed:false});
 if(renewJobs.has(account))return renewJobs.get(account);
 const job=(async()=>{
  const next=await publishOwnTsaRoster(client,account);
  return Object.freeze({state:'signed-roster-renewed',expiresAt:next.expiresAt,renewed:true});
 })();
 renewJobs.set(account,job);
 try{return await job}finally{if(renewJobs.get(account)===job)renewJobs.delete(account)}
}
