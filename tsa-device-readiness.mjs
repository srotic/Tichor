// TSA staging-only recipient device readiness check.
// A successful query NEVER authorizes ciphertext distribution.
import {requireContactRootPin} from './tsa-contact-root-pin.mjs';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
function id(value){if(typeof value!=='string'||!UUID.test(value))throw Error('Invalid TSA account');return value;}
export async function readRecipientDeviceReadiness(supa,sender,recipient,observedRootFingerprint,store=localStorage){
 id(sender);id(recipient);
 if(sender===recipient)throw Error('Cannot query self as recipient');
 const {data:session,error:authError}=await supa.auth.getUser();
 if(authError||session?.user?.id!==sender)throw Error('TSA session mismatch');
 requireContactRootPin(store,sender,recipient,observedRootFingerprint);
 const {data,error}=await supa.rpc('tsa_recipient_device_readiness',{target:recipient});
 if(error)throw Error('TSA recipient readiness unavailable or unauthorized.');
 if(!Array.isArray(data)||data.length>50)throw Error('Invalid TSA readiness response');
 const ids=new Set();let pending=0,revoked=0,certificateCandidates=0,trustEvidenceCandidates=0;
 for(const row of data){
  if(!row||!UUID.test(row.device_id)||ids.has(row.device_id)||
     !['pending','revoked'].includes(row.device_state)||
     typeof row.certificate_present!=='boolean'||typeof row.trust_evidence_present!=='boolean'||
     row.delivery_authorized!==false)throw Error('TSA readiness response failed closed');
  ids.add(row.device_id);
  if(row.device_state==='pending')pending++;else revoked++;
  if(row.certificate_present)certificateCandidates++;
  if(row.trust_evidence_present)trustEvidenceCandidates++;
 }
 return Object.freeze({
  state:'device-readiness-preview-not-authorized',
  pending,revoked,certificateCandidates,trustEvidenceCandidates,
  deliveryAuthorized:false
 });
}
