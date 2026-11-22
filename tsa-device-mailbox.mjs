// TSA staged ciphertext transport adapter. NOT ACTIVE in TichorConnect chats.
// Transport methods only accept packets from the per-device envelope module.
// Server RLS intentionally denies reads/writes until active-device grants exist.
import {decryptDeviceCopy} from './tsa-multidevice-envelope.mjs';
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const MAX_PACKET=32768;
function id(x){if(typeof x!=='string'||!UUID.test(x))throw Error('Invalid TSA mailbox identity');return x;}
export function prepareDeviceEnvelopeRows({packet,deliveryAuthorized=false}){
 // A caller-provided boolean can never authorize live distribution.
 // This helper intentionally refuses all delivery until an independent
 // server-backed authorization protocol is implemented and audited.
 if(deliveryAuthorized!==false)throw Error('TSA delivery activation is not permitted');
 if(!packet||packet.v!==1||packet.protocol!=='TSA-experimental-multi-device-text'||
  !Array.isArray(packet.copies)||packet.copies.length<2||
  typeof packet.signature!=='string'||!packet.signature||
  JSON.stringify(packet).length>MAX_PACKET)throw Error('Invalid TSA ciphertext envelope');
 const sender=id(packet.from),recipient=id(packet.to),messageId=id(packet.messageId);
 const seen=new Set();
 return packet.copies.map(copy=>{
  const device=id(copy.device),account=id(copy.account);
  if(account!==sender&&account!==recipient)throw Error('Unrecognized TSA ciphertext account');
  if(seen.has(account+':'+device))throw Error('Duplicate TSA delivery destination');
  seen.add(account+':'+device);
  return Object.freeze({message_id:messageId,sender_id:sender,recipient_id:account,device_id:device,envelope:packet});
 });
}
export async function previewEncryptedMailboxBatch(packet){
 const rows=prepareDeviceEnvelopeRows({packet});
 return Object.freeze({state:'ciphertext-batch-preview-not-sent',rowCount:rows.length});
}
export async function publishEncryptedMailboxBatch(){
 throw Error('TSA mailbox transport disabled: no independently authorized active devices');
}
export async function receiveEncryptedMailbox(){
 throw Error('TSA mailbox retrieval disabled: no authorized device delivery sessions');
}
// Expose local cryptographic decryption via an explicit test-only helper;
// never fetch candidate device ciphertext from the server with this module.
export async function decryptLocalTsaPacket(args){
 return decryptDeviceCopy(args);
}

/**
 * Staging-only local cryptographic fanout preflight.
 * Verifies sender signature, packet membership and one recipient ciphertext
 * before presenting a batch preview. This is NOT server-side authorization:
 * other device copies and current revocations still need independent checks.
 * Neither plaintext nor mailbox inserts leave this function.
 */
export async function previewVerifiedEncryptedMailboxBatch({packet,localDevice}){
 if(!localDevice||typeof localDevice!=='object')throw Error('Local device verification required');
 const rows=prepareDeviceEnvelopeRows({packet});
 // Authenticated decryption rejects forged signatures, modified ciphertext,
 // modified routing identifiers, or unavailable local device keys.
 await decryptDeviceCopy({packet,recipientAccount:localDevice.recipientAccount,deviceId:localDevice.deviceId,privateKey:localDevice.privateKey,senderPublicKey:localDevice.senderPublicKey});
 return Object.freeze({
  state:'locally-verified-ciphertext-preview-not-sent',
  rowCount:rows.length,
  deliveryAuthorized:false
 });
}
