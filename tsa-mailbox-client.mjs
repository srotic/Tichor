// Experimental TSA staging mailbox client. NOT connected to the live composer.
// Uses existing non-extractable IndexedDB device signing/decryption keys. No
// browser privilege or client option can bypass the server's grant verification.
import {loadApprovedLocalDevice} from './e2ee-device-registry.js';
import {decryptDeviceCopyOnce} from './tsa-replay-receipts.mjs';

const E=new TextEncoder();
const ID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
function id(x){if(typeof x!=='string'||!ID.test(x))throw Error('Invalid TSA device mailbox identifier');return x;}
function b64(buffer){return btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
async function digest(text){return b64(await crypto.subtle.digest('SHA-256',E.encode(text)));}
export async function buildSignedTsaMailboxRequest({account,device,action,signingKey,packet,nonce=crypto.randomUUID(),issuedAt=Date.now()}){
 id(account);id(device);id(nonce);
 if(!['publish','receive'].includes(action))throw Error('Invalid TSA mailbox action');
 if(!signingKey||signingKey.type!=='private'||signingKey.extractable||
   signingKey.algorithm?.name!=='ECDSA')throw Error('Non-extractable device signer required');
 if(!Number.isSafeInteger(issuedAt)||issuedAt<=0)throw Error('Invalid TSA request timestamp');
 if(action==='receive'&&packet!==undefined)throw Error('Unexpected packet on receive');
 let packet_text;
 if(action==='publish'){
  if(!packet||packet.v!==1||packet.protocol!=='TSA-experimental-multi-device-text'||
   packet.from!==account||!ID.test(packet.to)||!ID.test(packet.messageId)||
   !Array.isArray(packet.copies)||packet.copies.length<2||packet.copies.length>16)
   throw Error('Invalid TSA ciphertext message');
  packet_text=JSON.stringify(packet);
  if(E.encode(packet_text).byteLength>32768)throw Error('TSA ciphertext batch exceeds limit');
 }
 const body={domain:'Tichor TSA mailbox request v1',action,account,device,nonce,issuedAt,
  digest:action==='publish'?await digest(packet_text):null};
 const signature=b64(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},signingKey,E.encode(JSON.stringify(body))));
 return {...body,signature,...(action==='publish'?{packet_text}:{})};
}
async function perform(client,account,action,packet){
 if(!client?.auth?.getUser||!client?.functions?.invoke)throw Error('Signed-in Supabase client required');
 const {data:auth,error:authError}=await client.auth.getUser();
 if(authError||auth?.user?.id!==account)throw Error('Mailbox account session mismatch');
 const device=await loadApprovedLocalDevice(client,account);
 const body=await buildSignedTsaMailboxRequest({account,device:device.deviceId,
  action,signingKey:device.signingKey,packet});
 const {data,error}=await client.functions.invoke('tsa-ciphertext-mailbox',{body});
 if(error||!data||typeof data!=='object')throw Error('Server-authorized encrypted mailbox unavailable');
 const expected=action==='publish'?'stored-staging-ciphertext':'staging-ciphertext-only';
 if(data.state!==expected)throw Error('Server refused authorized ciphertext operation');
 return {data,device};
}
export async function publishTsaCiphertextStaging(client,account,packet){
 const {data}=await perform(client,account,'publish',packet);
 if(!Number.isInteger(data.copied)||data.copied!==packet.copies.length)
  throw Error('Incomplete server-authorized ciphertext fanout');
 return Object.freeze({state:data.state,deviceCopies:data.copied,deliveryAuthorized:false});
}
// Receive only signed packets. Caller must supply a pinned, independently
// verified SENDER signing key, never trust a key embedded in a mailbox message.
export async function receiveTsaCiphertextStaging(client,account,resolvePinnedSenderKey,replayStore){
 if(typeof resolvePinnedSenderKey!=='function')throw Error('Verified sender key resolver required');
 const {data,device}=await perform(client,account,'receive');
 if(!Array.isArray(data.messages)||data.messages.length>30)
  throw Error('Malformed TSA mailbox response');
 const results=[];
 for(const message of data.messages){
  id(message.message_id);id(message.sender_id);id(message.peer_id);
  if(typeof message.packet_text!=='string'||message.packet_text.length>32768)
   throw Error('Malformed ciphertext mailbox row');
  const packet=JSON.parse(message.packet_text);
  if(packet.messageId!==message.message_id||packet.from!==message.sender_id||
    packet.to!==message.peer_id||!packet.copies?.some(c=>c.account===account&&c.device===device.deviceId))
   throw Error('Ciphertext mailbox routing mismatch');
  const senderPublicKey=await resolvePinnedSenderKey(message.sender_id);
  if(!senderPublicKey)throw Error('Sender identity not independently verified');
  const text=await decryptDeviceCopyOnce({packet,recipientAccount:account,deviceId:device.deviceId,
   privateKey:device.decryptionKey,senderPublicKey},replayStore);
  results.push(Object.freeze({messageId:message.message_id,senderId:message.sender_id,text}));
 }
 return Object.freeze(results);
}
