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
// Receive only signed packets. Caller must resolve the EXACT sending-device
// public key from a trusted, root-signed active-device roster, never from
// untrusted mailbox contents. A sender ACCOUNT key alone is insufficient.
export async function receiveTsaCiphertextStaging(client,account,resolvePinnedSenderKey,replayStore,conversationPeer){
 if(typeof resolvePinnedSenderKey!=='function')throw Error('Verified sender key resolver required');
 const {data,device}=await perform(client,account,'receive');
 if(!Array.isArray(data.messages)||data.messages.length>30)
  throw Error('Malformed TSA mailbox response');
 const results=[];
 for(const message of data.messages){
  id(message.message_id);id(message.sender_id);id(message.peer_id);id(message.signing_device_id);
  if(conversationPeer&&(message.sender_id!==conversationPeer&&message.peer_id!==conversationPeer))continue;
  if(typeof message.packet_text!=='string'||message.packet_text.length>32768)
   throw Error('Malformed ciphertext mailbox row');
  const packet=JSON.parse(message.packet_text);
  if(packet.messageId!==message.message_id||packet.from!==message.sender_id||
    packet.to!==message.peer_id||!packet.copies?.some(c=>c.account===account&&c.device===device.deviceId))
   throw Error('Ciphertext mailbox routing mismatch');
  const senderPublicKey=await resolvePinnedSenderKey(message.sender_id,message.signing_device_id);
  if(!senderPublicKey)throw Error('Sender identity not independently verified');
  let text;
  try{
   text=await decryptDeviceCopyOnce({packet,recipientAccount:account,deviceId:device.deviceId,
    privateKey:device.decryptionKey,senderPublicKey},replayStore);
  }catch(error){
   // Inbox reads are non-destructive. Previously authenticated messages
   // remain stored, so skip only atomic replay receipts, never signature errors.
   if(error?.message==='Duplicate TSA message or replay receipt unavailable')continue;
   throw error;
  }
  results.push(Object.freeze({messageId:message.message_id,senderId:message.sender_id,senderDeviceId:message.signing_device_id,text}));
 }
 return Object.freeze(results);
}

// End-to-end staging assembly: verified contact root -> signed complete device
// rosters -> own non-extractable signing key -> server-checked ciphertext fanout.
// Signed rosters are supplied by the caller pending a durable roster directory;
// this function refuses unverified contact identities instead of downgrading.
export async function encryptAndPublishTsaTextStaging(client,{account,recipient,text,senderRoster,recipientRoster,verifiedRootStore=localStorage}){
 id(account);id(recipient);
 if(account===recipient)throw Error('Cannot send TSA message to self');
 const {requireContactRootPin}=await import('./tsa-contact-root-pin.mjs');
 const {verifyTsaRoster,previewTsaRosterCoverage}=await import('./tsa-signed-roster.mjs');
 const {encryptDeviceCopies}=await import('./tsa-multidevice-envelope.mjs');
 const source=await loadApprovedLocalDevice(client,account);
 async function getAccountRoot(who){
  const {data,error}=await client.from('tichor_e2ee_identity_keys')
   .select('user_id,encryption_public_jwk,signing_public_jwk').eq('user_id',who).maybeSingle();
  if(error||data?.user_id!==who)throw Error('Trusted TSA root public key unavailable');
  const canonical=k=>JSON.stringify({kty:k.kty,crv:k.crv,x:k.x,y:k.y});
  const digest=await crypto.subtle.digest('SHA-256',E.encode(
   canonical(data.encryption_public_jwk)+'|'+canonical(data.signing_public_jwk)));
  const fingerprint=[...new Uint8Array(digest)].map(x=>x.toString(16).padStart(2,'0')).join('');
  return {signing:data.signing_public_jwk,fingerprint};
 }
 const [mine,peer]=await Promise.all([getAccountRoot(account),getAccountRoot(recipient)]);
 requireContactRootPin(verifiedRootStore,account,recipient,peer.fingerprint);
 const now=Date.now();
 const [from,to]=await Promise.all([
  verifyTsaRoster(senderRoster,mine.signing,now),
  verifyTsaRoster(recipientRoster,peer.signing,now)
 ]);
 if(from.account!==account||to.account!==recipient)throw Error('TSA signed roster account mismatch');
 const own=from.devices.find(d=>d.device===source.deviceId);
 const same=(a,b)=>['kty','crv','x','y'].every(k=>a?.[k]===b?.[k]);
 if(!own||!same(own.signingKey,source.signingPublicKey)||
  !same(own.encryptionKey,source.encryptionPublicKey))
  throw Error('Local signing device is missing or substituted in the approved sender roster');
 const targets=[
  ...from.devices.map(d=>({account,device:d.device,authorized:true,encryptionKey:d.encryptionKey})),
  ...to.devices.map(d=>({account:recipient,device:d.device,authorized:true,encryptionKey:d.encryptionKey}))
 ];
 const packet=await encryptDeviceCopies({sender:account,recipient,
  messageId:crypto.randomUUID(),text,targets,signingKey:source.signingKey,createdAt:now});
 const check=await previewTsaRosterCoverage({packet,senderRoster,recipientRoster,
  senderRoot:mine.signing,recipientRoot:peer.signing,now});
 if(check.deviceCount!==packet.copies.length||check.deliveryAuthorized!==false)
  throw Error('TSA recipient roster verification failed');
 return publishTsaCiphertextStaging(client,account,packet);
}

// Convenience inbox for staging: verify each sender's ROOT-SIGNED roster and
// the contact's independently pinned identity before selecting the signer key.
// rosterResolver must supply a signed roster; an unsigned directory row fails.
export async function receiveTsaVerifiedTextStaging(client,account,rosterResolver,store=localStorage,conversationPeer){
 id(account);
 if(typeof rosterResolver!=='function')throw Error('Signed roster resolver required');
 const {requireContactRootPin}=await import('./tsa-contact-root-pin.mjs');
 const {verifyTsaRoster}=await import('./tsa-signed-roster.mjs');
 const cache=new Map();
 async function senderKey(sender,device){
  const token=sender+':'+device;
  if(cache.has(token))return cache.get(token);
  const {data,error}=await client.from('tichor_e2ee_identity_keys')
   .select('user_id,encryption_public_jwk,signing_public_jwk').eq('user_id',sender).maybeSingle();
  if(error||data?.user_id!==sender)throw Error('Sender root key unavailable');
  const canonical=k=>JSON.stringify({kty:k.kty,crv:k.crv,x:k.x,y:k.y});
  const digest=await crypto.subtle.digest('SHA-256',E.encode(
   canonical(data.encryption_public_jwk)+'|'+canonical(data.signing_public_jwk)));
  const fingerprint=[...new Uint8Array(digest)].map(x=>x.toString(16).padStart(2,'0')).join('');
  if(sender!==account)requireContactRootPin(store,account,sender,fingerprint);
  const signed=await rosterResolver(sender);
  const roster=await verifyTsaRoster(signed,data.signing_public_jwk);
  if(roster.account!==sender)throw Error('Sender signed roster identity mismatch');
  const record=roster.devices.find(x=>x.device===device);
  if(!record)throw Error('Sending device is missing or revoked in its signed roster');
  cache.set(token,record.signingKey);
  return record.signingKey;
 }
 return receiveTsaCiphertextStaging(client,account,senderKey,undefined,conversationPeer);
}
