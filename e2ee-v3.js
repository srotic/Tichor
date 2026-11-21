// TichorConnect V3 experimental direct-text E2EE.
// Security note: no Signal Double Ratchet, forward secrecy, post-compromise security,
// device linking, encrypted attachments, or externally verified identities.
// Private identity keys remain in origin-local IndexedDB and are non-extractable.
const E = new TextEncoder(), D = new TextDecoder();
const b64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));
const ub64 = str => Uint8Array.from(atob(str), c => c.charCodeAt(0));
const DB_NAME = 'tichor-v3-e2ee-identity';
const PREFIX = 'tc-e2ee2.';
// Supabase chat_messages.body has a 5,000-character limit. Two encrypted copies expand text.
const MAX_PLAINTEXT_BYTES = 1100;
const MAX_CIPHERTEXT_CHARS = 5000;
const KEY_STORE = 'identities';
const cryptoAPI = globalThis.crypto?.subtle;
function mustCrypto(){if(!cryptoAPI || !globalThis.indexedDB)throw Error('Secure cryptography and IndexedDB are required on this device.');}
function dbOpen(){
  mustCrypto();
  return new Promise((resolve,reject)=>{
    const req=indexedDB.open(DB_NAME,1);
    req.onupgradeneeded=()=>{if(!req.result.objectStoreNames.contains(KEY_STORE))req.result.createObjectStore(KEY_STORE)};
    req.onsuccess=()=>resolve(req.result);req.onerror=()=>reject(req.error);
  });
}
async function dbGet(id){
  const db=await dbOpen();
  try{return await new Promise((resolve,reject)=>{const tx=db.transaction(KEY_STORE,'readonly');const req=tx.objectStore(KEY_STORE).get(id);req.onsuccess=()=>resolve(req.result||null);req.onerror=()=>reject(req.error)})}
  finally{db.close()}
}
async function dbPut(id,value){
  const db=await dbOpen();
  try{await new Promise((resolve,reject)=>{const tx=db.transaction(KEY_STORE,'readwrite');tx.objectStore(KEY_STORE).put(value,id);tx.oncomplete=resolve;tx.onerror=()=>reject(tx.error)})}
  finally{db.close()}
}
function canonicalJwk(jwk){return JSON.stringify({kty:jwk.kty,crv:jwk.crv,x:jwk.x,y:jwk.y});}
function assertPublicKey(jwk){if(!jwk || jwk.kty!=='EC'||jwk.crv!=='P-256'||typeof jwk.x!=='string'||typeof jwk.y!=='string'||jwk.x.length!==43||jwk.y.length!==43||jwk.d!==undefined)throw Error('Invalid public identity key. Message blocked.');}
async function fingerprint(row){
  const hashed=await cryptoAPI.digest('SHA-256',E.encode(canonicalJwk(row.encryption_public_jwk)+'|'+canonicalJwk(row.signing_public_jwk)));
  return Array.from(new Uint8Array(hashed),x=>x.toString(16).padStart(2,'0')).join('').match(/.{1,4}/g).join(' ');
}
function pinIdentity(id,fp){
  const key='tichor-e2ee-pin:'+id;
  const previous=localStorage.getItem(key);
  if(previous && previous!==fp)throw Error('Contact security key changed. Encrypted messaging stopped; verify their identity out of band.');
  if(!previous)localStorage.setItem(key,fp);
}
async function fetchPublic(supa,id){
  const {data,error}=await supa.from('tichor_e2ee_identity_keys').select('user_id,encryption_public_jwk,signing_public_jwk').eq('user_id',id).maybeSingle();
  if(error)throw Error('E2EE directory unavailable: '+error.message);
  if(!data)throw Error('This contact has not enabled encrypted messages yet.');
  if(data.user_id!==id)throw Error('Public identity does not match the requested account.');
  assertPublicKey(data.encryption_public_jwk);assertPublicKey(data.signing_public_jwk);
  pinIdentity(id,await fingerprint(data));
  return data;
}
export async function ensureIdentity(supa,userId){
  mustCrypto();
  if(!userId)throw Error('Sign in before enabling encryption.');
  const local=await dbGet(userId);
  if(local){
    // Key continuity check: never overwrite previously registered public keys.
    const published=await fetchPublic(supa,userId);
    const pubEnc=await cryptoAPI.exportKey('jwk',local.enc.publicKey);
    const pubSign=await cryptoAPI.exportKey('jwk',local.sign.publicKey);
    if(canonicalJwk(pubEnc)!==canonicalJwk(published.encryption_public_jwk)||canonicalJwk(pubSign)!==canonicalJwk(published.signing_public_jwk))
      throw Error('Local encryption identity does not match the published identity. No message was sent.');
    return {fingerprint:await fingerprint(published)};
  }
  const {data:existing,error:lookupErr}=await supa.from('tichor_e2ee_identity_keys').select('user_id').eq('user_id',userId).maybeSingle();
  if(lookupErr)throw Error('Unable to check encryption identity: '+lookupErr.message);
  if(existing)throw Error('This account already has an encryption identity on another browser. Secure device linking or recovery is required; keys will not be silently replaced.');
  const enc=await cryptoAPI.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
  const sign=await cryptoAPI.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
  const record={enc,sign};
  await dbPut(userId,record);
  const encryption_public_jwk=await cryptoAPI.exportKey('jwk',enc.publicKey);
  const signing_public_jwk=await cryptoAPI.exportKey('jwk',sign.publicKey);
  const {error}=await supa.from('tichor_e2ee_identity_keys').insert({user_id:userId,encryption_public_jwk,signing_public_jwk});
  if(error)throw Error('Encryption identity could not be published. Do not clear this browser: '+error.message);
  const row={encryption_public_jwk,signing_public_jwk};
  pinIdentity(userId,await fingerprint(row));
  return {fingerprint:await fingerprint(row)};
}
async function sealTo(text,publicJwk,senderId,recipientId){
  const ephemeral=await cryptoAPI.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
  const theirKey=await cryptoAPI.importKey('jwk',publicJwk,{name:'ECDH',namedCurve:'P-256'},false,[]);
  const bits=await cryptoAPI.deriveBits({name:'ECDH',public:theirKey},ephemeral.privateKey,256);
  const material=await cryptoAPI.importKey('raw',bits,'HKDF',false,['deriveKey']);
  const salt=crypto.getRandomValues(new Uint8Array(16));
  const key=await cryptoAPI.deriveKey({name:'HKDF',hash:'SHA-256',salt,info:E.encode('TichorConnect V3 experimental E2EE text v2')},material,{name:'AES-GCM',length:256},false,['encrypt']);
  const iv=crypto.getRandomValues(new Uint8Array(12));
  const aad=E.encode(JSON.stringify([senderId,recipientId]));
  const ciphertext=await cryptoAPI.encrypt({name:'AES-GCM',iv,additionalData:aad},key,E.encode(text));
  return {epk:await cryptoAPI.exportKey('jwk',ephemeral.publicKey),salt:b64(salt),iv:b64(iv),ct:b64(ciphertext)};
}
export function isEncrypted(body){return typeof body==='string'&&body.startsWith(PREFIX)}
export async function encryptDirectText(supa,senderId,recipientId,text){
  if(!text||typeof text!=='string')throw Error('An encrypted text message is required.');
  mustCrypto();
  if(E.encode(text).byteLength>MAX_PLAINTEXT_BYTES)throw Error('Encrypted text exceeds the 1,100-byte safety limit. Split it into smaller messages.');
  const mine=await dbGet(senderId);
  if(!mine)throw Error('Enable encryption on this device before sending.');
  const receiver=await fetchPublic(supa,recipientId);
  const sender=await fetchPublic(supa,senderId);
  const envelope={v:2,from:senderId,to:recipientId,
    forRecipient:await sealTo(text,receiver.encryption_public_jwk,senderId,recipientId),
    forSender:await sealTo(text,sender.encryption_public_jwk,senderId,recipientId)};
  const signature=await cryptoAPI.sign({name:'ECDSA',hash:'SHA-256'},mine.sign.privateKey,E.encode(JSON.stringify(envelope)));
  const payload=PREFIX+b64(E.encode(JSON.stringify({...envelope,sig:b64(signature)})));
  if(payload.length>MAX_CIPHERTEXT_CHARS)throw Error('Encrypted payload is too long for the server message limit. No message was sent.');
  return payload;
}
export async function decryptDirectText(supa,userId,message){
  if(!isEncrypted(message.body))throw Error('This message is not encrypted.');
  mustCrypto();
  if(message.body.length>MAX_CIPHERTEXT_CHARS)throw Error('Encrypted message exceeds allowed size.');
  const obj=JSON.parse(D.decode(ub64(message.body.slice(PREFIX.length))));
  if(!obj||obj.v!==2||obj.from!==message.sender_id||obj.to!==message.recipient_id||!obj.forSender||!obj.forRecipient||typeof obj.sig!=='string')throw Error('Encrypted message identity mismatch.');
  if(userId!==obj.from&&userId!==obj.to)throw Error('Not a participant.');
  const me=await dbGet(userId);
  if(!me)throw Error('Encryption key unavailable on this device.');
  const sender=await fetchPublic(supa,obj.from);
  const verifyKey=await cryptoAPI.importKey('jwk',sender.signing_public_jwk,{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
  const {sig,...signed}=obj;
  const verified=await cryptoAPI.verify({name:'ECDSA',hash:'SHA-256'},verifyKey,ub64(sig),E.encode(JSON.stringify(signed)));
  if(!verified)throw Error('Message signature failed verification.');
  const slot=userId===obj.from?obj.forSender:obj.forRecipient;
  const ephemeral=await cryptoAPI.importKey('jwk',slot.epk,{name:'ECDH',namedCurve:'P-256'},false,[]);
  const bits=await cryptoAPI.deriveBits({name:'ECDH',public:ephemeral},me.enc.privateKey,256);
  const material=await cryptoAPI.importKey('raw',bits,'HKDF',false,['deriveKey']);
  const key=await cryptoAPI.deriveKey({name:'HKDF',hash:'SHA-256',salt:ub64(slot.salt),info:E.encode('TichorConnect V3 experimental E2EE text v2')},material,{name:'AES-GCM',length:256},false,['decrypt']);
  const plain=await cryptoAPI.decrypt({name:'AES-GCM',iv:ub64(slot.iv),additionalData:E.encode(JSON.stringify([obj.from,obj.to]))},key,ub64(slot.ct));
  return D.decode(plain);
}
export async function encryptionStatus(supa,userId,recipientId){
  const mine=await dbGet(userId);
  if(!mine)return {ready:false,reason:'Enable encryption in this browser first.'};
  try{const info=await fetchPublic(supa,recipientId);return {ready:true,fingerprint:await fingerprint(info)}}catch(e){return {ready:false,reason:e.message}}
}
