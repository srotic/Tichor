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
  const {data:session,error:sessionError}=await supa.auth.getUser();
  if(sessionError||session?.user?.id!==senderId)throw Error('Encryption session mismatch. No message was sent.');
  const receiver=await fetchPublic(supa,recipientId);
  const sender=await fetchPublic(supa,senderId);
  // Do not send ciphertext when the local root keys no longer match the directory.
  if(!mine.enc?.privateKey||!mine.sign?.privateKey||mine.enc.privateKey.extractable||mine.sign.privateKey.extractable||
     canonicalJwk(await cryptoAPI.exportKey('jwk',mine.enc.publicKey))!==canonicalJwk(sender.encryption_public_jwk)||
     canonicalJwk(await cryptoAPI.exportKey('jwk',mine.sign.publicKey))!==canonicalJwk(sender.signing_public_jwk))
    throw Error('Local encryption identity does not match the registered identity. No message was sent.');
  const envelope={v:2,from:senderId,to:recipientId,
    forRecipient:await sealTo(text,receiver.encryption_public_jwk,senderId,recipientId),
    forSender:await sealTo(text,sender.encryption_public_jwk,senderId,recipientId)};
  const signature=await cryptoAPI.sign({name:'ECDSA',hash:'SHA-256'},mine.sign.privateKey,E.encode(JSON.stringify(envelope)));
  const {data:latestSession,error:latestSessionError}=await supa.auth.getUser();
  if(latestSessionError||latestSession?.user?.id!==senderId)throw Error('Encryption session changed. No message was sent.');
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

 // Preview only: sign an enrollment transcript, not a messaging authorization.
export async function signEnrollmentPreview(supa,account,request,confirmedFingerprint){
 if(request.user_id!==account||request.state!=='pending')throw Error('Not a pending request for this account.');
 const {data,error}=await supa.auth.getUser();
 if(error||data?.user?.id!==account)throw Error('Sign in again.');
 const local=await dbGet(account);
 if(!local)throw Error('Use the original encryption browser.');
 const published=await fetchPublic(supa,account);
 if(canonicalJwk(await cryptoAPI.exportKey('jwk',local.sign.publicKey))!==canonicalJwk(published.signing_public_jwk)||canonicalJwk(await cryptoAPI.exportKey('jwk',local.enc.publicKey))!==canonicalJwk(published.encryption_public_jwk))throw Error('Original identity mismatch.');
 const {requestFingerprint,signDeviceApproval,verifyDeviceApproval}=await import('./e2ee-device-approval.mjs');
 const {data:current,error:lookupError}=await supa.from('tichor_e2ee_devices').select('user_id,device_id,state,encryption_public_jwk,signing_public_jwk').eq('user_id',account).eq('device_id',request.device_id).maybeSingle();
 if(lookupError||!current||current.state!=='pending')throw Error('Request no longer pending.');
 if(await requestFingerprint(current)!==confirmedFingerprint||await requestFingerprint(request)!==confirmedFingerprint)throw Error('Fingerprint mismatch.');
 const {requireFreshLinkEvidence}=await import('./device-link-registry.mjs');
 const proof=await requireFreshLinkEvidence(supa,account,current.device_id);
 if(canonicalJwk(proof.request.encryptionKey)!==canonicalJwk(current.encryption_public_jwk)||canonicalJwk(proof.request.signingKey)!==canonicalJwk(current.signing_public_jwk)||Date.now()>=proof.request.expiresAt)throw Error('Fresh device proof does not match confirmed keys or has expired.');
 const proto=await import('./device-link-proof.mjs');
 // The immutable original account identity is the root signer, identified by account UUID.
 const approved=await proto.approveDeviceRequest(proof,account,account,local.sign.privateKey,await proto.requestFingerprint(proof));
 await proto.verifyDeviceApproval(approved,account,current.device_id,proof.request.nonce,account,published.signing_public_jwk);
 const eligibility=await proto.createEligibilityCertificate(approved,account,current.device_id,proof.request.nonce,published.signing_public_jwk,local.sign.privateKey);
 return {nonce:proof.request.nonce,signature:approved.signature,eligibility};
}

// Fresh nonce-bound evidence only; legacy previews cannot confer this status.
async function checkNoncePreview(supa,account,request,root){
 const {requireFreshLinkEvidence}=await import('./device-link-registry.mjs');
 const proto=await import('./device-link-proof.mjs');
 let proof;
 try{proof=await requireFreshLinkEvidence(supa,account,request.device_id);}catch{return 'missing';}
 if(canonicalJwk(proof.request.encryptionKey)!==canonicalJwk(request.encryption_public_jwk)||canonicalJwk(proof.request.signingKey)!==canonicalJwk(request.signing_public_jwk))return 'invalid';
 const {data,error}=await supa.from('tichor_e2ee_nonce_approvals').select('signature').eq('user_id',account).eq('nonce',proof.request.nonce).maybeSingle();
 if(error)throw error;
 if(!data)return 'missing';
 try{
  await proto.verifyDeviceApproval({approval:{domain:'TichorConnect V3 device-link approval v1',approver:account,request:proof.request,deviceProof:proof.proof},signature:data.signature},account,request.device_id,proof.request.nonce,account,root.signing_public_jwk);
 }catch{return 'invalid';}
 const {data:latest,error:latestError}=await supa.from('tichor_e2ee_devices').select('state').eq('user_id',account).eq('device_id',request.device_id).maybeSingle();
 if(latestError)throw latestError;
 return latest?.state==='pending'?'directory-verified-preview':'inactive';
}
export async function readEnrollmentPreview(supa,account,request){
 if(request.user_id!==account||request.state!=='pending')return 'inactive';
 const {data:session,error}=await supa.auth.getUser();
 if(error||session?.user?.id!==account)throw Error('Session mismatch.');
 return checkNoncePreview(supa,account,request,await fetchPublic(supa,account));
}
export async function saveEnrollmentPreview(supa,account,request,confirmedFingerprint){
 const {requestFingerprint}=await import('./e2ee-device-approval.mjs');
 if(await requestFingerprint(request)!==confirmedFingerprint)throw Error('Fingerprint mismatch.');
 const previous=await readEnrollmentPreview(supa,account,request);
 if(previous!=='missing'&&previous!=='directory-verified-preview')throw Error('Invalid or inactive preview; refresh or revoke the request.');
 const approved=await signEnrollmentPreview(supa,account,request,confirmedFingerprint);
 const {error}=await supa.from('tichor_e2ee_nonce_approvals').insert({user_id:account,nonce:approved.nonce,signature:approved.signature});
 if(error&&error.code!=='23505')throw error;
 const cert=approved.eligibility;
 const {error:certificateError}=await supa.from('tichor_e2ee_eligibility_certificates').insert({user_id:account,nonce:approved.nonce,issued_at_ms:cert.certificate.issuedAt,expires_at_ms:cert.certificate.expiresAt,signature:cert.signature});
 if(certificateError&&certificateError.code!=='23505')throw certificateError;
 // Publish only a newly persisted certificate; duplicate evidence requires a renewed request.
 if(!certificateError){
  const {error:directoryError}=await supa.from('tichor_e2ee_recipient_directory').insert({user_id:account,device_id:request.device_id,nonce:approved.nonce,certificate:cert.certificate,signature:cert.signature,expires_at_ms:cert.certificate.expiresAt});
  if(directoryError)throw Error('Certificate stored but discovery publication failed. Refresh registration and retry.');
 }
 const result=await readEnrollmentPreview(supa,account,request);
 if(result!=='directory-verified-preview')throw Error('Stored nonce-bound preview could not be verified. Refresh registration.');
 return result;
}

 // Local trust preview: the original browser's complete fingerprint must be
 // confirmed out of band. Directory-only verification never establishes trust.
export async function getConfirmedRootPreview(supa,account,typed){
 const {data,error}=await supa.auth.getUser();
 if(error||data?.user?.id!==account)throw Error('Session mismatch.');
 const root=await fetchPublic(supa,account);
 const fp=(await fingerprint(root)).replace(/\s/g,'');
 const storageKey='tichor-v3-confirmed-root-preview:'+account;
 const previous=localStorage.getItem(storageKey);
 if(previous&&previous!==fp)throw Error('Confirmed original identity changed.');
 if(typed!==undefined){
  if(typeof typed!=='string'||typed.toLowerCase().replace(/\s/g,'')!==fp)throw Error('Original device fingerprint mismatch.');
  localStorage.setItem(storageKey,fp);
 }
 return (previous===fp||typed!==undefined)?fp:null;
}

 // Verify the approval against the same root whose fingerprint was confirmed.
 // This is enrollment evidence only, never a message-delivery authorization.
export async function verifyConfirmedEnrollmentPreview(supa,account,request){
 if(request.user_id!==account||request.state!=='pending')return 'inactive';
 const {data:session,error:authError}=await supa.auth.getUser();
 if(authError||session?.user?.id!==account)throw Error('Session mismatch.');
 const pinned=localStorage.getItem('tichor-v3-confirmed-root-preview:'+account);
 if(!pinned)return 'root-unconfirmed';
 const root=await fetchPublic(supa,account);
 if((await fingerprint(root)).replace(/\s/g,'')!==pinned)throw Error('Confirmed original identity changed.');
 const result=await checkNoncePreview(supa,account,request,root);
 return result==='directory-verified-preview'?'confirmed-root-preview':result;
}

// Owner-only certificate verification preview. The root fingerprint must have
// been independently confirmed. No certificate authorizes message distribution.
export async function readEligibilityCertificatePreview(supa,account,device){
 const {data:session,error:authError}=await supa.auth.getUser();
 if(authError||session?.user?.id!==account)throw Error('Session mismatch.');
 const pinned=localStorage.getItem('tichor-v3-confirmed-root-preview:'+account);
 if(!pinned)return {state:'root-unconfirmed'};
 const root=await fetchPublic(supa,account);
 if((await fingerprint(root)).replace(/\s/g,'')!==pinned)throw Error('Confirmed original identity changed.');
 const {data:row,error:rowError}=await supa.from('tichor_e2ee_devices').select('user_id,device_id,state,encryption_public_jwk,signing_public_jwk').eq('user_id',account).eq('device_id',device).maybeSingle();
 if(rowError)throw rowError;
 if(row?.state!=='pending')return {state:'inactive'};
 const {data:evidence,error:evidenceError}=await supa.from('tichor_e2ee_link_evidence').select('nonce,issued_at_ms,expires_at_ms').eq('user_id',account).eq('device_id',device).order('issued_at_ms',{ascending:false}).limit(50);
 if(evidenceError)throw evidenceError;
 const proto=await import('./device-link-proof.mjs');
 for(const e of evidence||[]){
  const {data:cert,error}=await supa.from('tichor_e2ee_eligibility_certificates').select('issued_at_ms,expires_at_ms,signature').eq('user_id',account).eq('nonce',e.nonce).gt('expires_at_ms',Date.now()).maybeSingle();
  if(error)throw error;
  if(!cert)continue;
  const request={account,device,nonce:e.nonce,issuedAt:Number(e.issued_at_ms),expiresAt:Number(e.expires_at_ms),encryptionKey:row.encryption_public_jwk,signingKey:row.signing_public_jwk};
  const {data:latest,error:latestError}=await supa.from('tichor_e2ee_devices').select('user_id,device_id,state,encryption_public_jwk,signing_public_jwk').eq('user_id',account).eq('device_id',device).maybeSingle();
  if(latestError)throw latestError;
  if(latest?.state!=='pending')return {state:'inactive'};
  try{return await proto.verifyEligibilityCertificate({certificate:{domain:'TichorConnect V3 device eligibility preview v1',request,issuedAt:Number(cert.issued_at_ms),expiresAt:Number(cert.expires_at_ms)},signature:cert.signature},account,device,root.signing_public_jwk,latest);}catch{}
 }
 return {state:'missing-or-invalid'};
}

// Discovery is intentionally diagnostic. It cannot supply encryption targets.
// Independently confirmed contact root, live revocation and delivery authorization
// are separate requirements. Directory evidence alone never satisfies them.
// TSA discovery verification: a count is never evidence of device authorization.
// The root fingerprint MUST be independently compared with the recipient
// out-of-band; directory key substitution must fail closed. This does not
// establish current device state, so these keys must not be used for delivery.
export async function discoverRecipientCertificatePreviews(supa,sender,recipient,confirmedRootFingerprint){
 const {data:session,error:authError}=await supa.auth.getUser();
 if(authError||session?.user?.id!==sender||sender===recipient)throw Error('Invalid discovery session.');
 if(typeof confirmedRootFingerprint!=='string'||!/^[a-f0-9]{64}$/i.test(confirmedRootFingerprint.replace(/\s/g,'')))
  throw Error('Recipient root fingerprint must be independently confirmed before discovery.');
 const root=await fetchPublic(supa,recipient);
 const actual=(await fingerprint(root)).replace(/\s/g,'');
 if(actual!==confirmedRootFingerprint.toLowerCase().replace(/\s/g,''))
  throw Error('Recipient root identity mismatch. Discovery blocked.');
 const {data,error}=await supa.from('tichor_e2ee_recipient_directory')
  .select('user_id,device_id,nonce,certificate,signature,expires_at_ms')
  .eq('user_id',recipient).gt('expires_at_ms',Date.now()).limit(50);
 if(error)throw Error('Recipient certificate directory unavailable.');
 const proto=await import('./device-link-proof.mjs');
 const verified=new Set();
 for(const row of data||[]){
  const request=row.certificate?.request;
  if(row.user_id!==recipient||request?.account!==recipient||
     request?.device!==row.device_id||request?.nonce!==row.nonce||
     row.certificate?.expiresAt!==Number(row.expires_at_ms))continue;
  // Verify signatures, certificate lifetimes and key structure. The registry
  // projection below is NOT a live revocation check or delivery authorization.
  const projection={user_id:recipient,device_id:row.device_id,state:'pending',
    encryption_public_jwk:request.encryptionKey,signing_public_jwk:request.signingKey};
  try{
   await proto.verifyEligibilityCertificate({certificate:row.certificate,signature:row.signature},
      recipient,row.device_id,root.signing_public_jwk,projection);
   verified.add(row.device_id);
  }catch{}
 }
 return {state:'verified-certificate-preview-not-authorized',verifiedCertificateDevices:verified.size};
}
