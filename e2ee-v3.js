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
// Restore the existing root only; this does not authorize a messaging device.
// Staging bootstrap: publish the encrypted backup before the public root.
export async function prepareLoginIdentity(supa,userId,password){
  mustCrypto();
  const assertCurrent=async()=>{
    const {data,error}=await supa.auth.getUser();
    if(error||data?.user?.id!==userId||!data.user.email_confirmed_at)throw Error('Verified account required.');
    const current=await supa.rpc('tichor_session_is_current');
    if(current.error||current.data!==true)throw Error('Current login required.');
  };
  await assertCurrent();
  if(await dbGet(userId))return ensureIdentity(supa,userId);
  const {data:root,error}=await supa.from('tichor_e2ee_identity_keys').select('user_id').eq('user_id',userId).maybeSingle();
  if(error)throw error;
  if(root)return restoreLoginIdentity(supa,userId,password);
  const {readEncryptedIdentityBackup,storeEncryptedIdentityBackupOnce}=await import('./tase-backup-storage.mjs');
  if(await readEncryptedIdentityBackup(supa,userId))throw Error('Interrupted identity bootstrap; recovery required before creating another root.');
  const {createRecoverableIdentity}=await import('./tase-recoverable-identity.mjs');
  const created=await createRecoverableIdentity({userId,password});
  await assertCurrent();
  await storeEncryptedIdentityBackupOnce(supa,userId,created.backup);
  await assertCurrent();
  const published=await supa.from('tichor_e2ee_identity_keys').insert({user_id:userId,encryption_public_jwk:created.encryption_public_jwk,signing_public_jwk:created.signing_public_jwk});
  if(published.error)throw published.error;
  await assertCurrent();
  await dbPut(userId,created.keys);
  return ensureIdentity(supa,userId);
}
export async function restoreLoginIdentity(supa,userId,password){
  mustCrypto();
  const assertCurrent=async()=>{
    const {data,error}=await supa.auth.getUser();
    if(error||data?.user?.id!==userId)throw Error('Recovery account mismatch.');
    const current=await supa.rpc('tichor_session_is_current');
    if(current.error||current.data!==true)throw Error('Recovery requires the current login session.');
  };
  await assertCurrent();
  if(await dbGet(userId))return ensureIdentity(supa,userId);
  const root=await fetchPublic(supa,userId);
  const {readEncryptedIdentityBackup}=await import('./tase-backup-storage.mjs');
  const backup=await readEncryptedIdentityBackup(supa,userId);
  if(!backup)throw Error('No recoverable encryption identity backup exists.');
  const {restoreRecoverableIdentity}=await import('./tase-recoverable-identity.mjs');
  const keys=await restoreRecoverableIdentity({userId,password,backup,expectedPublicKeys:root});
  await assertCurrent();
  const latest=await fetchPublic(supa,userId);
  if(await fingerprint(root)!==await fingerprint(latest))throw Error('Identity changed during recovery.');
  await assertCurrent();
  await dbPut(userId,keys);
  return ensureIdentity(supa,userId);
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
 // TSA: persist only locally root-signed device trust evidence.
 // This is NOT a delivery authorization and cannot enable multi-device E2EE.
 const localRoot=await dbGet(account);
 const currentRoot=await fetchPublic(supa,account);
 if(!localRoot?.sign?.privateKey||localRoot.sign.privateKey.extractable||
    canonicalJwk(await cryptoAPI.exportKey('jwk',localRoot.sign.publicKey))!==canonicalJwk(currentRoot.signing_public_jwk))
  throw Error('Original root signer unavailable. Trust evidence was not persisted.');
 const {data:liveDevice,error:deviceError}=await supa.from('tichor_e2ee_devices')
  .select('user_id,device_id,state,encryption_public_jwk,signing_public_jwk')
  .eq('user_id',account).eq('device_id',request.device_id).maybeSingle();
 if(deviceError||liveDevice?.state!=='pending')throw Error('Device no longer eligible for trust evidence.');
 const trustModule=await import('./tsa-device-trust.mjs');
 const signedTrust=await trustModule.createDeviceTrustEvidence(cert,account,request.device_id,
    currentRoot.signing_public_jwk,localRoot.sign.privateKey,liveDevice);
 const grant=signedTrust.grant;
 const {error:trustError}=await supa.from('tichor_e2ee_device_trust_evidence').insert({
  user_id:account,device_id:request.device_id,nonce:approved.nonce,
  issued_at_ms:grant.issuedAt,expires_at_ms:grant.expiresAt,signature:signedTrust.signature
 });
 if(trustError&&trustError.code!=='23505')throw Error('Root-signed trust evidence could not be recorded.');
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
// Explicit user fingerprint comparison is required only when first pinning a contact.
// Subsequent discovery requires the previously confirmed, account-scoped pin.
export async function confirmRecipientRootForTSA(supa,sender,recipient,typedFingerprint){
 const {data:session,error:authError}=await supa.auth.getUser();
 if(authError||session?.user?.id!==sender||sender===recipient)throw Error('Invalid root confirmation session.');
 const root=await fetchPublic(supa,recipient);
 const actual=await fingerprint(root);
 const {confirmContactRootPin}=await import('./tsa-contact-root-pin.mjs');
 return confirmContactRootPin(localStorage,sender,recipient,typedFingerprint,actual);
}
export async function discoverRecipientCertificatePreviews(supa,sender,recipient,confirmedRootFingerprint){
 const {data:session,error:authError}=await supa.auth.getUser();
 if(authError||session?.user?.id!==sender||sender===recipient)throw Error('Invalid discovery session.');
 const root=await fetchPublic(supa,recipient);
 const actual=await fingerprint(root);
 const pins=await import('./tsa-contact-root-pin.mjs');
 if(confirmedRootFingerprint!==undefined){
  // A supplied fingerprint cannot be silently treated as confirmation.
  // Call confirmRecipientRootForTSA after an out-of-band identity comparison.
  if(pins.normalizeRootFingerprint(confirmedRootFingerprint)!==pins.normalizeRootFingerprint(actual))
   throw Error('Recipient root identity mismatch. Discovery blocked.');
 }
 pins.requireContactRootPin(localStorage,sender,recipient,actual);
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

// TSA V3: the ORIGINAL account identity browser alone signs activation.
// This state transition does not provide transport keys or enable delivery.
// The privileged Edge verifier independently checks every signature and nonce.
export async function registerPersistentDeviceTrust(supa,account,device){
 const local=await dbGet(account);
 const root=await fetchPublic(supa,account);
 if(!local?.sign?.privateKey||canonicalJwk(await cryptoAPI.exportKey('jwk',local.sign.publicKey))!==canonicalJwk(root.signing_public_jwk))throw Error('Root key required');
 const {data:d,error}=await supa.from('tichor_e2ee_devices').select('state,encryption_public_jwk,signing_public_jwk').eq('user_id',account).eq('device_id',device).maybeSingle();
 if(error||d?.state!=='active')throw Error('Active device required');
 const {signPersistentTrust}=await import('./tsa-persistent-device-trust.mjs');
 const packet=await signPersistentTrust({account,device,revision:1,encryptionKey:d.encryption_public_jwk,signingKey:d.signing_public_jwk},local.sign.privateKey);
 const root_signature=b64(packet.signature).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
 const result=await supa.functions.invoke('tsa-ciphertext-mailbox',{body:{action:'register-trust',account,device,nonce:crypto.randomUUID(),root_signature}});
 if(result.error||result.data?.state!=='persistent-trust-registered')throw Error('Persistent trust registration failed');
 return true;
}
export async function activateConfirmedDevice(supa,account,device){
 const {data:session,error:authError}=await supa.auth.getUser();
 if(authError||session?.user?.id!==account)throw Error('Account session changed; device activation blocked.');
 const confirmed=await getConfirmedRootPreview(supa,account);
 if(!confirmed)throw Error('Independently confirm the original account identity before device activation.');
 const local=await dbGet(account);
 const root=await fetchPublic(supa,account);
 if(!local?.sign?.privateKey||local.sign.privateKey.extractable||
   canonicalJwk(await cryptoAPI.exportKey('jwk',local.sign.publicKey))!==canonicalJwk(root.signing_public_jwk))
  throw Error('Only the original encryption browser can activate a device.');
 const {data:registry,error:registryError}=await supa.from('tichor_e2ee_devices')
  .select('user_id,device_id,state,encryption_public_jwk,signing_public_jwk')
  .eq('user_id',account).eq('device_id',device).maybeSingle();
 if(registryError||registry?.state!=='pending')throw Error('Device is not pending or was revoked.');
 const {data:grants,error:grantsError}=await supa.from('tichor_e2ee_device_trust_evidence')
  .select('nonce,issued_at_ms,expires_at_ms,signature')
  .eq('user_id',account).eq('device_id',device).gt('expires_at_ms',Date.now())
  .order('issued_at_ms',{ascending:false}).limit(20);
 if(grantsError||!grants?.length)throw Error('No current independently root-signed trust evidence for this device.');
 const proto=await import('./tsa-device-trust.mjs');
 const grantModule=await import('./tsa-active-device-grant.mjs');
 for(const evidence of grants){
  const {data:directory,error:directoryError}=await supa.from('tichor_e2ee_recipient_directory')
   .select('user_id,device_id,nonce,certificate,signature,expires_at_ms')
   .eq('user_id',account).eq('nonce',evidence.nonce).maybeSingle();
  if(directoryError)throw Error('Trusted device certificate lookup failed.');
  if(directory?.device_id!==device)continue;
  try{
   await proto.verifyDeviceTrustEvidence({
    grant:{domain:'TichorConnect V3 root device trust evidence v1',
     account,device,nonce:evidence.nonce,certificateSignature:directory.signature,
     issuedAt:Number(evidence.issued_at_ms),expiresAt:Number(evidence.expires_at_ms)},
    signature:evidence.signature
   },{certificate:directory.certificate,signature:directory.signature},
   account,device,root.signing_public_jwk,registry);
  }catch{continue}
  const now=Date.now();
  // Do not impose an additional one-hour cutoff on verified trust evidence.
  // Existing server protocol still caps signed grants at 24 hours.
  const expiresAt=Math.min(now+86400000,Number(evidence.expires_at_ms),Number(directory.expires_at_ms));
  if(expiresAt<=now+1000)continue;
  const approval=await grantModule.signActiveDeviceGrant({
   account,device,nonce:evidence.nonce,issuedAt:now,expiresAt,
   encryptionKey:registry.encryption_public_jwk,signingKey:registry.signing_public_jwk
  },local.sign.privateKey);
  const {data:check,error:checkError}=await supa.auth.getUser();
  if(checkError||check?.user?.id!==account)throw Error('Account changed before device activation.');
  const {data:result,error:edgeError}=await supa.functions.invoke('tsa-activate-device',{body:approval});
  if(edgeError||result?.state!=='active-device-evidence-not-delivery-authorized')
   throw Error('Server could not verify the original-device authorization. No activation performed.');
  const {data:latest,error:latestError}=await supa.from('tichor_e2ee_devices')
   .select('state').eq('user_id',account).eq('device_id',device).maybeSingle();
  if(latestError||latest?.state!=='active')throw Error('Device activation did not persist.');
  await registerPersistentDeviceTrust(supa,account,device);
  return {state:'active-not-delivery-authorized',device,expiresAt};
 }
 throw Error('No valid signed trust evidence; renew device enrollment before activation.');
}

// The original browser can sign a short-lived active-device roster without
// exporting its private root key. Linked browsers cannot impersonate the root.
export async function signRootDeviceRoster(supa,account,body){
 mustCrypto();
 const {data:auth,error:authError}=await supa.auth.getUser();
 if(authError||auth?.user?.id!==account)throw Error('Account session mismatch while signing device roster.');
 const stored=await dbGet(account);
 if(!stored||stored.sign?.privateKey?.extractable||stored.sign?.privateKey?.algorithm?.name!=='ECDSA')
  throw Error('Only the original encryption browser can sign a device roster.');
 const {data:identity,error}=await supa.from('tichor_e2ee_identity_keys')
  .select('user_id,signing_public_jwk').eq('user_id',account).maybeSingle();
 if(error||identity?.user_id!==account)throw Error('Original encryption identity unavailable.');
 if(canonicalJwk(await cryptoAPI.exportKey('jwk',stored.sign.publicKey))!==canonicalJwk(identity.signing_public_jwk))
  throw Error('Original encryption identity changed. Roster signing blocked.');
 const {signTsaRoster}=await import('./tsa-signed-roster.mjs');
 return signTsaRoster(body,stored.sign.privateKey);
}

/** Run only after the server confirms a user-authorized identity reset. */
export async function clearLocalIdentityAfterServerReset(userId){
 if(!userId)throw Error('Account required');
 const db=await dbOpen();
 try{await new Promise((resolve,reject)=>{
  const tx=db.transaction(KEY_STORE,'readwrite');
  tx.objectStore(KEY_STORE).delete(userId);
  tx.oncomplete=resolve;tx.onerror=()=>reject(tx.error);tx.onabort=()=>reject(tx.error);
 })}finally{db.close()}
 localStorage.removeItem('tichor-e2ee-pin:'+userId);
}
