// Device enrollment and non-extractable local-key retrieval for staging TSA.\n// Pending keys are NOT usable for messaging; activation requires server-backed root grants.
const table='tichor_e2ee_devices';
const dbName='tichor-v3-pending-devices';
function openDB(){return new Promise((resolve,reject)=>{const r=indexedDB.open(dbName,1);r.onupgradeneeded=()=>r.result.createObjectStore('devices');r.onsuccess=()=>resolve(r.result);r.onerror=()=>reject(r.error);r.onblocked=()=>reject(Error('Close other Tichor tabs and retry.'));});}
async function local(account,record){
 const db=await openDB();
 try{return await new Promise((resolve,reject)=>{const t=db.transaction('devices',record?'readwrite':'readonly');const store=t.objectStore('devices');const r=record?store.add(record,account):store.get(account);t.oncomplete=()=>resolve(record||r.result);t.onerror=()=>reject(t.error);t.onabort=()=>reject(t.error);});}finally{db.close();}
}
function publicOnly(k){return {kty:k.kty,crv:k.crv,x:k.x,y:k.y};}
function same(a,b){return ['kty','crv','x','y'].every(k=>a?.[k]===b?.[k]);}
async function checkAccount(client,account){const {data,error}=await client.auth.getUser();if(error||data?.user?.id!==account)throw Error('Sign in again before managing devices.');}
export async function requestDevice(client,account){
 if(!globalThis.isSecureContext||!crypto.subtle||!navigator.locks?.request||!globalThis.indexedDB)throw Error('Secure browser storage and cross-tab locking are required.');
 return navigator.locks.request('tichor-v3-pending-device:'+account,async()=>{
  await checkAccount(client,account);
  let record=await local(account);
  if(!record){
   record={id:crypto.randomUUID(),enc:await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits']),sign:await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify'])};
   await local(account,record);
  }
  const encryption_public_jwk=publicOnly(await crypto.subtle.exportKey('jwk',record.enc.publicKey));
  const signing_public_jwk=publicOnly(await crypto.subtle.exportKey('jwk',record.sign.publicKey));
  await checkAccount(client,account);
  const {createDeviceRequest}=await import('./device-link-proof.mjs');
  const {registerPendingDevice}=await import('./device-link-registry.mjs');
  const now=Date.now();
  const packet=await createDeviceRequest({account,device:record.id,nonce:crypto.randomUUID(),issuedAt:now,expiresAt:now+300000,encryptionKey:encryption_public_jwk,signingKey:signing_public_jwk},record.sign.privateKey,now);
  await checkAccount(client,account);
  const registered=await registerPendingDevice(client,packet,account);
  return {id:registered.device_id,state:registered.state};
 });
}
export async function listDeviceRequests(client,account){
 await checkAccount(client,account);
 const {data,error}=await client.from(table).select('user_id,device_id,state,created_at,encryption_public_jwk,signing_public_jwk').eq('user_id',account).order('created_at',{ascending:false});
 if(error)throw error;
 return data||[];
}
export async function revokeDeviceRequest(client,account,id){
 await checkAccount(client,account);
 const {data,error}=await client.from(table).update({state:'revoked'}).eq('user_id',account).eq('device_id',id).in('state',['pending','active']).select('device_id');
 if(error)throw error;
 if(data?.length!==1)throw Error('Device is already revoked or not registered.');
 // Database revocation triggers synchronous withdrawal of any published
 // candidate certificate. Fail closed if the withdrawal cannot be confirmed.
 const {data:published,error:directoryError}=await client.from('tichor_e2ee_recipient_directory')
  .select('nonce').eq('user_id',account).eq('device_id',id).limit(1);
 if(directoryError||published?.length)throw Error('Revocation could not be confirmed in the recipient directory. Stop secure device operations.');

}

 // Read from local non-extractable key pairs, never from a directory row.
export async function localDeviceFingerprint(client,account){
 await checkAccount(client,account);
 const record=await local(account);
 if(!record)return null;
 if(record.enc.privateKey.extractable||record.sign.privateKey.extractable)throw Error('Unsafe local device identity.');
 const {requestFingerprint}=await import('./e2ee-device-approval.mjs');
 const request={user_id:account,device_id:record.id,encryption_public_jwk:publicOnly(await crypto.subtle.exportKey('jwk',record.enc.publicKey)),signing_public_jwk:publicOnly(await crypto.subtle.exportKey('jwk',record.sign.publicKey))};
 return {id:record.id,fingerprint:await requestFingerprint(request)};
}

// Prove that the browser actually possesses the non-extractable signing key.
// This is a LOCAL cryptographic self-check, not an approval or server grant.
export async function proveLocalDeviceKeyPossession(privateKey,publicJwk){
 if(!globalThis.crypto?.subtle||!privateKey||privateKey.extractable||
    privateKey.algorithm?.name!=='ECDSA'||privateKey.algorithm?.namedCurve!=='P-256')
  throw Error('A valid non-extractable local signing key is required.');
 if(publicJwk?.kty!=='EC'||publicJwk?.crv!=='P-256'||publicJwk?.d!==undefined||
    typeof publicJwk.x!=='string'||typeof publicJwk.y!=='string')
  throw Error('Invalid local signing public key.');
 const challenge=crypto.getRandomValues(new Uint8Array(32));
 const verifier=await crypto.subtle.importKey('jwk',publicJwk,{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
 const signature=await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},privateKey,challenge);
 if(!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},verifier,signature,challenge))
  throw Error('Local device signing-key possession check failed.');
 return true;
}

// Fail closed on revoked/pending devices and expired server grants.
export function assertCurrentDeviceAuthorization(registered,grant,account,device,now=Date.now()){
 if(registered?.user_id!==account||registered?.device_id!==device||registered?.state!=='active')
  throw Error('Local TSA device is not active or has been revoked.');
 if(grant?.user_id!==account||grant?.device_id!==device||
    !Number.isSafeInteger(Number(grant?.expires_at_ms))||
    Number(grant.expires_at_ms)<=now)
  throw Error('Local TSA device authorization is missing or expired.');
 return true;
}

// Load only the browser's existing non-extractable keys for a CURRENTLY active
// and root-approved device. Pending-device keys never authorize mailbox access.
// No key material is copied to Supabase or exported from IndexedDB.
export async function loadApprovedLocalDevice(client,account){
 await checkAccount(client,account);
 if(!globalThis.isSecureContext||!crypto.subtle||!globalThis.indexedDB)
  throw Error('Secure browser cryptography is required for the device mailbox.');
 const record=await local(account);
 if(!record||!record.enc?.privateKey||!record.sign?.privateKey)
  throw Error('This browser has no local registered device keys.');
 if(record.enc.privateKey.extractable||record.sign.privateKey.extractable||
    record.enc.privateKey.algorithm?.name!=='ECDH'||record.sign.privateKey.algorithm?.name!=='ECDSA')
  throw Error('Unsafe local TSA device keys.');
 const {data:registered,error:registryError}=await client.from(table)
  .select('user_id,device_id,state,encryption_public_jwk,signing_public_jwk')
  .eq('user_id',account).eq('device_id',record.id).maybeSingle();
 if(registryError||registered?.state!=='active'||registered.user_id!==account)
  throw Error('Local TSA device is not active or has been revoked.');
 const publishedEncryption=publicOnly(await crypto.subtle.exportKey('jwk',record.enc.publicKey));
 const publishedSigning=publicOnly(await crypto.subtle.exportKey('jwk',record.sign.publicKey));
 if(!same(publishedEncryption,registered.encryption_public_jwk)||!same(publishedSigning,registered.signing_public_jwk))
  throw Error('Local TSA device keys do not match the immutable registry.');
 await proveLocalDeviceKeyPossession(record.sign.privateKey,publishedSigning);
 const {data:grant,error:grantError}=await client.from('tichor_e2ee_active_device_grants')
  .select('user_id,device_id,expires_at_ms').eq('user_id',account)
  .eq('device_id',record.id).maybeSingle();
 if(grantError)throw Error('Local TSA device authorization is unavailable.');
 assertCurrentDeviceAuthorization(registered,grant,account,record.id);
 await checkAccount(client,account);
 return Object.freeze({account,deviceId:record.id,signingKey:record.sign.privateKey,
  decryptionKey:record.enc.privateKey,signingPublicKey:publishedSigning,encryptionPublicKey:publishedEncryption});
}

/** Delete only this account's obsolete local device after confirmed server reset. */
export async function clearLocalDeviceAfterServerReset(account){
 if(!account)throw Error('Account required');
 const db=await openDB();
 try{await new Promise((resolve,reject)=>{
  const tx=db.transaction('devices','readwrite');
  tx.objectStore('devices').delete(account);
  tx.oncomplete=resolve;tx.onerror=()=>reject(tx.error);tx.onabort=()=>reject(tx.error);
 })}finally{db.close()}
}
