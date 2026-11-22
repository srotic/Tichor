// Pending device enrollment only. Never use these keys for message encryption.
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
  const {data,error}=await client.from(table).select('device_id,state,encryption_public_jwk,signing_public_jwk').eq('user_id',account).eq('device_id',record.id).maybeSingle();
  if(error)throw error;
  if(data){
   if(!same(data.encryption_public_jwk,encryption_public_jwk)||!same(data.signing_public_jwk,signing_public_jwk))throw Error('Registered device keys differ. Enrollment stopped.');
   return {id:record.id,state:data.state};
  }
  const result=await client.from(table).insert({user_id:account,device_id:record.id,encryption_public_jwk,signing_public_jwk});
  if(result.error)throw result.error;
  return {id:record.id,state:'pending'};
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
 const {data,error}=await client.from(table).update({state:'revoked'}).eq('user_id',account).eq('device_id',id).eq('state','pending').select('device_id');
 if(error)throw error;
 if(data?.length!==1)throw Error('Request is no longer pending.');
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
