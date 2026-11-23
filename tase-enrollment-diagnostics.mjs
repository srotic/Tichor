// Read-only Tichor V3 enrollment diagnostics.
// Never exports private keys, resets an identity, or approves a device.
const open=(name,store)=>new Promise((resolve,reject)=>{
 const request=indexedDB.open(name);
 request.onerror=()=>reject(request.error);
 request.onupgradeneeded=()=>{request.transaction.abort();reject(Error('Local key database does not exist'))};
 request.onsuccess=()=>{const db=request.result;
  if(!db.objectStoreNames.contains(store)){db.close();resolve(null);return}
  const tx=db.transaction(store,'readonly'),get=tx.objectStore(store).get.bind(tx.objectStore(store));
  const read=get(window.__tichorDiagnosticAccount);
  read.onsuccess=()=>{const value=read.result;db.close();resolve(value||null)};
  read.onerror=()=>{db.close();reject(read.error)};
 };
});
function readRecord(name,store,account){
 return new Promise((resolve,reject)=>{
  const request=indexedDB.open(name);
  request.onerror=()=>reject(request.error);
  request.onupgradeneeded=()=>{request.transaction.abort();resolve(null)};
  request.onsuccess=()=>{const db=request.result;
   if(!db.objectStoreNames.contains(store)){db.close();resolve(null);return}
   const tx=db.transaction(store,'readonly'),get=tx.objectStore(store).get(account);
   get.onsuccess=()=>resolve(get.result||null);
   get.onerror=()=>reject(get.error);
   tx.oncomplete=()=>db.close();
  };
 });
}
export async function diagnoseDeviceEnrollment(client,account){
 const {data:auth,error}=await client.auth.getUser();
 if(error||auth?.user?.id!==account)throw Error('Authenticated account required');
 if(!globalThis.indexedDB)throw Error('IndexedDB unavailable');
 const [identity,device]=await Promise.all([
  readRecord('tichor-v3-e2ee-identity','identities',account),
  readRecord('tichor-v3-pending-devices','devices',account)
 ]);
 const [registered,devices,grants]=await Promise.all([
  client.from('tichor_e2ee_identity_keys').select('user_id').eq('user_id',account).maybeSingle(),
  client.from('tichor_e2ee_devices').select('device_id,state').eq('user_id',account),
  client.from('tichor_e2ee_active_device_grants').select('device_id,expires_at_ms').eq('user_id',account)
 ]);
 if(registered.error||devices.error||grants.error)throw Error('Unable to read device registration state');
 return Object.freeze({
  originalIdentityPresentLocally:Boolean(identity?.enc?.privateKey&&identity?.sign?.privateKey),
  originalIdentityRegistered:Boolean(registered.data),
  localDeviceKeysPresent:Boolean(device?.enc?.privateKey&&device?.sign?.privateKey),
  localDeviceMatchesRegistry:Boolean(device?.id&&devices.data?.some(d=>d.device_id===device.id)),
  registeredDevices:devices.data?.length||0,
  pendingDevices:devices.data?.filter(d=>d.state==='pending').length||0,
  activeDevices:devices.data?.filter(d=>d.state==='active').length||0,
  unexpiredGrants:grants.data?.filter(g=>Number(g.expires_at_ms)>Date.now()).length||0
 });
}
