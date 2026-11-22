// TSA replay protection for the experimental per-device ciphertext envelope.
// Browser-local durable, atomic receipt claims. NOT a substitute for a
// Double Ratchet, delivery authorization, or end-to-end protocol review.
import {decryptDeviceCopy} from './tsa-multidevice-envelope.mjs';

const ID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const DB='tichor-v3-tsa-replay-receipts';
const STORE='message-receipts';
function id(value){
 if(typeof value!=='string'||!ID.test(value))throw Error('Invalid TSA receipt identity');
 return value;
}
function receiptKey(packet,account,device){
 if(!packet||packet.v!==1||packet.protocol!=='TSA-experimental-multi-device-text')
  throw Error('Unsupported TSA ciphertext receipt');
 if(account!==packet.from&&account!==packet.to)throw Error('Not a participant in this message');
 return [id(account),id(device),id(packet.from),id(packet.to),id(packet.messageId)].join(':');
}
export function createIndexedDbTsaReplayStore(storage=globalThis.indexedDB){
 if(!storage)throw Error('Persistent replay protection unavailable; decryption blocked');
 function connect(){
  return new Promise((resolve,reject)=>{
   const request=storage.open(DB,1);
   request.onupgradeneeded=()=>{
    if(!request.result.objectStoreNames.contains(STORE))request.result.createObjectStore(STORE);
   };
   request.onsuccess=()=>resolve(request.result);
   request.onerror=()=>reject(request.error||Error('TSA replay store inaccessible'));
   request.onblocked=()=>reject(Error('Close other tabs to upgrade TSA replay storage'));
  });
 }
 return {
  async claim(key){
   const db=await connect();
   try{
    return await new Promise((resolve,reject)=>{
     const transaction=db.transaction(STORE,'readwrite');
     let duplicate=false;
     const entry=transaction.objectStore(STORE).add(Date.now(),key);
     entry.onerror=()=>{
      if(entry.error?.name==='ConstraintError'){
       duplicate=true;
       // Prevent constraint error from aborting the read-write transaction.
       // Do NOT suppress unrelated storage errors.
       return;
      }
     };
     transaction.oncomplete=()=>resolve(!duplicate);
     transaction.onerror=()=>reject(transaction.error||Error('TSA replay receipt write failed'));
     transaction.onabort=()=>{
      if(transaction.error?.name==='ConstraintError')resolve(false);
      else reject(transaction.error||Error('TSA replay receipt transaction aborted'));
     };
    });
   }finally{db.close()}
  }
 };
}
// Authentication/decryption occurs before marking a receipt; failed signatures
// never consume an ID. Once claimed, repeated authenticated packets fail closed.
// Calls to this function must preserve the plaintext UI cache if reloading
// already-decrypted historical messages is needed.
export async function decryptDeviceCopyOnce(args,replayStore=createIndexedDbTsaReplayStore()){
 const {packet,recipientAccount,deviceId}=args||{};
 const key=receiptKey(packet,recipientAccount,deviceId);
 if(!replayStore||typeof replayStore.claim!=='function')
  throw Error('Durable atomic TSA replay receipt storage required');
 const plaintext=await decryptDeviceCopy(args);
 if(await replayStore.claim(key)!==true)throw Error('Duplicate TSA message or replay receipt unavailable');
 return plaintext;
}
