// Tichor attachment key distribution: only call with independently VERIFIED
// active-device roster entries. Never use unverified directory keys.
const E=new TextEncoder();
const B=(a)=>new Uint8Array(a);
const base64=(v)=>{let s='';for(const b of v)s+=String.fromCharCode(b);return btoa(s)};
const unbase64=(s)=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
function validateDevice(d){
 if(typeof d?.device!=='string'||!d.device||d.state!=='active'||d.encryptionKey?.kty!=='EC'||d.encryptionKey?.crv!=='P-256'||!d.encryptionKey.x||!d.encryptionKey.y||d.encryptionKey.d!==undefined)throw Error('Unverified or invalid device entry');
}
function context(account,device,attachmentId){return E.encode(JSON.stringify(['TICHOR-ATTACHMENT-KEY-V1',account,device,attachmentId]))}
export async function wrapAttachmentKey(rawKey,{account,attachmentId,verifiedDevices}){
 if(!(rawKey instanceof Uint8Array)||rawKey.length!==32||typeof account!=='string'||!account||typeof attachmentId!=='string'||!attachmentId||!Array.isArray(verifiedDevices)||!verifiedDevices.length)throw Error('Invalid attachment key recipients');
 const unique=new Set(),slots=[];
 for(const d of verifiedDevices){
  validateDevice(d);
  if(unique.has(d.device))throw Error('Duplicate device in verified roster');
  unique.add(d.device);
  const peer=await crypto.subtle.importKey('jwk',d.encryptionKey,{name:'ECDH',namedCurve:'P-256'},false,[]);
  const ephemeral=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},true,['deriveBits']);
  const secret=await crypto.subtle.deriveBits({name:'ECDH',public:peer},ephemeral.privateKey,256);
  const hkdf=await crypto.subtle.importKey('raw',secret,'HKDF',false,['deriveKey']);
  const salt=crypto.getRandomValues(new Uint8Array(32)),iv=crypto.getRandomValues(new Uint8Array(12));
  const info=context(account,d.device,attachmentId);
  const aes=await crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt,info},hkdf,{name:'AES-GCM',length:256},false,['encrypt']);
  const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:info},aes,rawKey);
  slots.push({device:d.device,ephemeral:await crypto.subtle.exportKey('jwk',ephemeral.publicKey),salt:base64(salt),iv:base64(iv),ciphertext:base64(B(ct))});
 }
 return {v:1,account,attachmentId,slots};
}
export async function unwrapAttachmentKey(envelope,{account,device,privateKey}){
 if(envelope?.v!==1||envelope.account!==account||typeof envelope.attachmentId!=='string'||!privateKey||privateKey.extractable||privateKey.algorithm?.name!=='ECDH'||privateKey.algorithm?.namedCurve!=='P-256')throw Error('Invalid device attachment envelope');
 const matches=envelope.slots?.filter(x=>x.device===device);
 if(matches?.length!==1)throw Error('No unique device key envelope');
 const slot=matches[0];
 const peer=await crypto.subtle.importKey('jwk',slot.ephemeral,{name:'ECDH',namedCurve:'P-256'},false,[]);
 const secret=await crypto.subtle.deriveBits({name:'ECDH',public:peer},privateKey,256);
 const hkdf=await crypto.subtle.importKey('raw',secret,'HKDF',false,['deriveKey']);
 const info=context(account,device,envelope.attachmentId);
 const aes=await crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt:unbase64(slot.salt),info},hkdf,{name:'AES-GCM',length:256},false,['decrypt']);
 const raw=B(await crypto.subtle.decrypt({name:'AES-GCM',iv:unbase64(slot.iv),additionalData:info},aes,unbase64(slot.ciphertext)));
 if(raw.length!==32)throw Error('Invalid decrypted attachment key');
 return raw;
}
