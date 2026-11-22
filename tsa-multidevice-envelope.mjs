// TSA multi-device ciphertext envelope v1 — experimental staging primitive.
// This is NOT a Signal Double Ratchet, a delivery protocol, or authorization.
// Callers MUST independently verify recipient roots, signed device trust,
// current server-side revocation and complete recipient membership.
const encoder=new TextEncoder(),decoder=new TextDecoder();
const ID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const MAX_BYTES=1100,MAX_DEVICES=16;
function requireId(x){if(typeof x!=='string'||!ID.test(x))throw Error('Invalid TSA identifier');return x;}
function key(j){if(!j||j.kty!=='EC'||j.crv!=='P-256'||typeof j.x!=='string'||typeof j.y!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(j.x)||!/^[A-Za-z0-9_-]{43}$/.test(j.y)||'d' in j)throw Error('Invalid TSA public key');return {kty:'EC',crv:'P-256',x:j.x,y:j.y};}
const same=(a,b)=>JSON.stringify(key(a))===JSON.stringify(key(b));
const b64=v=>btoa(String.fromCharCode(...new Uint8Array(v))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
function unb64(s,max){if(typeof s!=='string'||!new RegExp('^[A-Za-z0-9_-]{1,'+max+'}$').test(s))throw Error('Malformed ciphertext encoding');return Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'='.repeat((4-s.length%4)%4)),c=>c.charCodeAt(0));}
function normalizedTarget(t){
 if(!t||!t.authorized||t.revoked===true)throw Error('Device authorization is missing or revoked');
 return {account:requireId(t.account),device:requireId(t.device),encryptionKey:key(t.encryptionKey)};
}
function aad(message,target){return encoder.encode(JSON.stringify(['Tichor TSA multi-device staging v1',message.from,message.to,message.messageId,target.account,target.device]));}
async function encFor(text,message,target){
 const eph=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
 const recipient=await crypto.subtle.importKey('jwk',target.encryptionKey,{name:'ECDH',namedCurve:'P-256'},false,[]);
 const bits=await crypto.subtle.deriveBits({name:'ECDH',public:recipient},eph.privateKey,256);
 const ikm=await crypto.subtle.importKey('raw',bits,'HKDF',false,['deriveKey']);
 const salt=crypto.getRandomValues(new Uint8Array(16)),iv=crypto.getRandomValues(new Uint8Array(12));
 const keyDerived=await crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt,info:encoder.encode('Tichor TSA multi-device staging key v1')},ikm,{name:'AES-GCM',length:256},false,['encrypt']);
 const ct=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:aad(message,target)},keyDerived,encoder.encode(text));
 return {account:target.account,device:target.device,epk:key(await crypto.subtle.exportKey('jwk',eph.publicKey)),salt:b64(salt),iv:b64(iv),ct:b64(ct)};
}
function checkedMessage(header){
 if(!header||header.v!==1||header.protocol!=='TSA-experimental-multi-device-text'||!Number.isSafeInteger(header.createdAt)||header.createdAt<=0)throw Error('Invalid TSA message header');
 return {v:1,protocol:header.protocol,from:requireId(header.from),to:requireId(header.to),messageId:requireId(header.messageId),createdAt:header.createdAt};
}
export async function encryptDeviceCopies({sender,recipient,messageId,text,targets,signingKey,createdAt=Date.now()}){
 if(typeof text!=='string'||!text||encoder.encode(text).byteLength>MAX_BYTES)throw Error('TSA plaintext exceeds safety limit');
 if(!Array.isArray(targets)||targets.length<2||targets.length>MAX_DEVICES)throw Error('Expected multiple authorized devices');
 const header=checkedMessage({v:1,protocol:'TSA-experimental-multi-device-text',from:sender,to:recipient,messageId,createdAt});
 if(!signingKey||signingKey.type!=='private'||signingKey.algorithm?.name!=='ECDSA')throw Error('Missing TSA sender signing key');
 const seen=new Set(),normalized=targets.map(t=>{
  const target=normalizedTarget(t);
  if(target.account!==recipient&&target.account!==sender)throw Error('Unexpected destination account');
  const label=target.account+':'+target.device;
  if(seen.has(label))throw Error('Duplicate device ciphertext target');
  seen.add(label);return target;
 });
 if(!normalized.some(t=>t.account===recipient)||!normalized.some(t=>t.account===sender))
  throw Error('Sender archive and recipient device required');
 const copies=[];
 for(const target of normalized)copies.push(await encFor(text,header,target));
 const signed={...header,copies};
 const signature=b64(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},signingKey,encoder.encode(JSON.stringify(signed))));
 return {...signed,signature};
}
export async function decryptDeviceCopy({packet,recipientAccount,deviceId,privateKey,senderPublicKey}){
 const header=checkedMessage(packet);
 const a=requireId(recipientAccount),d=requireId(deviceId);
 if(a!==header.from&&a!==header.to)throw Error('Not a TSA conversation participant');
 if(!privateKey||privateKey.type!=='private'||privateKey.algorithm?.name!=='ECDH')throw Error('Missing local device private key');
 const copies=packet.copies;
 if(!Array.isArray(copies)||copies.length<2||copies.length>MAX_DEVICES)throw Error('Invalid TSA recipient list');
 const seen=new Set();
 for(const row of copies){
  if(!row||!ID.test(row.account)||!ID.test(row.device)||![header.from,header.to].includes(row.account))throw Error('Invalid TSA recipient');
  const label=row.account+':'+row.device;if(seen.has(label))throw Error('Duplicate TSA recipient');seen.add(label);
 }
 const verify=await crypto.subtle.importKey('jwk',key(senderPublicKey),{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
 const {signature,...signed}=packet;
 if(!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},verify,unb64(signature,88),encoder.encode(JSON.stringify(signed))))
  throw Error('TSA sender signature invalid');
 const slot=copies.find(v=>v.account===a&&v.device===d);
 if(!slot)throw Error('No ciphertext for this device');
 if(unb64(slot.salt,24).byteLength!==16||unb64(slot.iv,16).byteLength!==12)throw Error('Invalid TSA nonce');
 const eph=await crypto.subtle.importKey('jwk',key(slot.epk),{name:'ECDH',namedCurve:'P-256'},false,[]);
 const bits=await crypto.subtle.deriveBits({name:'ECDH',public:eph},privateKey,256);
 const material=await crypto.subtle.importKey('raw',bits,'HKDF',false,['deriveKey']);
 const derived=await crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt:unb64(slot.salt,24),info:encoder.encode('Tichor TSA multi-device staging key v1')},material,{name:'AES-GCM',length:256},false,['decrypt']);
 const text=await crypto.subtle.decrypt({name:'AES-GCM',iv:unb64(slot.iv,16),additionalData:aad(header,slot)},derived,unb64(slot.ct,3000));
 return decoder.decode(text);
}
