// Tichor V3 encrypted binary attachment envelope (client side only).
// Upload ONLY the returned ciphertext. Share the raw AES key solely through
// an independently authenticated per-device E2EE key wrapping channel.
const enc=new TextEncoder();
const MAX_BYTES=100*1024*1024;
function bytes(v){return v instanceof Uint8Array?v:new Uint8Array(v);}
export async function encryptAttachment(plain,{mime='application/octet-stream',name='attachment'}={}){
 const data=bytes(plain);
 if(!data.byteLength||data.byteLength>MAX_BYTES)throw Error('Invalid attachment size');
 if(typeof mime!=='string'||mime.length>128||typeof name!=='string'||name.length>255)
  throw Error('Invalid attachment metadata');
 const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},true,['encrypt','decrypt']);
 const iv=crypto.getRandomValues(new Uint8Array(12));
 const metadata=JSON.stringify({v:1,mime,name,size:data.byteLength});
 const aad=enc.encode('TICHOR-ATTACHMENT-V1:'+metadata);
 const ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:aad,tagLength:128},key,data);
 const rawKey=await crypto.subtle.exportKey('raw',key);
 return {ciphertext:new Uint8Array(ciphertext),key:new Uint8Array(rawKey),iv,metadata};
}
export async function decryptAttachment(envelope){
 const {ciphertext,key,iv,metadata}=envelope||{};
 if(!(key instanceof Uint8Array)||key.byteLength!==32||
    !(iv instanceof Uint8Array)||iv.byteLength!==12||
    typeof metadata!=='string')throw Error('Invalid encrypted attachment');
 const meta=JSON.parse(metadata);
 if(meta?.v!==1||!Number.isSafeInteger(meta.size)||meta.size<1||meta.size>MAX_BYTES||
    typeof meta.name!=='string'||meta.name.length>255||
    typeof meta.mime!=='string'||meta.mime.length>128)throw Error('Invalid attachment metadata');
 const imported=await crypto.subtle.importKey('raw',key,{name:'AES-GCM'},false,['decrypt']);
 const plaintext=await crypto.subtle.decrypt({name:'AES-GCM',iv,additionalData:enc.encode('TICHOR-ATTACHMENT-V1:'+metadata),tagLength:128},imported,bytes(ciphertext));
 if(plaintext.byteLength!==meta.size)throw Error('Attachment size mismatch');
 return {data:new Uint8Array(plaintext),mime:meta.mime,name:meta.name};
}
