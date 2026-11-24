// Media encryption primitive. Storage and messaging integration are separate.
const MAX=10*1024*1024;
const E=new TextEncoder();
const aad=id=>E.encode('Tichor encrypted attachment v1:'+id);
const valid=id=>typeof id==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(id);
export async function encryptAttachment(file){
 if(!(file instanceof Blob)||file.size<1||file.size>MAX)throw Error('Choose a file up to 10 MB');
 const id=crypto.randomUUID(),iv=crypto.getRandomValues(new Uint8Array(12));
 const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},true,['encrypt']);
 const ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:aad(id)},key,await file.arrayBuffer());
 const raw=await crypto.subtle.exportKey('raw',key);
 return {ciphertext:new Blob([ciphertext],{type:'application/octet-stream'}),descriptor:{v:1,id,key:Array.from(new Uint8Array(raw)),iv:Array.from(iv),size:file.size,name:String(file.name||'attachment').slice(0,255),mime:String(file.type||'application/octet-stream').slice(0,128)}};
}
export async function decryptAttachment(ciphertext,d){
 const bytes=(a,n)=>Array.isArray(a)&&a.length===n&&a.every(x=>Number.isInteger(x)&&x>=0&&x<=255);
 if(!d||d.v!==1||!valid(d.id)||!bytes(d.key,32)||!bytes(d.iv,12)||!Number.isInteger(d.size)||d.size<1||d.size>MAX||!(ciphertext instanceof Blob)||ciphertext.size!==d.size+16)throw Error('Invalid encrypted attachment');
 const key=await crypto.subtle.importKey('raw',new Uint8Array(d.key),{name:'AES-GCM'},false,['decrypt']);
 const clear=await crypto.subtle.decrypt({name:'AES-GCM',iv:new Uint8Array(d.iv),additionalData:aad(d.id)},key,await ciphertext.arrayBuffer());
 // Never render arbitrary active content directly.
 return new Blob([clear],{type:'application/octet-stream'});
}
