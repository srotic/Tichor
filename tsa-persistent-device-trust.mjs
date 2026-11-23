// Durable device trust is distinct from permission to use a live session.
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const coord=/^[A-Za-z0-9_-]{43}$/;
function id(x){if(typeof x!=='string'||!uuid.test(x))throw Error('Invalid identifier');return x}
function key(k){if(k?.kty!=='EC'||k.crv!=='P-256'||!coord.test(k.x)||!coord.test(k.y)||'d' in k)throw Error('Invalid public key');return {kty:'EC',crv:'P-256',x:k.x,y:k.y}}
export function persistentTrustBody({account,device,revision,encryptionKey,signingKey}){
 if(!Number.isSafeInteger(revision)||revision<1)throw Error('Invalid trust revision');
 return {domain:'Tichor TSA persistent device trust v1',account:id(account),device:id(device),revision,encryptionKey:key(encryptionKey),signingKey:key(signingKey)};
}
const bytes=b=>new TextEncoder().encode(JSON.stringify(b));
export async function signPersistentTrust(input,rootPrivateKey){
 const trust=persistentTrustBody(input);
 return {trust,signature:Array.from(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},rootPrivateKey,bytes(trust))))};
}
export async function verifyPersistentTrust(packet,rootPublicKey,expected){
 const trust=persistentTrustBody(packet.trust);
 if(JSON.stringify(trust)!==JSON.stringify(persistentTrustBody(expected)))throw Error('Trust binding mismatch');
 if(!Array.isArray(packet.signature)||packet.signature.length!==64||packet.signature.some(x=>!Number.isInteger(x)||x<0||x>255))throw Error('Invalid signature');
 const root=await crypto.subtle.importKey('jwk',key(rootPublicKey),{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
 if(!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},root,Uint8Array.from(packet.signature),bytes(trust)))throw Error('Invalid root signature');
 return trust;
}
