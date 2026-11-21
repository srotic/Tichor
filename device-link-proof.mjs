// Experimental device-link proof primitives. Not a messaging protocol or trust store.
// Caller MUST obtain the approver key from an independently trusted identity, compare
// the request fingerprint out of band, and enforce expiry, revocation and one-time use.
// Never use pending registry keys for message delivery.
const enc=new TextEncoder();
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const coord=/^[A-Za-z0-9_-]{43}$/;
function id(v){if(typeof v!=='string'||!uuid.test(v))throw Error('Invalid identifier');return v}
function key(j){if(!j||j.kty!=='EC'||j.crv!=='P-256'||!coord.test(j.x)||!coord.test(j.y)||typeof j.x!=='string'||typeof j.y!=='string'||'d' in j)throw Error('Invalid public key');return {kty:'EC',crv:'P-256',x:j.x,y:j.y}}
function b64(b){return btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')}
function bytes(s){if(typeof s!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(s))throw Error('Invalid signature');return Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'=='),c=>c.charCodeAt(0))}
function canonical(r){
 if(!r||!Number.isSafeInteger(r.issuedAt)||!Number.isSafeInteger(r.expiresAt)||r.expiresAt<=r.issuedAt||r.expiresAt-r.issuedAt>300000)throw Error('Invalid approval lifetime');
 return {domain:'TichorConnect V3 device-link request v1',account:id(r.account),device:id(r.device),nonce:id(r.nonce),issuedAt:r.issuedAt,expiresAt:r.expiresAt,encryptionKey:key(r.encryptionKey),signingKey:key(r.signingKey)};
}
function fresh(r,now){if(!Number.isSafeInteger(now)||now<r.issuedAt||now>=r.expiresAt)throw Error('Device request expired or not yet valid')}
async function importSign(j){return crypto.subtle.importKey('jwk',key(j),{name:'ECDSA',namedCurve:'P-256'},false,['verify'])}
async function validatePoints(r){await crypto.subtle.importKey('jwk',r.encryptionKey,{name:'ECDH',namedCurve:'P-256'},false,[]);await importSign(r.signingKey)}
async function sign(k,v){return b64(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},k,enc.encode(JSON.stringify(v))))}
async function verify(k,v,s){return crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},k,bytes(s),enc.encode(JSON.stringify(v)))}
export async function createDeviceRequest(request,devicePrivateKey,now=Date.now()){
 const r=canonical(request);fresh(r,now);await validatePoints(r);
 const proof=await sign(devicePrivateKey,r);
 if(!await verify(await importSign(r.signingKey),r,proof))throw Error('Device signing key mismatch');
 return {request:r,proof};
}
export async function requestFingerprint(packet){
 const r=canonical(packet.request);
 const hash=await crypto.subtle.digest('SHA-256',enc.encode(JSON.stringify(r)));
 return Array.from(new Uint8Array(hash),b=>b.toString(16).padStart(2,'0')).join('');
}
export async function verifyDeviceRequest(packet,account,now=Date.now()){
 const r=canonical(packet.request);fresh(r,now);if(r.account!==id(account))throw Error('Wrong account');
 await validatePoints(r);
 if(!await verify(await importSign(r.signingKey),r,packet.proof))throw Error('Invalid device proof');
 return r;
}
export async function approveDeviceRequest(packet,account,approver,privateKey,confirmedFingerprint,now=Date.now()){
 const r=await verifyDeviceRequest(packet,account,now);
 if(await requestFingerprint(packet)!==confirmedFingerprint)throw Error('Fingerprint not verified');
 const approval={domain:'TichorConnect V3 device-link approval v1',approver:id(approver),request:r,deviceProof:packet.proof};
 if(approval.approver===r.device)throw Error('Self approval prohibited');
 return {approval,signature:await sign(privateKey,approval)};
}
export async function verifyDeviceApproval(packet,account,expectedDevice,expectedNonce,trustedApprover,authoritativePublicKey,now=Date.now()){
 const a=packet.approval;
 if(!a||a.domain!=='TichorConnect V3 device-link approval v1'||a.approver!==id(trustedApprover))throw Error('Unexpected approver');
 const r=await verifyDeviceRequest({request:a.request,proof:a.deviceProof},account,now);
 if(r.device!==id(expectedDevice)||r.nonce!==id(expectedNonce)||r.device===a.approver)throw Error('Unexpected device or request');
 const canonicalApproval={domain:a.domain,approver:a.approver,request:r,deviceProof:a.deviceProof};
 if(!await verify(await importSign(authoritativePublicKey),canonicalApproval,packet.signature))throw Error('Invalid approval signature');
 // Proof only: not an authorization decision. Nonce consumption and revocation
 // must be enforced transactionally by the future trusted-device lifecycle.
 return r;
}
