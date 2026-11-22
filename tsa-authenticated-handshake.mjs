// TSA experimental authenticated ephemeral session handshake.
// Strictly staging-only. This is not X3DH/PQXDH, a ratchet, or device authorization.
const E=new TextEncoder();
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const COORD=/^[A-Za-z0-9_-]{43}$/;
const TTL=120000;
function id(s){if(typeof s!=='string'||!UUID.test(s))throw Error('Invalid TSA session identity');return s}
function jwk(k){if(!k||k.kty!=='EC'||k.crv!=='P-256'||!COORD.test(k.x)||!COORD.test(k.y)||'d' in k)throw Error('Invalid TSA public key');return {kty:'EC',crv:'P-256',x:k.x,y:k.y}}
function b64(arr){return btoa(String.fromCharCode(...new Uint8Array(arr))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'')}
function raw(s){if(typeof s!=='string'||!/^[-_A-Za-z0-9]{86}$/.test(s))throw Error('Invalid TSA signature encoding');return Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'=='),c=>c.charCodeAt(0))}
function transcript(p){if(!p||p.domain!=='TSA authenticated ephemeral handshake v1'||!Number.isSafeInteger(p.issuedAt)||!Number.isSafeInteger(p.expiresAt)||p.expiresAt-p.issuedAt!==TTL)throw Error('Invalid TSA session transcript');return {domain:p.domain,initiatorAccount:id(p.initiatorAccount),initiatorDevice:id(p.initiatorDevice),responderAccount:id(p.responderAccount),responderDevice:id(p.responderDevice),nonce:id(p.nonce),issuedAt:p.issuedAt,expiresAt:p.expiresAt,initiatorEphemeral:jwk(p.initiatorEphemeral)}}
async function verify(p,s,publicKey){const imported=await crypto.subtle.importKey('jwk',jwk(publicKey),{name:'ECDSA',namedCurve:'P-256'},false,['verify']);return crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},imported,raw(s),E.encode(JSON.stringify(p)))}
async function sign(privateKey,p){if(privateKey?.type!=='private'||privateKey.algorithm?.name!=='ECDSA')throw Error('Missing local signing key');return b64(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},privateKey,E.encode(JSON.stringify(p))))}
function fresh(issuedAt,expiresAt,now){if(!Number.isSafeInteger(now)||now<issuedAt||now>=expiresAt)throw Error('TSA handshake expired or not yet valid')}
export async function initiateTsaHandshake({initiatorAccount,initiatorDevice,responderAccount,responderDevice,signingKey,now=Date.now()}){
 const privateEphemeral=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
 const request=transcript({domain:'TSA authenticated ephemeral handshake v1',initiatorAccount,initiatorDevice,responderAccount,responderDevice,nonce:crypto.randomUUID(),issuedAt:now,expiresAt:now+TTL,initiatorEphemeral:await crypto.subtle.exportKey('jwk',privateEphemeral.publicKey)});
 if(request.initiatorAccount===request.responderAccount&&request.initiatorDevice===request.responderDevice)throw Error('Self handshake prohibited');
 return {request,signature:await sign(signingKey,request),privateEphemeral:privateEphemeral.privateKey};
}
export async function answerTsaHandshake({request,signature,initiatorSigningPublic,expectedResponderAccount,expectedResponderDevice,responderSigningKey,now=Date.now()}){
 const p=transcript(request);fresh(p.issuedAt,p.expiresAt,now);
 if(p.responderAccount!==id(expectedResponderAccount)||p.responderDevice!==id(expectedResponderDevice))throw Error('TSA responder mismatch');
 if(!await verify(p,signature,initiatorSigningPublic))throw Error('Unauthenticated TSA initiator');
 const eph=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
 const response={domain:'TSA authenticated ephemeral response v1',request:p,requestSignature:signature,responderEphemeral:jwk(await crypto.subtle.exportKey('jwk',eph.publicKey))};
 const responseSignature=await sign(responderSigningKey,response);
 return {response,responseSignature,privateEphemeral:eph.privateKey};
}
export async function verifyTsaHandshake({request,signature,response,responseSignature,initiatorSigningPublic,responderSigningPublic,expectedInitiatorAccount,expectedInitiatorDevice,expectedResponderAccount,expectedResponderDevice,now=Date.now()}){
 const p=transcript(request);fresh(p.issuedAt,p.expiresAt,now);
 if(p.initiatorAccount!==id(expectedInitiatorAccount)||p.initiatorDevice!==id(expectedInitiatorDevice)||p.responderAccount!==id(expectedResponderAccount)||p.responderDevice!==id(expectedResponderDevice))throw Error('TSA handshake identity mismatch');
 if(!await verify(p,signature,initiatorSigningPublic))throw Error('Unauthenticated TSA initiator');
 const canonical={domain:'TSA authenticated ephemeral response v1',request:p,requestSignature:signature,responderEphemeral:jwk(response?.responderEphemeral)};
 if(JSON.stringify(canonical)!==JSON.stringify(response)||!await verify(canonical,responseSignature,responderSigningPublic))throw Error('Unauthenticated TSA responder');
 // Only transcript authentication; session keys and delivery grants require a
 // vetted ratchet and independent device authorization.
 return Object.freeze({state:'authenticated-transcript-only-no-delivery',nonce:p.nonce,initiatorDevice:p.initiatorDevice,responderDevice:p.responderDevice,expiresAt:p.expiresAt});
}
