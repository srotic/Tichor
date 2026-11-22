// Experimental approval transcript helpers. Not used to authorize message delivery.
const encoder=new TextEncoder();
const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
function key(j){
 if(!j||j.kty!=='EC'||j.crv!=='P-256'||j.d!==undefined||![j.x,j.y].every(v=>typeof v==='string'&&/^[A-Za-z0-9_-]{43}$/.test(v)))throw Error('Invalid public key');
 return {kty:j.kty,crv:j.crv,x:j.x,y:j.y};
}
export function approvalTranscript(request){
 if(!uuid.test(request.user_id)||!uuid.test(request.device_id))throw Error('Invalid device identity');
 return encoder.encode(JSON.stringify(['TichorConnect/device-approval/preview/v1',request.user_id,request.device_id,key(request.encryption_public_jwk),key(request.signing_public_jwk)]));
}
export async function requestFingerprint(request){
 const digest=await crypto.subtle.digest('SHA-256',approvalTranscript(request));
 return Array.from(new Uint8Array(digest),v=>v.toString(16).padStart(2,'0')).join('').match(/.{4}/g).join(' ');
}
export async function signDeviceApproval(request,privateKey){
 if(privateKey?.type!=='private'||privateKey.extractable||privateKey.algorithm?.name!=='ECDSA'||privateKey.algorithm?.namedCurve!=='P-256')throw Error('Expected local non-extractable signing identity');
 return new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},privateKey,approvalTranscript(request)));
}
export async function verifyDeviceApproval(request,signature,trustedSigningJwk){
 if(!(signature instanceof Uint8Array)||signature.length!==64)return false;
 const pub=await crypto.subtle.importKey('jwk',key(trustedSigningJwk),{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
 return crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},pub,signature,approvalTranscript(request));
}
