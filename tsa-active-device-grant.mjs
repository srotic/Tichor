// TSA root-signed active device grant v1.
// This activates enrolled device STATUS only; not E2EE message delivery.
// A verified original account key must sign the exact immutable device keys.
const E=new TextEncoder();
const UUID=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const C=/^[A-Za-z0-9_-]{43}$/;
function id(x){if(typeof x!=='string'||!UUID.test(x))throw Error('Invalid TSA activation identifier');return x}
function key(k){if(!k||k.kty!=='EC'||k.crv!=='P-256'||!C.test(k.x)||!C.test(k.y)||'d' in k)throw Error('Invalid TSA activation public key');return {kty:'EC',crv:'P-256',x:k.x,y:k.y}}
const b64=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const binary=s=>{if(typeof s!=='string'||!/^[A-Za-z0-9_-]{86}$/.test(s))throw Error('Invalid activation signature');return Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'=='),x=>x.charCodeAt(0))};
export function activeGrantBody({account,device,nonce,issuedAt,expiresAt,encryptionKey,signingKey}){
 if(!Number.isSafeInteger(issuedAt)||!Number.isSafeInteger(expiresAt)||expiresAt<=issuedAt||expiresAt-issuedAt>86400000)throw Error('Invalid activation duration');
 return {domain:'TichorConnect TSA active device grant v1',account:id(account),device:id(device),nonce:id(nonce),
  issuedAt,expiresAt,encryptionKey:key(encryptionKey),signingKey:key(signingKey)};
}
export async function signActiveDeviceGrant(args,originalRootPrivateKey){
 if(!originalRootPrivateKey||originalRootPrivateKey.type!=='private'||originalRootPrivateKey.extractable||
   originalRootPrivateKey.algorithm?.name!=='ECDSA')throw Error('Trusted original account signer required');
 const grant=activeGrantBody(args);
 const signature=b64(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},originalRootPrivateKey,E.encode(JSON.stringify(grant))));
 return {grant,signature};
}
export async function verifyActiveDeviceGrant(packet,rootPublicKey,now=Date.now()){
 const g=activeGrantBody(packet?.grant||{});
 if(now<g.issuedAt-30000||now>=g.expiresAt||g.issuedAt<now-120000)throw Error('Stale active device approval');
 const pub=await crypto.subtle.importKey('jwk',key(rootPublicKey),{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
 if(!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},pub,binary(packet.signature),E.encode(JSON.stringify(g))))
  throw Error('Invalid original root authorization signature');
 return {state:'root-signed-active-grant-verified-not-delivery',device:g.device,expiresAt:g.expiresAt};
}
