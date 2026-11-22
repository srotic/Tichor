// Tichor Secure Architecture: root-signed device trust evidence.
// This is a durable authorization *candidate*, not a messaging protocol.
// No device grants or certificate previews can authorize E2EE transport yet.
import {verifyEligibilityCertificate} from './device-link-proof.mjs';
const enc=new TextEncoder();
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const SIG=/^[A-Za-z0-9_-]{86}$/;
function id(x){if(typeof x!=='string'||!UUID.test(x))throw Error('Invalid device identity');return x;}
function base64(buf){return btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
function bytes(s){if(typeof s!=='string'||!SIG.test(s))throw Error('Invalid root authorization signature');return Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'=='),x=>x.charCodeAt(0));}
function rootKey(jwk){if(!jwk||jwk.kty!=='EC'||jwk.crv!=='P-256'||typeof jwk.x!=='string'||typeof jwk.y!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(jwk.x)||!/^[A-Za-z0-9_-]{43}$/.test(jwk.y)||'d' in jwk)throw Error('Invalid root signing key');return {kty:'EC',crv:'P-256',x:jwk.x,y:jwk.y};}
function body(cert,account,device,issuedAt,expiresAt){
 if(!cert||!SIG.test(cert.signature)||!Number.isSafeInteger(issuedAt)||!Number.isSafeInteger(expiresAt)||
  !Number.isSafeInteger(cert.certificate?.expiresAt)||issuedAt<cert.certificate.issuedAt||expiresAt<=issuedAt||
  expiresAt>cert.certificate.expiresAt||expiresAt-issuedAt>24*60*60*1000)throw Error('Invalid trust grant lifetime');
 return {domain:'TichorConnect V3 root device trust evidence v1',account:id(account),device:id(device),
  nonce:id(cert.certificate.request?.nonce),certificateSignature:cert.signature,issuedAt,expiresAt};
}
export async function createDeviceTrustEvidence(cert,account,device,rootPublic,rootPrivate,registry,now=Date.now()){
 await verifyEligibilityCertificate(cert,account,device,rootPublic,registry,now);
 const grant=body(cert,account,device,now,Math.min(now+24*60*60*1000,cert.certificate.expiresAt));
 const signature=base64(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},rootPrivate,enc.encode(JSON.stringify(grant))));
 const result={grant,signature};
 await verifyDeviceTrustEvidence(result,cert,account,device,rootPublic,registry,now);
 return result;
}
export async function verifyDeviceTrustEvidence(packet,cert,account,device,rootPublic,registry,now=Date.now()){
 await verifyEligibilityCertificate(cert,account,device,rootPublic,registry,now);
 const g=packet?.grant;
 if(!g||g.domain!=='TichorConnect V3 root device trust evidence v1')throw Error('Invalid trust grant domain');
 const canonical=body(cert,account,device,g.issuedAt,g.expiresAt);
 if(JSON.stringify(canonical)!==JSON.stringify(g))throw Error('Trust grant content mismatch');
 if(!Number.isSafeInteger(now)||now<g.issuedAt||now>=g.expiresAt)throw Error('Trust grant expired or not yet valid');
 const pub=await crypto.subtle.importKey('jwk',rootKey(rootPublic),{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
 if(!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},pub,bytes(packet.signature),enc.encode(JSON.stringify(canonical))))
  throw Error('Invalid trust grant root signature');
 return {state:'verified-trust-evidence-not-delivery-authorized',device,expiresAt:g.expiresAt};
}
