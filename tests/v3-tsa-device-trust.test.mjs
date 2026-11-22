import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createDeviceRequest,requestFingerprint,approveDeviceRequest,createEligibilityCertificate} from '../device-link-proof.mjs';
import {createDeviceTrustEvidence,verifyDeviceTrustEvidence} from '../tsa-device-trust.mjs';

const account='11111111-1111-4111-8111-111111111111';
const device='22222222-2222-4222-8222-222222222222';
const nonce='44444444-4444-4444-8444-444444444444';
const now=1700000000000;
async function fixture(){
 const root=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
 const sign=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
 const enc=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
 const rootPublic=await crypto.subtle.exportKey('jwk',root.publicKey);
 const request={account,device,nonce,issuedAt:now,expiresAt:now+300000,
  encryptionKey:await crypto.subtle.exportKey('jwk',enc.publicKey),
  signingKey:await crypto.subtle.exportKey('jwk',sign.publicKey)};
 const proof=await createDeviceRequest(request,sign.privateKey,now);
 const approval=await approveDeviceRequest(proof,account,account,root.privateKey,await requestFingerprint(proof),now);
 const certificate=await createEligibilityCertificate(approval,account,device,nonce,rootPublic,root.privateKey,now);
 const row={user_id:account,device_id:device,state:'pending',
  encryption_public_jwk:request.encryptionKey,signing_public_jwk:request.signingKey};
 return {root,rootPublic,certificate,row};
}
test('root-signed trust evidence is verifiable and expires after a day',async()=>{
 const f=await fixture();
 const signed=await createDeviceTrustEvidence(f.certificate,account,device,f.rootPublic,f.root.privateKey,f.row,now);
 const verified=await verifyDeviceTrustEvidence(signed,f.certificate,account,device,f.rootPublic,f.row,now+1);
 assert.equal(verified.state,'verified-trust-evidence-not-delivery-authorized');
 assert.equal(verified.device,device);
 assert.equal(signed.grant.expiresAt,now+24*60*60*1000);
 await assert.rejects(verifyDeviceTrustEvidence(signed,f.certificate,account,device,f.rootPublic,f.row,now+24*60*60*1000),/expired/);
});
test('revoked devices, wrong account, tampering and root substitution fail closed',async()=>{
 const f=await fixture();
 const signed=await createDeviceTrustEvidence(f.certificate,account,device,f.rootPublic,f.root.privateKey,f.row,now);
 await assert.rejects(verifyDeviceTrustEvidence(signed,f.certificate,account,device,f.rootPublic,{...f.row,state:'revoked'},now+1),/revoked/);
 await assert.rejects(verifyDeviceTrustEvidence(signed,f.certificate,account,'33333333-3333-4333-8333-333333333333',f.rootPublic,f.row,now+1),/identity mismatch/);
 const altered=structuredClone(signed);altered.grant.expiresAt-=1000;
 await assert.rejects(verifyDeviceTrustEvidence(altered,f.certificate,account,device,f.rootPublic,f.row,now+1),/Invalid trust grant root signature/);
 const wrong=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
 await assert.rejects(verifyDeviceTrustEvidence(signed,f.certificate,account,device,await crypto.subtle.exportKey('jwk',wrong.publicKey),f.row,now+1),/Invalid eligibility signature/);
});
