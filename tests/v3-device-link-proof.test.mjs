import {test} from 'node:test';
import assert from 'node:assert/strict';
import {createDeviceRequest,requestFingerprint,approveDeviceRequest,verifyDeviceApproval,verifyDeviceRequest} from '../device-link-proof.mjs';
const account='11111111-1111-4111-8111-111111111111',device='22222222-2222-4222-8222-222222222222',approver='33333333-3333-4333-8333-333333333333',nonce='44444444-4444-4444-8444-444444444444';
const now=1700000000000;
async function fixture(){
 const sign=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
 const root=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign','verify']);
 const enc=await crypto.subtle.generateKey({name:'ECDH',namedCurve:'P-256'},false,['deriveBits']);
 const req={account,device,nonce,issuedAt:now,expiresAt:now+300000,encryptionKey:await crypto.subtle.exportKey('jwk',enc.publicKey),signingKey:await crypto.subtle.exportKey('jwk',sign.publicKey)};
 const packet=await createDeviceRequest(req,sign.privateKey,now);
 const fingerprint=await requestFingerprint(packet);
 const approved=await approveDeviceRequest(packet,account,approver,root.privateKey,fingerprint,now);
 return {packet,approved,root,sign,fingerprint,publicKey:await crypto.subtle.exportKey('jwk',root.publicKey)};
}
test('valid proof binds account, device, nonce and trusted approver',async()=>{
 const f=await fixture();
 const result=await verifyDeviceApproval(f.approved,account,device,nonce,approver,f.publicKey,now);
 assert.equal(result.device,device);assert.equal(result.nonce,nonce);
});
test('rejects changed device, wrong account and expired request',async()=>{
 const f=await fixture();
 const altered=structuredClone(f.packet);altered.request.device=approver;
 await assert.rejects(verifyDeviceRequest(altered,account,now),/Invalid device proof/);
 await assert.rejects(verifyDeviceRequest(f.packet,device,now),/Wrong account/);
 await assert.rejects(verifyDeviceRequest(f.packet,account,now+300000),/expired/);
});
test('rejects unconfirmed fingerprint and self approval',async()=>{
 const f=await fixture();
 await assert.rejects(approveDeviceRequest(f.packet,account,approver,f.root.privateKey,'wrong',now),/Fingerprint/);
 await assert.rejects(approveDeviceRequest(f.packet,account,device,f.root.privateKey,f.fingerprint,now),/Self approval/);
});
test('rejects wrong nonce, signer substitution and altered signature',async()=>{
 const f=await fixture();
 await assert.rejects(verifyDeviceApproval(f.approved,account,device,approver,approver,f.publicKey,now),/Unexpected device/);
 const attacker=await crypto.subtle.exportKey('jwk',f.sign.publicKey);
 await assert.rejects(verifyDeviceApproval(f.approved,account,device,nonce,approver,attacker,now),/Invalid approval signature/);
 const changed=structuredClone(f.approved);changed.signature=(changed.signature[0]==='A'?'B':'A')+changed.signature.slice(1);
 await assert.rejects(verifyDeviceApproval(changed,account,device,nonce,approver,f.publicKey,now),/Invalid approval signature/);
});

test('root approval cannot be transferred to a refreshed request with the same device keys',async()=>{
 const f=await fixture();
 const nextNonce='55555555-5555-4555-8555-555555555555';
 const renewed=await createDeviceRequest({...f.packet.request,nonce:nextNonce},f.sign.privateKey,now);
 const substituted={approval:{...f.approved.approval,request:renewed.request,deviceProof:renewed.proof},signature:f.approved.signature};
 await assert.rejects(verifyDeviceApproval(substituted,account,device,nextNonce,approver,f.publicKey,now),/Invalid approval signature/);
});
test('account root signer approval expires even with an otherwise valid signature',async()=>{
 const f=await fixture();
 const approved=await approveDeviceRequest(f.packet,account,account,f.root.privateKey,f.fingerprint,now);
 assert.equal((await verifyDeviceApproval(approved,account,device,nonce,account,f.publicKey,now)).nonce,nonce);
 await assert.rejects(verifyDeviceApproval(approved,account,device,nonce,account,f.publicKey,now+300000),/expired/);
});
