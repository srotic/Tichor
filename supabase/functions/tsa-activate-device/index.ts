// TSA active-device verifier. STAGING ONLY; does not enable E2EE delivery.
// Requires the caller's JWT, independently verifiable root-signed evidence,
// immutable registry keys, fresh nonce-bound approval and atomic SQL activation.
import { createClient } from 'https://esm.sh/@supabase/supabase-js@2.49.8';
const E=new TextEncoder();
const uuid=/^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/;
const coord=/^[A-Za-z0-9_-]{43}$/;
const signaturePattern=/^[A-Za-z0-9_-]{86}$/;
function key(k){if(!k||k.kty!=='EC'||k.crv!=='P-256'||typeof k.x!=='string'||typeof k.y!=='string'||!coord.test(k.x)||!coord.test(k.y)||'d' in k)throw Error('Bad public key');return {kty:'EC',crv:'P-256',x:k.x,y:k.y};}
function equal(a,b){return JSON.stringify(key(a))===JSON.stringify(key(b));}
function id(v){if(typeof v!=='string'||!uuid.test(v))throw Error('Invalid identity');return v;}
function safeTime(n){if(!Number.isSafeInteger(n)||n<=0)throw Error('Invalid timestamp');return n;}
function bytes(s){if(typeof s!=='string'||!signaturePattern.test(s))throw Error('Invalid signature bytes');return Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'=='),c=>c.charCodeAt(0));}
async function signed(obj,sig,publicJwk){
 const pub=await crypto.subtle.importKey('jwk',key(publicJwk),{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
 return crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},pub,bytes(sig),E.encode(JSON.stringify(obj)));
}
async function one(db,table,columns,account,nonce,device){
 let request=db.from(table).select(columns).eq('user_id',account);
 if(nonce)request=request.eq('nonce',nonce);
 if(device)request=request.eq('device_id',device);
 const {data,error}=await request.maybeSingle();
 if(error||!data)throw Error('Required verified device evidence unavailable: '+table);
 return data;
}
function canonicalRequest(r){
 return {domain:'TichorConnect V3 device-link request v1',account:id(r.account),device:id(r.device),nonce:id(r.nonce),issuedAt:safeTime(r.issuedAt),expiresAt:safeTime(r.expiresAt),encryptionKey:key(r.encryptionKey),signingKey:key(r.signingKey)};
}
const allowedOrigin='https://v3.tichor.com';
Deno.serve(async req=>{
 const origin=req.headers.get('origin');
 const headers={'Content-Type':'application/json','Cache-Control':'no-store',
  'Access-Control-Allow-Origin':allowedOrigin,'Vary':'Origin',
  'Access-Control-Allow-Headers':'authorization, x-client-info, x-supabase-api-version, apikey, content-type',
  'Access-Control-Allow-Methods':'POST, OPTIONS'};
 const reply=(status,message)=>new Response(JSON.stringify({state:'not-authorized',message}),{status,headers});
 if(origin&&origin!==allowedOrigin)return reply(403,'Origin not allowed');
 if(req.method==='OPTIONS')return new Response(null,{status:204,headers});
 if(req.method!=='POST')return reply(405,'POST required');
 try{
  const authorization=req.headers.get('authorization')||'';
  if(!authorization.startsWith('Bearer '))return reply(401,'Sign in required');
  const url=Deno.env.get('SUPABASE_URL'),adminKey=Deno.env.get('SUPABASE_SERVICE_ROLE_KEY');
  if(!url||!adminKey)throw Error('Verifier not configured');
  const db=createClient(url,adminKey,{auth:{persistSession:false,autoRefreshToken:false}});
  const {data:session,error:authError}=await db.auth.getUser(authorization.slice(7));
  if(authError||!session?.user?.id)return reply(401,'Invalid session');
  const input=await req.json();
  if(typeof input!=='object'||input===null||Array.isArray(input))throw Error('Invalid device grant');
  const g=input.grant;const account=id(g?.account),device=id(g?.device),nonce=id(g?.nonce);
  if(account!==session.user.id)throw Error('Signed-in account mismatch');
  if(g.domain!=='TichorConnect TSA active device grant v1')throw Error('Unexpected grant domain');
  const now=Date.now(),issuedAt=safeTime(g.issuedAt),expiresAt=safeTime(g.expiresAt);
  if(issuedAt<now-120000||issuedAt>now+30000||expiresAt<=now||expiresAt-issuedAt>86400000)throw Error('Activation grant expired');
  const registry=await one(db,'tichor_e2ee_devices','user_id,device_id,state,encryption_public_jwk,signing_public_jwk',account,null,device);
  if(registry.state!=='pending'||!equal(g.encryptionKey,registry.encryption_public_jwk)||!equal(g.signingKey,registry.signing_public_jwk))
   throw Error('Device key or state mismatch');
  const {data:root,error:rootError}=await db.from('tichor_e2ee_identity_keys').select('user_id,signing_public_jwk').eq('user_id',account).maybeSingle();
  if(rootError||root?.user_id!==account)throw Error('Original account signing identity missing');
  const canonicalGrant={domain:g.domain,account,device,nonce,issuedAt,expiresAt,encryptionKey:key(g.encryptionKey),signingKey:key(g.signingKey)};
  if(JSON.stringify(canonicalGrant)!==JSON.stringify(g)||!await signed(canonicalGrant,input.signature,root.signing_public_jwk))
   throw Error('Original root signature verification failed');
  const evidence=await one(db,'tichor_e2ee_link_evidence','user_id,device_id,nonce,issued_at_ms,expires_at_ms,proof',account,nonce,null);
  if(evidence.device_id!==device)throw Error('Device link nonce mismatch');
  const certificate=await one(db,'tichor_e2ee_eligibility_certificates','user_id,nonce,issued_at_ms,expires_at_ms,signature',account,nonce,null);
  const trust=await one(db,'tichor_e2ee_device_trust_evidence','user_id,device_id,nonce,issued_at_ms,expires_at_ms,signature',account,nonce,null);
  const approval=await one(db,'tichor_e2ee_nonce_approvals','user_id,nonce,signature',account,nonce,null);
  const directory=await one(db,'tichor_e2ee_recipient_directory','user_id,device_id,nonce,certificate,signature,expires_at_ms',account,nonce,null);
  if(directory.device_id!==device||trust.device_id!==device||
    certificate.signature!==directory.signature||Number(certificate.expires_at_ms)!==Number(directory.expires_at_ms))throw Error('Published eligibility mismatch');
  const cert=directory.certificate;
  if(cert?.domain!=='TichorConnect V3 device eligibility preview v1')throw Error('Invalid root certificate');
  const request=canonicalRequest(cert.request);
  if(request.account!==account||request.device!==device||request.nonce!==nonce||
    request.issuedAt!==Number(evidence.issued_at_ms)||request.expiresAt!==Number(evidence.expires_at_ms)||
    !equal(request.encryptionKey,registry.encryption_public_jwk)||!equal(request.signingKey,registry.signing_public_jwk))throw Error('Nonce and device identity mismatch');
  if(request.expiresAt-request.issuedAt>300000||request.expiresAt<=request.issuedAt)throw Error('Invalid request duration');
  if(!await signed(request,evidence.proof,request.signingKey))throw Error('Device possession proof invalid');
  const approvalBody={domain:'TichorConnect V3 device-link approval v1',approver:account,request,deviceProof:evidence.proof};
  if(!await signed(approvalBody,approval.signature,root.signing_public_jwk))throw Error('Original enrollment approval invalid');
  const certBody={domain:cert.domain,request,issuedAt:safeTime(cert.issuedAt),expiresAt:safeTime(cert.expiresAt)};
  if(cert.issuedAt!==Number(certificate.issued_at_ms)||cert.expiresAt!==Number(certificate.expires_at_ms)||
     certBody.issuedAt>=now||certBody.expiresAt<=now||certBody.expiresAt-certBody.issuedAt>30*86400000||
     certBody.issuedAt<request.issuedAt||certBody.issuedAt>=request.expiresAt||
     !await signed(certBody,certificate.signature,root.signing_public_jwk))throw Error('Invalid eligibility certificate');
  const trustBody={domain:'TichorConnect V3 root device trust evidence v1',account,device,nonce,
    certificateSignature:certificate.signature,issuedAt:Number(trust.issued_at_ms),expiresAt:Number(trust.expires_at_ms)};
  if(!Number.isSafeInteger(trustBody.issuedAt)||!Number.isSafeInteger(trustBody.expiresAt)||
     trustBody.issuedAt<certBody.issuedAt||trustBody.expiresAt>certBody.expiresAt||
     trustBody.expiresAt<=now||trustBody.expiresAt-trustBody.issuedAt>86400000||
     !await signed(trustBody,trust.signature,root.signing_public_jwk))throw Error('Invalid root-signed trust evidence');
  if(expiresAt>trustBody.expiresAt)throw Error('Grant exceeds trust evidence expiry');
  const {data:activated,error:activateError}=await db.rpc('tsa_activate_device_verified',{
   a_user:account,a_device:device,a_nonce:nonce,a_issued_at_ms:issuedAt,a_expires_at_ms:expiresAt,a_signature:input.signature
  });
  if(activateError||activated!==true)throw Error('Atomic device activation denied');
  return new Response(JSON.stringify({state:'active-device-evidence-not-delivery-authorized',device,expiresAt}),{status:200,headers});
 }catch(err){
  console.warn('TSA device authorization rejected');
  return reply(403,'Device authorization rejected; verify original account and device evidence.');
 }
});
