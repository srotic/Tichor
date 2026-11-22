// TSA V3 experimental signed-roster preflight. No network operations or delivery authority.
// The caller MUST supply independently pinned root verification keys and obtain a fresh
// server-side revocation snapshot before any future delivery activation.
const E=new TextEncoder();
const ID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const B64=/^[A-Za-z0-9_-]{86}$/;
const C=/^[A-Za-z0-9_-]{43}$/;
function id(x){if(typeof x!=='string'||!ID.test(x))throw Error('Invalid TSA account/device identifier');return x;}
function publicKey(k){if(!k||k.kty!=='EC'||k.crv!=='P-256'||!C.test(k.x)||!C.test(k.y)||'d' in k)throw Error('Invalid TSA roster public key');return {kty:'EC',crv:'P-256',x:k.x,y:k.y};}
const encoded=b=>btoa(String.fromCharCode(...new Uint8Array(b))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');
const bytes=s=>{if(typeof s!=='string'||!B64.test(s))throw Error('Invalid TSA roster signature');return Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')+'=='),c=>c.charCodeAt(0));};
function canonical(r){
 if(!r||r.domain!=='Tichor TSA experimental device roster v1')throw Error('Wrong TSA roster domain');
 const account=id(r.account),revision=r.revision;
 if(!Number.isSafeInteger(revision)||revision<1||!Number.isSafeInteger(r.issuedAt)||!Number.isSafeInteger(r.expiresAt)||
 r.expiresAt<=r.issuedAt||r.expiresAt-r.issuedAt>300000)throw Error('Invalid TSA roster lifetime or revision');
 if(!Array.isArray(r.devices)||r.devices.length<1||r.devices.length>16)throw Error('Invalid TSA roster size');
 const seen=new Set();
 const devices=r.devices.map(v=>{
  const device=id(v?.device);
  if(seen.has(device)||v.state!=='active')throw Error('Duplicate or inactive TSA device');
  seen.add(device);
  return {device,state:'active',encryptionKey:publicKey(v.encryptionKey),signingKey:publicKey(v.signingKey)};
 });
 if(devices.some((d,i)=>i>0&&devices[i-1].device>=d.device))throw Error('TSA roster order is not canonical');
 return {domain:r.domain,account,revision,issuedAt:r.issuedAt,expiresAt:r.expiresAt,devices};
}
export function makeTsaRosterBody({account,revision,issuedAt,expiresAt,devices}){
 return canonical({domain:'Tichor TSA experimental device roster v1',account,revision,issuedAt,expiresAt,
 devices:[...devices].sort((a,b)=>a.device.localeCompare(b.device))});
}
export async function signTsaRoster(body,rootPrivateKey){
 const roster=canonical(body);
 if(!rootPrivateKey||rootPrivateKey.type!=='private'||rootPrivateKey.extractable||rootPrivateKey.algorithm?.name!=='ECDSA')
  throw Error('Non-extractable root signing key required');
 return {roster,signature:encoded(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},rootPrivateKey,E.encode(JSON.stringify(roster))))};
}
export async function verifyTsaRoster(packet,pinnedRootPublicKey,now=Date.now()){
 const roster=canonical(packet?.roster);
 if(JSON.stringify(roster)!==JSON.stringify(packet.roster))throw Error('Noncanonical TSA roster');
 if(!Number.isSafeInteger(now)||now<roster.issuedAt-30000||now>=roster.expiresAt)throw Error('TSA roster stale');
 const verify=await crypto.subtle.importKey('jwk',publicKey(pinnedRootPublicKey),{name:'ECDSA',namedCurve:'P-256'},false,['verify']);
 if(!await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},verify,bytes(packet.signature),E.encode(JSON.stringify(roster))))
  throw Error('TSA root-signed roster invalid');
 return roster;
}
// Compare a prepared envelope with BOTH independently pinned, signed rosters.
// This only proves consistency of the *supplied* snapshot; it does not establish
// that a device remains authorized in the database at delivery time.
export async function previewTsaRosterCoverage({packet,senderRoster,recipientRoster,senderRoot,recipientRoot,now=Date.now()}){
 if(!packet||packet.v!==1||packet.protocol!=='TSA-experimental-multi-device-text')throw Error('Invalid TSA envelope');
 if(packet.from===packet.to)throw Error('Self-message roster is unsupported');
 const [from,to]=await Promise.all([
  verifyTsaRoster(senderRoster,senderRoot,now),
  verifyTsaRoster(recipientRoster,recipientRoot,now)
 ]);
 if(from.account!==id(packet.from)||to.account!==id(packet.to))throw Error('TSA roster account mismatch');
 const expected=new Set([...from.devices.map(v=>from.account+':'+v.device),...to.devices.map(v=>to.account+':'+v.device)]);
 if(!Array.isArray(packet.copies)||packet.copies.length!==expected.size)throw Error('TSA fanout membership incomplete');
 const seen=new Set();
 for(const copy of packet.copies){
  const name=id(copy.account)+':'+id(copy.device);
  if(!expected.has(name)||seen.has(name))throw Error('TSA fanout contains unapproved or duplicate device');
  seen.add(name);
 }
 return Object.freeze({state:'signed-roster-coverage-preview-not-sent',deviceCount:seen.size,
 senderRevision:from.revision,recipientRevision:to.revision,deliveryAuthorized:false});
}
