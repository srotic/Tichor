// TASE device-renewal client proof. No trust is granted locally.
// The server MUST issue a single-use challenge and verify the signature,
// account, device, expiry, active status and original root authorization.
const encoder=new TextEncoder();
export function renewalPayload({account,device,challenge,expiresAt}){
 if(typeof account!=='string'||!account||typeof device!=='string'||!device||
    typeof challenge!=='string'||!challenge||!Number.isSafeInteger(expiresAt))
  throw Error('Invalid device renewal challenge.');
 return 'TICHOR-TASE-RENEWAL-V1\n'+account+'\n'+device+'\n'+challenge+'\n'+expiresAt;
}
export async function signRenewalChallenge(privateKey,request,now=Date.now()){
 if(!privateKey||privateKey.extractable||privateKey.algorithm?.name!=='ECDSA'||
    privateKey.algorithm?.namedCurve!=='P-256')
  throw Error('Renewal requires a non-extractable trusted device signing key.');
 if(!Number.isSafeInteger(now)||request?.expiresAt<=now||
    request.expiresAt>now+300000)
  throw Error('Device renewal challenge is expired or invalid.');
 const bytes=encoder.encode(renewalPayload(request));
 const signature=await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},privateKey,bytes);
 return {account:request.account,device:request.device,challenge:request.challenge,
  expiresAt:request.expiresAt,signature:Array.from(new Uint8Array(signature))};
}
