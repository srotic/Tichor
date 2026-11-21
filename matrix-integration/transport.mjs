// Matrix transport integration scaffold. No production chat routing.
const ALGORITHM='m.megolm.v1.aes-sha2';
export async function withMatrixSession(sdk,session,work){
 if(!globalThis.isSecureContext||!globalThis.indexedDB||!navigator.locks?.request)throw Error('Secure persistent browser storage and locking required');
 const base=new URL(session.baseUrl);
 if(base.protocol!=='https:'||base.origin!=='https://matrix.tichor.com'||base.username||base.password||base.pathname!=='/'||base.search||base.hash)throw Error('Unapproved Matrix homeserver');
 if(!session.userId||!session.deviceId||!session.accessToken)throw Error('Authenticated Matrix device session required');
 const prefix='tichor-matrix:'+JSON.stringify([base.origin,session.userId,session.deviceId]);
 return navigator.locks.request(prefix,{ifAvailable:true},async lock=>{
  if(!lock)throw Error('Matrix device is already open in another tab');
  const client=sdk.createClient({baseUrl:base.origin,userId:session.userId,deviceId:session.deviceId,accessToken:session.accessToken});
  try{
   const identity=await client.whoami();
   if(identity.user_id!==session.userId||identity.device_id!==session.deviceId)throw Error('Matrix session identity mismatch');
   await client.initRustCrypto({useIndexedDB:true,cryptoDatabasePrefix:prefix});
   if(!client.getCrypto())throw Error('Cryptography initialization failed');
   await client.startClient();
   return await work(client);
  }finally{client.stopClient()}
 });
}
// Invite-only rooms begin encrypted; no legacy Supabase fallback.
export async function createEncryptedRoom(client,invite){
 if(!client.getCrypto())throw Error('Crypto not initialized');
 if(!Array.isArray(invite)||!invite.length||invite.some(x=>typeof x!=='string'||!x.startsWith('@')))throw Error('Matrix participants required');
 return client.createRoom({visibility:'private',preset:'private_chat',invite,initial_state:[{type:'m.room.encryption',state_key:'',content:{algorithm:ALGORITHM}},{type:'m.room.history_visibility',state_key:'',content:{history_visibility:'joined'}}]});
}
export async function sendEncryptedText(client,roomId,text){
 if(!client.getCrypto()||typeof text!=='string'||!text.trim())throw Error('Encrypted text unavailable');
 const room=client.getRoom(roomId);
 if(!room||room.getMyMembership()!=='join')throw Error('Joined room required');
 const state=room.currentState.getStateEvents('m.room.encryption','');
 if(state?.getContent()?.algorithm!==ALGORITHM)throw Error('Refusing unencrypted room');
 return client.sendTextMessage(roomId,text);
}
