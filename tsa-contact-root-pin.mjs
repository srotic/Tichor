// TSA browser-scoped verified identity pin. Public fingerprints only;
// not a cryptographic key store or an authorization for message delivery.
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const FINGERPRINT=/^[a-f0-9]{64}$/;
function accountId(value){
 if(typeof value!=='string'||!UUID.test(value))throw Error('Invalid account identifier.');
 return value;
}
export function normalizeRootFingerprint(value){
 if(typeof value!=='string')throw Error('Invalid identity fingerprint.');
 const fingerprint=value.toLowerCase().replace(/\s/g,'');
 if(!FINGERPRINT.test(fingerprint))throw Error('Identity fingerprint must be 64 hexadecimal characters.');
 return fingerprint;
}
function key(account,contact){
 accountId(account);accountId(contact);
 if(account===contact)throw Error('A contact root must belong to a different account.');
 return 'tichor-v3-verified-contact-root:'+account+':'+contact;
}
// Caller must obtain 'typed' from a deliberate out-of-band comparison.
export function confirmContactRootPin(store,account,contact,typed,observed){
 const fingerprint=normalizeRootFingerprint(observed);
 if(normalizeRootFingerprint(typed)!==fingerprint)
  throw Error('Contact root verification failed. Trust was not saved.');
 const location=key(account,contact);
 const existing=store.getItem(location);
 if(existing!==null&&existing!==fingerprint)
  throw Error('Contact identity changed. Verify and resolve the key change before proceeding.');
 if(existing===null)store.setItem(location,fingerprint);
 return fingerprint;
}
export function readContactRootPin(store,account,contact){
 const location=key(account,contact);
 const pinned=store.getItem(location);
 return pinned===null?null:normalizeRootFingerprint(pinned);
}
export function requireContactRootPin(store,account,contact,observed){
 const pinned=readContactRootPin(store,account,contact);
 if(!pinned)throw Error('Contact root not independently verified. Discovery blocked.');
 if(pinned!==normalizeRootFingerprint(observed))
  throw Error('Pinned contact root changed. Discovery blocked.');
 return pinned;
}

// Explicit out-of-band rotation; compare-and-swap prevents stale confirmations.
export function rotateContactRootPin(store,account,contact,previous,typed,observed){
 const location=key(account,contact);
 const next=normalizeRootFingerprint(observed);
 if(normalizeRootFingerprint(typed)!==next)throw Error('Replacement fingerprint verification failed.');
 if(store.getItem(location)!==normalizeRootFingerprint(previous))throw Error('Contact pin changed during verification. Retry.');
 store.setItem(location,next);
 return next;
}
