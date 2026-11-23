// Safe recovery of a missing LOCAL TASE device identity.
// Existing server-side device identities are never replaced or impersonated.
import {listDeviceRequests,localDeviceFingerprint} from './e2ee-device-registry.js';
import {taseEnrollFirstDevice} from './tase-auto-enrollment.mjs';
export async function repairMissingLocalDevice(client,account,{onStage}={}){
 if(!client?.auth?.getUser||typeof account!=='string'||!account)throw Error('Authenticated account required');
 const {data,error}=await client.auth.getUser();
 if(error||data?.user?.id!==account)throw Error('Sign in again before repairing device enrollment');
 const local=await localDeviceFingerprint(client,account);
 if(local)return Object.freeze({state:'local-keys-present',device:local.id});
 const registry=await listDeviceRequests(client,account);
 if(registry.length!==0){
  // Never silently create a second device or replace root keys; this
  // browser cannot prove possession of any previously registered device.
  return Object.freeze({state:'existing-device-approval-or-recovery-required',registeredDevices:registry.length});
 }
 return taseEnrollFirstDevice(client,account,{onStage});
}
