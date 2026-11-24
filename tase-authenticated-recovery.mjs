// TichorConnect V3 authenticated identity recovery coordinator.
// This module is intentionally fail-closed and does not change login or enroll
// devices until an authenticated backup store and server-side authorization exist.
import { restoreRecoverableIdentity } from './tase-recoverable-identity.mjs';

function assertUser(sessionUser, userId) {
  if (!sessionUser?.id || sessionUser.id !== userId)
    throw Error('Authenticated account does not match encrypted backup owner');
}
export async function recoverForAuthenticatedSession({
  supa, userId, password, backup, expectedPublicKeys, authorizeRestoredDevice
}) {
  if (!supa?.auth?.getUser) throw Error('Authenticated Supabase client required');
  if (typeof authorizeRestoredDevice !== 'function')
    throw Error('Verified device authorization service is required');
  const { data, error } = await supa.auth.getUser();
  if (error) throw Error('Unable to verify current account session');
  assertUser(data?.user, userId);
  const keys = await restoreRecoverableIdentity({
    userId, password, backup, expectedPublicKeys
  });
  // The caller must obtain a server-validated grant bound to the recovered
  // identity and the *new* device. Password knowledge alone is not approval.
  const grant = await authorizeRestoredDevice({ userId, keys, expectedPublicKeys });
  if (!grant || grant.authorized !== true)
    throw Error('Secure device authorization not confirmed; encryption remains unavailable');
  const { data: latest, error: latestError } = await supa.auth.getUser();
  if (latestError) throw Error('Session expired during encryption recovery');
  assertUser(latest?.user, userId);
  return { keys, grant };
}
