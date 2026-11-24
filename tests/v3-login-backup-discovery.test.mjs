import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
const html = readFileSync(new URL('../chat.html', import.meta.url), 'utf8');
test('login discovers backup after authenticated account setup', () => {
 const login = html.slice(html.indexOf('async function loggedIn(u)'),html.indexOf('async function loggedIn(u)')+4200);
 assert.match(login, /readEncryptedIdentityBackup\(supa,onboardingAccount\)/);
 assert.ok(login.indexOf('readEncryptedIdentityBackup(supa,onboardingAccount)') < login.indexOf('taseEnrollFirstDevice(supa,onboardingAccount'));
 assert.match(login, /Recovery requires verified device authorization/);
});
test('login backup discovery does not attempt password recovery or overwrite keys', () => {
 const login = html.slice(html.indexOf('async function loggedIn(u)'),html.indexOf('async function loggedIn(u)')+1500);
 assert.doesNotMatch(login, /restoreRecoverableIdentity|createRecoverableIdentity|storeEncryptedIdentityBackupOnce|unwrapIdentityMaterial/);
});
