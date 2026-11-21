const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const read=name=>fs.readFileSync(path.join(root,name),'utf8');
test('V3 security hardening migration restricts privileged RPC and anonymous roles',()=>{
 const migration=read('supabase/migrations/20261121_v3_authenticated_contact_security.sql');
 assert.match(migration,/revoke all on function public\.rls_auto_enable\(\)/);
 assert.match(migration,/revoke all on function public\.v3_guard_chat_message_update\(\)/);
 assert.match(migration,/revoke all on public\.chat_messages/);
 assert.match(migration,/char_length\(body\) between 1 and 5000/);
 assert.match(migration,/tichor_contact_allowed\(recipient_id\)/);
 assert.match(migration,/drop policy if exists v3_calls_insert_sender/);
 assert.doesNotMatch(migration,/drop event trigger/i);
});
test('Cloudflare V3 security headers are configured and copied in staging',()=>{
 const headers=read('_headers'),builder=read('scripts/build-v3-staging.cjs');
 assert.match(headers,/Strict-Transport-Security: max-age=15552000/);
 assert.match(headers,/X-Content-Type-Options: nosniff/);
 assert.match(headers,/Referrer-Policy: strict-origin-when-cross-origin/);
 assert.match(headers,/X-Frame-Options: DENY/);
 assert.match(headers,/Content-Security-Policy: frame-ancestors 'none'; object-src 'none'; base-uri 'self'/);
 assert.match(headers,/Permissions-Policy:/);
 assert.match(headers,/\/chat\.html\s+Cache-Control: no-store/);
 assert.match(headers,/\/public-config\.js\s+Cache-Control: no-store/);
 assert.match(builder,/cloudflareMetadataNames=new Set\(\['_headers'\]\)/);
 assert.doesNotMatch(read('staging-public-config.js'),/sb_secret_|service_role\s*[:=]/);
});
