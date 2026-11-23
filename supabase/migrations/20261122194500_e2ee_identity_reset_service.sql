-- Service-role-only, transactional encryption identity reset.
-- Never invoke this from an unauthenticated browser or directly from the Data API.
create table if not exists public.tichor_e2ee_identity_reset_audit (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  reset_at timestamptz not null default now(),
  previous_identity_fingerprint text not null,
  reset_reason text not null default 'user-authorized-unrecoverable-keys'
);
alter table public.tichor_e2ee_identity_reset_audit enable row level security;
revoke all on public.tichor_e2ee_identity_reset_audit from public, anon, authenticated;
grant select, insert on public.tichor_e2ee_identity_reset_audit to service_role;

create or replace function public.tichor_e2ee_reset_identity_service(p_user_id uuid)
returns boolean
language plpgsql
security invoker
set search_path = ''
as $$
declare v_old record;
begin
  if current_user <> 'service_role' then
    raise exception 'Service role only' using errcode='42501';
  end if;
  if p_user_id is null then raise exception 'Missing account'; end if;
  -- Serialize concurrent resets and enrollment for this user as far as possible.
  perform pg_advisory_xact_lock(hashtextextended(p_user_id::text, 0));
  select encryption_public_jwk, signing_public_jwk into v_old
    from public.tichor_e2ee_identity_keys where user_id=p_user_id for update;
  if not found then return false; end if;
  -- Retain non-secret public identity material in the audit record for incident review.
  insert into public.tichor_e2ee_identity_reset_audit(user_id,previous_identity_fingerprint)
  values(p_user_id,encode(sha256(
    convert_to(v_old.encryption_public_jwk::text || '|' || v_old.signing_public_jwk::text,'UTF8')),'hex'));
  delete from public.tichor_tase_renewal_challenges where user_id=p_user_id;
  delete from public.tichor_e2ee_recipient_directory where user_id=p_user_id;
  delete from public.tichor_e2ee_active_device_grants where user_id=p_user_id;
  delete from public.tichor_e2ee_device_trust_evidence where user_id=p_user_id;
  delete from public.tichor_e2ee_eligibility_certificates where user_id=p_user_id;
  delete from public.tichor_e2ee_nonce_approvals where user_id=p_user_id;
  delete from public.tichor_e2ee_link_evidence where user_id=p_user_id;
  delete from public.tichor_e2ee_approval_previews where user_id=p_user_id;
  delete from public.tichor_e2ee_devices where user_id=p_user_id;
  delete from public.tichor_e2ee_identity_keys where user_id=p_user_id;
  return true;
end;
$$;
revoke all on function public.tichor_e2ee_reset_identity_service(uuid) from public, anon, authenticated;
grant execute on function public.tichor_e2ee_reset_identity_service(uuid) to service_role;
