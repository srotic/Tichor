-- TSA V3 staging: independently verified root-signed active-device grants.
-- Applied to staging on 2026-11-22. NOT a production E2EE switch.
-- The Edge Function tsa-activate-device MUST verify the complete signed
-- chain before invoking the service-role-only activation RPC.

alter table public.tichor_e2ee_devices
 drop constraint if exists tichor_e2ee_devices_state_check;
alter table public.tichor_e2ee_devices
 add constraint tichor_e2ee_devices_state_check
 check (state in ('pending','active','revoked'));

create policy device_owner_revoke_active on public.tichor_e2ee_devices
 for update to authenticated
 using (user_id=(select auth.uid()) and state='active')
 with check (user_id=(select auth.uid()) and state='revoked');

create table public.tichor_e2ee_active_device_grants(
 user_id uuid not null,
 device_id uuid not null,
 nonce uuid not null,
 issued_at_ms bigint not null,
 expires_at_ms bigint not null,
 root_signature text not null check(root_signature ~ '^[A-Za-z0-9_-]{86}$'),
 activated_at timestamptz not null default clock_timestamp(),
 primary key(user_id,device_id),
 unique(user_id,nonce),
 foreign key(user_id,device_id) references public.tichor_e2ee_devices(user_id,device_id) on delete cascade,
 foreign key(user_id,nonce) references public.tichor_e2ee_eligibility_certificates(user_id,nonce) on delete cascade,
 constraint tsa_active_grant_lifetime check(
  issued_at_ms>0 and expires_at_ms>issued_at_ms and expires_at_ms-issued_at_ms<=86400000
 )
);
alter table public.tichor_e2ee_active_device_grants enable row level security;
revoke all on public.tichor_e2ee_active_device_grants from public,anon,authenticated;
grant select,delete on public.tichor_e2ee_active_device_grants to authenticated;
create policy tsa_active_grant_owner_read on public.tichor_e2ee_active_device_grants
 for select to authenticated using(user_id=(select auth.uid()));
create policy tsa_active_grant_owner_revoke on public.tichor_e2ee_active_device_grants
 for delete to authenticated using(user_id=(select auth.uid()));

create or replace function public.tsa_activate_device_verified(
 a_user uuid,a_device uuid,a_nonce uuid,a_issued_at_ms bigint,a_expires_at_ms bigint,a_signature text
) returns boolean language plpgsql security definer set search_path=''
as $$
declare now_ms bigint := (extract(epoch from clock_timestamp())*1000)::bigint;
begin
 if (select auth.role()) is distinct from 'service_role' then
  raise exception 'Privileged verifier required' using errcode='42501';
 end if;
 if a_signature !~ '^[A-Za-z0-9_-]{86}$'
    or a_issued_at_ms>now_ms+30000 or a_issued_at_ms<now_ms-120000
    or a_expires_at_ms<=now_ms or a_expires_at_ms>a_issued_at_ms+86400000 then
  raise exception 'Stale or malformed device authorization';
 end if;
 perform 1 from public.tichor_e2ee_devices d
  where d.user_id=a_user and d.device_id=a_device and d.state='pending'
  for update;
 if not found then raise exception 'Device is not pending'; end if;
 if not exists(
  select 1 from public.tichor_e2ee_eligibility_certificates c
  join public.tichor_e2ee_link_evidence e on e.user_id=c.user_id and e.nonce=c.nonce
  join public.tichor_e2ee_device_trust_evidence t on t.user_id=c.user_id and t.nonce=c.nonce
  where c.user_id=a_user and c.nonce=a_nonce and e.device_id=a_device
    and t.device_id=a_device and c.expires_at_ms>now_ms
    and t.expires_at_ms>now_ms and a_expires_at_ms<=c.expires_at_ms
 ) then raise exception 'Root trust evidence missing or expired'; end if;
 insert into public.tichor_e2ee_active_device_grants
 (user_id,device_id,nonce,issued_at_ms,expires_at_ms,root_signature)
 values(a_user,a_device,a_nonce,a_issued_at_ms,a_expires_at_ms,a_signature);
 update public.tichor_e2ee_devices set state='active'
 where user_id=a_user and device_id=a_device and state='pending';
 if not found then raise exception 'Concurrent device state change'; end if;
 return true;
end;
$$;
revoke all on function public.tsa_activate_device_verified(uuid,uuid,uuid,bigint,bigint,text) from public,anon,authenticated;
grant execute on function public.tsa_activate_device_verified(uuid,uuid,uuid,bigint,bigint,text) to service_role;
comment on function public.tsa_activate_device_verified(uuid,uuid,uuid,bigint,bigint,text) is
 'Called only by JWT-protected Edge Function after complete P-256 ECDSA verification; does not enable delivery.';

create or replace function public.tsa_withdraw_revoked_device_grants()
returns trigger language plpgsql security invoker set search_path=''
as $$
begin
 if old.state is distinct from new.state and new.state='revoked' then
  delete from public.tichor_e2ee_active_device_grants
  where user_id=new.user_id and device_id=new.device_id;
 end if;
 return new;
end;
$$;
revoke all on function public.tsa_withdraw_revoked_device_grants() from public,anon;
create trigger tsa_active_grants_withdraw_on_revoke
 after update of state on public.tichor_e2ee_devices
 for each row when(old.state is distinct from new.state and new.state='revoked')
 execute function public.tsa_withdraw_revoked_device_grants();
