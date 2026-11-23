-- Staging-only, single-use device renewal challenges. No authorization grants minted.
create table if not exists public.tichor_tase_renewal_challenges (
 user_id uuid not null references auth.users(id) on delete cascade,
 device_id uuid not null,
 challenge uuid not null default gen_random_uuid(),
 issued_at timestamptz not null default now(),
 expires_at timestamptz not null default (now()+interval '2 minutes'),
 consumed_at timestamptz,
 primary key(user_id,challenge),
 foreign key(user_id,device_id) references public.tichor_e2ee_devices(user_id,device_id) on delete cascade,
 constraint tase_challenge_ttl check(expires_at>issued_at and expires_at<=issued_at+interval '5 minutes')
);
create index if not exists tase_renewal_device_idx on public.tichor_tase_renewal_challenges(user_id,device_id,expires_at);
alter table public.tichor_tase_renewal_challenges enable row level security;
revoke all on public.tichor_tase_renewal_challenges from anon,authenticated;
-- This function is callable by the service role only. Signature verification
-- occurs in the Edge Function before calling it. Row locks prevent replay.
create or replace function public.tsa_consume_renewal_challenge(
 a_user uuid,a_device uuid,a_challenge uuid,a_expires_at_ms bigint
) returns boolean language plpgsql security invoker set search_path=public,pg_temp as $$
declare valid boolean;
begin
 update public.tichor_tase_renewal_challenges c
 set consumed_at=clock_timestamp()
 where c.user_id=a_user and c.device_id=a_device and c.challenge=a_challenge
  and c.consumed_at is null and c.expires_at>clock_timestamp()
  and floor(extract(epoch from c.expires_at)*1000)::bigint=a_expires_at_ms
  and exists(select 1 from public.tichor_e2ee_devices d where d.user_id=a_user and d.device_id=a_device and d.state='active')
  and exists(select 1 from public.tichor_e2ee_active_device_grants g where g.user_id=a_user and g.device_id=a_device and g.expires_at_ms>floor(extract(epoch from clock_timestamp())*1000)::bigint)
 returning true into valid;
 return coalesce(valid,false);
end; $$;
revoke all on function public.tsa_consume_renewal_challenge(uuid,uuid,uuid,bigint) from public,anon,authenticated;
grant execute on function public.tsa_consume_renewal_challenge(uuid,uuid,uuid,bigint) to service_role;
