create table public.tsa_persistent_device_trust (
 user_id uuid not null references auth.users(id) on delete cascade,
 device_id uuid not null,
 revision bigint not null check(revision>0),
 root_signing_key jsonb not null,
 encryption_key jsonb not null,
 signing_key jsonb not null,
 root_signature text not null check(root_signature ~ '^[A-Za-z0-9_-]{86}$'),
 verified_at timestamptz not null default now(),
 primary key(user_id,device_id)
);
alter table public.tsa_persistent_device_trust enable row level security;
revoke all on public.tsa_persistent_device_trust from public,anon,authenticated;
grant select,insert,delete on public.tsa_persistent_device_trust to service_role;
create function public.tsa_has_persistent_device_trust(a_account uuid,a_device uuid)
returns boolean language sql stable security invoker set search_path='' as $$
 select exists(select 1 from public.tsa_persistent_device_trust t
 join public.tichor_e2ee_devices d on d.user_id=t.user_id and d.device_id=t.device_id
 join public.tichor_e2ee_identity_keys r on r.user_id=t.user_id
 where t.user_id=a_account and t.device_id=a_device and d.state='active'
 and t.root_signing_key=r.signing_public_jwk
 and t.encryption_key=d.encryption_public_jwk and t.signing_key=d.signing_public_jwk)
$$;
revoke all on function public.tsa_has_persistent_device_trust(uuid,uuid) from public,anon,authenticated;
grant execute on function public.tsa_has_persistent_device_trust(uuid,uuid) to service_role;