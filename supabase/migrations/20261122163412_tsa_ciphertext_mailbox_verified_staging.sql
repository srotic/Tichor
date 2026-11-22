-- Applied only to V3 staging; production remains unchanged.
-- V3 staging experimental ciphertext mailbox. Not wired to public chat.
-- Every read/publish is service-role-only; Edge verifies device signatures before RPC.
create table if not exists public.tsa_ciphertext_mailbox (
 message_id uuid not null,
 sender_id uuid not null,
 peer_id uuid not null,
 recipient_id uuid not null,
 device_id uuid not null,
 packet_text text not null check (octet_length(packet_text) between 64 and 32768),
 created_at timestamptz not null default clock_timestamp(),
 primary key(message_id,recipient_id,device_id),
 constraint tsa_mailbox_participant_check check (recipient_id=sender_id or recipient_id=peer_id),
 constraint tsa_mailbox_not_self check (sender_id<>peer_id)
);
create index if not exists tsa_mailbox_device_created on public.tsa_ciphertext_mailbox(recipient_id,device_id,created_at);
alter table public.tsa_ciphertext_mailbox enable row level security;
revoke all on public.tsa_ciphertext_mailbox from public,anon,authenticated;
grant select,insert on public.tsa_ciphertext_mailbox to service_role;
create table if not exists public.tsa_ciphertext_nonces (
 account_id uuid not null,
 nonce uuid not null,
 created_at timestamptz not null default clock_timestamp(),
 primary key(account_id,nonce)
);
alter table public.tsa_ciphertext_nonces enable row level security;
revoke all on public.tsa_ciphertext_nonces from public,anon,authenticated;
grant insert,select on public.tsa_ciphertext_nonces to service_role;

create or replace function public.tsa_publish_ciphertext_verified(
 a_sender uuid,a_peer uuid,a_signing_device uuid,a_message uuid,
 a_nonce uuid,a_packet_text text,a_destinations jsonb
) returns integer
language plpgsql security definer set search_path=''
as $$
declare
 now_ms bigint := (extract(epoch from clock_timestamp())*1000)::bigint;
 expected_count integer;
 supplied_count integer;
 copied integer;
begin
 if current_setting('request.jwt.claim.role',true) is distinct from 'service_role' then
  raise exception 'Privileged verifier required' using errcode='42501';
 end if;
 if a_sender=a_peer or a_packet_text is null or octet_length(a_packet_text) not between 64 and 32768
    or jsonb_typeof(a_destinations) is distinct from 'array' then
  raise exception 'Malformed ciphertext batch';
 end if;
 -- Serialize sender and peer device membership against activation/revocation updates.
 perform 1 from public.tichor_e2ee_devices d
 where d.user_id in (a_sender,a_peer)
 order by d.user_id,d.device_id for update;
 if not exists(
   select 1 from public.tichor_e2ee_devices d
   join public.tichor_e2ee_active_device_grants g on g.user_id=d.user_id and g.device_id=d.device_id
   where d.user_id=a_sender and d.device_id=a_signing_device and d.state='active' and g.expires_at_ms>now_ms
 ) then raise exception 'Signing device not active'; end if;
 if exists(
  select 1 from public.tichor_e2ee_devices d
  where d.user_id in (a_sender,a_peer) and d.state='active'
  and not exists(select 1 from public.tichor_e2ee_active_device_grants g
    where g.user_id=d.user_id and g.device_id=d.device_id and g.expires_at_ms>now_ms)
 ) then raise exception 'An active device has no current root authorization'; end if;
 select count(*) into expected_count
 from public.tichor_e2ee_devices d join public.tichor_e2ee_active_device_grants g
 on g.user_id=d.user_id and g.device_id=d.device_id
 where d.user_id in (a_sender,a_peer) and d.state='active' and g.expires_at_ms>now_ms;
 supplied_count:=jsonb_array_length(a_destinations);
 if expected_count<2 or expected_count>16 or expected_count<>supplied_count then
  raise exception 'Incomplete or excessive device fanout';
 end if;
 if exists(
  select 1 from jsonb_array_elements(a_destinations) j
  where jsonb_typeof(j) is distinct from 'object'
  or (j->>'account') is null or (j->>'device') is null
  or not exists(
    select 1 from public.tichor_e2ee_devices d
    join public.tichor_e2ee_active_device_grants g on g.user_id=d.user_id and g.device_id=d.device_id
    where d.user_id::text=j->>'account' and d.device_id::text=j->>'device'
      and d.user_id in (a_sender,a_peer) and d.state='active' and g.expires_at_ms>now_ms
  )
 ) then raise exception 'Untrusted ciphertext destination'; end if;
 if (select count(distinct (j->>'account',j->>'device')) from jsonb_array_elements(a_destinations) j)<>supplied_count then
  raise exception 'Duplicate ciphertext device destination';
 end if;
 insert into public.tsa_ciphertext_nonces(account_id,nonce) values(a_sender,a_nonce);
 insert into public.tsa_ciphertext_mailbox(message_id,sender_id,peer_id,recipient_id,device_id,packet_text)
 select a_message,a_sender,a_peer,(j->>'account')::uuid,(j->>'device')::uuid,a_packet_text
 from jsonb_array_elements(a_destinations) j;
 get diagnostics copied=row_count;
 return copied;
end
$$;
revoke all on function public.tsa_publish_ciphertext_verified(uuid,uuid,uuid,uuid,uuid,text,jsonb) from public,anon,authenticated;
grant execute on function public.tsa_publish_ciphertext_verified(uuid,uuid,uuid,uuid,uuid,text,jsonb) to service_role;

create or replace function public.tsa_read_ciphertext_verified(
 a_account uuid,a_device uuid,a_nonce uuid,a_limit integer default 30
) returns table(message_id uuid, sender_id uuid, peer_id uuid, packet_text text, created_at timestamptz)
language plpgsql security definer set search_path=''
as $$
declare now_ms bigint := (extract(epoch from clock_timestamp())*1000)::bigint;
begin
 if current_setting('request.jwt.claim.role',true) is distinct from 'service_role' then
  raise exception 'Privileged verifier required' using errcode='42501';
 end if;
 if a_limit<1 or a_limit>50 then raise exception 'Invalid inbox limit'; end if;
 perform 1 from public.tichor_e2ee_devices d where d.user_id=a_account and d.device_id=a_device for share;
 if not exists(
   select 1 from public.tichor_e2ee_devices d
   join public.tichor_e2ee_active_device_grants g on d.user_id=g.user_id and d.device_id=g.device_id
   where d.user_id=a_account and d.device_id=a_device and d.state='active' and g.expires_at_ms>now_ms
 ) then raise exception 'Device revoked, expired or not authorized'; end if;
 insert into public.tsa_ciphertext_nonces(account_id,nonce) values(a_account,a_nonce);
 return query select m.message_id,m.sender_id,m.peer_id,m.packet_text,m.created_at
 from public.tsa_ciphertext_mailbox m
 where m.recipient_id=a_account and m.device_id=a_device
 order by m.created_at desc,m.message_id desc limit a_limit;
end
$$;
revoke all on function public.tsa_read_ciphertext_verified(uuid,uuid,uuid,integer) from public,anon,authenticated;
grant execute on function public.tsa_read_ciphertext_verified(uuid,uuid,uuid,integer) to service_role;
