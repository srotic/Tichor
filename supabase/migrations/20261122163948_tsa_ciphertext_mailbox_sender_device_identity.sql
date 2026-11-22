-- TSA V3 staging only: persist the immutable verified sending-device identity in each ciphertext row.
ALTER TABLE public.tsa_ciphertext_mailbox ADD COLUMN signing_device_id uuid NOT NULL;
CREATE OR REPLACE FUNCTION public.tsa_publish_ciphertext_verified(a_sender uuid, a_peer uuid, a_signing_device uuid, a_message uuid, a_nonce uuid, a_packet_text text, a_destinations jsonb)
 RETURNS integer
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
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
 insert into public.tsa_ciphertext_mailbox(message_id,sender_id,peer_id,recipient_id,device_id,signing_device_id,packet_text)
 select a_message,a_sender,a_peer,(j->>'account')::uuid,(j->>'device')::uuid,a_signing_device,a_packet_text
 from jsonb_array_elements(a_destinations) j;
 get diagnostics copied=row_count;
 return copied;
end
$function$
;
DROP FUNCTION public.tsa_read_ciphertext_verified(uuid,uuid,uuid,integer);
CREATE OR REPLACE FUNCTION public.tsa_read_ciphertext_verified(a_account uuid, a_device uuid, a_nonce uuid, a_limit integer DEFAULT 30)
 RETURNS TABLE(message_id uuid, sender_id uuid, peer_id uuid, signing_device_id uuid, packet_text text, created_at timestamp with time zone)
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO ''
AS $function$
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
 return query select m.message_id,m.sender_id,m.peer_id,m.signing_device_id,m.packet_text,m.created_at
 from public.tsa_ciphertext_mailbox m
 where m.recipient_id=a_account and m.device_id=a_device
 order by m.created_at desc,m.message_id desc limit a_limit;
end
$function$
;
REVOKE ALL ON FUNCTION public.tsa_read_ciphertext_verified(uuid,uuid,uuid,integer) FROM public,anon,authenticated;
GRANT EXECUTE ON FUNCTION public.tsa_read_ciphertext_verified(uuid,uuid,uuid,integer) TO service_role;
