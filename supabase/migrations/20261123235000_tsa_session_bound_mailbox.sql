-- Session-bound mailbox access, preserving existing cryptographic grant checks.
-- Service-role wrappers serialize access against replacement of the active login.
create or replace function public.tsa_assert_current_mailbox_session(a_account uuid,a_session uuid)
returns void language plpgsql security definer set search_path='' as $$
begin
 if not exists(select 1 from public.tichor_active_sessions s
 where s.user_id=a_account and s.session_id=a_session for update) then
 raise exception 'Session replaced' using errcode='42501';
 end if;
 if not exists(select 1 from auth.sessions s where s.id=a_session and s.user_id=a_account) then
 raise exception 'Session ended' using errcode='42501';
 end if;
end;
$$;
revoke all on function public.tsa_assert_current_mailbox_session(uuid,uuid) from public,anon,authenticated;
grant execute on function public.tsa_assert_current_mailbox_session(uuid,uuid) to service_role;

create or replace function public.tsa_publish_ciphertext_session_verified(a_sender uuid,a_peer uuid,a_signing_device uuid,a_message uuid,a_nonce uuid,a_packet_text text,a_destinations jsonb,a_session uuid)
returns integer language plpgsql security definer set search_path='' as $$
begin
 perform public.tsa_assert_current_mailbox_session(a_sender,a_session);
 return public.tsa_publish_ciphertext_verified(a_sender,a_peer,a_signing_device,a_message,a_nonce,a_packet_text,a_destinations);
end;
$$;
revoke all on function public.tsa_publish_ciphertext_session_verified(uuid,uuid,uuid,uuid,uuid,text,jsonb,uuid) from public,anon,authenticated;
grant execute on function public.tsa_publish_ciphertext_session_verified(uuid,uuid,uuid,uuid,uuid,text,jsonb,uuid) to service_role;

create or replace function public.tsa_read_ciphertext_session_verified(a_account uuid,a_device uuid,a_nonce uuid,a_session uuid,a_limit integer default 30)
returns table(message_id uuid,sender_id uuid,peer_id uuid,signing_device_id uuid,packet_text text,created_at timestamptz)
language plpgsql security definer set search_path='' as $$
begin
 perform public.tsa_assert_current_mailbox_session(a_account,a_session);
 return query select * from public.tsa_read_ciphertext_verified(a_account,a_device,a_nonce,a_limit);
end;
$$;
revoke all on function public.tsa_read_ciphertext_session_verified(uuid,uuid,uuid,uuid,integer) from public,anon,authenticated;
grant execute on function public.tsa_read_ciphertext_session_verified(uuid,uuid,uuid,uuid,integer) to service_role;
