create or replace function public.tsa_register_persistent_trust_verified(a_account uuid,a_device uuid,a_session uuid,a_root jsonb,a_encryption jsonb,a_signing jsonb,a_signature text)
returns void language plpgsql security invoker set search_path='' as $$
begin
 perform public.tsa_assert_current_mailbox_session(a_account,a_session);
 perform 1 from public.tichor_e2ee_identity_keys where user_id=a_account and signing_public_jwk=a_root for update;
 if not found then raise exception 'Root changed'; end if;
 perform 1 from public.tichor_e2ee_devices where user_id=a_account and device_id=a_device and state='active' and encryption_public_jwk=a_encryption and signing_public_jwk=a_signing for update;
 if not found then raise exception 'Device changed or revoked'; end if;
 insert into public.tsa_persistent_device_trust(user_id,device_id,revision,root_signing_key,encryption_key,signing_key,root_signature) values(a_account,a_device,1,a_root,a_encryption,a_signing,a_signature) on conflict(user_id,device_id) do nothing;
 if not public.tsa_has_persistent_device_trust(a_account,a_device) then raise exception 'Conflicting trust record'; end if;
end $$;
revoke all on function public.tsa_register_persistent_trust_verified(uuid,uuid,uuid,jsonb,jsonb,jsonb,text) from public,anon,authenticated;
grant execute on function public.tsa_register_persistent_trust_verified(uuid,uuid,uuid,jsonb,jsonb,jsonb,text) to service_role;