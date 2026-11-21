-- TichorConnect V3 staging hardening snapshot, applied 2026-11-21.
-- This file documents the applied database changes for review and repeatable setup.
-- Apply carefully to a separate staging project; not a production release approval.
create or replace function public.v3_guard_chat_message_update()
returns trigger language plpgsql set search_path = '' as $$
begin
 if new.id is distinct from old.id then
   raise exception 'Message identity cannot be modified' using errcode='42501';
 end if;
 if (select auth.uid()) = old.sender_id then
   if new.sender_id is distinct from old.sender_id
      or new.recipient_id is distinct from old.recipient_id
      or new.created_at is distinct from old.created_at
      or new.delivered_at is distinct from old.delivered_at
      or new.read_at is distinct from old.read_at then
     raise exception 'Sender may only edit message body' using errcode='42501';
   end if;
   if left(old.body,9)='tc-e2ee2.' and new.body is distinct from old.body then
     raise exception 'Encrypted messages cannot be edited; send a new encrypted message' using errcode='42501';
   end if;
 elsif (select auth.uid()) = old.recipient_id then
   if new.sender_id is distinct from old.sender_id
      or new.recipient_id is distinct from old.recipient_id
      or new.created_at is distinct from old.created_at
      or new.body is distinct from old.body then
     raise exception 'Recipient may only update delivery and read receipts' using errcode='42501';
   end if;
   if (old.delivered_at is not null and new.delivered_at is distinct from old.delivered_at)
      or (old.read_at is not null and new.read_at is distinct from old.read_at) then
     raise exception 'Receipt timestamps cannot be overwritten' using errcode='42501';
   end if;
   if new.delivered_at is not null and new.read_at is not null and new.read_at < new.delivered_at then
     raise exception 'Read timestamp cannot precede delivery timestamp' using errcode='22023';
   end if;
 else
   raise exception 'Not a message participant' using errcode='42501';
 end if;
 return new;
end;
$$;
drop policy if exists "V3 attachments participant select" on public.tichor_attachments;
create policy "V3 attachments participant select" on public.tichor_attachments
for select to authenticated using (
 (select auth.uid()) in (sender_id,recipient_id)
 and exists (select 1 from public.chat_messages m
  where m.id=tichor_attachments.message_id
   and m.sender_id=tichor_attachments.sender_id
   and m.recipient_id=tichor_attachments.recipient_id)
);
drop policy if exists "V3 attachments sender insert" on public.tichor_attachments;
create policy "V3 attachments sender insert" on public.tichor_attachments
for insert to authenticated with check (
 (select auth.uid())=sender_id
 and storage_path like sender_id::text || '/' || message_id::text || '/%'
 and exists (select 1 from public.chat_messages m
  where m.id=tichor_attachments.message_id
   and m.sender_id=tichor_attachments.sender_id
   and m.recipient_id=tichor_attachments.recipient_id)
);
revoke truncate,references,trigger on public.chat_messages from authenticated;
revoke truncate,references,trigger on public.tichor_attachments from authenticated;
revoke update,delete,truncate,references,trigger on public.tichor_e2ee_identity_keys from authenticated;
revoke all on public.tichor_e2ee_identity_keys from anon;
grant select,insert on public.tichor_e2ee_identity_keys to authenticated;
-- Existing RPCs require authenticated access. PUBLIC and anon must not execute them.
revoke execute on function
 public.tichor_contact_allowed(uuid),
 public.tichor_group_create(text),
 public.tichor_group_delete(uuid),
 public.tichor_group_invite(uuid,uuid),
 public.tichor_group_leave(uuid),
 public.tichor_group_respond(uuid,boolean),
 public.tichor_group_set_admin(uuid,uuid,boolean),
 public.tichor_group_set_invites(uuid,boolean),
 public.tichor_request_contact(text),
 public.tichor_request_usernames(),
 public.tichor_respond_contact(uuid,text)
from public,anon;
grant execute on function
 public.tichor_contact_allowed(uuid),
 public.tichor_group_create(text),
 public.tichor_group_delete(uuid),
 public.tichor_group_invite(uuid,uuid),
 public.tichor_group_leave(uuid),
 public.tichor_group_respond(uuid,boolean),
 public.tichor_group_set_admin(uuid,uuid,boolean),
 public.tichor_group_set_invites(uuid,boolean),
 public.tichor_request_contact(text),
 public.tichor_request_usernames(),
 public.tichor_respond_contact(uuid,text)
to authenticated;
-- A staged database may already have the constraint; do not add it twice.
do $$
begin
 if not exists (select 1 from pg_constraint where conname='v3_e2ee_public_key_structure'
  and conrelid='public.tichor_e2ee_identity_keys'::regclass) then
  alter table public.tichor_e2ee_identity_keys
   add constraint v3_e2ee_public_key_structure check (
    jsonb_typeof(encryption_public_jwk)='object'
    and jsonb_typeof(signing_public_jwk)='object'
    and encryption_public_jwk ->> 'kty' = 'EC'
    and encryption_public_jwk ->> 'crv' = 'P-256'
    and signing_public_jwk ->> 'kty' = 'EC'
    and signing_public_jwk ->> 'crv' = 'P-256'
    and length(encryption_public_jwk ->> 'x')=43
    and length(encryption_public_jwk ->> 'y')=43
    and length(signing_public_jwk ->> 'x')=43
    and length(signing_public_jwk ->> 'y')=43
    and (encryption_public_jwk ->> 'x') ~ '^[a-zA-Z0-9_-]{43}$'
    and (encryption_public_jwk ->> 'y') ~ '^[a-zA-Z0-9_-]{43}$'
    and (signing_public_jwk ->> 'x') ~ '^[a-zA-Z0-9_-]{43}$'
    and (signing_public_jwk ->> 'y') ~ '^[a-zA-Z0-9_-]{43}$'
    and not (encryption_public_jwk ? 'd')
    and not (signing_public_jwk ? 'd')
   );
 end if;
end;
$$;
