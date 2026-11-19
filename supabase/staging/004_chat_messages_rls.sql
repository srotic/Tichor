-- TichorConnect V3 staging ONLY: direct messages and read/delivery receipts.
-- Run in the SQL editor of project dasxibyqqkthibycduzr, NEVER production.
create extension if not exists pgcrypto;
create table if not exists public.chat_messages (
 id uuid primary key default gen_random_uuid(),
 sender_id uuid not null references auth.users(id) on delete cascade,
 recipient_id uuid not null references auth.users(id) on delete cascade,
 body text not null default '',
 created_at timestamptz not null default now(),
 delivered_at timestamptz,
 read_at timestamptz,
 constraint chat_messages_body_length check (char_length(body)<=20000)
);
create index if not exists v3_chat_messages_sender_recent on public.chat_messages(sender_id,created_at desc);
create index if not exists v3_chat_messages_recipient_recent on public.chat_messages(recipient_id,created_at desc);
alter table public.chat_messages enable row level security;
alter table public.chat_messages force row level security;
drop policy if exists v3_chat_select_participant on public.chat_messages;
create policy v3_chat_select_participant on public.chat_messages for select to authenticated
using (auth.uid()=sender_id or auth.uid()=recipient_id);
drop policy if exists v3_chat_insert_sender on public.chat_messages;
create policy v3_chat_insert_sender on public.chat_messages for insert to authenticated
with check (auth.uid()=sender_id and recipient_id<>sender_id);
drop policy if exists v3_chat_update_participant on public.chat_messages;
create policy v3_chat_update_participant on public.chat_messages for update to authenticated
using (auth.uid()=sender_id or auth.uid()=recipient_id)
with check (auth.uid()=sender_id or auth.uid()=recipient_id);
drop policy if exists v3_chat_delete_sender on public.chat_messages;
create policy v3_chat_delete_sender on public.chat_messages for delete to authenticated
using (auth.uid()=sender_id);
revoke all on public.chat_messages from anon,public;
grant select,insert,update,delete on public.chat_messages to authenticated;
-- Restrict receipt updates to recipients and message edits to senders.
-- Column grants alone cannot restrict each row's update columns, so use trigger.
create or replace function public.v3_guard_chat_message_update()
returns trigger language plpgsql security invoker set search_path=public as $$
begin
 if auth.uid()=old.sender_id then
   if new.sender_id is distinct from old.sender_id
     or new.recipient_id is distinct from old.recipient_id
     or new.created_at is distinct from old.created_at
     or new.delivered_at is distinct from old.delivered_at
     or new.read_at is distinct from old.read_at then
     raise exception 'Sender may only edit message body';
   end if;
 elsif auth.uid()=old.recipient_id then
   if new.sender_id is distinct from old.sender_id
     or new.recipient_id is distinct from old.recipient_id
     or new.created_at is distinct from old.created_at
     or new.body is distinct from old.body then
     raise exception 'Recipient may only update delivery and read receipts';
   end if;
 else raise exception 'Not a message participant';
 end if;
 return new;
end $$;
drop trigger if exists v3_chat_message_update_guard on public.chat_messages;
create trigger v3_chat_message_update_guard before update on public.chat_messages
for each row execute function public.v3_guard_chat_message_update();
