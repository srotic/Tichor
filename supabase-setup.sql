-- Run in Supabase SQL Editor. Review policies before using with real data.
create table if not exists public.chat_messages (
 id uuid primary key default gen_random_uuid(),
 sender_id uuid not null references auth.users(id) on delete cascade,
 recipient_id uuid not null references auth.users(id) on delete cascade,
 body text not null check (char_length(body) between 1 and 16000),
 created_at timestamptz not null default now(),
 constraint no_self_messages check (sender_id <> recipient_id)
);
create index if not exists chat_messages_sender_time on public.chat_messages(sender_id,created_at);
create index if not exists chat_messages_recipient_time on public.chat_messages(recipient_id,created_at);
alter table public.chat_messages enable row level security;
revoke all on public.chat_messages from anon;
grant select,insert on public.chat_messages to authenticated;
drop policy if exists "participants read" on public.chat_messages;
create policy "participants read" on public.chat_messages for select to authenticated using (auth.uid() = sender_id or auth.uid() = recipient_id);
drop policy if exists "sender inserts" on public.chat_messages;
create policy "sender inserts" on public.chat_messages for insert to authenticated with check (auth.uid() = sender_id);
-- A SECURITY DEFINER lookup avoids exposing the auth.users table directly.
create or replace function public.find_chat_user(lookup_email text)
returns uuid language sql security definer set search_path = '' as $$
 select id from auth.users where lower(email)=lower(trim(lookup_email)) and email_confirmed_at is not null limit 1
$$;
revoke all on function public.find_chat_user(text) from public;
grant execute on function public.find_chat_user(text) to authenticated;
-- Enable Realtime for chat_messages using Supabase Dashboard > Database > Publications,
-- or execute the following once (skip if already a member):
-- alter publication supabase_realtime add table public.chat_messages;

-- For projects previously initialized with v3, expand message size for ciphertext:
alter table public.chat_messages drop constraint if exists chat_messages_body_check;
alter table public.chat_messages add constraint chat_messages_body_check check (char_length(body) between 1 and 16000);
