-- Tichor v6 ADDITIONS. Run after v4 chat_messages setup.
-- Existing chat messages are not deleted or modified.
create table if not exists public.tichor_profiles (
 user_id uuid primary key references auth.users(id) on delete cascade,
 username text unique not null check (username ~ '^[a-z][a-z0-9_]{2,23}$'),
 phone text unique check (phone is null or phone ~ '^\+[1-9][0-9]{6,14}$'),
 phone_discoverable boolean not null default false,
 created_at timestamptz not null default now()
);
alter table public.tichor_profiles enable row level security;
revoke all on public.tichor_profiles from anon;
grant select,insert,update on public.tichor_profiles to authenticated;
drop policy if exists "own profile read" on public.tichor_profiles;
create policy "own profile read" on public.tichor_profiles for select to authenticated using (auth.uid()=user_id);
drop policy if exists "own profile insert" on public.tichor_profiles;
create policy "own profile insert" on public.tichor_profiles for insert to authenticated with check (auth.uid()=user_id);
drop policy if exists "own profile update" on public.tichor_profiles;
create policy "own profile update" on public.tichor_profiles for update to authenticated using (auth.uid()=user_id) with check (auth.uid()=user_id);
-- Lookup returns only the matching user ID, not their contact details.
-- Email lookup is retained for compatibility; consider abuse/rate limits before public launch.
create or replace function public.find_tichor_user(lookup text) returns uuid
language sql security definer set search_path = '' as $$
 select p.user_id from public.tichor_profiles p where
 (left(trim(lookup),1)='@' and p.username=lower(substring(trim(lookup) from 2)))
 or (p.username=lower(trim(lookup)) and position('@' in trim(lookup))=0 and left(trim(lookup),1)<>'+')
 or (p.phone_discoverable and p.phone=trim(lookup))
 union all
 select u.id from auth.users u where lower(u.email)=lower(trim(lookup)) and u.email_confirmed_at is not null
 limit 1
$$;
revoke all on function public.find_tichor_user(text) from public;
grant execute on function public.find_tichor_user(text) to authenticated;
-- Ephemeral call signaling events; contents include SDP/ICE network metadata.
create table if not exists public.tichor_call_events (
 id uuid primary key default gen_random_uuid(),
 call_id uuid not null,
 sender_id uuid not null references auth.users(id) on delete cascade,
 recipient_id uuid not null references auth.users(id) on delete cascade,
 kind text not null check (kind in ('offer','answer','candidate','hangup')),
 payload jsonb not null default '{}'::jsonb check (pg_column_size(payload)<65536),
 created_at timestamptz not null default now(),
 constraint call_not_self check (sender_id<>recipient_id)
);
create index if not exists tichor_calls_recipient_time on public.tichor_call_events(recipient_id,created_at);
create index if not exists tichor_calls_sender_time on public.tichor_call_events(sender_id,created_at);
alter table public.tichor_call_events enable row level security;
revoke all on public.tichor_call_events from anon;
grant select,insert on public.tichor_call_events to authenticated;
drop policy if exists "participants read calls" on public.tichor_call_events;
create policy "participants read calls" on public.tichor_call_events for select to authenticated using (auth.uid()=sender_id or auth.uid()=recipient_id);
drop policy if exists "sender inserts calls" on public.tichor_call_events;
create policy "sender inserts calls" on public.tichor_call_events for insert to authenticated with check (auth.uid()=sender_id);
-- Call events accumulate. Add a scheduled retention cleanup before public launch.
