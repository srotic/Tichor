-- Tichor Guest Rooms extension. Run AFTER v4/v6 setup.
-- Requires Supabase Dashboard > Authentication > Providers > Anonymous Sign-Ins enabled.
-- Existing registered chats and profiles are untouched.
create table if not exists public.tichor_guest_rooms (
 id uuid primary key default gen_random_uuid(),
 invite_hash text not null unique check (invite_hash ~ '^[a-f0-9]{64}$'),
 creator_id uuid not null references auth.users(id) on delete cascade,
 created_at timestamptz not null default now(),
 expires_at timestamptz not null default (now() + interval '7 days')
);
create table if not exists public.tichor_guest_members (
 room_id uuid not null references public.tichor_guest_rooms(id) on delete cascade,
 user_id uuid not null references auth.users(id) on delete cascade,
 display_name text not null check (char_length(display_name) between 1 and 40),
 joined_at timestamptz not null default now(),
 primary key(room_id,user_id)
);
create index if not exists tichor_guest_members_user on public.tichor_guest_members(user_id);
create table if not exists public.tichor_guest_messages (
 id uuid primary key default gen_random_uuid(),
 room_id uuid not null references public.tichor_guest_rooms(id) on delete cascade,
 sender_id uuid not null references auth.users(id) on delete cascade,
 body text not null check (char_length(body) between 1 and 16000),
 created_at timestamptz not null default now()
);
create index if not exists tichor_guest_messages_room_time on public.tichor_guest_messages(room_id,created_at);
create table if not exists public.tichor_guest_calls (
 id uuid primary key default gen_random_uuid(),
 room_id uuid not null references public.tichor_guest_rooms(id) on delete cascade,
 sender_id uuid not null references auth.users(id) on delete cascade,
 call_id uuid not null,
 kind text not null check (kind in ('offer','answer','candidate','hangup')),
 payload jsonb not null default '{}'::jsonb check (pg_column_size(payload) < 65536),
 created_at timestamptz not null default now()
);
create index if not exists tichor_guest_calls_room_time on public.tichor_guest_calls(room_id,created_at);

alter table public.tichor_guest_rooms enable row level security;
alter table public.tichor_guest_members enable row level security;
alter table public.tichor_guest_messages enable row level security;
alter table public.tichor_guest_calls enable row level security;
revoke all on public.tichor_guest_rooms from anon,authenticated;
revoke all on public.tichor_guest_members from anon,authenticated;
revoke all on public.tichor_guest_messages from anon;
revoke all on public.tichor_guest_calls from anon;
grant select on public.tichor_guest_members to authenticated;
grant select,insert on public.tichor_guest_messages to authenticated;
grant select,insert on public.tichor_guest_calls to authenticated;

drop policy if exists "guest members see own membership" on public.tichor_guest_members;
create policy "guest members see own membership" on public.tichor_guest_members
 for select to authenticated using (user_id = (select auth.uid()));
drop policy if exists "guest members read messages" on public.tichor_guest_messages;
create policy "guest members read messages" on public.tichor_guest_messages
 for select to authenticated using (exists (select 1 from public.tichor_guest_members m where m.room_id = tichor_guest_messages.room_id and m.user_id = (select auth.uid())));
drop policy if exists "guest members send messages" on public.tichor_guest_messages;
create policy "guest members send messages" on public.tichor_guest_messages
 for insert to authenticated with check (sender_id = (select auth.uid()) and exists (select 1 from public.tichor_guest_members m where m.room_id = tichor_guest_messages.room_id and m.user_id = (select auth.uid())));
drop policy if exists "guest members read calls" on public.tichor_guest_calls;
create policy "guest members read calls" on public.tichor_guest_calls
 for select to authenticated using (exists (select 1 from public.tichor_guest_members m where m.room_id = tichor_guest_calls.room_id and m.user_id = (select auth.uid())));
drop policy if exists "guest members signal calls" on public.tichor_guest_calls;
create policy "guest members signal calls" on public.tichor_guest_calls
 for insert to authenticated with check (sender_id = (select auth.uid()) and exists (select 1 from public.tichor_guest_members m where m.room_id = tichor_guest_calls.room_id and m.user_id = (select auth.uid())));

-- SECURITY DEFINER functions perform invite-token validation and enforce room capacity.
-- The browser never needs direct access to the invite hash or room table.
create or replace function public.tichor_create_guest_room(invite_token text, guest_name text)
returns uuid language plpgsql security definer set search_path = '' as $$
declare r uuid;
begin
 if auth.uid() is null then raise exception 'Sign in or join anonymously first'; end if;
 if invite_token is null or invite_token !~ '^[a-f0-9]{64}$' then raise exception 'Invalid invitation token'; end if;
 if length(trim(coalesce(guest_name,''))) not between 1 and 40 then raise exception 'Invalid display name'; end if;
 insert into public.tichor_guest_rooms(invite_hash,creator_id)
 values (encode(sha256(convert_to(invite_token,'UTF8')),'hex'),auth.uid()) returning id into r;
 insert into public.tichor_guest_members(room_id,user_id,display_name) values(r,auth.uid(),trim(guest_name));
 return r;
end $$;
create or replace function public.tichor_join_guest_room(invite_token text, guest_name text)
returns uuid language plpgsql security definer set search_path = '' as $$
declare r uuid; n integer;
begin
 if auth.uid() is null then raise exception 'Sign in or join anonymously first'; end if;
 if invite_token is null or invite_token !~ '^[a-f0-9]{64}$' then raise exception 'Invalid invitation token'; end if;
 if length(trim(coalesce(guest_name,''))) not between 1 and 40 then raise exception 'Invalid display name'; end if;
 select id into r from public.tichor_guest_rooms
 where invite_hash=encode(sha256(convert_to(invite_token,'UTF8')),'hex') and expires_at>now()
 for update;
 if r is null then raise exception 'Invitation invalid or expired'; end if;
 if exists(select 1 from public.tichor_guest_members where room_id=r and user_id=auth.uid()) then
  update public.tichor_guest_members set display_name=trim(guest_name) where room_id=r and user_id=auth.uid();
  return r;
 end if;
 select count(*) into n from public.tichor_guest_members where room_id=r;
 if n >= 2 then raise exception 'This private room already has two participants'; end if;
 insert into public.tichor_guest_members(room_id,user_id,display_name) values(r,auth.uid(),trim(guest_name));
 return r;
end $$;
revoke all on function public.tichor_create_guest_room(text,text) from public;
revoke all on function public.tichor_join_guest_room(text,text) from public;
grant execute on function public.tichor_create_guest_room(text,text) to authenticated;
grant execute on function public.tichor_join_guest_room(text,text) to authenticated;
-- Rooms and call signaling records are NOT automatically deleted at expiry.
-- A future maintenance task should delete expired rooms, cascading messages and call events.
