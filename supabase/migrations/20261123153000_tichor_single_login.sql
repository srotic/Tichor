-- Single active login registry. No client direct access.
create table if not exists public.tichor_active_sessions (
 user_id uuid primary key references auth.users(id) on delete cascade,
 session_id uuid not null,
 updated_at timestamptz not null default now()
);
alter table public.tichor_active_sessions enable row level security;
revoke all on public.tichor_active_sessions from anon, authenticated;
create table if not exists public.tichor_login_devices (
 user_id uuid not null references auth.users(id) on delete cascade,
 device_token_hash text not null,
 first_seen_at timestamptz not null default now(),
 last_seen_at timestamptz not null default now(),
 primary key(user_id,device_token_hash)
);
alter table public.tichor_login_devices enable row level security;
revoke all on public.tichor_login_devices from anon,authenticated;
create table if not exists public.tichor_login_alerts (
 id bigint generated always as identity primary key,
 user_id uuid not null references auth.users(id) on delete cascade,
 session_id uuid not null,
 created_at timestamptz not null default now(),
 delivered_at timestamptz,
 unique(user_id,session_id)
);
alter table public.tichor_login_alerts enable row level security;
revoke all on public.tichor_login_alerts from anon,authenticated;
create or replace function public.tichor_register_login(p_device_token_hash text)
returns jsonb language plpgsql security definer set search_path = ''
as $$
declare v_user uuid := auth.uid(); v_session uuid; v_new boolean; v_prev uuid;
begin
 if v_user is null then raise exception 'Authentication required'; end if;
 if p_device_token_hash !~ '^[0-9a-f]{64}$' then raise exception 'Invalid device token digest'; end if;
 begin v_session := (auth.jwt()->>'session_id')::uuid;
 exception when others then raise exception 'Invalid session'; end;
 if v_session is null or not exists (select 1 from auth.sessions where id=v_session and user_id=v_user) then
  raise exception 'Session not active';
 end if;
 perform pg_advisory_xact_lock(hashtextextended(v_user::text,0));
 select session_id into v_prev from public.tichor_active_sessions where user_id=v_user;
 insert into public.tichor_active_sessions(user_id,session_id) values(v_user,v_session)
 on conflict(user_id) do update set session_id=excluded.session_id,updated_at=now();
 insert into public.tichor_login_devices(user_id,device_token_hash) values(v_user,p_device_token_hash)
 on conflict do nothing;
 get diagnostics v_new = row_count;
 update public.tichor_login_devices set last_seen_at=now() where user_id=v_user and device_token_hash=p_device_token_hash;
 if v_new then insert into public.tichor_login_alerts(user_id,session_id) values(v_user,v_session) on conflict do nothing; end if;
 return jsonb_build_object('active',true,'new_device',v_new,'replaced_previous',v_prev is distinct from v_session and v_prev is not null);
end $$;
revoke all on function public.tichor_register_login(text) from public,anon;
grant execute on function public.tichor_register_login(text) to authenticated;
create or replace function public.tichor_session_is_current()
returns boolean language sql stable security definer set search_path = ''
as $$
 select auth.uid() is not null and exists (
 select 1 from public.tichor_active_sessions s
 where s.user_id=auth.uid() and s.session_id::text=auth.jwt()->>'session_id'
 and exists(select 1 from auth.sessions a where a.id=s.session_id and a.user_id=s.user_id)
 )
$$;
revoke all on function public.tichor_session_is_current() from public,anon;
grant execute on function public.tichor_session_is_current() to authenticated;
-- Restrictive RLS applies in addition to all existing permissive policies.
create policy tichor_current_session_only on public.chat_messages
as restrictive for all to authenticated using ((select public.tichor_session_is_current()))
with check ((select public.tichor_session_is_current()));
