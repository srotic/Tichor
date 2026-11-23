-- Staging proposal: server-owned one-session lease; never grant direct table access.
create table if not exists public.tichor_account_active_sessions (
 user_id uuid primary key references auth.users(id) on delete cascade,
 session_id uuid not null,
 updated_at timestamptz not null default now()
);
alter table public.tichor_account_active_sessions enable row level security;
revoke all on public.tichor_account_active_sessions from public, anon, authenticated;
create or replace function public.tichor_claim_active_session(p_user uuid,p_session uuid)
returns boolean language plpgsql security definer set search_path = ''
as $$
declare old_session uuid;
begin
 if current_user <> 'service_role' then raise exception 'Service role required'; end if;
 if not exists(select 1 from auth.sessions where id=p_session and user_id=p_user)
 then raise exception 'Invalid authenticated session'; end if;
 select session_id into old_session from public.tichor_account_active_sessions where user_id=p_user for update;
 insert into public.tichor_account_active_sessions(user_id,session_id,updated_at)
 values(p_user,p_session,now())
 on conflict(user_id) do update set session_id=excluded.session_id,updated_at=now();
 return old_session is distinct from p_session;
end $$;
revoke all on function public.tichor_claim_active_session(uuid,uuid) from public, anon, authenticated;
grant execute on function public.tichor_claim_active_session(uuid,uuid) to service_role;
create or replace function public.tichor_is_active_session(p_user uuid,p_session uuid)
returns boolean language sql security definer set search_path = ''
as $$
 select current_user = 'service_role' and exists (
 select 1 from public.tichor_account_active_sessions
 where user_id=p_user and session_id=p_session
 ) $$;
revoke all on function public.tichor_is_active_session(uuid,uuid) from public, anon, authenticated;
grant execute on function public.tichor_is_active_session(uuid,uuid) to service_role;
