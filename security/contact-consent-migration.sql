-- DRAFT ONLY. DO NOT RUN IN PRODUCTION. Requires schema/permissions review and removal of legacy permissive INSERT policies.
-- Tichor contact-consent migration. Review in a staging Supabase project first.
-- Requires existing public.chat_messages(sender_id,recipient_id),
-- public.tichor_call_events(sender_id,recipient_id), and public.tichor_profiles(user_id,username).
begin;
create table if not exists public.tichor_contact_requests (
 id uuid primary key default gen_random_uuid(),
 requester_id uuid not null references auth.users(id) on delete cascade,
 recipient_id uuid not null references auth.users(id) on delete cascade,
 status text not null default 'pending' check(status in ('pending','accepted','declined','blocked')),
 created_at timestamptz not null default now(),
 updated_at timestamptz not null default now(),
 constraint tichor_request_distinct check(requester_id <> recipient_id),
 unique(requester_id,recipient_id)
);
create index if not exists tichor_contact_requests_recipient on public.tichor_contact_requests(recipient_id,status);
alter table public.tichor_contact_requests enable row level security;
drop policy if exists tichor_requests_read on public.tichor_contact_requests;
create policy tichor_requests_read on public.tichor_contact_requests for select to authenticated using(auth.uid()=requester_id or auth.uid()=recipient_id);
-- No client insert/update/delete: use security-definer RPCs with explicit authorization.
create or replace function public.tichor_request_contact(target_username text)
returns text language plpgsql security definer set search_path = public, pg_temp as $$
declare target uuid; existing text;
begin
 if auth.uid() is null then raise exception 'Sign in required'; end if;
 if target_username is null or target_username !~ '^@?[A-Za-z][A-Za-z0-9_]{2,23}$' then raise exception 'Enter a valid username'; end if;
 select user_id into target from public.tichor_profiles where lower(username)=lower(trim(leading '@' from target_username)) limit 1;
 -- Generic result prevents enumeration of usernames.
 if target is null or target=auth.uid() then return 'If this username accepts requests, the request has been submitted.'; end if;
 if exists(select 1 from public.tichor_contact_requests where requester_id=target and recipient_id=auth.uid() and status='blocked') then return 'If this username accepts requests, the request has been submitted.'; end if;
 select status into existing from public.tichor_contact_requests where requester_id=auth.uid() and recipient_id=target;
 if existing is null then
   insert into public.tichor_contact_requests(requester_id,recipient_id) values(auth.uid(),target);
 elsif existing='declined' then
   update public.tichor_contact_requests set status='pending',updated_at=now() where requester_id=auth.uid() and recipient_id=target;
 end if;
 return 'If this username accepts requests, the request has been submitted.';
end $$;
create or replace function public.tichor_respond_contact(request_id uuid, decision text)
returns void language plpgsql security definer set search_path = public, pg_temp as $$
begin
 if auth.uid() is null then raise exception 'Sign in required'; end if;
 if decision not in ('accepted','declined','blocked') then raise exception 'Invalid response'; end if;
 update public.tichor_contact_requests set status=decision,updated_at=now()
 where id=request_id and recipient_id=auth.uid() and status in ('pending','accepted','declined');
 if not found then raise exception 'Request not found or not permitted'; end if;
end $$;
create or replace function public.tichor_contact_allowed(other_id uuid)
returns boolean language sql stable security definer set search_path=public,pg_temp as $$
 select auth.uid() is not null and other_id is not null and (
  exists(select 1 from public.tichor_contact_requests r where r.status='accepted'
     and ((r.requester_id=auth.uid() and r.recipient_id=other_id) or (r.recipient_id=auth.uid() and r.requester_id=other_id)))
 ) and not exists(select 1 from public.tichor_contact_requests b where b.status='blocked'
    and ((b.requester_id=auth.uid() and b.recipient_id=other_id) or (b.recipient_id=auth.uid() and b.requester_id=other_id)));
$$;
revoke all on function public.tichor_request_contact(text) from public;
revoke all on function public.tichor_respond_contact(uuid,text) from public;
revoke all on function public.tichor_contact_allowed(uuid) from public;
grant execute on function public.tichor_request_contact(text),public.tichor_respond_contact(uuid,text),public.tichor_contact_allowed(uuid) to authenticated;
-- Replace ONLY INSERT policies; preserve existing participant SELECT/UPDATE/DELETE rules.
drop policy if exists tichor_messages_consent_insert on public.chat_messages;
create policy tichor_messages_consent_insert on public.chat_messages for insert to authenticated
 with check(sender_id=auth.uid() and public.tichor_contact_allowed(recipient_id));
-- IMPORTANT: Remove any OTHER permissive INSERT policies on chat_messages,
-- otherwise PostgreSQL ORs them and consent can be bypassed.
drop policy if exists tichor_calls_consent_insert on public.tichor_call_events;
create policy tichor_calls_consent_insert on public.tichor_call_events for insert to authenticated
 with check(sender_id=auth.uid() and public.tichor_contact_allowed(recipient_id));
-- IMPORTANT: Remove any OTHER permissive INSERT policies on tichor_call_events.
commit;
