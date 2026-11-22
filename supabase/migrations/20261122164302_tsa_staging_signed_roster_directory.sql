-- Staging-only signed active-device roster directory. Signed contents are verified client-side.
-- Publishing requires authenticated ownership; reading requires accepted contact status.
create table if not exists public.tsa_signed_device_rosters(
 user_id uuid primary key references auth.users(id) on delete cascade,
 roster jsonb not null check(jsonb_typeof(roster)='object' and octet_length(roster::text)<24000),
 signature text not null check(signature ~ '^[A-Za-z0-9_-]{86}$'),
 updated_at timestamptz not null default clock_timestamp()
);
alter table public.tsa_signed_device_rosters enable row level security;
revoke all on public.tsa_signed_device_rosters from public,anon,authenticated;
grant select,insert,update on public.tsa_signed_device_rosters to authenticated;
create policy tsa_roster_owner_and_accepted_contact_read on public.tsa_signed_device_rosters
 for select to authenticated using (
   user_id=(select auth.uid()) or public.tichor_contact_allowed(user_id)
 );
create policy tsa_roster_owner_insert on public.tsa_signed_device_rosters
 for insert to authenticated with check(
   user_id=(select auth.uid()) and roster->>'account'=user_id::text
 );
create policy tsa_roster_owner_update on public.tsa_signed_device_rosters
 for update to authenticated using(user_id=(select auth.uid()))
 with check(user_id=(select auth.uid()) and roster->>'account'=user_id::text);
create or replace function public.tsa_roster_revision_guard()
returns trigger language plpgsql security invoker set search_path=''
as $$
declare now_ms bigint := (extract(epoch from clock_timestamp())*1000)::bigint;
begin
 if new.roster->>'domain' is distinct from 'Tichor TSA experimental device roster v1'
    or new.roster->>'account' is distinct from new.user_id::text
    or (new.roster->>'revision') is null
    or not (new.roster->>'revision' ~ '^[1-9][0-9]{0,12}$')
    or not (new.roster->>'issuedAt' ~ '^[1-9][0-9]{9,12}$')
    or not (new.roster->>'expiresAt' ~ '^[1-9][0-9]{9,12}$')
 then raise exception 'Invalid signed roster metadata'; end if;
 if (new.roster->>'issuedAt')::bigint>now_ms+30000
    or (new.roster->>'issuedAt')::bigint<now_ms-60000
    or (new.roster->>'expiresAt')::bigint<=now_ms
    or (new.roster->>'expiresAt')::bigint-(new.roster->>'issuedAt')::bigint>300000
 then raise exception 'Signed roster must be fresh'; end if;
 if tg_op='UPDATE' and (new.roster->>'revision')::bigint<=(old.roster->>'revision')::bigint
 then raise exception 'Signed roster revision must increase'; end if;
 new.updated_at:=clock_timestamp();
 return new;
end;
$$;
revoke all on function public.tsa_roster_revision_guard() from public,anon,authenticated;
create trigger tsa_roster_revision_validate
 before insert or update on public.tsa_signed_device_rosters
 for each row execute function public.tsa_roster_revision_guard();
