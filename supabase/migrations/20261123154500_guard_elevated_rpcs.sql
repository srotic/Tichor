-- Protect SECURITY DEFINER RPCs that bypass table RLS.
-- Rebuilds their original definitions with a current-session guard.
-- Fails rather than silently skipping unexpected function shapes.
do $guard$
declare f record; definition text; guarded text; body_start int;
begin
 for f in
  select p.oid,p.proname,l.lanname
  from pg_proc p
  join pg_namespace n on n.oid=p.pronamespace
  join pg_language l on l.oid=p.prolang
  where n.nspname='public' and p.prosecdef
   and p.proname in (
    'tichor_group_create','tichor_group_delete','tichor_group_invite',
    'tichor_group_leave','tichor_group_respond','tichor_group_set_admin',
    'tichor_group_set_invites','tichor_request_contact','tichor_respond_contact',
    'tichor_contact_allowed','tichor_request_usernames')
 loop
  definition:=pg_get_functiondef(f.oid);
  if f.lanname='plpgsql' then
   guarded:=replace(definition, 'begin' || chr(10), 'begin' || chr(10) || ' if not public.tichor_session_is_current() then raise exception ''Session superseded'' using errcode=''42501''; end if;' || chr(10));
   if guarded=definition then raise exception 'No PL/pgSQL BEGIN found: %',f.proname; end if;
  elsif f.proname='tichor_contact_allowed' then
   guarded:=replace(definition,'select (select auth.uid()) is not null','select (select public.tichor_session_is_current()) and (select auth.uid()) is not null');
  elsif f.proname='tichor_request_usernames' then
   guarded:=replace(definition,'where (select auth.uid()) is not null','where (select public.tichor_session_is_current()) and (select auth.uid()) is not null');
  else
   raise exception 'Unexpected SQL function %',f.proname;
  end if;
  if guarded=definition then raise exception 'Unable to guard function %',f.proname; end if;
  execute guarded;
 end loop;
end $guard$;
