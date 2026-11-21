-- TichorConnect V3 STAGING security hardening.
-- Already applied to Supabase project dasxibyqqkthibycduzr.
-- Review and separately test before applying to production.
-- Keep the ensure_rls event trigger enabled; revoke user/API execution only.

revoke all on function public.rls_auto_enable() from public, anon, authenticated;
revoke all on function public.v3_guard_chat_message_update() from public, anon, authenticated;

drop policy if exists v3_chat_insert_sender on public.chat_messages;
create policy v3_chat_insert_sender on public.chat_messages
 for insert to authenticated
 with check (
   sender_id=(select auth.uid())
   and recipient_id<>sender_id
   and char_length(body) between 1 and 5000
   and public.tichor_contact_allowed(recipient_id)
 );

drop policy if exists v3_calls_insert_sender on public.tichor_call_events;
create policy v3_calls_insert_sender on public.tichor_call_events
 for insert to authenticated
 with check (
   sender_id=(select auth.uid())
   and recipient_id<>sender_id
   and public.tichor_contact_allowed(recipient_id)
 );

revoke all on public.chat_messages, public.tichor_call_events,
 public.tichor_contact_requests, public.tichor_contacts,
 public.tichor_profiles, public.tichor_tasks,
 public.tichor_group_invites, public.tichor_group_members,
 public.tichor_group_messages, public.tichor_groups from anon;

do $body$
declare f record;
begin
 for f in select p.oid::regprocedure as signature
 from pg_proc p join pg_namespace n on n.oid=p.pronamespace
 where n.nspname='public' and p.prosecdef and p.proname like 'tichor_%'
 loop
  execute format('revoke execute on function %s from public, anon',f.signature);
 end loop;
end $body$;
