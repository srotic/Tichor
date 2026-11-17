-- Group owner-only permanent deletion. Execute in Supabase SQL editor.
create or replace function public.tichor_group_delete(g uuid)
returns void language plpgsql security definer set search_path = '' as $$
begin
 if auth.uid() is null or not exists (
  select 1 from public.tichor_groups where id=g and owner_id=auth.uid()
 ) then raise exception 'Only the group owner can delete this group'; end if;
 delete from public.tichor_groups where id=g;
end $$;
revoke all on function public.tichor_group_delete(uuid) from public;
grant execute on function public.tichor_group_delete(uuid) to authenticated;
