-- Run once in the Supabase SQL Editor for Tichor Connect.
-- Only usernames associated with requests involving the authenticated user are returned.
create or replace function public.tichor_request_usernames()
returns table(user_id uuid, username text)
language sql
stable
security definer
set search_path = ''
as $$
  select distinct p.user_id, p.username::text
  from public.tichor_profiles p
  where auth.uid() is not null
    and exists (
      select 1 from public.tichor_contact_requests r
      where (r.requester_id = auth.uid() and r.recipient_id = p.user_id)
         or (r.recipient_id = auth.uid() and r.requester_id = p.user_id)
    );
$$;
revoke all on function public.tichor_request_usernames() from public, anon;
grant execute on function public.tichor_request_usernames() to authenticated;
