-- TichorConnect V3 STAGING ONLY: restrict task table privileges.
-- Revoke unnecessary table privileges that are not needed for app task CRUD.
begin;
revoke references, trigger, truncate on table public.tichor_tasks from authenticated;
commit;
-- Verify effective direct grants to the authenticated role.
select grantee, privilege_type
from information_schema.role_table_grants
where table_schema='public' and table_name='tichor_tasks'
  and grantee in ('anon','authenticated')
order by grantee, privilege_type;
