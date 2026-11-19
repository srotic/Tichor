-- Run in TichorConnect V3 STAGING SQL Editor after applying 001_tichor_tasks_rls.sql.
-- Read-only policy and grant inventory; inspect results before live tests.
select n.nspname as schemaname, c.relname as tablename,
       c.relrowsecurity as rowsecurity, c.relforcerowsecurity as forcerowsecurity
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where n.nspname='public' and c.relname='tichor_tasks' and c.relkind in ('r','p');
select policyname, permissive, roles, cmd, qual, with_check
from pg_policies where schemaname='public' and tablename='tichor_tasks'
order by policyname;
select grantee, privilege_type
from information_schema.role_table_grants
where table_schema='public' and table_name='tichor_tasks'
order by grantee, privilege_type;
