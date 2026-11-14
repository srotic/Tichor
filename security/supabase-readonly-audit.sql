-- Tichor read-only Supabase security inventory.
-- Run as the project administrator in Supabase SQL Editor. Do not publish results containing secrets.
-- 1. RLS status and policy counts for application tables.
select t.schemaname,t.tablename,t.rowsecurity as rls_enabled,
 (select count(*) from pg_policies p where p.schemaname=t.schemaname and p.tablename=t.tablename) as policy_count
from pg_tables t where t.schemaname='public' order by t.tablename;
-- 2. Policies, including potentially permissive USING/WITH CHECK clauses.
select schemaname,tablename,policyname,permissive,roles,cmd,qual,with_check
from pg_policies where schemaname in ('public','storage')
order by schemaname,tablename,policyname;
-- 3. Grants to anonymous/authenticated roles.
select table_schema,table_name,grantee,privilege_type
from information_schema.role_table_grants
where table_schema='public' and grantee in ('anon','authenticated','PUBLIC')
order by table_name,grantee,privilege_type;
-- 4. Bucket exposure and upload limits.
select id,public,file_size_limit,allowed_mime_types from storage.buckets order by id;
-- 5. Security-definer routines (manual review required).
select n.nspname as schema,p.proname as function_name,
 pg_get_userbyid(p.proowner) as owner,p.prosecdef as security_definer,
 p.proconfig as function_settings
from pg_proc p join pg_namespace n on n.oid=p.pronamespace
where n.nspname='public' order by p.proname;
-- 6. Extensions available to public-facing schemas.
select e.extname,n.nspname as installed_schema from pg_extension e
join pg_namespace n on n.oid=e.extnamespace order by e.extname;
