-- TichorConnect V3 STAGING ONLY. Review before running in staging SQL Editor.
-- Creates the task table required by chat.html; does not copy production data.
begin;
create table if not exists public.tichor_tasks (
  id uuid primary key,
  user_id uuid not null references auth.users(id) on delete cascade,
  description text not null,
  due_at timestamptz,
  completed boolean not null default false,
  created_at timestamptz not null default now()
);
create index if not exists tichor_tasks_user_id_idx on public.tichor_tasks(user_id);
alter table public.tichor_tasks enable row level security;
alter table public.tichor_tasks force row level security;
-- Grant only necessary operations to authenticated clients.
revoke all on table public.tichor_tasks from public, anon;
grant select, insert, update, delete on table public.tichor_tasks to authenticated;
-- Re-running this script should replace only policies with these exact names.
drop policy if exists "v3_tasks_select_own" on public.tichor_tasks;
drop policy if exists "v3_tasks_insert_own" on public.tichor_tasks;
drop policy if exists "v3_tasks_update_own" on public.tichor_tasks;
drop policy if exists "v3_tasks_delete_own" on public.tichor_tasks;
create policy "v3_tasks_select_own" on public.tichor_tasks for select to authenticated using ((select auth.uid()) = user_id);
create policy "v3_tasks_insert_own" on public.tichor_tasks for insert to authenticated with check ((select auth.uid()) = user_id);
create policy "v3_tasks_update_own" on public.tichor_tasks for update to authenticated using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "v3_tasks_delete_own" on public.tichor_tasks for delete to authenticated using ((select auth.uid()) = user_id);
commit;
-- WARNING: This does not inspect or remove unrelated policies already present.
-- Use only on a fresh staging project and review policy inventory first.
