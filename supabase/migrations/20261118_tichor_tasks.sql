-- Run in the Supabase SQL Editor for the TichorConnect project.
-- Task data is private to the authenticated user.
create table if not exists public.tichor_tasks (
 id uuid primary key,
 user_id uuid not null references auth.users(id) on delete cascade,
 description text not null check (char_length(description) between 1 and 180),
 due_at timestamptz,
 completed boolean not null default false,
 created_at timestamptz not null default now(),
 updated_at timestamptz not null default now()
);
create index if not exists tichor_tasks_user_idx on public.tichor_tasks(user_id);
alter table public.tichor_tasks enable row level security;
drop policy if exists tichor_tasks_select_own on public.tichor_tasks;
drop policy if exists tichor_tasks_insert_own on public.tichor_tasks;
drop policy if exists tichor_tasks_update_own on public.tichor_tasks;
drop policy if exists tichor_tasks_delete_own on public.tichor_tasks;
create policy tichor_tasks_select_own on public.tichor_tasks for select to authenticated using ((select auth.uid())=user_id);
create policy tichor_tasks_insert_own on public.tichor_tasks for insert to authenticated with check ((select auth.uid())=user_id);
create policy tichor_tasks_update_own on public.tichor_tasks for update to authenticated using ((select auth.uid())=user_id) with check ((select auth.uid())=user_id);
create policy tichor_tasks_delete_own on public.tichor_tasks for delete to authenticated using ((select auth.uid())=user_id);
grant select,insert,update,delete on public.tichor_tasks to authenticated;
