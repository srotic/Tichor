-- Run once in Supabase SQL Editor AFTER existing v7 setup.
create table if not exists public.tichor_push_subscriptions (
 id bigint generated always as identity primary key,
 user_id uuid not null references auth.users(id) on delete cascade,
 endpoint text not null unique,
 p256dh text not null,
 auth text not null,
 updated_at timestamptz not null default now()
);
create index if not exists tichor_push_user_idx on public.tichor_push_subscriptions(user_id);
alter table public.tichor_push_subscriptions enable row level security;
revoke all on public.tichor_push_subscriptions from anon;
grant select,insert,update,delete on public.tichor_push_subscriptions to authenticated;
drop policy if exists "push own select" on public.tichor_push_subscriptions;
create policy "push own select" on public.tichor_push_subscriptions for select to authenticated using (user_id=auth.uid());
drop policy if exists "push own insert" on public.tichor_push_subscriptions;
create policy "push own insert" on public.tichor_push_subscriptions for insert to authenticated with check (user_id=auth.uid());
drop policy if exists "push own update" on public.tichor_push_subscriptions;
create policy "push own update" on public.tichor_push_subscriptions for update to authenticated using (user_id=auth.uid()) with check (user_id=auth.uid());
drop policy if exists "push own delete" on public.tichor_push_subscriptions;
create policy "push own delete" on public.tichor_push_subscriptions for delete to authenticated using (user_id=auth.uid());
-- IMPORTANT: webhook delivery requires 3 separately configured Database Webhooks (README-V8).
