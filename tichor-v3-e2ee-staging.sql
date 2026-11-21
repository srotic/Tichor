-- Apply to the TichorConnect V3 staging Supabase project only.
-- This migration creates a public-key directory, not an encryption-key escrow.
create table if not exists public.tichor_e2ee_identity_keys (
  user_id uuid primary key references auth.users(id) on delete cascade,
  encryption_public_jwk jsonb not null,
  signing_public_jwk jsonb not null,
  created_at timestamptz not null default now()
);
alter table public.tichor_e2ee_identity_keys enable row level security;
revoke all on public.tichor_e2ee_identity_keys from anon;
grant select, insert on public.tichor_e2ee_identity_keys to authenticated;
drop policy if exists e2ee_identity_read_authenticated on public.tichor_e2ee_identity_keys;
create policy e2ee_identity_read_authenticated on public.tichor_e2ee_identity_keys
 for select to authenticated using (true);
drop policy if exists e2ee_identity_insert_own on public.tichor_e2ee_identity_keys;
create policy e2ee_identity_insert_own on public.tichor_e2ee_identity_keys
 for insert to authenticated with check ((select auth.uid()) = user_id);
-- Deliberately no UPDATE or DELETE for browser users.
