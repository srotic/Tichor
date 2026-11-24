-- Staging-only append-only encrypted identity backup store.
-- Does not enable automatic recovery; PBKDF2 backups require a stronger
-- production security review before the application can write real keys.
create table if not exists public.tichor_e2ee_identity_backups (
 user_id uuid not null references auth.users(id) on delete cascade,
 backup_version integer not null check (backup_version = 1),
 kdf text not null check (kdf = 'PBKDF2-SHA256'),
 iterations integer not null check (iterations = 600000),
 salt text not null check (length(salt) between 40 and 48),
 iv text not null check (length(iv) between 16 and 20),
 ciphertext text not null check (length(ciphertext) between 24 and 24000),
 created_at timestamptz not null default now(),
 primary key (user_id, backup_version)
);
alter table public.tichor_e2ee_identity_backups enable row level security;
revoke all on public.tichor_e2ee_identity_backups from public, anon, authenticated;
grant select, insert on public.tichor_e2ee_identity_backups to authenticated;
drop policy if exists "identity_backup_owner_read" on public.tichor_e2ee_identity_backups;
drop policy if exists "identity_backup_owner_create" on public.tichor_e2ee_identity_backups;
create policy "identity_backup_owner_read" on public.tichor_e2ee_identity_backups for select to authenticated using ((select auth.uid()) = user_id);
create policy "identity_backup_owner_create" on public.tichor_e2ee_identity_backups for insert to authenticated with check ((select auth.uid()) = user_id);
