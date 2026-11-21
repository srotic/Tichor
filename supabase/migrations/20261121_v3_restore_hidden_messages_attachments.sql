-- TichorConnect V3: restore missing per-user hidden-message records and secure attachment metadata.
-- Applied to V3 staging (dasxibyqqkthibycduzr). Idempotent for deployment.
-- Existing chat_messages are untouched.

create table if not exists public.tichor_hidden_messages (
  user_id uuid not null references auth.users(id) on delete cascade,
  message_id uuid not null references public.chat_messages(id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (user_id, message_id)
);
alter table public.tichor_hidden_messages enable row level security;

drop policy if exists "V3 hide select own" on public.tichor_hidden_messages;
create policy "V3 hide select own" on public.tichor_hidden_messages
  for select to authenticated using (user_id = (select auth.uid()));
drop policy if exists "V3 hide insert participant" on public.tichor_hidden_messages;
create policy "V3 hide insert participant" on public.tichor_hidden_messages
  for insert to authenticated with check (
    user_id = (select auth.uid()) and exists (
      select 1 from public.chat_messages m
      where m.id = message_id
        and (m.sender_id = (select auth.uid()) or m.recipient_id = (select auth.uid()))
    )
  );
drop policy if exists "V3 hide delete own" on public.tichor_hidden_messages;
create policy "V3 hide delete own" on public.tichor_hidden_messages
  for delete to authenticated using (user_id = (select auth.uid()));
revoke all on public.tichor_hidden_messages from public, anon;
grant select, insert, delete on public.tichor_hidden_messages to authenticated;

create table if not exists public.tichor_attachments (
  message_id uuid primary key references public.chat_messages(id) on delete cascade,
  sender_id uuid not null references auth.users(id) on delete cascade,
  recipient_id uuid not null references auth.users(id) on delete cascade,
  storage_path text not null unique,
  file_name text not null check (char_length(file_name) between 1 and 200),
  mime_type text not null check (char_length(mime_type) <= 200),
  byte_size bigint not null check (byte_size between 1 and 20971520),
  created_at timestamptz not null default now(),
  constraint tichor_attachment_path_layout check (
    storage_path like sender_id::text || '/' || message_id::text || '/%'
    and char_length(storage_path) <= 500
  )
);
alter table public.tichor_attachments enable row level security;

drop policy if exists "V3 attachments participant select" on public.tichor_attachments;
create policy "V3 attachments participant select" on public.tichor_attachments
  for select to authenticated using (
    (sender_id=(select auth.uid()) or recipient_id=(select auth.uid()))
    and exists (
      select 1 from public.chat_messages m where m.id=message_id
        and m.sender_id=sender_id and m.recipient_id=recipient_id
    )
  );
drop policy if exists "V3 attachments sender insert" on public.tichor_attachments;
create policy "V3 attachments sender insert" on public.tichor_attachments
  for insert to authenticated with check (
    sender_id=(select auth.uid()) and exists (
      select 1 from public.chat_messages m where m.id=message_id
        and m.sender_id=sender_id and m.recipient_id=recipient_id
    )
  );
drop policy if exists "V3 attachments sender delete" on public.tichor_attachments;
create policy "V3 attachments sender delete" on public.tichor_attachments
  for delete to authenticated using (sender_id=(select auth.uid()));
revoke all on public.tichor_attachments from public,anon;
grant select,insert,delete on public.tichor_attachments to authenticated;

insert into storage.buckets (id,name,public,file_size_limit)
  values ('tichor-attachments','tichor-attachments',false,20971520)
  on conflict(id) do update set public=false,file_size_limit=20971520;

drop policy if exists "V3 sender upload attachment" on storage.objects;
create policy "V3 sender upload attachment" on storage.objects
  for insert to authenticated with check (
    bucket_id='tichor-attachments'
    and (storage.foldername(name))[1]=(select auth.uid())::text
    and exists (
      select 1 from public.chat_messages m
      where m.id::text=(storage.foldername(name))[2]
        and m.sender_id=(select auth.uid())
    )
  );
drop policy if exists "V3 participants read attachment" on storage.objects;
create policy "V3 participants read attachment" on storage.objects
  for select to authenticated using (
    bucket_id='tichor-attachments'
    and exists (
      select 1 from public.chat_messages m
      where m.id::text=(storage.foldername(name))[2]
        and m.sender_id::text=(storage.foldername(name))[1]
        and (m.sender_id=(select auth.uid()) or m.recipient_id=(select auth.uid()))
    )
  );
drop policy if exists "V3 sender delete attachment" on storage.objects;
create policy "V3 sender delete attachment" on storage.objects
  for delete to authenticated using (
    bucket_id='tichor-attachments'
    and (storage.foldername(name))[1]=(select auth.uid())::text
  );
notify pgrst, 'reload schema';
