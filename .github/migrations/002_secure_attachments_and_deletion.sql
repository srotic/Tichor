-- Tichor secure attachments and message deletion (review before running).
-- Apply in Supabase SQL Editor before testing the feature branch.
create table if not exists public.tichor_hidden_messages (
  user_id uuid not null references auth.users(id) on delete cascade,
  message_id uuid not null references public.chat_messages(id) on delete cascade,
  hidden_at timestamptz not null default now(),
  primary key (user_id, message_id)
);
alter table public.tichor_hidden_messages enable row level security;
grant select,insert,delete on public.tichor_hidden_messages to authenticated;
drop policy if exists tichor_hidden_own_select on public.tichor_hidden_messages;
create policy tichor_hidden_own_select on public.tichor_hidden_messages for select to authenticated using (user_id=auth.uid());
drop policy if exists tichor_hidden_own_insert on public.tichor_hidden_messages;
create policy tichor_hidden_own_insert on public.tichor_hidden_messages for insert to authenticated
with check (user_id=auth.uid() and exists (
 select 1 from public.chat_messages m where m.id=message_id and (m.sender_id=auth.uid() or m.recipient_id=auth.uid())
));
drop policy if exists tichor_hidden_own_delete on public.tichor_hidden_messages;
create policy tichor_hidden_own_delete on public.tichor_hidden_messages for delete to authenticated using (user_id=auth.uid());

create table if not exists public.tichor_attachments (
 id uuid primary key default gen_random_uuid(),
 message_id uuid not null unique references public.chat_messages(id) on delete cascade,
 sender_id uuid not null references auth.users(id),
 recipient_id uuid not null references auth.users(id),
 storage_path text not null unique,
 file_name text not null,
 mime_type text not null,
 byte_size bigint not null check (byte_size > 0 and byte_size <= 10485760),
 created_at timestamptz not null default now(),
 constraint tichor_attachment_path check (storage_path like sender_id::text || '/%')
);
alter table public.tichor_attachments enable row level security;
grant select,insert,delete on public.tichor_attachments to authenticated;
drop policy if exists tichor_attachments_participants_read on public.tichor_attachments;
create policy tichor_attachments_participants_read on public.tichor_attachments for select to authenticated
using (auth.uid()=sender_id or auth.uid()=recipient_id);
drop policy if exists tichor_attachments_sender_insert on public.tichor_attachments;
create policy tichor_attachments_sender_insert on public.tichor_attachments for insert to authenticated
with check (
 sender_id=auth.uid() and exists (
  select 1 from public.chat_messages m where m.id=message_id
  and m.sender_id=auth.uid() and m.recipient_id=tichor_attachments.recipient_id
 )
);
drop policy if exists tichor_attachments_sender_delete on public.tichor_attachments;
create policy tichor_attachments_sender_delete on public.tichor_attachments for delete to authenticated using (sender_id=auth.uid());

-- Sender can delete a message for everyone. Existing read/update policies remain unchanged.
grant delete on public.chat_messages to authenticated;
drop policy if exists tichor_sender_delete_message on public.chat_messages;
create policy tichor_sender_delete_message on public.chat_messages for delete to authenticated
using (sender_id=auth.uid());

insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
values ('tichor-attachments','tichor-attachments',false,10485760,
array['application/pdf','application/msword','application/vnd.openxmlformats-officedocument.wordprocessingml.document',
'application/vnd.ms-excel','application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
'image/png','image/jpeg','image/webp','text/plain'])
on conflict (id) do update set public=false,file_size_limit=10485760,allowed_mime_types=excluded.allowed_mime_types;

drop policy if exists tichor_storage_upload_own on storage.objects;
create policy tichor_storage_upload_own on storage.objects for insert to authenticated
with check (
 bucket_id='tichor-attachments'
 and (storage.foldername(name))[1]=auth.uid()::text
 and exists (
   select 1 from public.chat_messages m
   where m.id::text=(storage.foldername(name))[2]
   and m.sender_id=auth.uid()
 )
);
drop policy if exists tichor_storage_participant_read on storage.objects;
create policy tichor_storage_participant_read on storage.objects for select to authenticated
using (
 bucket_id='tichor-attachments'
 and (
   -- Uploading sender must be able to access their own pending object for cleanup.
   (storage.foldername(name))[1]=auth.uid()::text
   or exists (
     select 1 from public.tichor_attachments a
     where a.storage_path=name and a.recipient_id=auth.uid()
   )
 )
);
drop policy if exists tichor_storage_sender_delete on storage.objects;
create policy tichor_storage_sender_delete on storage.objects for delete to authenticated
using (bucket_id='tichor-attachments' and (storage.foldername(name))[1]=auth.uid()::text);
