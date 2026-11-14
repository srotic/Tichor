-- Tichor v11, idempotent migration for existing v9 installations.
-- Tichor v10: Run once in Supabase SQL Editor after v9.
-- Read receipts and saved contacts for registered users.
create table if not exists public.tichor_contacts (
 owner_id uuid not null references auth.users(id) on delete cascade,
 contact_id uuid not null references auth.users(id) on delete cascade,
 label text not null default 'Tichor contact',
 created_at timestamptz not null default now(),
 primary key(owner_id,contact_id),
 constraint contact_not_self check(owner_id<>contact_id)
);
alter table public.tichor_contacts enable row level security;
grant select,insert,update,delete on public.tichor_contacts to authenticated;
drop policy if exists contacts_own_select on public.tichor_contacts;
create policy contacts_own_select on public.tichor_contacts for select to authenticated using (owner_id=auth.uid());
drop policy if exists contacts_own_insert on public.tichor_contacts;
create policy contacts_own_insert on public.tichor_contacts for insert to authenticated with check (owner_id=auth.uid());
drop policy if exists contacts_own_update on public.tichor_contacts;
create policy contacts_own_update on public.tichor_contacts for update to authenticated using (owner_id=auth.uid()) with check (owner_id=auth.uid());
drop policy if exists contacts_own_delete on public.tichor_contacts;
create policy contacts_own_delete on public.tichor_contacts for delete to authenticated using (owner_id=auth.uid());

grant update on public.chat_messages to authenticated;
alter table public.chat_messages add column if not exists delivered_at timestamptz;
alter table public.chat_messages add column if not exists read_at timestamptz;
-- Only recipient can set receipts. Existing message read policy must already permit participants.
drop policy if exists chat_recipient_receipts on public.chat_messages;
create policy chat_recipient_receipts on public.chat_messages for update to authenticated
 using (recipient_id=auth.uid()) with check (recipient_id=auth.uid());
-- Protect immutable message fields, including sender/recipient/body, from changes via receipt updates.
create or replace function public.tichor_receipt_guard() returns trigger language plpgsql set search_path = '' as $$
begin
 if (new.id,new.sender_id,new.recipient_id,new.body,new.created_at) is distinct from
    (old.id,old.sender_id,old.recipient_id,old.body,old.created_at) then
   raise exception 'Message fields cannot be changed';
 end if;
 if auth.uid() is distinct from old.recipient_id then raise exception 'Only the recipient may acknowledge a message'; end if;
 if old.delivered_at is not null and new.delivered_at is distinct from old.delivered_at then raise exception 'Delivery timestamp cannot be changed'; end if;
 if old.read_at is not null and new.read_at is distinct from old.read_at then raise exception 'Read timestamp cannot be changed'; end if;
 if new.read_at is not null and new.delivered_at is null then new.delivered_at := new.read_at; end if;
 return new;
end $$;
drop trigger if exists tichor_receipt_guard_trigger on public.chat_messages;
create trigger tichor_receipt_guard_trigger before update on public.chat_messages
 for each row execute function public.tichor_receipt_guard();
