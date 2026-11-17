-- TichorConnect group messaging: run in Supabase SQL editor before enabling the group UI.
create table if not exists public.tichor_groups (
 id uuid primary key default gen_random_uuid(),
 name text not null check (char_length(trim(name)) between 1 and 80),
 owner_id uuid not null references auth.users(id),
 members_can_invite boolean not null default false,
 created_at timestamptz not null default now()
);
create table if not exists public.tichor_group_members (
 group_id uuid not null references public.tichor_groups(id) on delete cascade,
 user_id uuid not null references auth.users(id),
 role text not null default 'member' check(role in ('owner','admin','member')),
 joined_at timestamptz not null default now(),
 primary key(group_id,user_id)
);
create table if not exists public.tichor_group_invites (
 id uuid primary key default gen_random_uuid(),
 group_id uuid not null references public.tichor_groups(id) on delete cascade,
 invited_user uuid not null references auth.users(id),
 invited_by uuid not null references auth.users(id),
 status text not null default 'pending' check(status in ('pending','accepted','declined')),
 created_at timestamptz not null default now(),
 unique(group_id,invited_user)
);
create table if not exists public.tichor_group_messages (
 id uuid primary key default gen_random_uuid(),
 group_id uuid not null references public.tichor_groups(id) on delete cascade,
 sender_id uuid not null references auth.users(id),
 body text not null check(char_length(trim(body)) between 1 and 5000),
 created_at timestamptz not null default now()
);
create index if not exists tichor_group_messages_recent on public.tichor_group_messages(group_id,created_at desc);
create index if not exists tichor_group_invites_recipient on public.tichor_group_invites(invited_user,status);
create or replace function public.tichor_group_member(g uuid, u uuid)
returns boolean language sql stable security definer set search_path = '' as $$
 select exists(select 1 from public.tichor_group_members m where m.group_id=g and m.user_id=u)
$$;
create or replace function public.tichor_group_admin(g uuid,u uuid)
returns boolean language sql stable security definer set search_path = '' as $$
 select exists(select 1 from public.tichor_group_members m where m.group_id=g and m.user_id=u and m.role in ('owner','admin'))
$$;
revoke all on function public.tichor_group_member(uuid,uuid) from public;
revoke all on function public.tichor_group_admin(uuid,uuid) from public;
grant execute on function public.tichor_group_member(uuid,uuid) to authenticated;
grant execute on function public.tichor_group_admin(uuid,uuid) to authenticated;
create or replace function public.tichor_group_create(group_name text)
returns uuid language plpgsql security definer set search_path = '' as $$
declare gid uuid;
begin
 if auth.uid() is null or length(trim(group_name)) not between 1 and 80 then raise exception 'Invalid group name'; end if;
 insert into public.tichor_groups(name,owner_id) values(trim(group_name),auth.uid()) returning id into gid;
 insert into public.tichor_group_members(group_id,user_id,role) values(gid,auth.uid(),'owner');
 return gid;
end $$;
create or replace function public.tichor_group_invite(g uuid, recipient uuid)
returns void language plpgsql security definer set search_path = '' as $$
begin
 if auth.uid() is null or recipient=auth.uid() then raise exception 'Invalid invitation'; end if;
 if not exists(select 1 from public.tichor_groups x where x.id=g and (x.members_can_invite and public.tichor_group_member(g,auth.uid()) or public.tichor_group_admin(g,auth.uid()))) then raise exception 'Not allowed to invite'; end if;
 if public.tichor_group_member(g,recipient) then raise exception 'Already a member'; end if;
 insert into public.tichor_group_invites(group_id,invited_user,invited_by,status) values(g,recipient,auth.uid(),'pending')
 on conflict(group_id,invited_user) do update set invited_by=excluded.invited_by,status='pending',created_at=now();
end $$;
create or replace function public.tichor_group_respond(invite_id uuid, accept_invite boolean)
returns void language plpgsql security definer set search_path = '' as $$
declare inv public.tichor_group_invites%rowtype;
begin
 select * into inv from public.tichor_group_invites where id=invite_id and invited_user=auth.uid() and status='pending' for update;
 if not found then raise exception 'Invitation unavailable'; end if;
 if accept_invite then
  insert into public.tichor_group_members(group_id,user_id,role) values(inv.group_id,auth.uid(),'member') on conflict do nothing;
 end if;
 update public.tichor_group_invites set status=case when accept_invite then 'accepted' else 'declined' end where id=invite_id;
end $$;
create or replace function public.tichor_group_set_invites(g uuid, allow_members boolean)
returns void language plpgsql security definer set search_path = '' as $$
begin
 if not public.tichor_group_admin(g,auth.uid()) then raise exception 'Admins only'; end if;
 update public.tichor_groups set members_can_invite=allow_members where id=g;
end $$;
create or replace function public.tichor_group_set_admin(g uuid, target uuid, make_admin boolean)
returns void language plpgsql security definer set search_path = '' as $$
begin
 if not public.tichor_group_admin(g,auth.uid()) then raise exception 'Admins only'; end if;
 update public.tichor_group_members set role=case when make_admin then 'admin' else 'member' end
 where group_id=g and user_id=target and role<>'owner';
end $$;
create or replace function public.tichor_group_leave(g uuid)
returns void language plpgsql security definer set search_path = '' as $$
begin
 if exists(select 1 from public.tichor_groups where id=g and owner_id=auth.uid()) then raise exception 'Owner must transfer ownership or delete group'; end if;
 delete from public.tichor_group_members where group_id=g and user_id=auth.uid();
end $$;
revoke all on function public.tichor_group_create(text),public.tichor_group_invite(uuid,uuid),public.tichor_group_respond(uuid,boolean),public.tichor_group_set_invites(uuid,boolean),public.tichor_group_set_admin(uuid,uuid,boolean),public.tichor_group_leave(uuid) from public;
grant execute on function public.tichor_group_create(text),public.tichor_group_invite(uuid,uuid),public.tichor_group_respond(uuid,boolean),public.tichor_group_set_invites(uuid,boolean),public.tichor_group_set_admin(uuid,uuid,boolean),public.tichor_group_leave(uuid) to authenticated;
alter table public.tichor_groups enable row level security;
alter table public.tichor_group_members enable row level security;
alter table public.tichor_group_invites enable row level security;
alter table public.tichor_group_messages enable row level security;
create policy "members read groups" on public.tichor_groups for select to authenticated using(public.tichor_group_member(id,auth.uid()));
create policy "members read membership" on public.tichor_group_members for select to authenticated using(public.tichor_group_member(group_id,auth.uid()));
create policy "recipients read invitations" on public.tichor_group_invites for select to authenticated using(invited_user=auth.uid());
create policy "members read group messages" on public.tichor_group_messages for select to authenticated using(public.tichor_group_member(group_id,auth.uid()));
create policy "members send group messages" on public.tichor_group_messages for insert to authenticated with check(sender_id=auth.uid() and public.tichor_group_member(group_id,auth.uid()));
-- Group messages are not end-to-end encrypted in this initial schema.
