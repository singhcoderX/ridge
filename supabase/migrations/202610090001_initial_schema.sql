create extension if not exists pgcrypto;

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  username text not null,
  public_key text,
  created_at timestamptz not null default now()
);
create unique index profiles_username_lower_unique on public.profiles (lower(username));

create table public.key_backups (
  user_id uuid primary key references auth.users(id) on delete cascade,
  encrypted_private_key jsonb not null,
  updated_at timestamptz not null default now()
);

create table public.conversations (
  id uuid primary key default gen_random_uuid(),
  type text not null check (type in ('dm', 'group')),
  name text,
  encrypted boolean not null default false,
  created_by uuid not null references auth.users(id),
  dm_key text unique,
  created_at timestamptz not null default now(),
  check ((type = 'dm' and name is null and dm_key is not null) or (type = 'group' and name is not null and dm_key is null))
);

create table public.conversation_members (
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  last_read_message_id bigint not null default 0,
  wrapped_key jsonb,
  joined_at timestamptz not null default now(),
  primary key (conversation_id, user_id)
);
create index conversation_members_user_id on public.conversation_members(user_id);

create table public.messages (
  id bigint generated always as identity primary key,
  conversation_id uuid not null references public.conversations(id) on delete cascade,
  sender_id uuid not null references auth.users(id),
  body text not null,
  deleted boolean not null default false,
  pinned boolean not null default false,
  created_at timestamptz not null default now(),
  edited_at timestamptz
);
create index messages_conversation_id_id on public.messages(conversation_id, id desc);
alter table public.messages add constraint messages_body_length_check
check ((deleted and body = '') or (not deleted and length(body) between 1 and 24000));
alter table public.messages replica identity full;

create or replace function public.create_profile_for_new_user()
returns trigger language plpgsql security definer set search_path = '' as $$
declare requested_username text;
begin
  requested_username := new.raw_user_meta_data ->> 'username';
  if requested_username is null or requested_username !~ '^[A-Za-z0-9_]{3,20}$' or lower(requested_username) = 'assistant' then
    raise exception 'Choose a valid username (3–20 letters, numbers, or underscores).';
  end if;
  insert into public.profiles(id, username) values (new.id, requested_username);
  return new;
end;
$$;
create trigger create_profile_after_signup after insert on auth.users
for each row execute function public.create_profile_for_new_user();

create or replace function public.is_conversation_member(p_conversation_id uuid)
returns boolean language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.conversation_members cm
    where cm.conversation_id = p_conversation_id and cm.user_id = (select auth.uid())
  );
$$;
revoke all on function public.is_conversation_member(uuid) from public;
grant execute on function public.is_conversation_member(uuid) to authenticated;

create or replace function public.create_dm(p_other_user_id uuid, p_encrypted boolean, p_keys jsonb)
returns uuid language plpgsql security definer set search_path = '' as $$
declare
  me uuid := auth.uid();
  dmkey text;
  conversation_id uuid;
  other_key text;
  my_wrap jsonb;
  other_wrap jsonb;
begin
  if me is null or p_other_user_id is null or p_other_user_id = me then raise exception 'Pick another user.'; end if;
  if not exists (select 1 from public.profiles where id = p_other_user_id) then raise exception 'User not found.'; end if;
  if p_encrypted then
    if not exists (select 1 from public.profiles where id = me and public_key is not null) then raise exception 'Your encryption key is missing.'; end if;
    select public_key into other_key from public.profiles where id = p_other_user_id;
    if other_key is null then raise exception 'The other person has no encryption key yet.'; end if;
    my_wrap := p_keys -> (me::text);
    other_wrap := p_keys -> (p_other_user_id::text);
    if my_wrap is null or other_wrap is null or (my_wrap ->> 'by') <> me::text or (other_wrap ->> 'by') <> me::text then
      raise exception 'Conversation encryption keys are incomplete.';
    end if;
  end if;
  dmkey := least(me::text, p_other_user_id::text) || ':' || greatest(me::text, p_other_user_id::text) || ':' || p_encrypted::text;
  insert into public.conversations(type, encrypted, created_by, dm_key)
  values ('dm', p_encrypted, me, dmkey)
  on conflict (dm_key) do update set dm_key = excluded.dm_key
  returning id into conversation_id;
  insert into public.conversation_members(conversation_id, user_id, wrapped_key)
  values (conversation_id, me, my_wrap), (conversation_id, p_other_user_id, other_wrap)
  on conflict do nothing;
  return conversation_id;
end;
$$;

create or replace function public.create_group(p_name text, p_member_ids uuid[], p_encrypted boolean, p_keys jsonb)
returns uuid language plpgsql security definer set search_path = '' as $$
declare
  me uuid := auth.uid();
  ids uuid[];
  conversation_id uuid;
  member_id uuid;
  wrapped jsonb;
begin
  if me is null then raise exception 'Please sign in.'; end if;
  if length(trim(coalesce(p_name, ''))) not between 1 and 40 then raise exception 'Give the group a name (up to 40 characters).'; end if;
  select array_agg(distinct member_id) into ids
  from unnest(coalesce(p_member_ids, '{}'::uuid[]) || array[me]) as members(member_id);
  if cardinality(ids) < 2 then raise exception 'Add at least one other member.'; end if;
  if (select count(*) from public.profiles where id = any(ids)) <> cardinality(ids) then raise exception 'A selected user no longer exists.'; end if;
  if p_encrypted then
    if exists (select 1 from public.profiles where id = any(ids) and public_key is null) then raise exception 'Everyone in an encrypted group needs an encryption key.'; end if;
    foreach member_id in array ids loop
      wrapped := p_keys -> (member_id::text);
      if wrapped is null or (wrapped ->> 'by') <> me::text then raise exception 'Encryption keys are incomplete.'; end if;
    end loop;
  end if;
  insert into public.conversations(type, name, encrypted, created_by)
  values ('group', trim(p_name), p_encrypted, me) returning id into conversation_id;
  foreach member_id in array ids loop
    insert into public.conversation_members(conversation_id, user_id, wrapped_key)
    values (conversation_id, member_id, case when p_encrypted then p_keys -> (member_id::text) else null end);
  end loop;
  return conversation_id;
end;
$$;

create or replace function public.edit_message(p_message_id bigint, p_body text)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if length(trim(coalesce(p_body, ''))) not between 1 and 24000 then raise exception 'Message cannot be empty.'; end if;
  update public.messages set body = p_body, edited_at = now()
  where id = p_message_id and sender_id = auth.uid() and not deleted
    and public.is_conversation_member(conversation_id);
  if not found then raise exception 'Message not found or you cannot edit it.'; end if;
end;
$$;

create or replace function public.delete_message(p_message_id bigint)
returns void language plpgsql security definer set search_path = '' as $$
begin
  update public.messages set deleted = true, body = '', pinned = false
  where id = p_message_id and sender_id = auth.uid() and not deleted
    and public.is_conversation_member(conversation_id);
  if not found then raise exception 'Message not found or you cannot delete it.'; end if;
end;
$$;

create or replace function public.toggle_pin(p_message_id bigint, p_pinned boolean)
returns void language plpgsql security definer set search_path = '' as $$
begin
  update public.messages set pinned = p_pinned
  where id = p_message_id and not deleted and public.is_conversation_member(conversation_id);
  if not found then raise exception 'Message not found or you are not a member.'; end if;
end;
$$;

create or replace function public.set_read(p_conversation_id uuid, p_message_id bigint)
returns void language plpgsql security definer set search_path = '' as $$
begin
  if not exists (select 1 from public.messages where id = p_message_id and conversation_id = p_conversation_id) then
    raise exception 'Message does not belong to this conversation.';
  end if;
  update public.conversation_members set last_read_message_id = greatest(last_read_message_id, p_message_id)
  where conversation_id = p_conversation_id and user_id = auth.uid();
  if not found then raise exception 'You are not a member of this conversation.'; end if;
end;
$$;

revoke all on function public.create_dm(uuid, boolean, jsonb) from public;
revoke all on function public.create_group(text, uuid[], boolean, jsonb) from public;
revoke all on function public.edit_message(bigint, text) from public;
revoke all on function public.delete_message(bigint) from public;
revoke all on function public.toggle_pin(bigint, boolean) from public;
revoke all on function public.set_read(uuid, bigint) from public;
grant execute on function public.create_dm(uuid, boolean, jsonb) to authenticated;
grant execute on function public.create_group(text, uuid[], boolean, jsonb) to authenticated;
grant execute on function public.edit_message(bigint, text) to authenticated;
grant execute on function public.delete_message(bigint) to authenticated;
grant execute on function public.toggle_pin(bigint, boolean) to authenticated;
grant execute on function public.set_read(uuid, bigint) to authenticated;

alter table public.profiles enable row level security;
alter table public.key_backups enable row level security;
alter table public.conversations enable row level security;
alter table public.conversation_members enable row level security;
alter table public.messages enable row level security;

create policy "Authenticated users can find public profiles" on public.profiles
for select to authenticated using (true);
create policy "Users can edit their own profile" on public.profiles
for update to authenticated using (id = (select auth.uid())) with check (id = (select auth.uid()));
create policy "Users can read their own key backup" on public.key_backups
for select to authenticated using (user_id = (select auth.uid()));
create policy "Users can write their own key backup" on public.key_backups
for insert to authenticated with check (user_id = (select auth.uid()));
create policy "Users can refresh their own key backup" on public.key_backups
for update to authenticated using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));
create policy "Members can read their conversations" on public.conversations
for select to authenticated using (public.is_conversation_member(id));
create policy "Members can read membership rows" on public.conversation_members
for select to authenticated using (public.is_conversation_member(conversation_id));
create policy "Users can update their own membership state" on public.conversation_members
for update to authenticated using (user_id = (select auth.uid())) with check (user_id = (select auth.uid()));
create policy "Members can read messages" on public.messages
for select to authenticated using (public.is_conversation_member(conversation_id));
create policy "Members can send messages as themselves" on public.messages
for insert to authenticated with check (
  sender_id = (select auth.uid()) and public.is_conversation_member(conversation_id)
);

grant select on public.profiles, public.conversations, public.conversation_members, public.messages to authenticated;
grant update (public_key) on public.profiles to authenticated;
grant select, insert, update on public.key_backups to authenticated;
grant update (last_read_message_id) on public.conversation_members to authenticated;
grant insert on public.messages to authenticated;
grant usage, select on sequence public.messages_id_seq to authenticated;

create policy "Conversation members can receive room events" on realtime.messages
for select to authenticated using (
  realtime.topic() ~ '^conv:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
  and public.is_conversation_member(substring(realtime.topic() from 6)::uuid)
);
create policy "Conversation members can broadcast room events" on realtime.messages
for insert to authenticated with check (
  realtime.topic() ~ '^conv:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
  and public.is_conversation_member(substring(realtime.topic() from 6)::uuid)
);
create policy "Users can receive their membership events" on realtime.messages
for select to authenticated using (
  realtime.topic() = 'user:' || (select auth.uid())::text
);

do $$
begin
  if not exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'messages'
  ) then
    alter publication supabase_realtime add table public.messages;
  end if;
  if not exists (
    select 1 from pg_publication_tables
    where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = 'conversation_members'
  ) then
    alter publication supabase_realtime add table public.conversation_members;
  end if;
end;
$$;
