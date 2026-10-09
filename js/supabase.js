import { createClient } from 'https://esm.sh/@supabase/supabase-js@2';
import { SUPABASE_URL, SUPABASE_ANON_KEY, isConfigured } from './config.js';

export const configured = isConfigured();
export const supabase = configured ? createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: { persistSession: true, autoRefreshToken: true, detectSessionInUrl: true }
}) : null;

const fail = error => { if (error) throw new Error(error.message || 'The request could not be completed.'); };
const one = async query => { const { data, error } = await query; fail(error); return data; };
const usernamePattern = /^[a-zA-Z0-9_]{3,20}$/;
const roomChannels = new Map();
let membershipChannel;

function waitForChannel(channel) {
  return new Promise((resolve, reject) => channel.subscribe((status, error) => {
    if (status === 'SUBSCRIBED') return resolve();
    if (['CHANNEL_ERROR', 'TIMED_OUT', 'CLOSED'].includes(status)) {
      const detail = error?.message || error?.reason || error?.code || '';
      reject(new Error(`Realtime ${status.toLowerCase()}${detail ? `: ${detail}` : '. Check the Supabase Realtime service and channel policies.'}`));
    }
  }));
}

function profile(row) {
  return { id: row.id, username: row.username, pub: row.public_key || null };
}

function message(row, names) {
  return {
    id: Number(row.id), cid: row.conversation_id, senderId: row.sender_id,
    senderName: names.get(row.sender_id) || 'Someone', body: row.deleted ? '' : row.body,
    kind: 'text', deleted: !!row.deleted, pinned: !!row.pinned,
    createdAt: row.created_at, editedAt: row.edited_at || null
  };
}

async function namesFor(ids) {
  if (!ids.length) return new Map();
  const rows = await one(supabase.from('profiles').select('id,username').in('id', ids));
  return new Map(rows.map(row => [row.id, row.username]));
}

export async function register({ email, password, username, captchaToken }) {
  if (!usernamePattern.test(username)) throw new Error('Username must be 3–20 letters, numbers or underscores.');
  if (username.toLowerCase() === 'assistant') throw new Error('That username is reserved.');
  const { data, error } = await supabase.auth.signUp({
    email, password,
    options: { data: { username }, captchaToken: captchaToken || undefined }
  });
  fail(error);
  if (!data.session) throw new Error('Account created. Check your email to finish signing up. Email confirmation must be disabled in the Supabase dashboard for this $0 setup.');
  return data.user;
}

export async function signIn(email, password, captchaToken) {
  const { data, error } = await supabase.auth.signInWithPassword({
    email, password, options: { captchaToken: captchaToken || undefined }
  });
  fail(error);
  return data.user;
}

export async function signOut() {
  closeRealtime();
  const { error } = await supabase.auth.signOut();
  fail(error);
}

export async function getMyProfile() {
  const { data: authData, error: authError } = await supabase.auth.getUser();
  fail(authError);
  if (!authData.user) throw new Error('Please sign in.');
  const row = await one(supabase.from('profiles').select('id,username,public_key').eq('id', authData.user.id).single());
  const backup = await one(supabase.from('key_backups').select('encrypted_private_key').eq('user_id', authData.user.id).maybeSingle());
  return { ...profile(row), email: authData.user.email, keyBackup: backup?.encrypted_private_key || null };
}

export async function saveIdentity(publicKey, keyBackup) {
  const { data: authData, error: authError } = await supabase.auth.getUser();
  fail(authError);
  if (!authData.user) throw new Error('Please sign in.');
  const user = await one(supabase.from('profiles').update({ public_key: publicKey })
    .eq('id', authData.user.id).select('id').single());
  const { error } = await supabase.from('key_backups').upsert({ user_id: user.id, encrypted_private_key: keyBackup });
  fail(error);
}

async function hydrateConversations(conversationRows, memberRows) {
  if (!conversationRows.length) return [];
  const memberIds = [...new Set(memberRows.map(row => row.user_id))];
  const profiles = await one(supabase.from('profiles').select('id,username,public_key').in('id', memberIds));
  const profileMap = new Map(profiles.map(row => [row.id, row]));
  const self = (await supabase.auth.getUser()).data.user;
  return Promise.all(conversationRows.map(async row => {
    const members = memberRows.filter(member => member.conversation_id === row.id).map(member => {
      const p = profileMap.get(member.user_id) || {};
      return { id: member.user_id, username: p.username || 'Someone', pub: p.public_key || null,
        lastRead: Number(member.last_read_message_id || 0), wrappedKey: member.wrapped_key || null };
    });
    const selfMember = members.find(member => member.id === self.user.id);
    const lastRows = await one(supabase.from('messages').select('*').eq('conversation_id', row.id).order('id', { ascending: false }).limit(1));
    const last = lastRows[0] ? message(lastRows[0], new Map(profiles.map(p => [p.id, p.username]))) : null;
    let unread = 0;
    if (selfMember) {
      const { count, error } = await supabase.from('messages').select('id', { count: 'exact', head: true })
        .eq('conversation_id', row.id).neq('sender_id', self.user.id).gt('id', selfMember.lastRead).eq('deleted', false);
      fail(error); unread = count || 0;
    }
    return { id: row.id, type: row.type, name: row.name, encrypted: row.encrypted,
      wrappedKey: selfMember?.wrappedKey || null, members, last, unread, createdAt: row.created_at };
  }));
}

export async function listConversations() {
  const user = (await supabase.auth.getUser()).data.user;
  const memberRows = await one(supabase.from('conversation_members')
    .select('conversation_id,user_id,last_read_message_id,wrapped_key').eq('user_id', user.id));
  if (!memberRows.length) return [];
  const ids = memberRows.map(row => row.conversation_id);
  const rows = await one(supabase.from('conversations').select('*').in('id', ids));
  const allMembers = await one(supabase.from('conversation_members')
    .select('conversation_id,user_id,last_read_message_id,wrapped_key').in('conversation_id', ids));
  const hydrated = await hydrateConversations(rows, allMembers);
  return hydrated.sort((a, b) => new Date(b.last?.createdAt || b.createdAt) - new Date(a.last?.createdAt || a.createdAt));
}

export async function searchUsers(query) {
  const user = (await supabase.auth.getUser()).data.user;
  const rows = await one(supabase.from('profiles').select('id,username,public_key')
    .neq('id', user.id).ilike('username', `%${query}%`).order('username').limit(20));
  return rows.map(row => ({ ...profile(row), online: false }));
}

export async function searchMessages(query, conversations) {
  if (query.length < 2) return [];
  const ids = [...conversations.values()].filter(c => !c.encrypted).map(c => c.id);
  if (!ids.length) return [];
  const rows = await one(supabase.from('messages').select('*').in('conversation_id', ids)
    .eq('deleted', false).ilike('body', `%${query}%`).order('id', { ascending: false }).limit(30));
  const names = await namesFor([...new Set(rows.map(row => row.sender_id))]);
  return rows.map(row => message(row, names));
}

export async function createDm(userId, encrypted, keys = {}) {
  return one(supabase.rpc('create_dm', { p_other_user_id: userId, p_encrypted: encrypted, p_keys: keys }));
}

export async function createGroup(name, memberIds, encrypted, keys = {}) {
  return one(supabase.rpc('create_group', {
    p_name: name.trim(), p_member_ids: memberIds, p_encrypted: encrypted, p_keys: keys
  }));
}

export async function getConversation(id) {
  const memberRows = await one(supabase.from('conversation_members')
    .select('conversation_id,user_id,last_read_message_id,wrapped_key').eq('conversation_id', id));
  const rows = await one(supabase.from('conversations').select('*').eq('id', id).single());
  return (await hydrateConversations([rows], memberRows))[0];
}

export async function loadMessages(id, { before, limit = 50, pinned = false } = {}) {
  let query = supabase.from('messages').select('*').eq('conversation_id', id);
  if (pinned) query = query.eq('pinned', true).eq('deleted', false).order('id', { ascending: false }).limit(20);
  else {
    if (before) query = query.lt('id', before);
    query = query.order('id', { ascending: false }).limit(limit);
  }
  const rows = await one(query);
  if (!pinned) rows.reverse();
  const names = await namesFor([...new Set(rows.map(row => row.sender_id))]);
  return rows.map(row => message(row, names));
}

export async function postMessage(conversationId, body) {
  const user = (await supabase.auth.getUser()).data.user;
  const row = await one(supabase.from('messages').insert({ conversation_id: conversationId, sender_id: user.id, body }).select('*').single());
  const names = await namesFor([user.id]);
  return message(row, names);
}

export async function mutateMessage(type, { cid, id, body, on }) {
  if (type === 'edit') return one(supabase.rpc('edit_message', { p_message_id: id, p_body: body }));
  if (type === 'delete') return one(supabase.rpc('delete_message', { p_message_id: id }));
  if (type === 'pin') return one(supabase.rpc('toggle_pin', { p_message_id: id, p_pinned: on }));
  if (type === 'read') return one(supabase.rpc('set_read', { p_conversation_id: cid, p_message_id: id }));
  throw new Error('Unknown message action.');
}

export async function subscribeConversation(conversation, handlers) {
  const id = conversation.id;
  if (roomChannels.has(id)) return;
  await supabase.realtime.setAuth();
  const channel = supabase.channel(`conv:${id}`, { config: { private: true, presence: { key: (await supabase.auth.getUser()).data.user.id } } });
  channel.on('postgres_changes', { event: '*', schema: 'public', table: 'messages', filter: `conversation_id=eq.${id}` }, async payload => {
    const row = payload.new?.id ? payload.new : payload.old;
    if (!row?.id) return;
    const names = await namesFor([row.sender_id]);
    handlers.message(message(row, names), payload.eventType);
  });
  channel.on('broadcast', { event: 'typing' }, ({ payload }) => handlers.typing(payload));
  channel.on('broadcast', { event: 'read' }, ({ payload }) => handlers.read(payload));
  channel.on('presence', { event: 'sync' }, () => handlers.presence(channel.presenceState()));
  roomChannels.set(id, channel);
  try {
    await waitForChannel(channel);
    await channel.track({ user_id: (await supabase.auth.getUser()).data.user.id, username: handlers.username });
  } catch (error) {
    roomChannels.delete(id);
    await supabase.removeChannel(channel).catch(() => {});
    throw error;
  }
}

export async function subscribeMemberships(onConversation) {
  if (membershipChannel) return;
  const user = (await supabase.auth.getUser()).data.user;
  await supabase.realtime.setAuth();
  const channel = supabase.channel(`user:${user.id}`, { config: { private: true } });
  channel.on('postgres_changes', {
    event: 'INSERT', schema: 'public', table: 'conversation_members', filter: `user_id=eq.${user.id}`
  }, payload => onConversation(payload.new.conversation_id));
  membershipChannel = channel;
  try {
    await waitForChannel(channel);
  } catch (error) {
    membershipChannel = null;
    await supabase.removeChannel(channel).catch(() => {});
    throw error;
  }
}

export async function broadcast(conversationId, event, payload) {
  const channel = roomChannels.get(conversationId);
  if (channel) await channel.send({ type: 'broadcast', event, payload });
}

export function closeRealtime() {
  for (const channel of roomChannels.values()) supabase.removeChannel(channel);
  roomChannels.clear();
  if (membershipChannel) supabase.removeChannel(membershipChannel);
  membershipChannel = null;
}
