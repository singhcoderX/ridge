import E2E from './crypto.js';
import * as db from './supabase.js';
import { TURNSTILE_SITE_KEY } from './config.js';

const $ = selector => document.querySelector(selector);
const el = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
};
const hue = value => [...value].reduce((n, ch) => (n * 31 + ch.charCodeAt(0)) % 360, 0);
const fmtTime = value => new Date(value).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

let me = null, priv = null, active = null, mode = 'login', captchaToken = '', turnstileId = null;
const convs = new Map(), msgs = new Map(), pins = new Map(), convKeys = new Map(), online = new Set(), typingNow = new Map();
let typingOff;

function privateKeyStore(mode, callback) {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open('ridge', 1);
    request.onupgradeneeded = () => request.result.createObjectStore('keys');
    request.onerror = () => reject(request.error);
    request.onsuccess = () => {
      const database = request.result, transaction = database.transaction('keys', mode);
      const requestValue = callback(transaction.objectStore('keys'));
      transaction.oncomplete = () => resolve(requestValue?.result);
      transaction.onerror = () => reject(transaction.error);
    };
  });
}
const savePrivateKey = key => privateKeyStore('readwrite', store => store.put(key, 'priv:' + me.id));
const loadPrivateKey = id => privateKeyStore('readonly', store => store.get('priv:' + id));
const removePrivateKey = id => privateKeyStore('readwrite', store => store.delete('priv:' + id));

function showAuth(note = '') {
  $('#app').classList.add('hidden');
  $('#auth').classList.remove('hidden');
  $('#a-err').textContent = note;
}

function renderCaptcha() {
  if (!TURNSTILE_SITE_KEY || TURNSTILE_SITE_KEY.includes('YOUR_')) {
    $('#captcha').classList.add('hidden');
    $('#captcha-note').textContent = '';
    return;
  }
  $('#captcha').classList.remove('hidden');
  const tryRender = () => {
    if (!window.turnstile) return setTimeout(tryRender, 150);
    if (turnstileId !== null) window.turnstile.remove(turnstileId);
    turnstileId = window.turnstile.render('#captcha', {
      sitekey: TURNSTILE_SITE_KEY,
      callback: token => { captchaToken = token; $('#captcha-note').textContent = ''; },
      'expired-callback': () => { captchaToken = ''; }
    });
  };
  tryRender();
}

function setMode(next) {
  mode = next;
  const registering = mode === 'register';
  $('#tab-login').classList.toggle('on', !registering);
  $('#tab-register').classList.toggle('on', registering);
  $('#a-go').textContent = registering ? 'Create account' : 'Sign in';
  $('#auth h1').textContent = registering ? 'Join Ridge' : 'Welcome back';
  $('#a-sub').textContent = registering ? 'Create an account and find your people.' : 'Sign in to pick up where you left off.';
  $('#username-label').classList.toggle('hidden', !registering);
  $('#captcha').classList.remove('hidden');
  renderCaptcha();
  $('#captcha-note').classList.toggle('hidden', !$('#captcha-note').textContent);
  $('#a-pass').autocomplete = registering ? 'new-password' : 'current-password';
  $('#a-err').textContent = '';
}

async function unlock(password) {
  me = await db.getMyProfile();
  if (me.keyBackup) {
    try { priv = await E2E.unlockIdentity(password, me.keyBackup); }
    catch { throw new Error('This password cannot unlock your encrypted chat keys. Password reset is unavailable in this version.'); }
  } else {
    const identity = await E2E.createIdentity(password);
    await db.saveIdentity(identity.publicKey, identity.keyBackup);
    me.publicKey = identity.publicKey;
    priv = identity.privateKey;
  }
  await savePrivateKey(priv);
  await startApp();
}

async function submitAuth() {
  const button = $('#a-go'), oldLabel = button.textContent;
  button.disabled = true;
  try {
    const email = $('#a-email').value.trim(), password = $('#a-pass').value;
    if (!email || !password) throw new Error('Enter your email and password.');
    if (mode === 'register') {
      const username = $('#a-user').value.trim();
      if (!username || password.length < 8) throw new Error('Choose a username and a password with at least 8 characters.');
      if (TURNSTILE_SITE_KEY && !TURNSTILE_SITE_KEY.includes('YOUR_') && !captchaToken) {
        throw new Error('Complete the verification challenge before creating an account.');
      }
      button.textContent = 'Creating account…';
      const user = await db.register({ email, password, username, captchaToken });
      const identity = await E2E.createIdentity(password);
      me = await db.getMyProfile();
      await db.saveIdentity(identity.publicKey, identity.keyBackup);
      me.publicKey = identity.publicKey;
      priv = identity.privateKey;
      await savePrivateKey(priv);
      if (!user) throw new Error('Account creation did not return a user.');
      await startApp();
    } else {
      button.textContent = 'Signing in…';
      await db.signIn(email, password, captchaToken);
      await unlock(password);
    }
    $('#a-pass').value = '';
    captchaToken = '';
    if (window.turnstile && turnstileId !== null) window.turnstile.reset(turnstileId);
  } catch (error) {
    $('#a-err').textContent = error.message || 'Sign-in failed.';
    captchaToken = '';
    if (window.turnstile && turnstileId !== null) window.turnstile.reset(turnstileId);
  } finally {
    button.disabled = false;
    button.textContent = oldLabel;
  }
}

$('#tab-login').onclick = () => setMode('login');
$('#tab-register').onclick = () => setMode('register');
$('#a-go').onclick = submitAuth;
$('#a-pass').onkeydown = event => { if (event.key === 'Enter') submitAuth(); };
$('#a-user').onkeydown = event => { if (event.key === 'Enter') $('#a-email').focus(); };
$('#a-email').onkeydown = event => { if (event.key === 'Enter') $('#a-pass').focus(); };
setMode('login');

$('#logout').onclick = async () => {
  db.closeRealtime();
  await db.signOut().catch(() => {});
  if (me) await removePrivateKey(me.id).catch(() => {});
  me = null; priv = null; active = null;
  convs.clear(); msgs.clear(); pins.clear(); convKeys.clear(); online.clear();
  showAuth();
};

function convKey(conversation) {
  if (!convKeys.has(conversation.id)) {
    const wrapped = conversation.wrappedKey;
    const author = conversation.members.find(member => member.id === wrapped?.by);
    convKeys.set(conversation.id, wrapped && author
      ? E2E.unwrapConvKey(wrapped, priv, author.pub)
      : Promise.reject(new Error('This conversation key is unavailable.')));
    convKeys.get(conversation.id).catch(() => convKeys.delete(conversation.id));
  }
  return convKeys.get(conversation.id);
}

async function decryptMessage(message) {
  const conversation = convs.get(message.cid);
  if (!conversation?.encrypted || message.deleted || message._decrypted) return message;
  try { message.body = await E2E.decryptText(await convKey(conversation), message.body); }
  catch { message.body = '🔒 This message could not be decrypted on this device.'; }
  message._decrypted = true;
  return message;
}

const other = conversation => conversation.members.find(member => member.id !== me.id) || conversation.members[0];
const title = conversation => conversation.type === 'group' ? conversation.name : other(conversation)?.username || 'Conversation';

function snippet(message) {
  if (!message) return 'No messages yet';
  if (message.deleted) return 'Message deleted';
  return (message.senderId === me.id ? 'You: ' : '') + message.body;
}

function renderList() {
  const list = $('#list');
  list.replaceChildren();
  const conversations = [...convs.values()].sort((a, b) =>
    new Date(b.last?.createdAt || b.createdAt) - new Date(a.last?.createdAt || a.createdAt));
  if (!conversations.length) list.append(Object.assign(el('li', 'muted', 'No chats yet. Search for a username above.'), { style: 'padding:14px' }));
  for (const conversation of conversations) {
    const row = el('li', 'row-item' + (conversation.id === active ? ' on' : ''));
    const name = title(conversation);
    const avatar = el('div', 'avatar' + (conversation.type === 'group' ? ' group' : ''), name[0]?.toUpperCase() || '?');
    avatar.style.background = `hsl(${hue(name)} 38% 36%)`;
    if (conversation.type === 'dm' && online.has(other(conversation)?.id)) avatar.append(el('span', 'dot'));
    const meta = el('div', 'meta'), top = el('div', 'top');
    top.append(el('span', 'name', (conversation.encrypted ? '🔒 ' : '') + name),
      el('span', 'muted', conversation.last ? fmtTime(conversation.last.createdAt) : ''));
    meta.append(top, el('div', 'snippet', snippet(conversation.last)));
    row.append(avatar, meta);
    if (conversation.unread) row.append(el('span', 'badge', String(Math.min(conversation.unread, 99))));
    row.onclick = () => openConversation(conversation.id);
    list.append(row);
  }
}

async function loadConversations() {
  const rows = await db.listConversations();
  convs.clear();
  for (const conversation of rows) {
    convs.set(conversation.id, conversation);
    if (conversation.last) await decryptMessage(conversation.last);
  }
  renderList();
  for (const conversation of rows) await subscribe(conversation);
  await db.subscribeMemberships(async () => {
    try { await loadConversations(); }
    catch (error) { showError(error); }
  });
}

async function runSearch() {
  const query = $('#find').value.trim(), box = $('#results');
  if (!query) { box.classList.add('hidden'); $('#list').classList.remove('hidden'); return; }
  const [users, messages] = await Promise.all([db.searchUsers(query, me?.id), db.searchMessages(query, convs)]);
  box.replaceChildren(); $('#list').classList.add('hidden'); box.classList.remove('hidden');
  if (users.length) box.append(el('div', 'muted', 'People'));
  for (const user of users) {
    const row = el('div', 'row-item'), avatar = el('div', 'avatar', user.username[0].toUpperCase());
    avatar.style.background = `hsl(${hue(user.username)} 38% 36%)`;
    row.append(avatar, Object.assign(el('div', 'name', user.username), { style: 'flex:1' }));
    if (user.pub) {
      const secret = el('button', 'lockbtn', '🔒 Secret'); secret.type = 'button';
      secret.onclick = event => { event.stopPropagation(); startDm(user, true).catch(showError); };
      row.append(secret);
    }
    row.onclick = () => startDm(user, false).catch(showError);
    box.append(row);
  }
  if (messages.length) box.append(el('div', 'muted', 'Messages'));
  for (const message of messages) {
    const conversation = convs.get(message.cid);
    if (!conversation) continue;
    const row = el('div', 'row-item'), meta = el('div', 'meta');
    meta.append(el('div', 'name', title(conversation)), el('div', 'snippet', `${message.senderName}: ${message.body}`));
    row.append(meta); row.onclick = () => openConversation(conversation.id); box.append(row);
  }
  if (!users.length && !messages.length) box.append(el('div', 'muted', 'No matches.'));
}

let findTimer;
$('#find').oninput = () => { clearTimeout(findTimer); findTimer = setTimeout(() => runSearch().catch(showError), 200); };

async function startDm(user, encrypted) {
  const keys = {};
  if (encrypted) {
    if (!user.pub || !me.publicKey) throw new Error('Both people need an encryption key.');
    const key = await E2E.newConvKey();
    keys[me.id] = await E2E.wrapConvKey(key, priv, me.publicKey, me.id);
    keys[user.id] = await E2E.wrapConvKey(key, priv, user.pub, me.id);
  }
  const id = await db.createDm(user.id, encrypted, keys);
  const conversation = await db.getConversation(id);
  convs.set(conversation.id, conversation);
  $('#find').value = ''; $('#results').classList.add('hidden'); $('#list').classList.remove('hidden');
  await subscribe(conversation); renderList(); await openConversation(conversation.id);
}

function renderMessages(forceBottom = false) {
  const box = $('#msgs'), conversation = convs.get(active), list = msgs.get(active) || [];
  const nearBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 120;
  box.replaceChildren();
  let lastDay = '', myLast;
  for (const message of list) if (message.senderId === me.id && !message.deleted) myLast = message;
  for (const message of list) {
    const day = new Date(message.createdAt).toDateString();
    if (day !== lastDay) { box.append(el('div', 'day', day === new Date().toDateString() ? 'Today' : day)); lastDay = day; }
    const mine = message.senderId === me.id;
    const bubble = el('div', 'msg' + (mine ? ' mine' : '') + (message.deleted ? ' deleted' : ''));
    bubble.dataset.id = message.id; bubble.tabIndex = 0;
    if (conversation.type === 'group' && !mine) bubble.append(el('span', 'who', message.senderName));
    if (message.deleted) bubble.append('Message deleted');
    else {
      if (message.pinned) bubble.append(el('span', 'pinned-tag', '📌 Pinned'));
      bubble.append(document.createTextNode(message.body));
      bubble.append(el('span', 't', fmtTime(message.createdAt) + (message.editedAt ? ' · edited' : '')));
      const tools = el('div', 'tools'), pin = el('button', null, message.pinned ? 'Unpin' : 'Pin');
      pin.onclick = () => db.mutateMessage('pin', { cid: active, id: message.id, on: !message.pinned }).catch(showError);
      tools.append(pin);
      if (mine) {
        const edit = el('button', null, 'Edit');
        edit.onclick = async () => {
          const next = prompt('Edit message', message.body)?.trim();
          if (!next || next === message.body) return;
          const body = conversation.encrypted ? await E2E.encryptText(await convKey(conversation), next) : next;
          await db.mutateMessage('edit', { cid: active, id: message.id, body }).catch(showError);
        };
        const remove = el('button', null, 'Delete');
        remove.onclick = () => { if (confirm('Delete this for everyone?')) db.mutateMessage('delete', { cid: active, id: message.id }).catch(showError); };
        tools.append(edit, remove);
      }
      bubble.append(tools);
    }
    box.append(bubble);
    if (message === myLast) {
      const others = conversation.members.filter(member => member.id !== me.id);
      if (others.length && others.every(member => member.lastRead >= message.id)) box.append(el('div', 'seen', 'Seen'));
    }
  }
  if (forceBottom || nearBottom) box.scrollTop = box.scrollHeight;
}

$('#msgs').onscroll = async event => {
  const box = event.target, list = msgs.get(active);
  if (box.scrollTop > 0 || !list?.length || list._done || list._busy) return;
  list._busy = true;
  try {
    const older = await decryptAll(await db.loadMessages(active, { before: list[0].id }));
    if (!older.length) { list._done = true; return; }
    const height = box.scrollHeight;
    list.unshift(...older); renderMessages(false);
    box.scrollTop = box.scrollHeight - height;
  } catch (error) { showError(error); }
  finally { list._busy = false; }
};

function renderPins() {
  const list = pins.get(active) || [], bar = $('#pinbar');
  if (!list.length) { bar.classList.add('hidden'); return; }
  const message = list[0]; bar.classList.remove('hidden'); bar.replaceChildren();
  bar.append(el('span', 'pin-n', '📌'), el('span', 'pin-t', message.body));
  bar.onclick = () => $(`.msg[data-id="${message.id}"]`)?.scrollIntoView({ block: 'center', behavior: 'smooth' });
}

async function openConversation(id) {
  active = id;
  let conversation = convs.get(id);
  if (!conversation) { conversation = await db.getConversation(id); convs.set(id, conversation); }
  $('#app').classList.add('in-chat'); $('#empty').classList.add('hidden'); $('#pane').classList.remove('hidden');
  $('#c-title').textContent = (conversation.encrypted ? '🔒 ' : '') + title(conversation);
  $('#c-sub').textContent = conversation.encrypted ? 'End-to-end encrypted' : conversation.members.map(m => m.username).join(', ');
  $('#verify').classList.toggle('hidden', !(conversation.encrypted && conversation.type === 'dm'));
  $('#verify').onclick = async () => {
    const person = other(conversation);
    alert(`Safety code for you and ${person.username}:\n\n${await E2E.fingerprint(me.publicKey, person.pub)}\n\nCompare this with them on another trusted channel.`);
  };
  if (!msgs.has(id)) msgs.set(id, await decryptAll(await db.loadMessages(id)));
  if (!pins.has(id)) pins.set(id, await decryptAll(await db.loadMessages(id, { pinned: true })));
  await subscribe(conversation);
  if (active !== id) return;
  renderMessages(true); renderPins(); renderList(); markRead(); $('#text').focus({ preventScroll: true });
}

async function decryptAll(list) { await Promise.all(list.map(decryptMessage)); return list; }

function markRead() {
  const conversation = convs.get(active), list = msgs.get(active);
  if (!conversation || !list?.length || document.hidden) return;
  const id = list[list.length - 1].id, self = conversation.members.find(member => member.id === me.id);
  if (self && self.lastRead < id) {
    self.lastRead = id; conversation.unread = 0; renderList();
    db.mutateMessage('read', { cid: active, id }).catch(showError);
    db.broadcast(active, 'read', { userId: me.id, messageId: id });
  }
}
document.addEventListener('visibilitychange', markRead);

function showTyping(payload) {
  if (!payload?.userId || payload.userId === me.id) return;
  let users = typingNow.get(active);
  if (!users) typingNow.set(active, users = new Map());
  const previous = users.get(payload.userId);
  if (previous) clearTimeout(previous.timer);
  if (payload.on) users.set(payload.userId, { name: payload.username, timer: setTimeout(() => { users.delete(payload.userId); renderTyping(); }, 3500) });
  else users.delete(payload.userId);
  renderTyping();
}
function renderTyping() {
  const names = [...(typingNow.get(active)?.values() || [])].map(value => value.name);
  $('#typing').textContent = names.length ? `${names.join(', ')} ${names.length > 1 ? 'are' : 'is'} typing…` : '';
}

async function subscribe(conversation) {
  await db.subscribeConversation(conversation, {
    username: me.username,
    message: async (incoming, eventType) => {
      await decryptMessage(incoming);
      const current = convs.get(incoming.cid);
      if (!current) { await loadConversations(); return; }
      const list = msgs.get(incoming.cid) || [];
      const index = list.findIndex(message => message.id === incoming.id);
      if (index >= 0) list[index] = incoming; else list.push(incoming);
      list.sort((a, b) => a.id - b.id);
      msgs.set(incoming.cid, list); current.last = incoming;
      if (eventType === 'INSERT' && incoming.senderId !== me.id && !(active === incoming.cid && !document.hidden)) current.unread++;
      const pinList = pins.get(incoming.cid);
      if (pinList) {
        const next = pinList.filter(message => message.id !== incoming.id);
        if (incoming.pinned && !incoming.deleted) next.unshift(incoming);
        pins.set(incoming.cid, next);
      }
      if (active === incoming.cid) { renderMessages(true); renderPins(); markRead(); }
      renderList();
    },
    typing: showTyping,
    read: payload => {
      const current = convs.get(conversation.id), member = current?.members.find(m => m.id === payload.userId);
      if (member) member.lastRead = Math.max(member.lastRead, payload.messageId);
      if (active === conversation.id) renderMessages(false);
    },
    presence: state => {
      for (const member of conversation.members) if (member.id !== me.id) {
        const present = Object.values(state).flat().some(entry => entry.user_id === member.id);
        if (present) online.add(member.id); else online.delete(member.id);
      }
      renderList();
      if (active === conversation.id) $('#c-sub').textContent = conversation.encrypted
        ? 'End-to-end encrypted · ' + (online.has(other(conversation).id) ? 'Online' : 'Offline')
        : conversation.members.map(m => m.username).join(', ');
    }
  });
}

$('#back').onclick = () => { $('#app').classList.remove('in-chat'); active = null; renderList(); };
$('#text').oninput = () => {
  $('#text').style.height = 'auto';
  $('#text').style.height = Math.min($('#text').scrollHeight, 120) + 'px';
  if (active) db.broadcast(active, 'typing', { userId: me.id, username: me.username, on: true });
  clearTimeout(typingOff);
  typingOff = setTimeout(() => active && db.broadcast(active, 'typing', { userId: me.id, username: me.username, on: false }), 1800);
};

async function sendText() {
  const text = $('#text'), value = text.value.trim(), conversation = convs.get(active);
  if (!value || !conversation) return;
  try {
    const body = conversation.encrypted ? await E2E.encryptText(await convKey(conversation), value) : value;
    await db.postMessage(conversation.id, body);
    text.value = ''; text.style.height = 'auto';
    clearTimeout(typingOff); db.broadcast(active, 'typing', { userId: me.id, username: me.username, on: false });
  } catch (error) { showError(error); }
}
$('#send').onclick = sendText;
$('#text').onkeydown = event => { if (event.key === 'Enter' && !event.shiftKey) { event.preventDefault(); sendText(); } };

const selected = new Map();
$('#new-group').onclick = () => {
  selected.clear(); $('#g-name').value = ''; $('#g-find').value = ''; $('#g-err').textContent = '';
  $('#g-enc').checked = false; $('#g-results').replaceChildren(); renderSelected(); $('#group-dlg').showModal();
};
function renderSelected() {
  const box = $('#g-picked'); box.replaceChildren();
  for (const [id, user] of selected) {
    const button = el('button', 'chip', `${user.username} ×`); button.type = 'button';
    button.onclick = () => { selected.delete(id); renderSelected(); };
    box.append(button);
  }
}
let groupTimer;
$('#g-find').oninput = () => {
  clearTimeout(groupTimer);
  groupTimer = setTimeout(async () => {
    const query = $('#g-find').value.trim(), box = $('#g-results'); box.replaceChildren();
    if (!query) return;
    try {
      for (const user of await db.searchUsers(query, me?.id)) {
        if (selected.has(user.id)) continue;
        const button = el('button', 'chip', user.username); button.type = 'button';
        button.onclick = () => { selected.set(user.id, user); renderSelected(); button.remove(); };
        box.append(button);
      }
    } catch (error) { box.append(el('span', 'err', error.message)); }
  }, 200);
};
$('#g-create').onclick = async () => {
  try {
    const encrypted = $('#g-enc').checked, keys = {};
    if (selected.size < 1) throw new Error('Add at least one other member.');
    if (encrypted) {
      const unavailable = [...selected.values()].filter(user => !user.pub).map(user => user.username);
      if (!me.publicKey || unavailable.length) throw new Error(`Encryption keys are missing${unavailable.length ? ': ' + unavailable.join(', ') : ''}.`);
      const key = await E2E.newConvKey();
      keys[me.id] = await E2E.wrapConvKey(key, priv, me.publicKey, me.id);
      for (const [id, user] of selected) keys[id] = await E2E.wrapConvKey(key, priv, user.pub, me.id);
    }
    const id = await db.createGroup($('#g-name').value, [...selected.keys()], encrypted, keys);
    const conversation = await db.getConversation(id);
    convs.set(id, conversation); $('#group-dlg').close(); await subscribe(conversation); renderList(); await openConversation(id);
  } catch (error) { $('#g-err').textContent = error.message; }
};

function showError(error) { console.error(error); alert(error?.message || 'Something went wrong.'); }

async function startApp() {
  $('#auth').classList.add('hidden'); $('#app').classList.remove('hidden', 'in-chat');
  $('#me-name').textContent = me.username;
  $('#pane').classList.add('hidden'); $('#empty').classList.remove('hidden');
  $('#conn').textContent = 'connecting…';
  try {
    await loadConversations();
    $('#conn').textContent = 'connected'; $('#conn').classList.add('on');
  } catch (error) {
    $('#conn').textContent = 'offline'; $('#conn').classList.remove('on');
    showError(error);
  }
}

if (!db.configured) {
  showAuth('Connect a Supabase project first: set its project URL and public anon key in js/config.js.');
} else {
  try {
    const { data: { session } } = await db.supabase.auth.getSession();
    if (session) {
      me = await db.getMyProfile();
      const cached = await loadPrivateKey(me.id);
      if (cached) { priv = cached; await startApp(); }
      else { await db.signOut(); showAuth('Sign in again with your password to unlock encrypted chats on this device.'); }
    } else showAuth();
  } catch (error) { showAuth(error.message); }
}

function initCaptchaScript() {
  if (!document.querySelector('script[data-turnstile]')) {
    const script = document.createElement('script');
    script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
    script.async = true; script.defer = true; script.dataset.turnstile = 'true';
    document.head.append(script);
  }
}
initCaptchaScript();
