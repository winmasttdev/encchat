(() => {
  'use strict';

  if (!window.mqtt) {
    document.body.insertAdjacentHTML('afterbegin',
      '<div style="position:fixed;inset:0;display:flex;align-items:center;justify-content:center;background:#0f1220;color:#ff6b6b;font-family:sans-serif">Не удалось загрузить mqtt.min.js. Проверь сеть.</div>');
    return;
  }

  const $ = id => document.getElementById(id);
  const enc = new TextEncoder();
  const dec = new TextDecoder();
  const PBKDF2_ITER = 310000;

  const state = {
    client: null,
    roomKey: null,
    topicRoom: '',
    keyFp: '',
    room: '',
    nick: '',
    sid: '',
    broker: '',
    history: [],
    online: {},
    seen: [],
    connected: false
  };

  const uid = () => Math.random().toString(16).slice(2, 8);

  function toB64(u8) {
    let bin = '';
    for (let i = 0; i < u8.length; i += 0x8000) {
      bin += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
    }
    return btoa(bin);
  }

  function fromB64(s) {
    const bin = atob(s);
    const u8 = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
    return u8;
  }

  const aadFor = topic => enc.encode('encchat/v2/' + topic);

  async function sha256hex(s) {
    const h = await crypto.subtle.digest('SHA-256', enc.encode(s));
    return [...new Uint8Array(h)].map(b => b.toString(16).padStart(2, '0')).join('');
  }

  async function topicRoom(room, pass) {
    const h = await sha256hex('encchat/v2\n' + room + '\n' + pass);
    return h.slice(0, 16);
  }

  async function fingerprint(key) {
    const iv = new Uint8Array(12);
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode('encchat-fp-v1')));
    const hex = [...ct.slice(0, 4)].map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    return hex.slice(0, 4) + '-' + hex.slice(4);
  }

  async function deriveKey(passphrase, room) {
    const material = await crypto.subtle.importKey('raw', enc.encode('encchat:' + passphrase), 'PBKDF2', false, ['deriveKey']);
    const salt = enc.encode('encchat:v1:' + room);
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: PBKDF2_ITER, hash: 'SHA-256' },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  async function encrypt(key, aad, text) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, key, enc.encode(text));
    return { v: 1, iv: toB64(iv), ct: toB64(new Uint8Array(ct)) };
  }

  async function decrypt(key, aad, obj) {
    const ct = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: fromB64(obj.iv), additionalData: aad },
      key,
      fromB64(obj.ct)
    );
    return dec.decode(ct);
  }

  async function encryptBlob(key, obj) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(obj)));
    return JSON.stringify({ iv: toB64(iv), ct: toB64(new Uint8Array(ct)) });
  }

  async function decryptBlob(key, s) {
    const obj = JSON.parse(s);
    const ct = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: fromB64(obj.iv) }, key, fromB64(obj.ct));
    return dec.decode(ct);
  }

  const msgTopic = () => 'encchat/v2/' + state.topicRoom + '/msg';
  const presTopic = sid => 'encchat/v2/' + state.topicRoom + '/pres/' + (sid || state.sid);
  const presSub = () => 'encchat/v2/' + state.topicRoom + '/pres/+';

  function setStatus(text, cls) {
    const el = $('status');
    el.textContent = text;
    el.className = 'status' + (cls ? ' ' + cls : '');
  }

  function fmtTime(t) {
    return new Date(t).toLocaleTimeString('ru-RU', { hour: '2-digit', minute: '2-digit' });
  }

  function renderMessage(msg) {
    const row = document.createElement('div');
    row.className = 'msg' + (msg.me ? ' me' : '');

    const bubble = document.createElement('div');
    bubble.className = 'bubble';

    if (!msg.me) {
      const meta = document.createElement('div');
      meta.className = 'meta';
      meta.textContent = msg.n + ' · ' + fmtTime(msg.t);
      bubble.appendChild(meta);
    } else {
      const meta = document.createElement('div');
      meta.className = 'meta';
      meta.textContent = fmtTime(msg.t);
      bubble.appendChild(meta);
    }

    const text = document.createElement('div');
    text.textContent = msg.m;
    bubble.appendChild(text);

    row.appendChild(bubble);
    $('messages').appendChild(row);
  }

  function renderAll() {
    $('messages').innerHTML = '';
    state.history.forEach(renderMessage);
    $('messages').scrollTop = $('messages').scrollHeight;
  }

  function renderUsers() {
    const online = Object.entries(state.online).filter(([, p]) => p.on);
    $('users').innerHTML = '';
    if (!online.length) {
      const s = document.createElement('span');
      s.className = 'user';
      s.textContent = 'никого в сети';
      $('users').appendChild(s);
      return;
    }
    online.forEach(([sid, p]) => {
      const s = document.createElement('span');
      s.className = 'user';
      s.textContent = p.n + (sid === state.sid ? ' (вы)' : '');
      $('users').appendChild(s);
    });
  }

  function addSystem(text) {
    const el = document.createElement('div');
    el.className = 'sys';
    el.textContent = text;
    $('messages').appendChild(el);
  }

  async function saveHistory() {
    if (!state.roomKey) return;
    try {
      const blob = await encryptBlob(state.roomKey, state.history.slice(-500));
      localStorage.setItem('encchat:hist:' + state.topicRoom, blob);
    } catch (e) { /* ignore */ }
  }

  function addMessage(msg) {
    state.history.push(msg);
    renderMessage(msg);
    saveHistory();
    $('messages').scrollTop = $('messages').scrollHeight;
  }

  async function join() {
    const nick = $('nick').value.trim();
    const room = ($('room').value.trim() || 'room').toLowerCase().replace(/[^a-z0-9-]/g, '-');
    const pass = $('pass').value;

    if (!nick) { $('nick').focus(); return; }
    if (pass.length < 6) { $('pass').focus(); return; }

    state.nick = nick;
    state.room = room;
    state.sid = uid();
    state.broker = $('broker').value;
    state.history = [];
    state.online = {};
    state.seen = [];

    try {
      state.roomKey = await deriveKey(pass, room);
      state.topicRoom = await topicRoom(room, pass);
      state.keyFp = await fingerprint(state.roomKey);
    } catch (e) {
      alert('Ошибка шифрования: ' + e.message);
      return;
    }

    const stored = localStorage.getItem('encchat:hist:' + state.topicRoom);
    if (stored) {
      try {
        state.history = JSON.parse(await decryptBlob(state.roomKey, stored));
      } catch (e) {
        alert('Неверная фраза-пароль: не удалось расшифровать историю этой комнаты.');
        return;
      }
    }

    localStorage.setItem('encchat:nick', nick);
    localStorage.setItem('encchat:room', room);
    localStorage.setItem('encchat:broker', state.broker);
    if ($('savePass').checked) {
      localStorage.setItem('encchat:pass', pass);
    } else {
      localStorage.removeItem('encchat:pass');
    }
    updateQuickBtn();

    $('setup').classList.add('hidden');
    $('chat').classList.remove('hidden');
    $('roomTitle').textContent = room;
    $('myId').textContent = state.sid;
    $('keyFp').textContent = state.keyFp;

    renderAll();
    connect();
    $('msgInput').focus();
  }

  function connect() {
    setStatus('подключение…');

    state.client = mqtt.connect(state.broker, {
      clientId: 'encchat_' + uid(),
      keepalive: 30,
      reconnectPeriod: 2000,
      connectTimeout: 10000,
      will: {
        topic: presTopic(),
        payload: JSON.stringify({ n: state.nick, on: false, t: Date.now() }),
        retain: true,
        qos: 1
      }
    });

    state.client.on('connect', onConnect);
    state.client.on('message', onMessage);
    state.client.on('reconnect', () => setStatus('переподключение…'));
    state.client.on('offline', () => setStatus('офлайн', 'bad'));
    state.client.on('error', err => setStatus('ошибка: ' + err.message, 'bad'));
  }

  function onConnect() {
    state.connected = true;
    state.client.subscribe(msgTopic(), { qos: 1 });
    state.client.subscribe(presSub(), { qos: 1 });
    state.client.publish(
      presTopic(),
      JSON.stringify({ n: state.nick, on: true, t: Date.now() }),
      { retain: true, qos: 1 }
    );
    setStatus('онлайн · AES-256-GCM', 'ok');
    addSystem('Соединение установлено. Отпечаток ключа: ' + state.keyFp + ' — сверь с собеседником.');
  }

  async function onMessage(topic, payload) {
    let text;
    try {
      text = dec.decode(payload instanceof Uint8Array ? payload : new Uint8Array(payload));
    } catch (e) {
      return;
    }

    if (topic.endsWith('/msg')) {
      let outer;
      try { outer = JSON.parse(text); } catch (e) { return; }
      if (!outer || outer.v !== 1 || !outer.iv || !outer.ct) return;

      let data;
      try {
        data = JSON.parse(await decrypt(state.roomKey, aadFor(state.topicRoom), outer));
      } catch (e) {
        addSystem('Не удалось расшифровать сообщение: ключ не совпадает. Сверь отпечаток ключа ' + state.keyFp + ' в шапке с собеседником и проверь фразу-пароль.');
        return;
      }
      if (!data || typeof data.m !== 'string' || !data.n || !data.id) return;
      if (state.seen.includes(data.id)) return;
      state.seen.push(data.id);
      if (state.seen.length > 300) state.seen.splice(0, state.seen.length - 300);

      addMessage({ n: data.n, t: data.t || Date.now(), m: data.m, me: false });
    } else if (topic.startsWith('encchat/v2/' + state.topicRoom + '/pres/')) {
      const sid = topic.slice(topic.lastIndexOf('/') + 1);
      let p;
      try { p = JSON.parse(text); } catch (e) { return; }
      if (!p) return;
      const fresh = Date.now() - (p.t || 0) <= 90000;
      state.online[sid] = { n: p.n || '?', on: !!p.on && fresh, t: p.t || Date.now() };
      renderUsers();
    }
  }

  async function sendMessage() {
    const val = $('msgInput').value.trim();
    if (!val || !state.connected || !state.roomKey) return;

    const id = uid() + ':' + Date.now().toString(36);
    const plain = JSON.stringify({ id: id, n: state.nick, t: Date.now(), m: val });
    const payload = await encrypt(state.roomKey, aadFor(state.topicRoom), plain);

    state.client.publish(msgTopic(), JSON.stringify(payload), { qos: 1 });

    state.seen.push(id);
    if (state.seen.length > 300) state.seen.splice(0, state.seen.length - 300);

    addMessage({ n: state.nick, t: Date.now(), m: val, me: true });
    $('msgInput').value = '';
    $('msgInput').focus();
  }

  function clearHistory() {
    if (!confirm('Удалить локальную историю этой комнаты?')) return;
    state.history = [];
    $('messages').innerHTML = '';
    saveHistory();
  }

  function leave() {
    if (state.client) {
      try {
        state.client.publish(
          presTopic(),
          JSON.stringify({ n: state.nick, on: false, t: Date.now() }),
          { retain: true, qos: 1 }
        );
      } catch (e) { /* ignore */ }
      state.client.end(true);
    }
    state.client = null;
    state.connected = false;
    state.roomKey = null;

    $('chat').classList.add('hidden');
    $('setup').classList.remove('hidden');
    $('pass').value = '';
    updateQuickBtn();
    $('nick').focus();
  }

  function updateQuickBtn() {
    const saved = localStorage.getItem('encchat:pass');
    if (saved) {
      $('quickName').textContent = localStorage.getItem('encchat:nick') || '';
      $('quickBtn').classList.remove('hidden');
    } else {
      $('quickBtn').classList.add('hidden');
    }
  }

  function quickJoin() {
    $('nick').value = localStorage.getItem('encchat:nick') || '';
    $('room').value = localStorage.getItem('encchat:room') || '';
    $('pass').value = localStorage.getItem('encchat:pass') || '';
    $('broker').value = localStorage.getItem('encchat:broker') || $('broker').value;
    $('savePass').checked = true;
    join();
  }

  function init() {
    const q = new URLSearchParams(location.search);
    const qNick = q.get('nick');
    const qRoom = q.get('room');
    const qPass = q.get('pass');

    $('nick').value = qNick || localStorage.getItem('encchat:nick') || '';
    $('room').value = qRoom || localStorage.getItem('encchat:room') || '';
    $('broker').value = localStorage.getItem('encchat:broker') || $('broker').value;
    $('savePass').checked = localStorage.getItem('encchat:pass') !== null;
    if (qPass) $('pass').value = qPass;

    updateQuickBtn();
    if (qRoom && qNick && qPass) { join(); return; }

    $('joinBtn').addEventListener('click', join);
    $('quickBtn').addEventListener('click', quickJoin);
    $('sendBtn').addEventListener('click', sendMessage);
    $('clearBtn').addEventListener('click', clearHistory);
    $('leaveBtn').addEventListener('click', leave);
    $('msgInput').addEventListener('keydown', e => {
      if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
    });
  }

  init();
})();
