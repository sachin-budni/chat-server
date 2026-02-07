const express = require('express');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');
const crypto = require('crypto');
const jsonServer = require('json-server');
const path = require('path');
const { ExpressPeerServer } = require('peer');

const app = express();
const server = http.createServer(app);

const PORT = process.env.PORT || 3001;
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || 'http://localhost:4200' || 'http://192.168.31.164:4200';

app.use(express.json());
app.use(
  cors({
    origin: CLIENT_ORIGIN,
    credentials: true
  })
);

const tokens = new Map();
const dbPath = path.join(__dirname, 'db.json');
const jsonRouter = jsonServer.router(dbPath);
const jsonMiddlewares = jsonServer.defaults({ logger: false });
const MAX_HISTORY = 50;
const GLOBAL_GROUP_ID = 'global';

function createToken() {
  if (typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return crypto.randomBytes(16).toString('hex');
}

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

function normalizeUserKey(username) {
  return String(username || '').trim().toLowerCase();
}

function findUserByName(name) {
  const key = normalizeUserKey(name);
  const users = jsonRouter.db.get('users');
  const match =
    users.find({ usernameKey: key }).value() ||
    users
      .value()
      .find((user) => normalizeUserKey(user.username) === key);
  return { user: match, key };
}

function normalizeRoomId(roomId) {
  if (!roomId) {
    return `group:${GLOBAL_GROUP_ID}`;
  }
  const raw = String(roomId);
  if (raw.startsWith('dm:')) {
    const parts = raw.split(':');
    if (parts.length === 3) {
      return `dm:${normalizeUserKey(parts[1])}:${normalizeUserKey(parts[2])}`;
    }
  }
  return raw;
}

function getGroupById(groupId) {
  const groups = jsonRouter.db.get('groups');
  return groups.find((group) => String(group.id) === String(groupId)).value();
}

function getRoomHistory(roomId) {
  const all = jsonRouter.db.get('messages').value() || [];
  const normalized = normalizeRoomId(roomId);
  const filtered = all.filter((message) => {
    if (!message.roomId && normalized === `group:${GLOBAL_GROUP_ID}`) {
      return true;
    }
    return normalizeRoomId(message.roomId) === normalized;
  });
  return filtered.slice(-MAX_HISTORY);
}

function ensureCollections() {
  const db = jsonRouter.db;
  if (!Array.isArray(db.get('users').value())) {
    db.set('users', []).write();
  }
  if (!Array.isArray(db.get('messages').value())) {
    db.set('messages', []).write();
  }
  if (!Array.isArray(db.get('groups').value())) {
    db.set('groups', []).write();
  }

  const users = db.get('users');
  const updatedUsers = users.value().map((user) => {
    if (!user.usernameKey && user.username) {
      return { ...user, usernameKey: normalizeUserKey(user.username) };
    }
    return user;
  });
  users.set(updatedUsers).write();

  const messages = db.get('messages');
  const normalizedMessages = messages.value().map((message) => {
    if (message.roomType === 'dm' && message.roomId) {
      return { ...message, roomId: normalizeRoomId(message.roomId) };
    }
    return message;
  });
  messages.set(normalizedMessages).write();
}

app.get('/api/health', (req, res) => {
  res.json({ ok: true });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || typeof username !== 'string') {
    return res.status(400).json({ error: 'Username is required.' });
  }
  if (!password || typeof password !== 'string') {
    return res.status(400).json({ error: 'Password is required.' });
  }

  const cleanName = username.trim().slice(0, 24);
  const cleanPassword = password.trim();
  if (!cleanName) {
    return res.status(400).json({ error: 'Username is required.' });
  }
  if (cleanPassword.length < 4) {
    return res.status(400).json({ error: 'Password must be at least 4 characters.' });
  }

  const usersCollection = jsonRouter.db.get('users');
  const { user: existing, key } = findUserByName(cleanName);
  if (!existing) {
    usersCollection
      .push({
        id: createToken(),
        username: cleanName,
        usernameKey: key,
        passwordHash: hashPassword(cleanPassword),
        createdAt: Date.now()
      })
      .write();
  } else {
    const incomingHash = hashPassword(cleanPassword);
    if (existing.passwordHash !== incomingHash) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }
  }

  const displayName = existing?.username ?? cleanName;
  const token = createToken();
  tokens.set(token, { username: displayName, usernameKey: key, createdAt: Date.now() });

  return res.json({
    token,
    user: { username: displayName }
  });
});

app.post('/api/register', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || typeof username !== 'string') {
    return res.status(400).json({ error: 'Username is required.' });
  }
  if (!password || typeof password !== 'string') {
    return res.status(400).json({ error: 'Password is required.' });
  }

  const cleanName = username.trim().slice(0, 24);
  const cleanPassword = password.trim();
  if (!cleanName) {
    return res.status(400).json({ error: 'Username is required.' });
  }
  if (cleanPassword.length < 4) {
    return res.status(400).json({ error: 'Password must be at least 4 characters.' });
  }

  const usersCollection = jsonRouter.db.get('users');
  const { user: existing, key } = findUserByName(cleanName);
  if (existing) {
    return res.status(409).json({ error: 'Username already exists.' });
  }

  usersCollection
    .push({
      id: createToken(),
      username: cleanName,
      usernameKey: key,
      passwordHash: hashPassword(cleanPassword),
      createdAt: Date.now()
    })
    .write();

  const token = createToken();
  tokens.set(token, { username: cleanName, usernameKey: key, createdAt: Date.now() });

  return res.status(201).json({
    token,
    user: { username: cleanName }
  });
});

ensureCollections();
const existingGlobal = getGroupById(GLOBAL_GROUP_ID);
if (!existingGlobal) {
  jsonRouter.db
    .get('groups')
    .push({ id: GLOBAL_GROUP_ID, name: 'Global Lounge', createdAt: Date.now() })
    .write();
}

app.use(jsonMiddlewares);
app.use('/api', jsonRouter);

const peerServer = ExpressPeerServer(server, {
  path: '/',
  allow_discovery: true
});
app.use('/peerjs', peerServer);

const io = new Server(server, {
  cors: {
    origin: CLIENT_ORIGIN,
    credentials: true
  }
});

io.use((socket, next) => {
  const token = socket.handshake.auth && socket.handshake.auth.token;
  if (!token || !tokens.has(token)) {
    return next(new Error('Unauthorized'));
  }
  socket.user = tokens.get(token);
  return next();
});

io.on('connection', (socket) => {
  if (socket.user?.usernameKey) {
    socket.join(`user:${socket.user.usernameKey}`);
  }
  socket.emit('history', {
    roomId: `group:${GLOBAL_GROUP_ID}`,
    messages: getRoomHistory(`group:${GLOBAL_GROUP_ID}`)
  });

  socket.on('joinRoom', (payload, ack) => {
    if (!payload || typeof payload.type !== 'string') {
      return;
    }

    let roomId = '';
    let roomType = '';
    let roomName = '';

    if (payload.type === 'group') {
      const group = getGroupById(payload.groupId || GLOBAL_GROUP_ID);
      if (!group) {
        return;
      }
      roomType = 'group';
      roomId = `group:${group.id}`;
      roomName = group.name;
    }

    if (payload.type === 'dm') {
      const target = String(payload.target || '').trim();
      if (!target || target === socket.user.username) {
        return;
      }
      const { user: targetUser, key: targetKey } = findUserByName(target);
      if (!targetUser) {
        return;
      }
      const senderKey = normalizeUserKey(socket.user.username);
      const pair = [senderKey, targetKey].sort((a, b) => a.localeCompare(b));
      roomType = 'dm';
      roomId = `dm:${pair[0]}:${pair[1]}`;
      roomName = targetUser.username;
    }

    if (!roomId) {
      return;
    }

    socket.join(roomId);
    socket.emit('history', {
      roomId,
      messages: getRoomHistory(roomId)
    });
    if (typeof ack === 'function') {
      ack({ roomId, roomType, name: roomName });
    }
  });

  socket.on('message', (payload) => {
    if (!payload || typeof payload.text !== 'string') {
      return;
    }

    const text = payload.text.trim();
    if (!text) {
      return;
    }

    let roomId = '';
    let roomType = '';
    let roomMeta = {};

    if (payload.roomType === 'group') {
      const group = getGroupById(payload.groupId || GLOBAL_GROUP_ID);
      if (!group) {
        return;
      }
      roomType = 'group';
      roomId = `group:${group.id}`;
      roomMeta = { groupId: group.id };
    } else if (payload.roomType === 'dm') {
      const target = String(payload.target || '').trim();
      if (!target || target === socket.user.username) {
        return;
      }
      const { user: targetUser, key: targetKey } = findUserByName(target);
      if (!targetUser) {
        return;
      }
      const senderKey = normalizeUserKey(socket.user.username);
      const pair = [senderKey, targetKey].sort((a, b) => a.localeCompare(b));
      roomType = 'dm';
      roomId = `dm:${pair[0]}:${pair[1]}`;
      roomMeta = { to: targetUser.username, toKey: targetKey, fromKey: senderKey };
    } else {
      roomType = 'group';
      roomId = `group:${GLOBAL_GROUP_ID}`;
      roomMeta = { groupId: GLOBAL_GROUP_ID };
    }

    socket.join(roomId);

    const message = {
      id: createToken(),
      roomId,
      roomType,
      user: socket.user.username,
      text: text.slice(0, 500),
      timestamp: Date.now(),
      ...roomMeta
    };

    jsonRouter.db.get('messages').push(message).write();
    io.to(roomId).emit('message', message);
    if (roomType === 'dm' && roomMeta.toKey) {
      io.to(`user:${roomMeta.toKey}`).emit('directMessage', message);
    }
  });

  socket.on('disconnect', () => {
    // No-op for now. Could broadcast presence changes here.
  });
});

server.listen(PORT, () => {
  console.log(`Chat server listening on port ${PORT}`);
});
