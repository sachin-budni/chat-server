const http = require('http');
const crypto = require('crypto');
const { Server } = require('socket.io');
const { ExpressPeerServer } = require('peer');
const {
  app,
  jsonRouter,
  tokens,
  normalizeUserKey,
  findUserByName,
  getGroupById
} = require('./app');

const server = http.createServer(app);

const PORT = process.env.PORT || 3001;
const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || 'http://localhost:4200';
const MAX_HISTORY = 50;
const GLOBAL_GROUP_ID = 'global';

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
      id: crypto.randomUUID ? crypto.randomUUID() : crypto.randomBytes(16).toString('hex'),
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
});

server.listen(PORT, () => {
  console.log(`Chat server listening on port ${PORT}`);
});
