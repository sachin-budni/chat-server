const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const jsonServer = require('json-server');
const path = require('path');

const CLIENT_ORIGIN = process.env.CLIENT_ORIGIN || 'http://localhost:4200';

const app = express();
app.use(express.json());
app.use(
  cors({
    origin: CLIENT_ORIGIN,
    credentials: true
  })
);

const dbPath = path.join(__dirname, 'db.json');
const jsonRouter = jsonServer.router(dbPath);
const jsonMiddlewares = jsonServer.defaults({ logger: false });
const tokens = new Map();
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
    users.value().find((user) => normalizeUserKey(user.username) === key);
  return { user: match, key };
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
}

function getGroupById(groupId) {
  const groups = jsonRouter.db.get('groups');
  return groups.find((group) => String(group.id) === String(groupId)).value();
}

ensureCollections();
const existingGlobal = getGroupById(GLOBAL_GROUP_ID);
if (!existingGlobal) {
  jsonRouter.db
    .get('groups')
    .push({ id: GLOBAL_GROUP_ID, name: 'Global Lounge', createdAt: Date.now() })
    .write();
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

app.use(jsonMiddlewares);
app.use('/api', jsonRouter);

module.exports = {
  app,
  jsonRouter,
  tokens,
  normalizeUserKey,
  findUserByName,
  getGroupById
};
