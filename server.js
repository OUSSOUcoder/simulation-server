import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
import cors from 'cors';

const app = express();
app.use(cors());

const server = createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.FRONTEND_URL || '*',
    methods: ['GET', 'POST'],
    credentials: true
  },
  pingTimeout: 60000,
  pingInterval: 25000
});

const rooms = new Map();
const typingUsers = new Map();

const subtle = globalThis.crypto.subtle;
let serverSigningKeyPair;
let serverSigningPublicKeyJWK;

async function initServerKeys() {
  try {
    serverSigningKeyPair = await subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-256' },
      true,
      ['sign', 'verify']
    );
    serverSigningPublicKeyJWK = await subtle.exportKey('jwk', serverSigningKeyPair.publicKey);
    console.log('✅ Clés serveur générées avec succès');
  } catch (error) {
    console.error('❌ Erreur génération clés:', error);
    throw error;
  }
}

async function issueSenderCertificate(userId, senderKeyJWK, validityDays = 7) {
  const validUntil = new Date();
  validUntil.setDate(validUntil.getDate() + validityDays);
  const certData = { userId, senderKey: senderKeyJWK, validUntil: validUntil.toISOString() };
  const certBytes = new TextEncoder().encode(JSON.stringify(certData));
  const signature = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, serverSigningKeyPair.privateKey, certBytes);
  return { ...certData, signature: Array.from(new Uint8Array(signature)) };
}

app.get('/health', (req, res) => {
  res.json({ status: 'ok', rooms: rooms.size, sealedSender: { serverSigningPublicKeyJWK }, timestamp: new Date().toISOString() });
});

app.get('/', (req, res) => {
  res.json({ message: 'SecureChat Server', status: 'running', version: '1.0.0' });
});

io.on('connection', (socket) => {
  console.log('✅ Utilisateur connecté:', socket.id);
  let currentRoom = null;
  let currentUsername = null;

  socket.on('join-simulation', async ({ roomId, username, publicKey, publicKeyFingerprint, identityKey }) => {
    console.log(`👤 ${username} rejoint ${roomId}`);
    if (currentRoom) socket.leave(currentRoom);
    currentRoom = roomId;
    currentUsername = username;

    if (!rooms.has(roomId)) {
      rooms.set(roomId, { users: [], messages: [], attacks: [], sessions: new Map(), createdAt: Date.now() });
    }

    const room = rooms.get(roomId);
    let certificate = null;
    try {
      if (identityKey) certificate = await issueSenderCertificate(username, identityKey);
    } catch (e) {
      console.error('❌ Erreur certificat:', e);
    }

    const user = { id: socket.id, username, publicKey, publicKeyFingerprint, identityKey, certificate, joinedAt: Date.now() };
    const existingUserIndex = room.users.findIndex(u => u.username === username);
    if (existingUserIndex !== -1) {
      room.users[existingUserIndex].id = socket.id;
    } else {
      room.users.push(user);
    }

    socket.join(roomId);
    socket.emit('room-state', { messages: room.messages, attacks: room.attacks, users: room.users, serverSigningPublicKey: serverSigningPublicKeyJWK });
    socket.to(roomId).emit('user-joined', { user, users: room.users, serverSigningPublicKey: serverSigningPublicKeyJWK });
    console.log(`📊 Room ${roomId}: ${room.users.length} utilisateur(s)`);
  });

  socket.on('send-sealed-message', ({ roomId, to, sealedMessage }) => {
    if (!rooms.has(roomId)) return;
    const room = rooms.get(roomId);
    const message = { id: `msg-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`, from: null, to, sealed: true, sealedMessage, timestamp: Date.now() };
    room.messages.push(message);
    if (room.messages.length > 1000) room.messages = room.messages.slice(-1000);
    io.to(roomId).emit('new-message', message);
  });

  socket.on('user-typing', ({ roomId, username }) => {
    if (!typingUsers.has(roomId)) typingUsers.set(roomId, new Set());
    typingUsers.get(roomId).add(username);
    socket.to(roomId).emit('user-typing', { username });
    setTimeout(() => { if (typingUsers.has(roomId)) typingUsers.get(roomId).delete(username); }, 5000);
  });

  socket.on('stop-typing', ({ roomId, username }) => {
    if (typingUsers.has(roomId)) typingUsers.get(roomId).delete(username);
  });

  socket.on('disconnect', () => {
    console.log('❌ Déconnecté:', socket.id);
    if (currentRoom && rooms.has(currentRoom)) {
      const room = rooms.get(currentRoom);
      const user = room.users.find(u => u.id === socket.id);
      if (user) socket.to(currentRoom).emit('user-left', { username: user.username });
    }
  });
});

async function startServer() {
  try {
    await initServerKeys();
    const PORT = process.env.PORT || 10000;
    server.listen(PORT, '0.0.0.0', () => {
      console.log('-------------------------------------------');
      console.log(`🚀 SERVEUR LIVE SUR LE PORT ${PORT}`);
      console.log('-------------------------------------------');
    });
  } catch (error) {
    console.error('💥 Erreur:', error);
    process.exit(1);
  }
}

startServer();
