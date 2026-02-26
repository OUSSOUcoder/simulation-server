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

const rooms     = new Map();
const typingUsers = new Map();

// ─────────────────────────────────────────────
// CLÉS SERVEUR (Sealed Sender)
// ─────────────────────────────────────────────

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
    console.log('✅ Clés serveur générées');
  } catch (error) {
    console.error('❌ Erreur génération clés:', error);
    throw error;
  }
}

async function issueSenderCertificate(userId, senderKeyJWK, validityDays = 7) {
  const validUntil = new Date();
  validUntil.setDate(validUntil.getDate() + validityDays);
  const certData  = { userId, senderKey: senderKeyJWK, validUntil: validUntil.toISOString() };
  const certBytes = new TextEncoder().encode(JSON.stringify(certData));
  const signature = await subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, serverSigningKeyPair.privateKey, certBytes);
  return { ...certData, signature: Array.from(new Uint8Array(signature)) };
}

// ─────────────────────────────────────────────
// MITM PROXY (intégré directement — ES modules)
// ─────────────────────────────────────────────

const mitmState = {
  active:       false,
  targets:      new Set(),
  intercepted:  [],
  attackerName: 'Attaquant',
  startedAt:    null,
  stats: {
    totalIntercepted:    0,
    decryptionAttempts:  0,
    decryptionFailed:    0,
    metadataExtracted:   0,
  }
};

function attemptDecrypt(sealedMessage) {
  mitmState.stats.decryptionAttempts++;

  const visibleMetadata = {};
  let reason = 'Structure illisible — chiffrement multi-couche';

  try {
    if (sealedMessage && typeof sealedMessage === 'object') {
      if (sealedMessage.version)     visibleMetadata.version     = sealedMessage.version;
      if (sealedMessage.recipientId) visibleMetadata.recipientId = sealedMessage.recipientId;
      if (sealedMessage.timestamp)   visibleMetadata.timestamp   = sealedMessage.timestamp;

      const serialized = JSON.stringify(sealedMessage);
      visibleMetadata.sizeBytes    = serialized.length;
      visibleMetadata.sizeCategory = serialized.length < 500 ? 'court' : serialized.length < 2000 ? 'moyen' : 'long';

      if (sealedMessage.envelope) {
        reason = 'Envelope chiffrée — clé privée RSA-OAEP destinataire requise';
      } else if (sealedMessage.ciphertext) {
        reason = 'Ciphertext AES-GCM — tag d\'authentification invalide sans la clé';
      }
    }
  } catch (e) {
    reason = `Exception : ${e.message}`;
  }

  mitmState.stats.decryptionFailed++;
  mitmState.stats.metadataExtracted++;

  return {
    success:          false,
    reason,
    visibleMetadata,
    e2eeStatus:       'INTACT — E2EE a résisté à l\'attaque MITM',
    attackerNote:     'L\'attaquant voit : destinataire, taille, horodatage. Contenu : ILLISIBLE.'
  };
}

function withMITM(msgData, deliver) {
  if (!mitmState.active) { deliver(); return; }

  const isTargeted =
    mitmState.targets.size === 0 ||
    mitmState.targets.has(msgData.to) ||
    mitmState.targets.has(msgData.from);

  if (!isTargeted) { deliver(); return; }

  mitmState.stats.totalIntercepted++;

  const decryptResult = attemptDecrypt(msgData.sealedMessage || msgData.encryptedData);

  const interceptLog = {
    id:              `mitm_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
    timestamp:       Date.now(),
    from:            msgData.from || '???',
    to:              msgData.to,
    messageType:     msgData.sealedMessage ? 'SEALED_SENDER' : 'E2EE_CLASSIC',
    visibleMetadata: decryptResult.visibleMetadata,
    decryptAttempt: {
      success:      false,
      reason:       decryptResult.reason,
      e2eeStatus:   decryptResult.e2eeStatus,
      attackerNote: decryptResult.attackerNote
    },
    networkMetadata: {
      size:        JSON.stringify(msgData).length,
      hasX3DHInit: !!msgData.x3dhInit,
      isSealed:    !!msgData.sealedMessage,
      time:        new Date().toISOString()
    },
    action: 'INTERCEPTED_AND_FORWARDED'
  };

  mitmState.intercepted.push(interceptLog);

  // Diffuser le log à la room
  io.to(msgData.roomId).emit('mitm-intercept', {
    log:   interceptLog,
    stats: { ...mitmState.stats }
  });

  console.log(`🕵️ MITM intercepté: ${interceptLog.from} → ${interceptLog.to} | Déchiffrement: ÉCHEC`);

  deliver(); // retransmettre quand même
}

function registerMITMHandlers(socket) {
  socket.on('mitm-start', ({ roomId, targets = [] }) => {
    mitmState.active      = true;
    mitmState.attackerName = socket.data?.username || 'Attaquant';
    mitmState.startedAt   = Date.now();
    mitmState.targets     = new Set(targets);
    mitmState.intercepted = [];
    Object.keys(mitmState.stats).forEach(k => mitmState.stats[k] = 0);

    console.log(`🕵️ MITM activé dans ${roomId} par ${mitmState.attackerName}`);

    io.to(roomId).emit('mitm-status', {
      active:       true,
      attackerName: mitmState.attackerName,
      targets,
      startedAt:    mitmState.startedAt,
      message:      `⚠️ Attaque MITM activée par ${mitmState.attackerName}`
    });
  });

  socket.on('mitm-stop', ({ roomId }) => {
    const finalStats = { ...mitmState.stats };
    const duration   = Date.now() - (mitmState.startedAt || Date.now());
    mitmState.active  = false;
    mitmState.targets = new Set();

    console.log(`✅ MITM désactivé dans ${roomId}`);

    io.to(roomId).emit('mitm-status', {
      active:     false,
      finalStats,
      duration,
      message:    '✅ Attaque MITM terminée — E2EE a résisté'
    });
  });

  socket.on('mitm-get-logs', () => {
    socket.emit('mitm-logs', {
      logs:  mitmState.intercepted,
      stats: mitmState.stats
    });
  });

  socket.on('mitm-inject', ({ roomId, targetUsername }) => {
    const fakeMsg = {
      id:        `fake_${Date.now()}`,
      from:      mitmState.attackerName,
      to:        targetUsername,
      sealed:    true,
      sealedMessage: {
        version:     1,
        recipientId: targetUsername,
        envelope:    'FAKE_ENVELOPE_WILL_FAIL_VERIFICATION',
        mac:         'INVALID_MAC'
      },
      timestamp: Date.now(),
      injected:  true
    };

    // Envoyer à la room — les clients rejetteront (signature invalide)
    io.to(roomId).emit('mitm-injection-attempt', {
      fakeMessage: fakeMsg,
      result:      'REJECTED_BY_CLIENT',
      reason:      'Certificat Sealed Sender invalide — signature ECDSA serveur manquante'
    });

    console.log(`🕵️ MITM injection tentée sur ${targetUsername} → REJETÉE`);
    socket.emit('mitm-inject-result', { success: false, reason: 'Certificat serveur requis' });
  });

  socket.on('mitm-clear-logs', () => {
    mitmState.intercepted = [];
    Object.keys(mitmState.stats).forEach(k => mitmState.stats[k] = 0);
    socket.emit('mitm-logs-cleared');
  });
}

// ─────────────────────────────────────────────
// X3DH PREKEY STORE
// ─────────────────────────────────────────────

const preKeyBundles   = new Map(); // username → bundle
const OTPK_LOW_THRESHOLD = 10;

function registerX3DHHandlers(socket) {
  socket.on('publish-prekey-bundle', ({ username, bundle }) => {
    if (!username || !bundle) return;
    if (!bundle.identityKey || !bundle.signedPreKey || !bundle.oneTimePreKeys) {
      socket.emit('error', { message: 'Bundle PreKey invalide' });
      return;
    }

    const existing     = preKeyBundles.get(username);
    const existingOTPKs = existing?.oneTimePreKeys || [];
    const mergedOTPKs  = [
      ...existingOTPKs,
      ...bundle.oneTimePreKeys.filter(nk => !existingOTPKs.find(old => old.id === nk.id))
    ];

    preKeyBundles.set(username, {
      ...bundle,
      oneTimePreKeys: mergedOTPKs,
      publishedAt:    Date.now(),
      lastSeen:       Date.now()
    });

    console.log(`📦 Bundle X3DH publié pour ${username} — ${mergedOTPKs.length} OTPKs`);
    socket.emit('bundle-published', { otpkCount: mergedOTPKs.length });
  });

  socket.on('publish-new-prekeys', ({ oneTimePreKeys }) => {
    const username = socket.data?.username;
    if (!username) return;
    const bundle = preKeyBundles.get(username);
    if (!bundle) return;
    const merged = [
      ...bundle.oneTimePreKeys,
      ...oneTimePreKeys.filter(nk => !bundle.oneTimePreKeys.find(old => old.id === nk.id))
    ];
    bundle.oneTimePreKeys = merged;
    preKeyBundles.set(username, bundle);
    console.log(`📦 ${oneTimePreKeys.length} OTPKs ajoutées pour ${username}`);
  });

  socket.on('get-prekey-bundle', ({ username: targetUsername }) => {
    const bundle = preKeyBundles.get(targetUsername);
    if (!bundle) {
      socket.emit(`prekey-bundle:${targetUsername}`, null);
      return;
    }

    let usedOTPK        = null;
    let remainingOTPKs  = [...bundle.oneTimePreKeys];

    if (remainingOTPKs.length > 0) {
      usedOTPK              = remainingOTPKs.shift();
      bundle.oneTimePreKeys = remainingOTPKs;
      preKeyBundles.set(targetUsername, bundle);
    } else {
      console.warn(`⚠️ Plus d'OTPKs pour ${targetUsername} — fallback SPK`);
    }

    socket.emit(`prekey-bundle:${targetUsername}`, {
      identityKey:    bundle.identityKey,
      signedPreKey:   bundle.signedPreKey,
      oneTimePreKeys: usedOTPK ? [usedOTPK] : [],
      fetchedAt:      Date.now()
    });

    // Alerter si stock bas
    const count = bundle.oneTimePreKeys.length;
    if (count < OTPK_LOW_THRESHOLD) {
      for (const [, s] of io.sockets.sockets) {
        if (s.data?.username === targetUsername) {
          s.emit('prekeys-low', { remaining: count });
          break;
        }
      }
    }
  });
}

// ─────────────────────────────────────────────
// ROUTES HTTP
// ─────────────────────────────────────────────

app.get('/health', (req, res) => {
  res.json({
    status:   'ok',
    rooms:    rooms.size,
    mitm:     { active: mitmState.active, intercepted: mitmState.stats.totalIntercepted },
    x3dh:     { users: preKeyBundles.size },
    sealedSender: { serverSigningPublicKeyJWK },
    timestamp: new Date().toISOString()
  });
});

app.get('/', (req, res) => {
  res.json({ message: 'SecureChat Server', status: 'running', version: '2.0.0' });
});

// Debug X3DH (optionnel — désactiver en prod)
app.get('/api/x3dh/stats', (req, res) => {
  const stats = {};
  for (const [u, b] of preKeyBundles) {
    stats[u] = { otpkCount: b.oneTimePreKeys.length, publishedAt: b.publishedAt };
  }
  res.json(stats);
});

// ─────────────────────────────────────────────
// SOCKET.IO — HANDLERS PRINCIPAUX
// ─────────────────────────────────────────────

io.on('connection', (socket) => {
  console.log('✅ Connecté:', socket.id);
  let currentRoom     = null;
  let currentUsername = null;

  // ── Rejoindre une room ──────────────────────
  socket.on('join-simulation', async ({ roomId, username, publicKey, publicKeyFingerprint, identityKey }) => {
    console.log(`👤 ${username} rejoint ${roomId}`);

    if (currentRoom) socket.leave(currentRoom);
    currentRoom     = roomId;
    currentUsername = username;

    // ✅ Sauvegarder dans socket.data (requis pour MITM + X3DH)
    socket.data.username = username;

    if (!rooms.has(roomId)) {
      rooms.set(roomId, {
        users:     [],
        messages:  [],
        attacks:   [],
        sessions:  new Map(),
        createdAt: Date.now()
      });
    }

    const room = rooms.get(roomId);

    let certificate = null;
    try {
      if (identityKey) certificate = await issueSenderCertificate(username, identityKey);
    } catch (e) {
      console.error('❌ Erreur certificat:', e);
    }

    const user = {
      id: socket.id,
      username,
      publicKey,
      publicKeyFingerprint,
      identityKey,
      certificate,
      joinedAt: Date.now()
    };

    const existingIndex = room.users.findIndex(u => u.username === username);
    if (existingIndex !== -1) {
      room.users[existingIndex] = { ...room.users[existingIndex], id: socket.id, ...user };
    } else {
      room.users.push(user);
    }

    socket.join(roomId);
    socket.emit('room-state', {
      messages:             room.messages,
      attacks:              room.attacks,
      users:                room.users,
      serverSigningPublicKey: serverSigningPublicKeyJWK
    });
    socket.to(roomId).emit('user-joined', {
      user,
      users:                room.users,
      serverSigningPublicKey: serverSigningPublicKeyJWK
    });

    console.log(`📊 Room ${roomId}: ${room.users.length} utilisateur(s)`);
  });

  // ── Envoi message scellé ✅ AVEC MITM ───────
  socket.on('send-sealed-message', ({ roomId, to, sealedMessage, x3dhInit }) => {
    if (!rooms.has(roomId)) return;
    const room = rooms.get(roomId);
    const from = socket.data?.username || currentUsername;

    const message = {
      id:           `msg-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      from,         // ✅ from est maintenant renseigné
      to,
      sealed:       true,
      sealedMessage,
      x3dhInit:     x3dhInit || null,   // ✅ header X3DH transmis au destinataire
      timestamp:    Date.now()
    };

    room.messages.push(message);
    if (room.messages.length > 1000) room.messages = room.messages.slice(-1000);

    // ✅ MITM intercepte ici avant livraison
    withMITM({ ...message, roomId }, () => {
      io.to(roomId).emit('new-message', message);
    });
  });

  // ── Groupes — Sender Key Protocol ──────────
  socket.on('group-distribute-key', ({ roomId, groupId, groupName, encryptedKeys, members, keyVersion }) => {
    const from = socket.data?.username || currentUsername;
    // Envoyer la clé chiffrée à chaque membre individuellement
    for (const [, s] of io.sockets.sockets) {
      const memberUsername = s.data?.username;
      if (memberUsername && memberUsername !== from && encryptedKeys[memberUsername]) {
        s.emit('group-sender-key-distribution', {
          groupId,
          groupName,
          from,
          encryptedKey: encryptedKeys[memberUsername],
          members,
          keyVersion
        });
      }
    }
    console.log(`📦 SenderKey distribuée par ${from} dans groupe ${groupId} (${Object.keys(encryptedKeys).length} membres)`);
  });

  socket.on('send-group-message', ({ roomId, groupId, encryptedMsg }) => {
    const from = socket.data?.username || currentUsername;
    // Diffuser le même blob chiffré à tous les membres de la room
    socket.to(roomId).emit('group-message', {
      groupId,
      from,
      encryptedMsg,
      timestamp: Date.now()
    });
  });

  // ── Typing ──────────────────────────────────
  socket.on('user-typing', ({ roomId, username }) => {
    if (!typingUsers.has(roomId)) typingUsers.set(roomId, new Set());
    typingUsers.get(roomId).add(username);
    socket.to(roomId).emit('user-typing', { username });
    setTimeout(() => {
      if (typingUsers.has(roomId)) typingUsers.get(roomId).delete(username);
    }, 5000);
  });

  socket.on('stop-typing', ({ roomId, username }) => {
    if (typingUsers.has(roomId)) typingUsers.get(roomId).delete(username);
  });

  // ── Déconnexion ─────────────────────────────
  socket.on('disconnect', () => {
    console.log('❌ Déconnecté:', socket.id);
    if (currentRoom && rooms.has(currentRoom)) {
      const room = rooms.get(currentRoom);
      const user = room.users.find(u => u.id === socket.id);
      if (user) {
        room.users = room.users.filter(u => u.id !== socket.id);
        socket.to(currentRoom).emit('user-left', { username: user.username });
      }
    }
  });

  // ── MITM handlers ✅ ────────────────────────
  registerMITMHandlers(socket);

  // ── X3DH handlers ✅ ────────────────────────
  registerX3DHHandlers(socket);
});

// ─────────────────────────────────────────────
// DÉMARRAGE
// ─────────────────────────────────────────────

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
    console.error('💥 Erreur démarrage:', error);
    process.exit(1);
  }
}

startServer();