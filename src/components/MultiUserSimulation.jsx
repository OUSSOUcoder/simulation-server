import { useState, useEffect, useRef, useCallback } from 'react';
import { io } from 'socket.io-client';
import { EnhancedCrypto } from '../crypto/EnhancedCrypto';
import { PersistentStorage } from '../utils/PersistentStorage';
import soundGenerator from '../utils/SoundGenerator';
import { DHRatchet } from '../crypto/DHRatchet';
import { generateECDHKeyPair, performECDH, hkdf, importPublicKey } from '../crypto/Primitives';
import { SealedSenderEncryptor } from '../crypto/SealedSender';

// === COMPOSANTS UI ===

function Toast({ message, type = 'info', onClose }) {
  useEffect(() => {
    const timer = setTimeout(onClose, 5000);
    return () => clearTimeout(timer);
  }, [onClose]);

  const colors = {
    info: 'bg-blue-600 border-blue-500',
    success: 'bg-green-600 border-green-500',
    warning: 'bg-yellow-600 border-yellow-500',
    error: 'bg-red-600 border-red-500'
  };

  const icons = { info: 'ℹ', success: '✓', warning: '⚠', error: '✕' };

  return (
    <div className={`${colors[type]} border-l-4 p-4 rounded-lg shadow-xl backdrop-blur-sm animate-slide-in`}>
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <span className="text-xl font-bold">{icons[type]}</span>
          <p className="text-white font-medium text-sm">{message}</p>
        </div>
        <button onClick={onClose} className="text-white/80 hover:text-white text-lg leading-none font-bold">×</button>
      </div>
    </div>
  );
}

function ToastContainer({ toasts, removeToast }) {
  return (
    <div className="fixed top-4 right-4 z-50 space-y-2 max-w-md">
      {toasts.map((toast) => (
        <Toast key={toast.id} message={toast.message} type={toast.type} onClose={() => removeToast(toast.id)} />
      ))}
    </div>
  );
}

function TypingIndicator({ users }) {
  if (users.length === 0) return null;
  return (
    <div className="flex items-center gap-2 px-3 py-2 bg-gray-700/50 rounded-lg text-sm text-gray-300">
      <div className="flex gap-1">
        <span className="w-2 h-2 bg-blue-400 rounded-full animate-bounce" style={{ animationDelay: '0ms' }}></span>
        <span className="w-2 h-2 bg-blue-400 rounded-full animate-bounce" style={{ animationDelay: '150ms' }}></span>
        <span className="w-2 h-2 bg-blue-400 rounded-full animate-bounce" style={{ animationDelay: '300ms' }}></span>
      </div>
      <span>
        {users.length === 1
          ? `${users[0]} est en train d'écrire...`
          : `${users.length} personnes écrivent...`}
      </span>
    </div>
  );
}

// === COMPOSANT PRINCIPAL ===

function MultiUserSimulation() {
  const [socket, setSocket] = useState(null);
  const [connected, setConnected] = useState(false);
  const [roomId, setRoomId] = useState('');
  const [username, setUsername] = useState('');
  const [joined, setJoined] = useState(false);
  const [users, setUsers] = useState([]);
  const [messages, setMessages] = useState([]);
  const [attacks, setAttacks] = useState([]);
  const [selectedUser, setSelectedUser] = useState(null);
  const [messageText, setMessageText] = useState('');

  const [crypto] = useState(() => new EnhancedCrypto()); // Conservé pour compat UI, non utilisé en mode sealed+ratchet
  const [storage] = useState(() => new PersistentStorage());
  const [myPrivateKey, setMyPrivateKey] = useState(null);

  const [decryptedMessages, setDecryptedMessages] = useState({});
  const [showDecryptPanel, setShowDecryptPanel] = useState(false);
  const [currentDecrypting, setCurrentDecrypting] = useState(null);
  const [toasts, setToasts] = useState([]);
  const [typingUsers, setTypingUsers] = useState([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [isTyping, setIsTyping] = useState(false);
  const [hasMoreMessages, setHasMoreMessages] = useState(false);
  const [messagesPage, setMessagesPage] = useState(1);
  const [soundEnabled, setSoundEnabled] = useState(true);
  const [myFingerprint, setMyFingerprint] = useState(null);
  const [serverSigningPublicKey, setServerSigningPublicKey] = useState(null);
  const [myCertificate, setMyCertificate] = useState(null);

  // Identité Double Ratchet (ECDH P-256)
  const myIdentityKeyPairRef = useRef(null);
  const myIdentityPublicJWKRef = useRef(null);
  const ratchetsRef = useRef(new Map()); // contactUsername -> DHRatchet

  const toastIdRef = useRef(0);
  const messagesEndRef = useRef(null);
  const typingTimeoutRef = useRef(null);
  const messagesContainerRef = useRef(null);
  const usersRef = useRef([]);
  const cryptoSessionsReady = useRef(new Set());
  // ✅ Ref pour accéder à myPrivateKey dans les handlers sans closure périmée
  const myPrivateKeyRef = useRef(null);

  useEffect(() => { usersRef.current = users; }, [users]);
  useEffect(() => { myPrivateKeyRef.current = myPrivateKey; }, [myPrivateKey]);

  useEffect(() => {
    const init = async () => {
      try {
        await storage.init();
        soundGenerator.init();
      } catch (error) {
        console.error('Erreur init storage:', error);
      }
    };
    init();

    const cleanupInterval = setInterval(() => {
      crypto.cleanupExpiredSessions();
      storage.cleanupOldMessages();
    }, 60 * 60 * 1000);

    return () => clearInterval(cleanupInterval);
  }, [crypto, storage]);

  const showToast = useCallback((message, type = 'info') => {
    const id = toastIdRef.current++;
    setToasts(prev => [...prev, { id, message, type }]);
  }, []);

  const removeToast = useCallback((id) => {
    setToasts(prev => prev.filter(toast => toast.id !== id));
  }, []);

  const playSound = useCallback((soundType) => {
    if (!soundEnabled) return;
    switch (soundType) {
      case 'newMessage': soundGenerator.playNotification(); break;
      case 'sent': soundGenerator.playSent(); break;
      case 'error': soundGenerator.playError(); break;
      default: break;
    }
  }, [soundEnabled]);

  // ✅ ensureSession : initialise la session côté expéditeur uniquement
  const ensureSession = useCallback(async (userId, publicKeyStr) => {
    if (cryptoSessionsReady.current.has(userId)) return true;
    try {
      const publicKeyObj = typeof publicKeyStr === 'string'
        ? JSON.parse(publicKeyStr)
        : publicKeyStr;

      await crypto.initSession(userId, publicKeyObj);
      cryptoSessionsReady.current.add(userId);
      console.log(`✅ Session prête (expéditeur): ${userId}`);
      return true;
    } catch (err) {
      console.error(`❌ Échec session pour ${userId}:`, err);
      return false;
    }
  }, [crypto]);

  // Socket.io connection
  useEffect(() => {
    const newSocket = io('https://simulation-server-3.onrender.com', {
      transports: ['websocket'],
      reconnection: true,
      reconnectionAttempts: 5,
      reconnectionDelay: 1000
    });

    newSocket.on('connect', () => setConnected(true));
    newSocket.on('disconnect', () => setConnected(false));

    setSocket(newSocket);
    return () => newSocket.close();
  }, []);

  useEffect(() => {
    if (!socket) return;

    socket.on('user-joined', async ({ user, users: newUsers }) => {
      setUsers(newUsers);
      // Mise à jour clé serveur + mon certificat si présent dans ma fiche
      if (user?.username === username) {
        if (user.certificate) setMyCertificate(user.certificate);
      }
      if (user.username !== username && user.publicKey) {
        const ok = await ensureSession(user.id, user.publicKey);
        if (ok) showToast(`Session établie avec ${user.username}`, 'success');
        else showToast(`Erreur session avec ${user.username}`, 'error');
      }
    });

    socket.on('room-state', async ({ messages: roomMessages, users: roomUsers, serverSigningPublicKey: sspk }) => {
      setMessages(roomMessages);
      setUsers(roomUsers);
      if (sspk) setServerSigningPublicKey(sspk);

      const me = roomUsers.find(u => u.username === username);
      if (me?.certificate) setMyCertificate(me.certificate);

      const results = await Promise.allSettled(
        roomUsers
          .filter(u => u.username !== username && u.publicKey)
          .map(u => ensureSession(u.id, u.publicKey))
      );

      const count = results.filter(r => r.value === true).length;
      if (count > 0) showToast(`${count} session(s) prête(s)`, 'success');

      for (const msg of roomMessages) {
        await storage.saveMessage(roomId, msg).catch(console.error);
      }
    });

    socket.on('new-message', async (message) => {
      setMessages(prev => [...prev, message]);

      if (message.to === username) {
        setUnreadCount(prev => prev + 1);
        playSound('newMessage');
      }

      await storage.saveMessage(roomId, message).catch(console.error);
      scrollToBottom();
    });

    socket.on('attack-launched', (attack) => {
      setAttacks(prev => [...prev, attack]);
      showToast(`Attaque ${attack.type} lancée sur ${attack.target}`, 'warning');
    });

    socket.on('attack-stopped', (attack) => {
      setAttacks(prev => prev.map(a => a.id === attack.id ? attack : a));
      showToast('Attaque arrêtée', 'success');
    });

    socket.on('user-left', ({ username: leftUsername }) => {
      setUsers(prev => prev.filter(u => u.username !== leftUsername));
      const departed = usersRef.current.find(u => u.username === leftUsername);
      if (departed) cryptoSessionsReady.current.delete(departed.id);
      showToast(`${leftUsername} a quitté la room`, 'info');
    });

    socket.on('user-typing', ({ username: typingUsername }) => {
      if (typingUsername === username) return;
      setTypingUsers(prev =>
        prev.includes(typingUsername) ? prev : [...prev, typingUsername]
      );
      setTimeout(() => {
        setTypingUsers(prev => prev.filter(u => u !== typingUsername));
      }, 3000);
    });

    return () => {
      socket.off('user-joined');
      socket.off('room-state');
      socket.off('new-message');
      socket.off('attack-launched');
      socket.off('attack-stopped');
      socket.off('user-left');
      socket.off('user-typing');
    };
  }, [socket, username, roomId, ensureSession, storage, showToast, playSound]);

  // Calcul d'empreinte (SHA-256 SPKI -> hex groupé)
  const computePublicKeyFingerprint = async (publicKeyJWK) => {
    const publicKey = await window.crypto.subtle.importKey(
      'jwk',
      publicKeyJWK,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      true,
      ['encrypt']
    );
    const spki = await window.crypto.subtle.exportKey('spki', publicKey);
    const hash = await window.crypto.subtle.digest('SHA-256', spki);
    const bytes = new Uint8Array(hash);
    const hex = Array.from(bytes)
      .map(b => b.toString(16).padStart(2, '0'))
      .join('');
    // Regrouper par blocs de 4 octets: xxxx xxxx ...
    return hex.match(/.{1,8}/g).join(' ');
  };

  const generateKeys = async () => {
    try {
      // ⚠️ Pour éviter les incompatibilités avec d'anciennes clés (autres algos),
      // on régénère systématiquement une nouvelle paire RSA-OAEP propre.
      const { publicKey, privateKey, publicKeyJWK } = await crypto.generateIdentityKeys();
      setMyPrivateKey(privateKey);
      myPrivateKeyRef.current = privateKey;

      const privateKeyJWK = await window.crypto.subtle.exportKey("jwk", privateKey);
      await storage.saveKeys(username, publicKeyJWK, privateKeyJWK);

      const fingerprint = await computePublicKeyFingerprint(publicKeyJWK);
      setMyFingerprint(fingerprint);

      // Identité Double Ratchet (ECDH P-256)
      const identityKeyPair = await generateECDHKeyPair();
      myIdentityKeyPairRef.current = identityKeyPair;
      const identityPublicJWK = await window.crypto.subtle.exportKey('jwk', identityKeyPair.publicKey);
      myIdentityPublicJWKRef.current = identityPublicJWK;

      return { publicKeyJWK, fingerprint, identityPublicJWK };
    } catch (error) {
      console.error('Erreur génération clés:', error);
      showToast('Erreur génération des clés', 'error');
      return null;
    }
  };

  const joinRoom = async () => {
    if (!socket || !roomId || !username) {
      showToast('Remplissez tous les champs !', 'warning');
      return;
    }
    try {
      const keyInfo = await generateKeys();
      if (!keyInfo) return;

      socket.emit('join-simulation', {
        roomId,
        username,
        publicKey: keyInfo.publicKeyJWK,
        publicKeyFingerprint: keyInfo.fingerprint,
        identityKey: keyInfo.identityPublicJWK
      });
      setJoined(true);
      showToast('Connexion à la room...', 'info');

      const savedMessages = await storage.loadMessages(roomId);
      if (savedMessages.length > 0) {
        setMessages(savedMessages);
      }
    } catch (error) {
      console.error('Erreur rejoindre room:', error);
      showToast('Erreur lors de la connexion', 'error');
    }
  };

  // ✅ FIX PRINCIPAL : handleDecrypt utilise encryptedSessionKey du message directement
  const handleDecrypt = async (msg) => {
    if (currentDecrypting === msg.id) return;
    setCurrentDecrypting(msg.id);
    setShowDecryptPanel(true);

    try {
      const privateKey = myPrivateKeyRef.current;
      if (!privateKey) {
        throw new Error('Clé privée non disponible, reconnectez-vous');
      }
      if (!serverSigningPublicKey) {
        throw new Error('Clé serveur (vérification certificat) manquante');
      }

      // Mode SEALED + Double Ratchet
      if (msg.sealed && msg.sealedMessage) {
        const unsealed = await SealedSenderEncryptor.unseal(
          msg.sealedMessage,
          privateKey,
          serverSigningPublicKey
        );

        const senderUsername = unsealed.senderId;
        const sender = usersRef.current.find(u => u.username === senderUsername);
        if (!sender) {
          throw new Error('Expéditeur introuvable (a peut-être quitté la room)');
        }

        // Initialiser/obtenir le ratchet
        const contactId = senderUsername;
        let ratchet = ratchetsRef.current.get(contactId);
        if (!ratchet) {
          const myIdentityKeyPair = myIdentityKeyPairRef.current;
          const myIdentityPublic = myIdentityKeyPair?.publicKey;
          const myIdentityPrivate = myIdentityKeyPair?.privateKey;
          if (!myIdentityPrivate || !myIdentityPublic) {
            throw new Error('Identité ECDH locale manquante');
          }

          const senderIdentityJWK = sender.identityKey || sender.certificate?.senderKey || unsealed.senderIdentity;
          if (!senderIdentityJWK) {
            throw new Error('Clé identité ECDH expéditeur manquante');
          }

          const senderIdentityPublicKey = await importPublicKey(senderIdentityJWK);
          const sharedSecret = await performECDH(myIdentityPrivate, senderIdentityPublicKey);
          const rootKey = await hkdf(
            sharedSecret,
            new Uint8Array(32),
            new TextEncoder().encode('X3DH-session'),
            32
          );

          const isInitiator = username.localeCompare(contactId) < 0;
          ratchet = new DHRatchet(rootKey, isInitiator);

          if (isInitiator) {
            const dhKeyPair = await generateECDHKeyPair();
            // Remote = identité du contact (permet d'initialiser la sendingChain)
            await ratchet.initialize(dhKeyPair, senderIdentityPublicKey);
          } else {
            // Non-initiator: utilise notre identité comme première clé privée pour matcher l'initiateur
            await ratchet.initialize(myIdentityKeyPair, null);
          }

          ratchetsRef.current.set(contactId, ratchet);
        }

        const sealedInnerBytes = new Uint8Array(unsealed.message);
        const encryptedRatchetMsg = JSON.parse(new TextDecoder().decode(sealedInnerBytes));
        // Désérialisation des buffers en ArrayBuffer
        const toBuf = (arr) => new Uint8Array(arr).buffer;
        const decrypted = await ratchet.decrypt({
          ...encryptedRatchetMsg,
          ciphertext: toBuf(encryptedRatchetMsg.ciphertext),
          iv: toBuf(encryptedRatchetMsg.iv),
          mac: toBuf(encryptedRatchetMsg.mac),
          nonce: toBuf(encryptedRatchetMsg.nonce)
        });

        setDecryptedMessages(prev => ({
          ...prev,
          [msg.id]: {
            plaintext: decrypted,
            from: senderUsername,
            to: msg.to,
            timestamp: msg.timestamp,
            ciphertext: '(sealed)'
          }
        }));

        setUnreadCount(prev => Math.max(0, prev - 1));
        showToast('Message SEALED déchiffré ✓', 'success');
        return;
      }

      // Sinon: mode précédent (EnhancedCrypto)
      const sender = usersRef.current.find(u => u.username === msg.from);

      if (!sender) {
        throw new Error('Expéditeur introuvable (a peut-être quitté la room)');
      }
      if (!msg.encryptedData?.ciphertext) {
        throw new Error('Données chiffrées manquantes ou invalides');
      }
      if (!msg.encryptedData?.encryptedSessionKey) {
        throw new Error('Clé de session manquante dans le message. Mettez à jour EnhancedCrypto.js');
      }

      // ✅ Laisse EnhancedCrypto gérer la (ré)construction de session
      const plaintext = await crypto.decryptMessage(sender.id, msg.encryptedData, privateKey);

      // Si on arrive ici, la session est bien valide
      cryptoSessionsReady.current.add(sender.id);

      if (!plaintext) {
        throw new Error('Déchiffrement retourné vide');
      }

      setDecryptedMessages(prev => ({
        ...prev,
        [msg.id]: {
          plaintext,
          from: msg.from,
          to: msg.to,
          timestamp: msg.timestamp,
          ciphertext: msg.encryptedData.ciphertext
        }
      }));

      setUnreadCount(prev => Math.max(0, prev - 1));
      showToast('Message déchiffré avec succès ✓', 'success');
    } catch (err) {
      console.error('❌ handleDecrypt:', err);
      showToast('Erreur : ' + err.message, 'error');
      playSound('error');
    } finally {
      setCurrentDecrypting(null);
    }
  };

  const sendMessage = async () => {
    if (!messageText.trim() || !selectedUser) {
      showToast('Sélectionnez un destinataire et écrivez un message !', 'warning');
      return;
    }
    try {
      if (!serverSigningPublicKey) {
        throw new Error('Clé serveur manquante (certificats)');
      }
      if (!myCertificate) {
        throw new Error('Certificat expéditeur non disponible (rejoignez à nouveau la room)');
      }

      const myIdentityKeyPair = myIdentityKeyPairRef.current;
      if (!myIdentityKeyPair) throw new Error('Identité ECDH locale manquante');

      // Ratchet: init si besoin
      const contactId = selectedUser.username;
      let ratchet = ratchetsRef.current.get(contactId);
      if (!ratchet) {
        const recipientIdentityJWK = selectedUser.identityKey || selectedUser.certificate?.senderKey;
        if (!recipientIdentityJWK) throw new Error('Clé identité ECDH destinataire manquante');

        const recipientIdentityPublicKey = await importPublicKey(recipientIdentityJWK);
        const sharedSecret = await performECDH(myIdentityKeyPair.privateKey, recipientIdentityPublicKey);
        const rootKey = await hkdf(
          sharedSecret,
          new Uint8Array(32),
          new TextEncoder().encode('X3DH-session'),
          32
        );

        const isInitiator = username.localeCompare(contactId) < 0;
        ratchet = new DHRatchet(rootKey, isInitiator);

        if (isInitiator) {
          const dhKeyPair = await generateECDHKeyPair();
          await ratchet.initialize(dhKeyPair, recipientIdentityPublicKey);
        } else {
          await ratchet.initialize(myIdentityKeyPair, null);
        }

        ratchetsRef.current.set(contactId, ratchet);
      }

      const encryptedRatchet = await ratchet.encrypt(messageText);
      // Sérialiser en tableaux d'octets
      const toArr = (buf) => Array.from(new Uint8Array(buf));
      const payload = {
        ...encryptedRatchet,
        ciphertext: toArr(encryptedRatchet.ciphertext),
        iv: toArr(encryptedRatchet.iv),
        mac: toArr(encryptedRatchet.mac),
        nonce: toArr(encryptedRatchet.nonce)
      };
      const ratchetBytes = new TextEncoder().encode(JSON.stringify(payload));

      // Sealed Sender: sceller le message (expéditeur caché côté serveur)
      const sealed = await SealedSenderEncryptor.seal(
        Array.from(ratchetBytes),
        myCertificate,
        myIdentityKeyPair.publicKey,
        selectedUser.publicKey
      );

      socket.emit('send-sealed-message', {
        roomId,
        to: selectedUser.username,
        sealedMessage: sealed
      });

      setMessageText('');
      setIsTyping(false);
      socket.emit('stop-typing', { roomId, username });
      showToast(`Message envoyé à ${selectedUser.username}`, 'success');
      playSound('sent');
    } catch (err) {
      console.error('❌ sendMessage:', err);
      showToast('Erreur envoi : ' + err.message, 'error');
      playSound('error');
    }
  };

  const launchAttack = (attackType, targetUsername) => {
    socket.emit('launch-attack', { roomId, attackType, target: targetUsername });
  };

  const handleSelectUser = (user) => {
    if (user.username === username) {
      showToast('Vous ne pouvez pas vous envoyer de messages !', 'warning');
      return;
    }
    setSelectedUser(user);
    showToast(`${user.username} sélectionné`, 'info');
  };

  const handleTyping = (e) => {
    setMessageText(e.target.value);
    if (!isTyping) {
      setIsTyping(true);
      socket.emit('user-typing', { roomId, username });
    }
    clearTimeout(typingTimeoutRef.current);
    typingTimeoutRef.current = setTimeout(() => {
      setIsTyping(false);
      socket.emit('stop-typing', { roomId, username });
    }, 3000);
  };

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const loadMoreMessages = useCallback(async () => {
    const newPage = messagesPage + 1;
    const allMessages = await storage.loadMessages(roomId, newPage * 50);
    if (allMessages.length > messages.length) {
      setMessages(allMessages);
      setMessagesPage(newPage);
      setHasMoreMessages(allMessages.length === newPage * 50);
    } else {
      setHasMoreMessages(false);
    }
  }, [messages.length, messagesPage, roomId, storage]);

  const handleScroll = useCallback(() => {
    const container = messagesContainerRef.current;
    if (!container) return;
    if (container.scrollTop === 0 && hasMoreMessages) {
      loadMoreMessages();
    }
  }, [hasMoreMessages, loadMoreMessages]);

  useEffect(() => {
    const container = messagesContainerRef.current;
    if (container) {
      container.addEventListener('scroll', handleScroll);
      return () => container.removeEventListener('scroll', handleScroll);
    }
  }, [handleScroll]);

  useEffect(() => { scrollToBottom(); }, [messages]);

  // === RENDU ===

  if (!joined) {
    return (
      <>
        <ToastContainer toasts={toasts} removeToast={removeToast} />
        <div className="min-h-screen bg-gradient-to-br from-blue-900 via-purple-900 to-pink-900 flex items-center justify-center p-4">
          <div className="bg-white/10 backdrop-blur-lg rounded-2xl p-8 max-w-md w-full border border-white/20 shadow-2xl">
            <h1 className="text-3xl font-bold text-white mb-6 text-center">
              🌐 Simulation Multi-Utilisateurs
            </h1>

            <div className="space-y-4">
              <div className={`p-3 rounded-lg ${connected
                ? 'bg-green-500/20 border border-green-500/50'
                : 'bg-red-500/20 border border-red-500/50'}`}>
                <p className="text-white text-sm">
                  {connected ? '✓ Connecté au serveur' : '✕ Déconnecté du serveur'}
                </p>
              </div>

              <div>
                <label className="block text-white text-sm font-medium mb-2">ID de la Room</label>
                <input
                  type="text"
                  placeholder="Ex: room-demo-2025"
                  value={roomId}
                  onChange={(e) => setRoomId(e.target.value)}
                  className="w-full px-4 py-3 rounded-lg bg-white/10 border border-white/30 text-white placeholder-white/50 focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
                <p className="text-white/60 text-xs mt-1">
                  💡 Utilisez le même ID dans plusieurs onglets pour collaborer
                </p>
              </div>

              <div>
                <label className="block text-white text-sm font-medium mb-2">Votre Pseudo</label>
                <input
                  type="text"
                  placeholder="Ex: Alice"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  onKeyPress={(e) => e.key === 'Enter' && joinRoom()}
                  className="w-full px-4 py-3 rounded-lg bg-white/10 border border-white/30 text-white placeholder-white/50 focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>

              <button
                onClick={joinRoom}
                disabled={!connected || !roomId || !username}
                className="w-full px-6 py-4 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 rounded-lg font-semibold transition-all disabled:opacity-50 disabled:cursor-not-allowed text-white text-lg"
              >
                Rejoindre la simulation
              </button>

              <label className="flex items-center gap-2 cursor-pointer text-sm text-white/60">
                <input
                  type="checkbox"
                  checked={soundEnabled}
                  onChange={(e) => setSoundEnabled(e.target.checked)}
                  className="w-4 h-4"
                />
                <span>Sons activés</span>
              </label>
            </div>
          </div>
        </div>
      </>
    );
  }

  return (
    <>
      <ToastContainer toasts={toasts} removeToast={removeToast} />

      <div className="min-h-screen bg-gray-900 text-white p-4">
        <div className="max-w-7xl mx-auto mb-6">
          <div className="bg-gradient-to-r from-blue-600 to-purple-600 rounded-xl p-6 shadow-xl">
            <div className="flex items-center justify-between">
              <div>
                <h1 className="text-2xl font-bold mb-2">
                  🌐 Simulation Collaborative — Room: {roomId}
                </h1>
                <p className="text-blue-100">
                  Connecté en tant que <strong>{username}</strong> • {users.length} participant(s)
                </p>
              </div>
              <div className="flex items-center gap-4">
                <button
                  onClick={() => setSoundEnabled(!soundEnabled)}
                  className="px-4 py-2 bg-white/20 hover:bg-white/30 rounded-lg text-sm font-semibold transition-all"
                >
                  {soundEnabled ? '🔊 Son ON' : '🔇 Son OFF'}
                </button>
                {unreadCount > 0 && (
                  <div className="px-4 py-2 bg-red-500 rounded-lg text-sm font-bold animate-pulse">
                    {unreadCount} nouveau(x) message(s)
                  </div>
                )}
              </div>
            </div>
          </div>
        </div>

        <div className="max-w-7xl mx-auto grid grid-cols-1 lg:grid-cols-3 gap-6">

          {/* Panneau Participants */}
          <div className="bg-gray-800 rounded-xl p-6 border border-gray-700">
            <h2 className="text-xl font-bold mb-4 flex items-center justify-between">
              <span>👥 Participants ({users.length})</span>
              {selectedUser && (
                <span className="text-xs bg-blue-600 px-2 py-1 rounded">{selectedUser.username}</span>
              )}
            </h2>

            <div className="mb-4 p-3 bg-blue-900/30 border border-blue-600/50 rounded-lg text-sm">
              <p className="text-blue-300">
                💡 <strong>Cliquez</strong> sur un participant pour lui envoyer un message
              </p>
            </div>

            <div className="space-y-2">
              {users.map((user) => {
                const isMe = user.username === username;
                const isSelected = selectedUser?.id === user.id;
                return (
                  <div
                    key={user.id}
                    onClick={() => handleSelectUser(user)}
                    className={`relative p-4 rounded-lg transition-all ${
                      isSelected
                        ? 'bg-blue-600 border-2 border-blue-400 shadow-lg scale-105 cursor-pointer'
                        : isMe
                        ? 'bg-green-600/20 border border-green-600/50 cursor-not-allowed'
                        : 'bg-gray-700 hover:bg-gray-600 cursor-pointer'
                    }`}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex-1">
                        <p className="font-semibold text-lg flex items-center gap-2">
                          {isSelected && <span>👉</span>}
                          {user.username}
                          {isMe && (
                            <span className="text-xs bg-green-600 px-2 py-0.5 rounded">(Vous)</span>
                          )}
                        </p>
                        <p className="text-xs text-gray-400 mt-1">
                          ID: {user.id.substring(0, 8)}...
                        </p>
                        {user.publicKeyFingerprint && (
                          <p className="text-[11px] text-gray-500 mt-1 font-mono">
                            Empreinte: {user.publicKeyFingerprint}
                          </p>
                        )}
                        {!isMe && (
                          <p className="text-xs mt-1">
                            {cryptoSessionsReady.current.has(user.id)
                              ? <span className="text-green-400">🔒 Session active</span>
                              : <span className="text-yellow-400">⏳ Session en attente</span>
                            }
                          </p>
                        )}
                      </div>
                      {!isMe && (
                        <button
                          onClick={(e) => { e.stopPropagation(); launchAttack('MITM', user.username); }}
                          className="ml-2 px-3 py-1 bg-red-500 hover:bg-red-600 rounded text-xs font-semibold"
                        >
                          ⚠ MITM
                        </button>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>

            {users.length === 1 && (
              <div className="mt-4 p-3 bg-yellow-900/30 border border-yellow-600/50 rounded-lg text-sm">
                <p className="text-yellow-300">
                  ⚠ Vous êtes seul ! Ouvrez un nouvel onglet avec le même Room ID.
                </p>
              </div>
            )}
          </div>

          {/* Panneau Messages */}
          <div className={`bg-gray-800 rounded-xl p-6 border border-gray-700 ${showDecryptPanel ? 'lg:col-span-1' : 'lg:col-span-2'}`}>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-bold">
                💬 Messages chiffrés ({messages.length})
              </h2>
              {Object.keys(decryptedMessages).length > 0 && (
                <button
                  onClick={() => setShowDecryptPanel(!showDecryptPanel)}
                  className="px-3 py-1 bg-purple-600 hover:bg-purple-700 rounded text-sm"
                >
                  {showDecryptPanel ? '👁 Masquer' : '🔓 Déchiffrés'}
                </button>
              )}
            </div>

            <div
              ref={messagesContainerRef}
              className="h-96 overflow-y-auto bg-gray-900 rounded-lg p-4 mb-4 space-y-3"
            >
              {hasMoreMessages && (
                <button
                  onClick={loadMoreMessages}
                  className="w-full py-2 bg-gray-700 hover:bg-gray-600 rounded text-sm"
                >
                  ⬆ Charger plus de messages
                </button>
              )}

              {messages.length === 0 ? (
                <p className="text-gray-500 text-center py-8">Aucun message...</p>
              ) : (
                messages.map((msg) => {
                  const isFromMe = msg.from === username;
                  const isToMe = msg.to === username;
                  const isDecrypted = decryptedMessages[msg.id];

                  return (
                    <div
                      key={msg.id}
                      className={`p-3 rounded-lg transition-all ${
                        isFromMe
                          ? 'bg-blue-600 ml-auto max-w-md'
                          : isToMe
                          ? 'bg-green-600 mr-auto max-w-md'
                          : 'bg-gray-700'
                      } ${isDecrypted ? 'ring-2 ring-purple-400' : ''}`}
                    >
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-semibold">{msg.from} → {msg.to}</span>
                        <span className="text-xs text-gray-300">
                          {new Date(msg.timestamp).toLocaleTimeString()}
                        </span>
                      </div>

                      <div className="bg-black/30 p-2 rounded font-mono text-xs mb-2 overflow-x-auto">
                        {msg.sealed
                          ? '[SEALED] enveloppe chiffrée...'
                          : msg.encryptedData?.ciphertext
                            ? `${msg.encryptedData.ciphertext.substring(0, 60)}...`
                            : '[message]'}
                      </div>

                      {isToMe && (
                        <div className="flex items-center gap-2">
                          <button
                            onClick={() => handleDecrypt(msg)}
                            disabled={currentDecrypting === msg.id}
                            className="text-xs bg-white/20 hover:bg-white/30 px-3 py-1 rounded disabled:opacity-50 flex items-center gap-1"
                          >
                            {currentDecrypting === msg.id ? '⏳ Déchiffrement...' : '🔓 Déchiffrer'}
                          </button>
                          {isDecrypted && (
                            <span className="text-xs text-purple-300">✓ Déchiffré</span>
                          )}
                        </div>
                      )}
                    </div>
                  );
                })
              )}
              <div ref={messagesEndRef} />
            </div>

            {typingUsers.length > 0 && (
              <div className="mb-2">
                <TypingIndicator users={typingUsers} />
              </div>
            )}

            {selectedUser ? (
              selectedUser.username === username ? (
                <div className="p-4 bg-yellow-900/30 border border-yellow-600/50 rounded-lg">
                  <p className="text-yellow-300 text-sm">⚠ Sélectionnez un autre participant.</p>
                </div>
              ) : (
                <div>
                  <div className="flex gap-2 mb-2">
                    <input
                      type="text"
                      placeholder={`Message pour ${selectedUser.username}...`}
                      value={messageText}
                      onChange={handleTyping}
                      onKeyPress={(e) => e.key === 'Enter' && !e.shiftKey && sendMessage()}
                      className="flex-1 px-4 py-3 rounded-lg bg-gray-700 border border-gray-600 text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                    <button
                      onClick={sendMessage}
                      disabled={!messageText.trim()}
                      className="px-6 py-3 bg-blue-600 hover:bg-blue-700 rounded-lg font-semibold disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2"
                    >
                      <span>🔒</span>
                      <span>Envoyer</span>
                    </button>
                  </div>
                  <p className="text-xs text-gray-400">
                    Destinataire : <strong className="text-blue-400">{selectedUser.username}</strong>
                    {' • '}
                    <span className={cryptoSessionsReady.current.has(selectedUser.id) ? 'text-green-400' : 'text-yellow-400'}>
                      {cryptoSessionsReady.current.has(selectedUser.id)
                        ? '🔒 Session AES-256-GCM active'
                        : '⏳ Session en cours d\'établissement...'}
                    </span>
                  </p>
                </div>
              )
            ) : (
              <div className="p-4 bg-gray-700 border border-gray-600 rounded-lg text-center">
                <p className="text-gray-400">👈 Sélectionnez un participant pour commencer</p>
              </div>
            )}
          </div>

          {/* Panneau Déchiffrement */}
          {showDecryptPanel && (
            <div className="bg-gray-800 rounded-xl p-6 border border-purple-500 shadow-xl">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-xl font-bold text-purple-400">🔓 Messages Déchiffrés</h2>
                <button
                  onClick={() => setShowDecryptPanel(false)}
                  className="text-gray-400 hover:text-white text-xl font-bold"
                >
                  ✕
                </button>
              </div>

              <div className="h-96 overflow-y-auto space-y-3">
                {Object.keys(decryptedMessages).length === 0 ? (
                  <div className="text-center py-12">
                    <p className="text-gray-500 text-sm">Aucun message déchiffré.</p>
                    <p className="text-gray-600 text-xs mt-2">
                      Cliquez sur "🔓 Déchiffrer" dans les messages reçus
                    </p>
                  </div>
                ) : (
                  Object.entries(decryptedMessages).reverse().map(([msgId, decrypted]) => (
                    <div
                      key={msgId}
                      className="bg-gradient-to-br from-purple-900/50 to-pink-900/50 p-4 rounded-lg border border-purple-500/30"
                    >
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-xs font-semibold text-purple-300">
                          {decrypted.from} → {decrypted.to}
                        </span>
                        <span className="text-xs text-gray-400">
                          {new Date(decrypted.timestamp).toLocaleTimeString()}
                        </span>
                      </div>

                      <div className="bg-white/5 p-3 rounded-lg mb-3">
                        <p className="text-sm font-semibold text-green-400 mb-1">💬 Message en clair :</p>
                        <p className="text-white font-medium">{decrypted.plaintext}</p>
                      </div>

                      <details className="text-xs">
                        <summary className="cursor-pointer text-gray-400 hover:text-gray-300">
                          🔒 Voir le texte chiffré
                        </summary>
                        <div className="mt-2 bg-black/30 p-2 rounded font-mono text-[10px] break-all text-gray-500">
                          {decrypted.ciphertext}
                        </div>
                      </details>
                    </div>
                  ))
                )}
              </div>

              {Object.keys(decryptedMessages).length > 0 && (
                <div className="mt-4 p-3 bg-purple-900/30 border border-purple-600/50 rounded-lg">
                  <p className="text-xs text-purple-300 text-center">
                    📊 {Object.keys(decryptedMessages).length} message(s) déchiffré(s)
                  </p>
                </div>
              )}
            </div>
          )}
        </div>

        {attacks.length > 0 && (
          <div className="max-w-7xl mx-auto mt-6">
            <div className="bg-red-900/30 border border-red-500/50 rounded-xl p-6">
              <h2 className="text-xl font-bold mb-4 text-red-400">
                ⚠ Attaques détectées ({attacks.length})
              </h2>
              <div className="space-y-2">
                {attacks.map((attack) => (
                  <div key={attack.id} className="bg-red-900/50 p-3 rounded-lg">
                    <div className="flex items-center justify-between">
                      <div>
                        <span className="font-semibold">{attack.type}</span>
                        <span className="text-gray-400 text-sm ml-2">→ Cible: {attack.target}</span>
                      </div>
                      <span className={`px-2 py-1 rounded text-xs ${attack.status === 'active' ? 'bg-red-500' : 'bg-gray-500'}`}>
                        {attack.status}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}
      </div>

      <style jsx>{`
        @keyframes slide-in {
          from { transform: translateX(100%); opacity: 0; }
          to { transform: translateX(0); opacity: 1; }
        }
        .animate-slide-in { animation: slide-in 0.3s ease-out; }
        @keyframes bounce {
          0%, 100% { transform: translateY(0); }
          50% { transform: translateY(-10px); }
        }
        .animate-bounce { animation: bounce 1s infinite; }
      `}</style>
    </>



  );
}

export default MultiUserSimulation;