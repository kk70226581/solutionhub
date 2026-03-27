/**
 * PRESENCE MANAGEMENT – Handle user online status (consolidate duplicated logic)
 */

const { normalizeEmail } = require("../utils/shared-helpers.cjs");

const PRESENCE_USERS_KEY = "presence:users";
const PRESENCE_USER_SOCKETS_PREFIX = "presence:user-sockets:";

const getPresenceUserSocketsKey = (email) =>
  `${PRESENCE_USER_SOCKETS_PREFIX}${normalizeEmail(email)}`;

// Get online users snapshot from Redis or in-memory
const getOnlineUsersSnapshot = async (redisClient, redisReady, onlineUsers) => {
  if (!redisReady || !redisClient) {
    return { ...onlineUsers };
  }
  try {
    const raw = await redisClient.hGetAll(PRESENCE_USERS_KEY);
    const out = {};
    for (const [email, value] of Object.entries(raw || {})) {
      try {
        out[email] = JSON.parse(value);
      } catch {
        // ignore malformed presence records
      }
    }
    return out;
  } catch {
    return { ...onlineUsers };
  }
};

// Set presence in Redis
const setRedisPresence = async (redisClient, redisReady, email, presence) => {
  if (!redisReady || !redisClient || !email) return;
  try {
    const normalizedEmail = normalizeEmail(email);
    await redisClient.multi()
      .hSet(PRESENCE_USERS_KEY, normalizedEmail, JSON.stringify(presence))
      .sAdd(getPresenceUserSocketsKey(normalizedEmail), presence.socketId)
      .exec();
  } catch {
    // ignore redis presence write errors
  }
};

// Clear presence from Redis
const clearRedisPresenceSocket = async (redisClient, redisReady, email, socketId) => {
  if (!redisReady || !redisClient || !email || !socketId) return null;
  try {
    const normalizedEmail = normalizeEmail(email);
    const socketsKey = getPresenceUserSocketsKey(normalizedEmail);
    await redisClient.sRem(socketsKey, socketId);
    const remaining = await redisClient.sCard(socketsKey);
    if (remaining <= 0) {
      await redisClient.multi().hDel(PRESENCE_USERS_KEY, normalizedEmail).del(socketsKey).exec();
      return false;
    }
    return true;
  } catch {
    return null;
  }
};

// Add user to local online users map
const addLocalOnlineUser = (email, presence, localUserSockets, onlineUsers) => {
  const normalizedEmail = normalizeEmail(email);
  if (!normalizedEmail || !presence?.socketId) return;
  const sockets = localUserSockets.get(normalizedEmail) || new Set();
  sockets.add(presence.socketId);
  localUserSockets.set(normalizedEmail, sockets);
  onlineUsers[normalizedEmail] = {
    ...(onlineUsers[normalizedEmail] || {}),
    ...presence,
    socketId: presence.socketId,
  };
};

// Remove user from local online users
const removeLocalOnlineUser = (email, socketId, localUserSockets, onlineUsers) => {
  const normalizedEmail = normalizeEmail(email);
  const sockets = localUserSockets.get(normalizedEmail);
  if (!sockets) return false;
  sockets.delete(socketId);
  if (sockets.size === 0) {
    localUserSockets.delete(normalizedEmail);
    delete onlineUsers[normalizedEmail];
    return false;
  }
  const fallbackSocketId = sockets.values().next().value;
  if (onlineUsers[normalizedEmail]) {
    onlineUsers[normalizedEmail] = {
      ...onlineUsers[normalizedEmail],
      socketId: fallbackSocketId,
    };
  }
  return true;
};

module.exports = {
  PRESENCE_USERS_KEY,
  PRESENCE_USER_SOCKETS_PREFIX,
  getPresenceUserSocketsKey,
  getOnlineUsersSnapshot,
  setRedisPresence,
  clearRedisPresenceSocket,
  addLocalOnlineUser,
  removeLocalOnlineUser,
};
