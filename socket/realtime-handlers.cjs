/**
 * SOCKET HANDLERS – Chat & Call event handlers (separates ~370 lines from main server)
 */

const jwt = require("jsonwebtoken");
const {
  normalizeEmail,
  normalizePrivateRoom,
  parseRoomEmails,
  toChatAttachmentDataUrl,
  getChatAttachmentTypeFromMime,
} = require("../utils/shared-helpers.cjs");
const { getClientExpertChatAccess } = require("../utils/payment-access-helpers.cjs");

const JWT_SECRET = process.env.JWT_SECRET || "solutionhub_secret";

const getSocketIdentity = (socket, onlineUsers) => {
  if (socket.data.user?.email) return socket.data.user;

  const senderEntry = Object.entries(onlineUsers).find(
    ([, info]) => info.socketId === socket.id
  );

  return {
    email: normalizeEmail(senderEntry?.[0] || ""),
    role: String(senderEntry?.[1]?.role || "").toLowerCase(),
    name: String(senderEntry?.[1]?.name || "").trim(),
  };
};

const validatePrivateRoomAccess = async (room, socket, Expert, Message, Payment, onlineUsers) => {
  const identity = getSocketIdentity(socket, onlineUsers);
  const normalizedRoom = normalizePrivateRoom(room);
  const emails = parseRoomEmails(normalizedRoom);

  if (!identity?.email || !identity?.role) {
    return { ok: false, code: "unauthenticated", message: "Authenticate first" };
  }

  if (!normalizedRoom || emails.length !== 2 || !emails.includes(identity.email)) {
    return { ok: false, code: "invalid_room", message: "Invalid private room" };
  }

  const otherEmail = emails.find((e) => e !== identity.email) || "";
  const expertEmail = identity.role === "expert" ? identity.email : otherEmail;
  const clientEmail = identity.role === "client" ? identity.email : otherEmail;

  if (!clientEmail || !expertEmail) {
    return { ok: false, code: "invalid_room", message: "Invalid room participants" };
  }

  if (identity.role === "client") {
    const access = await getClientExpertChatAccess(Payment, Message, clientEmail, expertEmail);
    if (!access.hasAccess) {
      return {
        ok: false,
        code: access.reason || "payment_required",
        message:
          access.reason === "window_expired"
            ? "Your 24-hour call window has expired."
            : "Payment verification is required for calls.",
      };
    }
  }

  return { ok: true, room: normalizedRoom, identity };
};

// Register all socket event handlers
const registerSocketHandlers = (io, socket, models, onlineUsers, addLocalOnlineUser, removeLocalOnlineUser, emitUserPresence, redisPresence) => {
  const { Expert, Message, Payment } = models;

  console.log("🔌 Socket connected:", socket.id);

  socket.data.user = null;
  socket.data.callRooms = new Set();

  // ============================================================
  // AUTHENTICATION
  // ============================================================
  socket.on("authenticate", async ({ token }) => {
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const email = normalizeEmail(decoded.email || "");
      const role = String(decoded.role || "").toLowerCase();
      const name = String(decoded.name || email.split("@")[0] || "").trim();

      const expert = await Expert.findOne({ email });
      if (role === "expert" && (!expert || expert.status !== "approved")) {
        socket.emit("auth_error", "Expert not approved yet");
        return;
      }

      const presence = {
        socketId: socket.id,
        name,
        role,
        field: expert?.field,
        status: expert?.status || "client",
        connectedAt: new Date(),
      };
      addLocalOnlineUser(email, presence);
      await redisPresence.setRedisPresence(email, presence);

      socket.data.user = { email, role, name };

      console.log("✅ User authenticated:", email, role);
      socket.emit("auth_success", { email, role });
      await emitUserPresence(email, true);
    } catch (err) {
      console.error("❌ Socket auth error:", err.message);
      socket.emit("auth_error", "Invalid token");
    }
  });

  socket.on("user_online", async ({ email, name, role }) => {
    const normalizedEmail = normalizeEmail(email);
    const normalizedRole = String(role || "").toLowerCase();
    const normalizedName = String(name || normalizedEmail.split("@")[0] || "").trim();

    const presence = {
      socketId: socket.id,
      name: normalizedName,
      role: normalizedRole,
      connectedAt: new Date(),
    };
    addLocalOnlineUser(normalizedEmail, presence);
    socket.data.user = {
      email: normalizedEmail,
      role: normalizedRole,
      name: normalizedName,
    };
    await redisPresence.setRedisPresence(normalizedEmail, presence);
    await emitUserPresence(normalizedEmail, true);
  });

  // ============================================================
  // CHAT
  // ============================================================
  socket.on("join_private", async (room) => {
    socket.join(room);
    try {
      const history = await Message.find({ room })
        .sort({ createdAt: 1 })
        .limit(50);
      socket.emit("chat_history", history);
    } catch (err) {
      console.error("❌ Error loading chat history:", err);
    }
  });

  socket.on("send_private_message", async (data) => {
    try {
      const senderEntry = Object.entries(onlineUsers).find(
        ([, info]) => info.socketId === socket.id
      );
      const senderEmail = normalizeEmail(senderEntry?.[0] || data.author || "");
      const senderRole = String(senderEntry?.[1]?.role || data.authorRole || "").toLowerCase();
      const room = String(data.room || "");

      if (!room) {
        socket.emit("error", "Invalid room");
        return;
      }

      // Enforce payment/access window for client messages
      if (senderRole === "client") {
        const emails = parseRoomEmails(room);
        const expertEmail = emails.find((e) => e && e !== senderEmail) || "";
        const access = await getClientExpertChatAccess(Payment, Message, senderEmail, expertEmail);
        if (!access.hasAccess) {
          socket.emit("chat_access_denied", {
            reason: access.reason,
            message:
              access.reason === "window_expired"
                ? "Your 24-hour chat window has expired. Please make a new payment to continue."
                : "Please complete payment to continue chatting with this expert.",
          });
          return;
        }
      }

      const payload = {
        ...data,
        room,
        author: senderEmail || data.author,
        authorRole: senderRole || data.authorRole,
      };
      const text = String(payload.message || "").trim();
      const attachmentUrl = toChatAttachmentDataUrl(payload.attachmentUrl || payload.imageUrl);
      const attachmentMimeMatch = attachmentUrl.match(/^data:([^;]+);base64,/i);
      const attachmentMime = String(
        payload.attachmentMime || attachmentMimeMatch?.[1] || ""
      )
        .trim()
        .toLowerCase()
        .slice(0, 160);
      const attachmentType = getChatAttachmentTypeFromMime(attachmentMime);
      const attachmentName = String(payload.attachmentName || payload.imageName || "")
        .trim()
        .slice(0, 160);
      const hasText = Boolean(text);
      const hasAttachment = Boolean(attachmentUrl && attachmentType);

      if (!hasText && !hasAttachment) {
        socket.emit("error", "Message cannot be empty");
        return;
      }

      payload.messageType = hasAttachment ? attachmentType : "text";
      payload.message = text;
      payload.attachmentUrl = hasAttachment ? attachmentUrl : "";
      payload.attachmentName = hasAttachment ? attachmentName : "";
      payload.attachmentMime = hasAttachment ? attachmentMime : "";
      payload.imageUrl = attachmentType === "image" ? attachmentUrl : "";
      payload.imageName = attachmentType === "image" ? attachmentName : "";

      const msg = await Message.create(payload);
      io.to(room).emit("receive_message", msg);

      const emails = parseRoomEmails(room);
      emails.forEach((email) => {
        if (onlineUsers[email] && onlineUsers[email].socketId) {
          io.to(onlineUsers[email].socketId).emit("new_message_notification", {
            room,
            message: msg,
          });
        }
      });
    } catch (err) {
      console.error("❌ Message save failed:", err);
      socket.emit("error", "Message failed");
    }
  });

  // ============================================================
  // VIDEO CALLS
  // ============================================================
  socket.on("join-room", async ({ room }) => {
    try {
      const access = await validatePrivateRoomAccess(room, socket, Expert, Message, Payment, onlineUsers);
      if (!access.ok) {
        socket.emit("call_access_denied", {
          room,
          reason: access.code,
          message: access.message,
        });
        return;
      }

      socket.join(access.room);
      socket.data.callRooms.add(access.room);
      socket.emit("room_joined", { room: access.room });
    } catch (err) {
      console.error("❌ join-room failed:", err);
      socket.emit("call_access_denied", {
        room,
        reason: "server_error",
        message: "Could not join the call room.",
      });
    }
  });

  socket.on("offer", async ({ room, offer, callType }) => {
    try {
      const access = await validatePrivateRoomAccess(room, socket, Expert, Message, Payment, onlineUsers);
      if (!access.ok) {
        socket.emit("call_access_denied", {
          room,
          reason: access.code,
          message: access.message,
        });
        return;
      }

      socket.to(access.room).emit("offer", {
        room: access.room,
        offer,
        from: access.identity.email,
        callType: String(callType || "video").toLowerCase() === "audio" ? "audio" : "video",
      });
    } catch (err) {
      console.error("❌ offer relay failed:", err);
    }
  });

  socket.on("answer", async ({ room, answer, callType }) => {
    try {
      const access = await validatePrivateRoomAccess(room, socket, Expert, Message, Payment, onlineUsers);
      if (!access.ok) {
        socket.emit("call_access_denied", {
          room,
          reason: access.code,
          message: access.message,
        });
        return;
      }

      socket.to(access.room).emit("answer", {
        room: access.room,
        answer,
        from: access.identity.email,
        callType: String(callType || "video").toLowerCase() === "audio" ? "audio" : "video",
      });
    } catch (err) {
      console.error("❌ answer relay failed:", err);
    }
  });

  socket.on("ice-candidate", async ({ room, candidate }) => {
    try {
      const access = await validatePrivateRoomAccess(room, socket, Expert, Message, Payment, onlineUsers);
      if (!access.ok) {
        socket.emit("call_access_denied", {
          room,
          reason: access.code,
          message: access.message,
        });
        return;
      }

      socket.to(access.room).emit("ice-candidate", {
        room: access.room,
        candidate,
        from: access.identity.email,
      });
    } catch (err) {
      console.error("❌ ICE relay failed:", err);
    }
  });

  socket.on("call-ended", async ({ room }) => {
    try {
      const access = await validatePrivateRoomAccess(room, socket, Expert, Message, Payment, onlineUsers);
      if (!access.ok) return;
      socket.to(access.room).emit("call-ended", {
        room: access.room,
        from: access.identity.email,
      });
    } catch (err) {
      console.error("❌ call-ended relay failed:", err);
    }
  });

  socket.on("media-mode-changed", async ({ room, mode }) => {
    try {
      const access = await validatePrivateRoomAccess(room, socket, Expert, Message, Payment, onlineUsers);
      if (!access.ok) return;
      socket.to(access.room).emit("media-mode-changed", {
        room: access.room,
        mode: String(mode || "camera"),
        from: access.identity.email,
      });
    } catch (err) {
      console.error("❌ media mode relay failed:", err);
    }
  });

  // ============================================================
  // DISCONNECT
  // ============================================================
  socket.on("disconnect", async () => {
    if (socket.data.callRooms?.size) {
      for (const room of socket.data.callRooms) {
        socket.to(room).emit("peer-disconnected", {
          room,
          socketId: socket.id,
        });
      }
    }

    const userEmail = normalizeEmail(socket.data.user?.email || "");
    if (!userEmail) return;

    const stillOnlineLocally = removeLocalOnlineUser(userEmail, socket.id, new Map(), onlineUsers);
    const stillOnlineInRedis = await redisPresence.clearRedisPresenceSocket(userEmail, socket.id);
    await emitUserPresence(userEmail, stillOnlineInRedis !== null ? stillOnlineInRedis : stillOnlineLocally);
  });
};

module.exports = {
  registerSocketHandlers,
};
