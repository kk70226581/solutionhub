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

  const access = await getClientExpertChatAccess(Payment, Message, clientEmail, expertEmail);
  if (!access.hasAccess) {
    return {
      ok: false,
      code: access.reason || "payment_required",
      message:
        access.reason === "window_expired"
          ? "The 24-hour private room has expired."
          : "Payment verification is required for this private room.",
    };
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

    if (
      !socket.data.user?.email ||
      socket.data.user.email !== normalizedEmail ||
      socket.data.user.role !== normalizedRole
    ) {
      socket.emit("auth_error", "Authenticate before updating presence");
      return;
    }

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
    try {
      const access = await validatePrivateRoomAccess(room, socket, Expert, Message, Payment, onlineUsers);
      if (!access.ok) {
        socket.emit("chat_access_denied", {
          room,
          reason: access.code,
          message: access.message,
        });
        return;
      }
      socket.join(access.room);
      const history = await Message.find({ room: access.room })
        .sort({ createdAt: 1 })
        .limit(50);
      socket.emit("chat_history", history);
    } catch (err) {
      console.error("❌ Error loading chat history:", err);
    }
  });

  socket.on("send_private_message", async (data) => {
    try {
      const identity = getSocketIdentity(socket, onlineUsers);
      const senderEmail = normalizeEmail(identity?.email || "");
      const senderRole = String(identity?.role || "").toLowerCase();
      const room = String(data.room || "");

      if (!room || !senderEmail || !senderRole) {
        socket.emit("message_failed", {
          clientMessageId: String(data.clientMessageId || ""),
          message: "Authenticate before sending messages",
        });
        return;
      }

      const roomEmails = parseRoomEmails(room);
      if (roomEmails.length !== 2 || !roomEmails.includes(senderEmail)) {
        socket.emit("message_failed", {
          clientMessageId: String(data.clientMessageId || ""),
          message: "Invalid private room",
        });
        return;
      }

      const otherEmail = roomEmails.find((entry) => entry !== senderEmail) || "";
      const clientEmail = senderRole === "client" ? senderEmail : otherEmail;
      const expertEmail = senderRole === "expert" ? senderEmail : otherEmail;
      const access = await getClientExpertChatAccess(Payment, Message, clientEmail, expertEmail);
      if (!access.hasAccess) {
        socket.emit("chat_access_denied", {
          reason: access.reason,
          clientMessageId: String(data.clientMessageId || ""),
          message:
            access.reason === "window_expired"
              ? "The 24-hour chat window has expired. A new payment is required to continue."
              : "Payment verification is required for this conversation.",
        });
        return;
      }

      const payload = {
        ...data,
        room,
        author: senderEmail || data.author,
        authorRole: senderRole || data.authorRole,
        clientMessageId: String(data.clientMessageId || "").trim().slice(0, 120),
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
        socket.emit("message_failed", {
          clientMessageId: payload.clientMessageId,
          message: "Message cannot be empty",
        });
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
      socket.emit("message_failed", {
        clientMessageId: String(data?.clientMessageId || ""),
        message: "Message failed to send",
      });
    }
  });

  socket.on("typing", async ({ room, isTyping }) => {
    try {
      const access = await validatePrivateRoomAccess(room, socket, Expert, Message, Payment, onlineUsers);
      if (!access.ok) return;
      socket.to(access.room).emit("typing", {
        room: access.room,
        user: access.identity.email,
        name: access.identity.name || access.identity.email.split("@")[0],
        isTyping: Boolean(isTyping),
      });
    } catch (err) {
      console.error("❌ typing relay failed:", err);
    }
  });

  socket.on("stop_typing", async ({ room }) => {
    try {
      const access = await validatePrivateRoomAccess(room, socket, Expert, Message, Payment, onlineUsers);
      if (!access.ok) return;
      socket.to(access.room).emit("typing", {
        room: access.room,
        user: access.identity.email,
        name: access.identity.name || access.identity.email.split("@")[0],
        isTyping: false,
      });
    } catch (err) {
      console.error("❌ stop_typing relay failed:", err);
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

      const callPayload = {
        room: access.room,
        offer,
        from: access.identity.email,
        fromName: access.identity.name || access.identity.email.split("@")[0],
        callType: String(callType || "video").toLowerCase() === "audio" ? "audio" : "video",
      };
      socket.to(access.room).emit("offer", callPayload);

      // Deliver to every authenticated recipient socket that is not already in
      // the room. A user can have a dashboard socket and the global notifier
      // socket open at once; targeting only the latest socket loses calls.
      const recipientEmail = parseRoomEmails(access.room)
        .find((email) => email !== access.identity.email);
      const roomMembers = io.sockets.adapter.rooms.get(access.room);
      for (const [recipientSocketId, recipientSocket] of io.sockets.sockets) {
        if (
          normalizeEmail(recipientSocket?.data?.user?.email) === recipientEmail &&
          !roomMembers?.has(recipientSocketId)
        ) {
          io.to(recipientSocketId).emit("offer", callPayload);
        }
      }
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

  socket.on("call-declined", async ({ room }) => {
    try {
      const access = await validatePrivateRoomAccess(room, socket, Expert, Message, Payment, onlineUsers);
      if (!access.ok) return;
      socket.to(access.room).emit("call-declined", {
        room: access.room,
        from: access.identity.email,
        fromName: access.identity.name || access.identity.email.split("@")[0],
      });
    } catch (err) {
      console.error("❌ call-declined relay failed:", err);
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
