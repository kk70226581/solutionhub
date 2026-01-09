document.addEventListener("DOMContentLoaded", () => {

    /* ===============================
       LOGIN CHECK
    =============================== */

    const USERNAME = localStorage.getItem("username");
    if (!USERNAME) {
        window.location.href = "login.html";
        return;
    }

    /* ===============================
       BASIC CONFIG
    =============================== */

    const SERVER_URL = "http://localhost:3000";
    const ROOM_ID = "problem_101";

    /* ===============================
       DASHBOARD NAVIGATION
    =============================== */

    const navLinks = document.querySelectorAll(".nav-links a[data-page]");
    const pages = document.querySelectorAll(".page");

    navLinks.forEach(link => {
        link.addEventListener("click", (e) => {
            e.preventDefault();

            const target = link.dataset.page;

            // active nav
            navLinks.forEach(l => l.classList.remove("active"));
            link.classList.add("active");

            // active page
            pages.forEach(p => p.classList.remove("active"));
            const page = document.getElementById(target);
            if (page) page.classList.add("active");
        });
    });

    /* ===============================
       CHAT ELEMENTS
    =============================== */

    const chatWindow = document.getElementById("chatWindow");
    const messageInput = document.getElementById("messageInput");
    const sendBtn = document.getElementById("sendBtn");

    if (!chatWindow || !messageInput || !sendBtn) {
        console.error("Chat UI elements missing");
        return;
    }

    /* ===============================
       SOCKET.IO
    =============================== */

    if (typeof io === "undefined") {
        console.error("Socket.io not loaded");
        return;
    }

    const socket = io(SERVER_URL);

    socket.on("connect", () => {
        socket.emit("join_room", ROOM_ID);
    });

    /* ===============================
       RENDER MESSAGE
    =============================== */

    function renderMessage(msg) {
        const bubble = document.createElement("div");
        const isMe = msg.author === USERNAME;

        bubble.className = `message-bubble ${isMe ? "me" : "other"}`;
        bubble.innerHTML = `
            <strong>${msg.author}</strong>
            <p>${msg.message}</p>
            <small>${msg.time}</small>
        `;

        chatWindow.appendChild(bubble);
        chatWindow.scrollTop = chatWindow.scrollHeight;
    }

    /* ===============================
       LOAD CHAT HISTORY
    =============================== */

    socket.on("chat_history", (messages) => {
        chatWindow.innerHTML = "";
        messages.forEach(renderMessage);
    });

    /* ===============================
       RECEIVE MESSAGE
    =============================== */

    socket.on("receive_message", (msg) => {
        renderMessage(msg);
    });

    /* ===============================
       SEND MESSAGE
    =============================== */

    function sendMessage() {
        const text = messageInput.value.trim();
        if (!text) return;

        socket.emit("send_message", {
            room: ROOM_ID,
            author: USERNAME,
            message: text,
            time: new Date().toLocaleTimeString([], {
                hour: "2-digit",
                minute: "2-digit"
            })
        });

        messageInput.value = "";
    }

    sendBtn.addEventListener("click", sendMessage);

    messageInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
            sendMessage();
        }
    });
});

/* ===============================
   LOGOUT
=============================== */

const logoutBtn = document.getElementById("logoutBtn");
if (logoutBtn) {
    logoutBtn.addEventListener("click", () => {
        localStorage.clear();
        window.location.href = "login.html";
    });
}
