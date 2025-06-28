// Pixelz - @enafrosty
require('dotenv').config();
const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http);
const PORT = process.env.PORT || 3000;

// Middleware for JSON parsing 
app.use(express.json());
app.use(express.static('public'));

// Ensure backup directory exists and is safe
const backupDir = path.join(__dirname, 'backup');
if (!fs.existsSync(backupDir)) {
  fs.mkdirSync(backupDir, { recursive: true });
}

// In-memory canvas state and drawing flag.
let pixelState = {};
let drawingEnabled = true;

// Online users: mapping socket.id -> { username, admin, color }.
const onlineUsers = {};

// For non-enafrosty users, assign a fixed green color.
const DEFAULT_COLOR = "#00ff00";
// For enafrosty (or transferred privileges), use glowing cyan.
const ENA_COLOR = "#00ffff";

// Rate limiting (simple in-memory, per socket)
const RATE_LIMITS = {
  drawPixel: { windowMs: 1000, max: 10 }, // 10 draws per second
  broadcastMessage: { windowMs: 5000, max: 2 }, // 2 messages per 5 seconds
};
const userActions = {};

// Helper: sanitize username
function sanitizeUsername(username) {
  if (typeof username !== 'string') return '';
  return username.replace(/[^a-zA-Z0-9_\-]/g, '').slice(0, 20);
}

// Helper: validate color (hex)
function isValidColor(color) {
  return /^#[0-9a-fA-F]{6}$/.test(color);
}

// Helper: rate limit
function isRateLimited(socket, action) {
  const now = Date.now();
  if (!userActions[socket.id]) userActions[socket.id] = {};
  const actionData = userActions[socket.id][action] || { count: 0, last: now };
  if (now - actionData.last > RATE_LIMITS[action].windowMs) {
    actionData.count = 1;
    actionData.last = now;
  } else {
    actionData.count += 1;
  }
  userActions[socket.id][action] = actionData;
  return actionData.count > RATE_LIMITS[action].max;
}

// Broadcast online users as an array.
function broadcastOnlineUsers() {
  const users = Object.values(onlineUsers);
  io.emit('onlineUsers', users);
}

// Backup the canvas state to a JSON file every hour.
function backupCanvasState() {
  // Use only safe characters in filename
  const safeDate = new Date().toISOString().replace(/[^0-9T]/g, '-');
  const backupFile = path.join(
    backupDir,
    `canvas_backup_${safeDate}.json`
  );
  fs.writeFile(backupFile, JSON.stringify(pixelState), (err) => {
    if (err) console.error("Error writing backup:", err);
    else console.log("Canvas backup saved to", backupFile);
  });
}
setInterval(backupCanvasState, 3600000);

// Daily reset: clear canvas at midnight.
function scheduleDailyReset() {
  const now = new Date();
  const tomorrow = new Date(now);
  tomorrow.setDate(now.getDate() + 1);
  tomorrow.setHours(0, 0, 0, 0);
  const msUntilMidnight = tomorrow.getTime() - now.getTime();
  setTimeout(() => {
    pixelState = {};
    io.emit('canvasRevoked');
    console.log("Canvas reset at midnight.");
    scheduleDailyReset();
  }, msUntilMidnight);
}
scheduleDailyReset();

// Verify admin password using SHA-256. ADMIN_HASH is stored in .env.
function verifyAdminPassword(pwd) {
  if (typeof pwd !== 'string' || pwd.length > 100) return false;
  const hash = crypto.createHash('sha256').update(pwd).digest('hex');
  return hash === process.env.ADMIN_HASH;
}

// Limit pixelState size to prevent DoS
const MAX_PIXELS = 100000;

io.on('connection', (socket) => {
  console.log(`User connected: ${socket.id}`);

  socket.on('setUserData', (data) => {
    // data: { username, color, admin }
    let username = sanitizeUsername(data.username);
    if (!username) username = `user${Math.floor(Math.random() * 10000)}`;
    let color = isValidColor(data.color) ? data.color : DEFAULT_COLOR;

    // Enforce enafrosty privileges if username is "enafrosty"
    if (username.toLowerCase() === "enafrosty") {
      color = ENA_COLOR;
      onlineUsers[socket.id] = { username, color, admin: true };
    } else {
      onlineUsers[socket.id] = { username, color: DEFAULT_COLOR, admin: false };
    }
    broadcastOnlineUsers();
    socket.emit('init', pixelState);
    socket.emit('drawingStatus', drawingEnabled);
  });

  socket.on('verifyAdminPassword', (pwd) => {
    if (verifyAdminPassword(pwd)) {
      if (onlineUsers[socket.id]) {
        // Only one admin allowed (enafrosty or transferred)
        for (const id in onlineUsers) {
          if (onlineUsers[id].admin) {
            onlineUsers[id].admin = false;
            onlineUsers[id].color = DEFAULT_COLOR;
            io.to(id).emit('adminAccessRevoked');
          }
        }
        onlineUsers[socket.id].admin = true;
        if (onlineUsers[socket.id].username.toLowerCase() === "enafrosty") {
          onlineUsers[socket.id].color = ENA_COLOR;
        }
      }
      socket.emit('adminVerified');
      broadcastOnlineUsers();
    } else {
      socket.emit('adminVerificationFailed');
    }
  });

  socket.on('drawPixel', (data) => {
    if (!drawingEnabled) return;
    if (isRateLimited(socket, 'drawPixel')) return;
    if (
      typeof data.col !== 'number' ||
      typeof data.row !== 'number' ||
      !isValidColor(data.color)
    ) return;
    const key = `${data.col},${data.row}`;
    // Limit pixelState size
    if (Object.keys(pixelState).length > MAX_PIXELS) return;
    pixelState[key] = data.color;
    socket.broadcast.emit('pixelDrawn', data);
  });

  socket.on('toggleDrawing', () => {
    if (!(onlineUsers[socket.id] && onlineUsers[socket.id].admin)) return;
    drawingEnabled = !drawingEnabled;
    io.emit('drawingStatus', drawingEnabled);
  });

  socket.on('revokeCanvas', () => {
    if (!(onlineUsers[socket.id] && onlineUsers[socket.id].admin)) return;
    pixelState = {};
    io.emit('canvasRevoked');
  });

  socket.on('loadCanvasState', (data) => {
    if (!(onlineUsers[socket.id] && onlineUsers[socket.id].admin)) return;
    if (typeof data !== 'object' || Array.isArray(data)) return;
    // Limit pixelState size
    if (Object.keys(data).length > MAX_PIXELS) return;
    pixelState = data;
    io.emit('init', pixelState);
    console.log("Canvas state replaced by admin backup.");
  });

  socket.on('setCooldown', (data) => {
    if (!(onlineUsers[socket.id] && onlineUsers[socket.id].admin)) return;
    if (!data || typeof data.username !== 'string' || typeof data.disabled !== 'boolean') return;
    for (const [id, info] of Object.entries(onlineUsers)) {
      if (info.username.toLowerCase() === data.username.toLowerCase()) {
        io.to(id).emit('cooldownStatus', { username: data.username, disabled: data.disabled });
      }
    }
  });

  socket.on('kickUser', (data) => {
    if (!(onlineUsers[socket.id] && onlineUsers[socket.id].admin)) return;
    if (!data || typeof data.username !== 'string') return;
    for (const [id, info] of Object.entries(onlineUsers)) {
      if (info.username.toLowerCase() === data.username.toLowerCase()) {
        io.to(id).emit('kickUser');
        const targetSocket = io.sockets.sockets.get(id);
        if (targetSocket) targetSocket.disconnect(true);
      }
    }
  });

  socket.on('broadcastMessage', (data) => {
    if (!(onlineUsers[socket.id] && onlineUsers[socket.id].admin)) return;
    if (isRateLimited(socket, 'broadcastMessage')) return;
    if (!data || typeof data.message !== 'string' || data.message.length > 500) return;
    io.emit('broadcastMessage', { message: data.message });
  });

  // Transfer enafrosty privileges to another user.
  socket.on('transferEnaPrivileges', (data) => {
    if (!(onlineUsers[socket.id] && onlineUsers[socket.id].admin)) return;
    if (!data || typeof data.targetUsername !== 'string') return;
    const targetUsername = sanitizeUsername(data.targetUsername);
    if (!targetUsername || targetUsername.toLowerCase() === "enafrosty") {
      socket.emit('errorMessage', { message: "Cannot transfer to this user." });
      return;
    }
    if (onlineUsers[socket.id].username.toLowerCase() === targetUsername.toLowerCase()) {
      socket.emit('errorMessage', { message: "Cannot transfer to yourself." });
      return;
    }
    let targetSocketId = null;
    for (const [id, info] of Object.entries(onlineUsers)) {
      if (info.username.toLowerCase() === targetUsername.toLowerCase()) {
        targetSocketId = id;
        break;
      }
    }
    if (!targetSocketId) {
      socket.emit('errorMessage', { message: "Target user not found." });
      return;
    }
    // Remove enafrosty privileges from any user using that name.
    for (const [id, info] of Object.entries(onlineUsers)) {
      if (info.username.toLowerCase() === "enafrosty") {
        onlineUsers[id].admin = false;
        onlineUsers[id].color = DEFAULT_COLOR;
        io.to(id).emit('adminAccessRevoked');
      }
    }
    // Grant enafrosty privileges to the target user.
    onlineUsers[targetSocketId].admin = true;
    onlineUsers[targetSocketId].color = ENA_COLOR;
    io.to(targetSocketId).emit('enaPrivilegesGranted');
    broadcastOnlineUsers();
  });

  socket.on('cursorMove', (data) => {
    // Optionally validate data here
    socket.broadcast.emit('cursorMove', data);
  });

  socket.on('disconnect', () => {
    delete onlineUsers[socket.id];
    delete userActions[socket.id];
    broadcastOnlineUsers();
  });
});

process.on('uncaughtException', (err) => {
  console.error("Uncaught exception:", err);
});

http.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});