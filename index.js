// server.js
require('dotenv').config();
const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const app = express();
const http = require('http').createServer(app);
const io = require('socket.io')(http);
const PORT = process.env.PORT || 3000;

app.use(express.static('public'));

// Ensure backup directory exists.
const backupDir = path.join(__dirname, 'backup');
if (!fs.existsSync(backupDir)) {
  fs.mkdirSync(backupDir);
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

// Broadcast online users as an array.
function broadcastOnlineUsers() {
  const users = Object.values(onlineUsers);
  io.emit('onlineUsers', users);
}

// Backup the canvas state to a JSON file every hour.
function backupCanvasState() {
  const backupFile = path.join(
    backupDir,
    `canvas_backup_${new Date().toISOString().replace(/[:.]/g, '-')}.json`
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
  const hash = crypto.createHash('sha256').update(pwd).digest('hex');
  return hash === process.env.ADMIN_HASH;
}

// Use setUserData to accept persistent user data from the client.
io.on('connection', (socket) => {
  console.log(`User connected: ${socket.id}`);

  socket.on('setUserData', (data) => {
    // data: { username, color, admin }
    // If the username is "enafrosty", enforce enafrosty privileges.
    if(data.username.toLowerCase() === "enafrosty") {
      data.color = ENA_COLOR;
      data.admin = true;
    } else {
      // For any other user, assign default color.
      data.color = DEFAULT_COLOR;
    }
    onlineUsers[socket.id] = data;
    broadcastOnlineUsers();
    socket.emit('init', pixelState);
    socket.emit('drawingStatus', drawingEnabled);
  });

  socket.on('verifyAdminPassword', (pwd) => {
    if (verifyAdminPassword(pwd)) {
      if (onlineUsers[socket.id]) {
        onlineUsers[socket.id].admin = true;
        // Also assign enafrosty color if verifying for enafrosty.
        if(onlineUsers[socket.id].username.toLowerCase() === "enafrosty") {
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
    const key = `${data.col},${data.row}`;
    pixelState[key] = data.color;
    socket.broadcast.emit('pixelDrawn', data);
  });

  socket.on('toggleDrawing', () => {
    console.log("Toggle drawing requested by:", onlineUsers[socket.id]);
    if (!(onlineUsers[socket.id] && onlineUsers[socket.id].admin)) {
      console.log("Toggle drawing rejected; user is not admin.");
      return;
    }
    drawingEnabled = !drawingEnabled;
    console.log("Drawing enabled set to:", drawingEnabled);
    io.emit('drawingStatus', drawingEnabled);
  });

  socket.on('revokeCanvas', () => {
    if (!(onlineUsers[socket.id] && onlineUsers[socket.id].admin)) return;
    pixelState = {};
    io.emit('canvasRevoked');
  });

  socket.on('loadCanvasState', (data) => {
    if (!(onlineUsers[socket.id] && onlineUsers[socket.id].admin)) return;
    pixelState = data;
    io.emit('init', pixelState);
    console.log("Canvas state replaced by admin backup.");
  });

  socket.on('setCooldown', (data) => {
    if (!(onlineUsers[socket.id] && onlineUsers[socket.id].admin)) return;
    for (const [id, info] of Object.entries(onlineUsers)) {
      if (info.username.toLowerCase() === data.username.toLowerCase()) {
        io.to(id).emit('cooldownStatus', { username: data.username, disabled: data.disabled });
      }
    }
  });

  socket.on('kickUser', (data) => {
    if (!(onlineUsers[socket.id] && onlineUsers[socket.id].admin)) return;
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
    io.emit('broadcastMessage', { message: data.message });
  });

  // Transfer enafrosty privileges to another user.
  socket.on('transferEnaPrivileges', (data) => {
    if (!(onlineUsers[socket.id] && onlineUsers[socket.id].admin)) return;
    const targetUsername = data.targetUsername;
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
    // Remove enafrosty privileges from any user currently using that name.
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

  // (Optional) Handle cursor movement.
  socket.on('cursorMove', (data) => {
    socket.broadcast.emit('cursorMove', data);
  });

  socket.on('disconnect', () => {
    console.log(`User disconnected: ${socket.id}`);
    delete onlineUsers[socket.id];
    broadcastOnlineUsers();
  });
});

process.on('uncaughtException', (err) => {
  console.error("Uncaught exception:", err);
});

http.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
