// =========== CHECK TOKEN ===========
const token = localStorage.getItem("token");
if (!token) return;

// Decode token untuk ambil user_id
let payload;
try {
  payload = JSON.parse(atob(token.split(".")[1]));
} catch (err) {
  console.error("Invalid token", err);
  return;
}

const user_id = payload.sub;

// =========== FAST LOAD (nama dari localStorage) ===========
const cachedName = localStorage.getItem("full_name");
if (cachedName) {
  const hello = document.getElementById("userHello");
  if (hello) hello.textContent = `Halo, ${cachedName}`;
}

// =========== SETUP WEBSOCKET ===========
function connectWS() {
  const ws = new WebSocket(
    location.hostname === "localhost"
      ? "ws://localhost:8080/ws"
      : "wss://realtime-room-monitoring.onrender.com/ws"
  );

  // WS OPEN
  ws.onopen = () => {
    console.log("WS connected");

    // Kirim auth supaya server tahu ini milik user siapa
    ws.send(JSON.stringify({
      type: "auth",
      user_id
    }));
  };

  // WS MESSAGE
  ws.onmessage = (ev) => {
    const msg = JSON.parse(ev.data);

    if (msg.type === "profile_update") {

      console.log("Realtime update name:", msg.full_name);

      // Simpan ke localStorage
      localStorage.setItem("full_name", msg.full_name);

      // Update navbar
      const hello = document.getElementById("userHello");
      if (hello) hello.textContent = `Halo, ${msg.full_name}`;

      // Update di halaman settings kalau ada
      const prof = document.getElementById("profName");
      if (prof) prof.textContent = msg.full_name;
    }
  };

  // WS CLOSE → auto reconnect
  ws.onclose = () => {
    console.warn("WS closed. Reconnecting in 2s...");
    setTimeout(connectWS, 2000);
  };

  ws.onerror = () => {
    console.error("WS error");
    ws.close();
  };

  // Simpan di global untuk bisa dipakai settings.js
  window._roomwatchWS = ws;
}

connectWS();
