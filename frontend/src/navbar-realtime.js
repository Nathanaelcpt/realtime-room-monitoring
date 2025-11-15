const token = localStorage.getItem("token");
if (!token) return;

const payload = JSON.parse(atob(token.split(".")[1]));
const user_id = payload.sub;

const ws = new WebSocket(
  location.hostname === "localhost"
    ? "ws://localhost:8080/ws"
    : "wss://realtime-room-monitoring.onrender.com/ws"
);

// saat connect, kirim user_id biar server tahu ini channel siapa
ws.onopen = () => {
  ws.send(JSON.stringify({
    type: "auth",
    user_id
  }));
};

// kalau ada update profile dari server
ws.onmessage = ev => {
  const msg = JSON.parse(ev.data);

  if (msg.type === "profile_update") {
    // update di browser
    localStorage.setItem("full_name", msg.full_name);

    const hello = document.getElementById("userHello");
    if (hello) {
      hello.textContent = `Halo, ${msg.full_name}`;
    }
  }
};
