// Auto detect backend API URL
const API =
  window.location.hostname === "localhost"
    ? "http://localhost:8080"
    : "https://realtime-room-monitoring.onrender.com";

const container = document.getElementById("roomsContainer");

// Render room cards
function renderRooms(rooms) {
  container.innerHTML = "";

  rooms.forEach(r => {
    const color =
      r.status === "Tersedia" ? "success" :
        r.status === "Digunakan" ? "primary" :
          "warning";

    container.insertAdjacentHTML(
      "beforeend",
      `
      <div class="col-md-4 fade-room">
        <div class="card room-card border-${color} shadow-sm">
          <div class="card-body text-center py-4">
            <h5 class="card-title mb-3">${r.name}</h5>
            <span class="status-badge bg-${color} text-white">
              ${r.status}
            </span>
          </div>
        </div>
      </div>
      `
    );
  });

  // Apply fade animation
  document.querySelectorAll(".fade-room").forEach(el => {
    el.style.opacity = 0;
    setTimeout(() => {
      el.style.transition = "opacity .4s ease";
      el.style.opacity = 1;
    }, 50);
  });
}

// Initial load
fetch(`${API}/rooms`)
  .then(res => res.json())
  .then(renderRooms)
  .catch(() => {
    container.innerHTML = `
      <div class="col-12 text-center text-danger mt-4">
        <p>⚠ Gagal memuat data dari server.</p>
      </div>`;
  });

// WebSocket realtime update
const wsURL =
  window.location.hostname === "localhost"
    ? "ws://localhost:8080/ws"
    : "wss://realtime-room-monitoring.onrender.com/ws";

const ws = new WebSocket(wsURL);

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  if (data.rooms) renderRooms(data.rooms);
};
