// Auto detect API backend
const API =
  window.location.hostname === "localhost"
    ? "http://localhost:8080"
    : "https://your-railway-backend-url";

// Check auth
const token = localStorage.getItem("token");
if (!token) {
  window.location.href = "/login.html";
}

// Safe JWT decode
function decodeJWT(token) {
  try {
    const payload = token.split(".")[1];
    return JSON.parse(atob(payload));
  } catch {
    return {};
  }
}

const payload = decodeJWT(token);
const fullName = payload.full_name || payload.sub || "Admin";

// Display user name on navbar
const activeUserSpan = document.getElementById("activeUser");
activeUserSpan.textContent = "Halo, " + fullName;
activeUserSpan.classList.remove("d-none");

// Logout
document.getElementById("logoutBtn").onclick = () => {
  localStorage.removeItem("token");
  window.location.href = "/login.html";
};


//
// POPUP
//

function showPopup(message) {
  const popup = document.getElementById("notifPopup");
  const msg = document.getElementById("notifMessage");

  msg.textContent = message;

  popup.style.visibility = "visible";
  popup.style.opacity = "1";
  popup.style.transform = "translate(-50%, -50%) scale(1)";

  setTimeout(() => {
    popup.style.opacity = "0";
    popup.style.transform = "translate(-50%, -50%) scale(0.85)";
    setTimeout(() => (popup.style.visibility = "hidden"), 250);
  }, 1500);
}

//
// Fetch Rooms
//

const roomList = document.getElementById("roomList");

async function loadRooms() {
  const res = await fetch(`${API}/rooms`);
  const rooms = await res.json();
  renderRooms(rooms);
}

function renderRooms(rooms) {
  roomList.innerHTML = "";

  rooms.forEach(r => {
    roomList.insertAdjacentHTML(
      "beforeend",
      `
      <div class="col-md-4">
        <div class="card room-card p-3">
          <div class="card-body">

            <h5 class="fw-bold mb-3" style="color:#1e1b4b">${r.name}</h5>

            <label class="form-label fw-semibold">Status:</label>
            <select id="sel-${r.id}" class="form-select mb-3 shadow-sm">
              <option ${r.status==="Tersedia"?"selected":""}>Tersedia</option>
              <option ${r.status==="Digunakan"?"selected":""}>Digunakan</option>
              <option ${r.status==="Dipesan"?"selected":""}>Dipesan</option>
            </select>

            <button class="btn btn-gradient w-100" onclick="updateStatus(${r.id})">
              Simpan Perubahan
            </button>

          </div>
        </div>
      </div>
      `
    );
  });
}

//
// Update Room Status
//

window.updateStatus = async (id) => {
  const newStatus = document.getElementById(`sel-${id}`).value;

  await fetch(`${API}/update`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": "Bearer " + token,
    },
    body: JSON.stringify({ id, status: newStatus }),
  });

  showPopup("Status ruangan berhasil diperbarui!");
};

//
// WebSocket realtime
//

const wsURL =
  window.location.hostname === "localhost"
    ? "ws://localhost:8080/ws"
    : "wss://your-railway-backend-url/ws";

const ws = new WebSocket(wsURL);

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  if (data.rooms) renderRooms(data.rooms);
};

//
// Initial load
//
loadRooms();
