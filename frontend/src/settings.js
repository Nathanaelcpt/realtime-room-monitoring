// Custom popup confirm (promise-based)
function showConfirm(message) {
  return new Promise(resolve => {
    const popup = document.getElementById("confirmPopup");
    const text = document.getElementById("confirmText");
    const yes = document.getElementById("confirmYes");
    const no = document.getElementById("confirmNo");

    text.textContent = message;
    popup.classList.add("show");

    yes.onclick = () => {
      popup.classList.remove("show");
      resolve(true);
    };

    no.onclick = () => {
      popup.classList.remove("show");
      resolve(false);
    };
  });
}

// Auto-detect API
const API =
  window.location.hostname === "localhost"
    ? "http://localhost:8080"
    : "https://realtime-room-monitoring.onrender.com";

const token = localStorage.getItem("token");
if (!token) window.location.href = "/login.html";

document.getElementById("logoutBtn").onclick = () => {
  localStorage.removeItem("token");
  window.location.href = "/login.html";
};

// --- Load Profil ---
async function loadProfile() {
  const res = await fetch(`${API}/me`, {
    headers: { Authorization: "Bearer " + token },
  });
  const data = await res.json();

  document.getElementById("profUsername").textContent = data.username;
  document.getElementById("profName").textContent = data.full_name;
  document.getElementById("userHello").textContent = `Halo, ${data.full_name}`;
}

// --- Update Name ---
document.getElementById("btnUpdateName").onclick = async () => {
  const newName = document.getElementById("newName").value.trim();
  const msg = document.getElementById("nameMsg");

  if (!newName) {
    msg.textContent = "Nama tidak boleh kosong";
    msg.style.color = "red";
    return;
  }

  const res = await fetch(`${API}/update-name`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: "Bearer " + token,
    },
    body: JSON.stringify({ full_name: newName }),
  });

  if (res.ok) {
    msg.textContent = "Nama berhasil diperbarui!";
    msg.style.color = "green";
    loadProfile();
  } else {
    msg.textContent = "Gagal memperbarui nama";
    msg.style.color = "red";
  }
};

// --- Change Password ---
document.getElementById("btnChangePass").onclick = async () => {
  const oldPass = document.getElementById("oldPass").value;
  const newPass = document.getElementById("newPass").value;
  const confPass = document.getElementById("confPass").value;
  const msg = document.getElementById("passMsg");

  if (!oldPass || !newPass || !confPass) {
    msg.textContent = "Semua field harus diisi";
    msg.style.color = "red";
    return;
  }
  if (newPass !== confPass) {
    msg.textContent = "Password baru tidak cocok";
    msg.style.color = "red";
    return;
  }

  const res = await fetch(`${API}/change-password`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: "Bearer " + token,
    },
    body: JSON.stringify({
      old_password: oldPass,
      new_password: newPass,
    }),
  });

  if (res.ok) {
    msg.textContent = "Password berhasil diubah";
    msg.style.color = "green";
  } else {
    msg.textContent = "Gagal mengubah password";
    msg.style.color = "red";
  }
};

// --- Delete Account ---
document.getElementById("btnDelete").onclick = async () => {
  const ok = await showConfirm("Yakin menghapus akun Anda? Aksi ini permanen dan tidak bisa dipulihkan.");

  if (!ok) return;

  const res = await fetch(`${API}/delete-account`, {
    method: "DELETE",
    headers: { Authorization: "Bearer " + token },
  });

  const msg = document.getElementById("delMsg");

  if (res.ok) {
    msg.textContent = "Akun berhasil dihapus. Logout...";
    msg.style.color = "green";
    setTimeout(() => {
      localStorage.removeItem("token");
      window.location.href = "/login.html";
    }, 1500);
  } else {
    msg.textContent = "Gagal menghapus akun";
    msg.style.color = "red";
  }
};


// --- Load Login Activities ---
async function loadActivities() {
  const res = await fetch(`${API}/activities`, {
    headers: { Authorization: "Bearer " + token },
  });
  const list = await res.json();

  const tbody = document.getElementById("actTable");
  tbody.innerHTML = "";

  list.forEach(a => {
    tbody.insertAdjacentHTML(
      "beforeend",
      `
      <tr>
        <td>${new Date(a.created_at).toLocaleString()}</td>
        <td>${a.ip}</td>
        <td>${a.user_agent}</td>
      </tr>
      `
    );
  });
}

// INIT
loadProfile();
loadActivities();
