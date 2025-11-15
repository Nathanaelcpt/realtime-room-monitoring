const registerBtn = document.getElementById("registerBtn");
const msg = document.getElementById("message");
const card = document.getElementById("registerCard");

// Auto API base URL
const API =
  window.location.hostname === "localhost"
    ? "http://localhost:8080"
    : "https://your-railway-backend-url"; // GANTI saat deploy

const token = localStorage.getItem("token");

// Cegah akses tanpa login admin
if (!token) {
  window.location.href = "/login.html";
}

registerBtn.addEventListener("click", async () => {
  const full_name = document.getElementById("fullname").value.trim();
  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value.trim();

  msg.textContent = "";
  msg.style.color = "red";

  if (!full_name || !username || !password) {
    msg.textContent = "Semua field wajib diisi.";
    triggerShake();
    return;
  }

  try {
    const res = await fetch(`${API}/register`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer " + token,
      },
      body: JSON.stringify({ username, password, full_name }),
    });

    const data = await res.json();

    if (res.ok) {
      msg.style.color = "green";
      msg.textContent = "Akun admin berhasil dibuat!";
    } else {
      msg.textContent = data.error || "Gagal membuat akun";
      triggerShake();
    }

  } catch (err) {
    msg.textContent = "Tidak dapat menghubungi server backend";
    triggerShake();
  }
});

function triggerShake() {
  card.classList.add("shake");
  setTimeout(() => card.classList.remove("shake"), 350);
}
