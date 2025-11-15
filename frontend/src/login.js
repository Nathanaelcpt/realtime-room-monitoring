const btn = document.getElementById("loginBtn");
const msg = document.getElementById("message");
const card = document.getElementById("loginCard");

// Auto detect API backend
const API =
  window.location.hostname === "localhost"
    ? "http://localhost:8080"
    : "https://realtime-room-monitoring.onrender.com";

btn.addEventListener("click", async () => {
  const username = document.getElementById("username").value.trim();
  const password = document.getElementById("password").value.trim();

  msg.textContent = "";

  if (!username || !password) {
    msg.textContent = "Username dan password wajib diisi";
    triggerShake();
    return;
  }

  try {
    const res = await fetch(`${API}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });

    const data = await res.json();

    if (res.ok && data.token) {
      localStorage.setItem("token", data.token);
      window.location.href = "/admin.html";
    } else {
      msg.textContent = data.error || "Login gagal";
      triggerShake();
    }

  } catch (err) {
    msg.textContent = "Tidak bisa menghubungi server backend";
    triggerShake();
  }
});

function triggerShake() {
  card.classList.add("shake");
  setTimeout(() => card.classList.remove("shake"), 300);
}
