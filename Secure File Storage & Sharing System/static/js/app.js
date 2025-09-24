// Helper to show results in a div
function showMessage(containerId, message, type = "success") {
  const container = document.getElementById(containerId);
  if (container) {
    container.innerHTML = `<p class="${type}">${message}</p>`;
  }
}

// ---------------- REGISTER ----------------
const registerForm = document.getElementById("registerForm");
if (registerForm) {
  registerForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const data = {
      username: registerForm.username.value,
      password: registerForm.password.value,
    };

    try {
      const res = await fetch("/api/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      });

      const result = await res.json();
      if (result.success) {
        showMessage("qr-section", "Scan this QR in Google Authenticator:", "success");
        document.getElementById("qr-section").innerHTML +=
          `<img src="data:image/png;base64,${result.qr_code}" class="qr">`;
      } else {
        showMessage("qr-section", result.error, "error");
      }
    } catch (err) {
      showMessage("qr-section", "Server error. Try again.", "error");
    }
  });
}

// ---------------- LOGIN ----------------
const loginForm = document.getElementById("loginForm");
if (loginForm) {
  loginForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const data = {
      username: loginForm.username.value,
      password: loginForm.password.value,
      otp: loginForm.otp.value,
    };

    try {
      const res = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      });

      const result = await res.json();
      if (result.success) {
        alert("✅ Login successful!");
        window.location.href = "upload.html"; // redirect after login
      } else {
        alert("❌ " + result.error);
      }
    } catch (err) {
      alert("Server error. Try again.");
    }
  });
}

// ---------------- UPLOAD ----------------
const uploadForm = document.getElementById("uploadForm");
if (uploadForm) {
  uploadForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const formData = new FormData(uploadForm);

    try {
      const res = await fetch("/api/upload", {
        method: "POST",
        body: formData,
      });

      const result = await res.json();
      if (result.success) {
        alert("✅ File uploaded successfully!");
      } else {
        alert("❌ " + result.error);
      }
    } catch (err) {
      alert("Server error. Try again.");
    }
  });
}

// ---------------- DOWNLOAD ----------------
const downloadForm = document.getElementById("downloadForm");
if (downloadForm) {
  downloadForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const formData = new FormData(downloadForm);

    try {
      const res = await fetch("/api/download", {
        method: "POST",
        body: formData,
      });

      if (!res.ok) throw new Error("Download failed");

      // force file download
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = formData.get("filename").replace(".enc", ""); // remove .enc
      document.body.appendChild(a);
      a.click();
      a.remove();
    } catch (err) {
      alert("❌ Error downloading file.");
    }
  });
}

// ---------------- SHARE ----------------
const shareForm = document.getElementById("shareForm");
if (shareForm) {
  shareForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const filename = document.getElementById("filename").value;

    try {
      const res = await fetch("/api/share", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ filename }),
      });

      const result = await res.json();
      if (result.success) {
        document.getElementById("result").innerHTML =
          `<p class="success">Share link: <a href="${result.link}" target="_blank">${result.link}</a></p>
           <img src="data:image/png;base64,${result.qr_code}" class="qr">`;
      } else {
        showMessage("result", result.error, "error");
      }
    } catch (err) {
      showMessage("result", "Server error. Try again.", "error");
    }
  });
}
