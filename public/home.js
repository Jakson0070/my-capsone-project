document.addEventListener("DOMContentLoaded", fetchUserInfo);

async function fetchUserInfo() {
  const token = localStorage.getItem("token");
  if (!token) {
    window.location.href = "login.html";
    return;
  }

  const res = await fetch("http://localhost:3000/api/userinfo", {
    headers: { Authorization: token },
  });

  const user = await res.json();
  const userInfoDiv = document.getElementById("userInfo");
  if (user.username) {
    userInfoDiv.innerHTML = `<h1> ${user.username}</h1>`;
  } else {
    alert("Unauthorized");
    localStorage.removeItem("token");
    window.location.href = "login.html";
  }
}

function logout() {
  localStorage.removeItem("token");
  window.location.href = "login.html";
}
