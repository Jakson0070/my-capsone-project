const signupForm = document.getElementById("signupForm");

signupForm.addEventListener("submit", async (e) => {
  e.preventDefault();
  const username = document.getElementById("signupUsername").value;
  const password = document.getElementById("signupPassword").value;

  try {
    const res = await fetch("http://localhost:3000/api/register", {
      // Full URL with backend port
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });

    // Check if the response is OK (status 200-299)
    if (!res.ok) {
      const errorData = await res.text(); // Get error text message
      alert(`Error: ${errorData}`);
      return;
    }

    // Parse JSON only if content is not empty
    const data = res.status !== 204 ? await res.json() : {};

    if (data.message) {
      alert(data.message);
      window.location.href = "login.html";
    } else {
      alert(data.error);
    }
  } catch (error) {
    console.error("Signup Error:", error);
    alert("Signup failed. Please try again.");
  }
});
