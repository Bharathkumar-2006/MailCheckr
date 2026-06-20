document.addEventListener("DOMContentLoaded", () => {
    const loginBtn = document.getElementById("login-btn");
    const registerBtn = document.getElementById("register-btn");

    if (loginBtn) {
        loginBtn.addEventListener("click", () => {
            const username = document.getElementById("username").value;
            const password = document.getElementById("password").value;

            fetch("http://localhost:5000/api/login", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, password })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    localStorage.setItem("token", data.token);
                    chrome.storage.local.set({ token: data.token }, () => {
                        window.location.href = "popup.html"; 
                    });
                } else {
                    document.getElementById("error-message").textContent = data.message;
                }
            })
            .catch(error => {
                console.error("Login Error:", error);
                document.getElementById("error-message").textContent = "Login failed.";
            });
        });
    }

    if (registerBtn) {
        registerBtn.addEventListener("click", () => {
            const username = document.getElementById("username").value;
            const email = document.getElementById("email").value;
            const password = document.getElementById("password").value;

            fetch("http://localhost:5000/api/register", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ username, email, password })
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    window.location.href = "login.html"; 
                } else {
                    document.getElementById("error-message").textContent = data.message;
                }
            })
            .catch(error => {
                console.error("Registration Error:", error);
                document.getElementById("error-message").textContent = "Registration failed.";
            });
        });
    }
});
