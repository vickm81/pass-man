document.addEventListener("DOMContentLoaded", () => {
    const passwordList = document.getElementById("password-list");
    const addPasswordForm = document.getElementById("add-password-form");
    const logoutButton = document.getElementById("logout");
    const generatePasswordButton = document.getElementById("generate-password");
    const passwordField = document.getElementById("password");
    const toast = new bootstrap.Toast(document.getElementById('liveToast'));

     // Function to generate a secure password
     generatePasswordButton.addEventListener("click", async () => {
        const length = 16; // Default length for generated passwords
        try {
            const response = await fetch(`/generate_password?length=${length}`);
            if (response.ok) {
                const data = await response.json();
                passwordField.value = data.password; // Populate the password field
            } else {
                alert("Failed to generate password!");
            }
        } catch (error) {
            console.error("Error generating password:", error);
        }
    });


    // Handle add password form submission
    addPasswordForm.addEventListener("submit", async (e) => {
        e.preventDefault();
        const website = document.getElementById("website").value;
        const username = document.getElementById("username").value;
        const password = document.getElementById("password").value;

        try {
            const response = await fetch("/add_password", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ website, username, password }),
            });

            if (response.ok) {
                toast.show();
                addPasswordForm.reset();
            } else {
                alert("Failed to add password!");
            }
        } catch (error) {
            console.error("Error adding password:", error);
        }
    });

    // Handle logout
    logoutButton.addEventListener("click", async () => {
        try {
            const response = await fetch("/logout", { method: "POST" });
            if (response.ok) {
                window.location.href = "/";
            } else {
                alert("Logout failed!");
            }
        } catch (error) {
            console.error("Error during logout:", error);
        }
    });

    document.addEventListener("click", (event) => {
        if (event.target.classList.contains("copy-btn")) {
            const value = event.target.getAttribute("data-value"); // Get the value to copy
    
            navigator.clipboard.writeText(value).then(() => {
                // Change icon color temporarily to indicate success
                event.target.classList.add("text-success");
                setTimeout(() => event.target.classList.remove("text-success"), 1000);
            }).catch(err => {
                console.error("Failed to copy:", err);
            });
        }
    });
    
});
