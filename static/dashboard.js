document.addEventListener('DOMContentLoaded', function() {
    const passwordTable = document.getElementById('passwordTable');
    const addPasswordForm = document.getElementById('addPasswordForm');
    const generatePasswordBtn = document.getElementById('generatePasswordBtn');
    const togglePasswordBtn = document.getElementById('togglePassword');
    const passwordInput = document.getElementById('password');

    // Load passwords
    function loadPasswords() {
        passwordTable.classList.add('loading');
        fetch('/get_passwords')
            .then(response => response.text())
            .then(html => {
                passwordTable.innerHTML = html;
                passwordTable.classList.remove('loading');
                setupPasswordTableInteractions();
            })
            .catch(error => {
                console.error('Error loading passwords:', error);
                passwordTable.classList.remove('loading');
                passwordTable.innerHTML = `
                    <div class="alert alert-danger">
                        Error loading passwords. Please try again.
                    </div>
                `;
            });
    }


    // Setup interactions for password table (toggle and copy)
    function setupPasswordTableInteractions() {
        // Toggle password visibility
        document.querySelectorAll('.toggle-password').forEach(button => {
            button.addEventListener('click', function() {
                const passwordCell = this.previousElementSibling;
                const isHidden = passwordCell.textContent.trim() === '••••••••';
                
                if (isHidden) {
                    passwordCell.textContent = passwordCell.dataset.password;
                    this.innerHTML = '<i class="bi bi-eye-slash"></i>';
                } else {
                    passwordCell.textContent = '••••••••';
                    this.innerHTML = '<i class="bi bi-eye"></i>';
                }
            });
        });


        // Copy credentials to clipboard
        document.querySelectorAll('.copy-credentials').forEach(button => {
            button.addEventListener('click', function() {
                const row = this.closest('tr');
                const website = row.querySelector('td:nth-child(1)').textContent;
                const username = row.querySelector('td:nth-child(2)').textContent;
                const password = row.querySelector('.password-cell').dataset.password;

                const textToCopy = `Website: ${website}\nUsername: ${username}\nPassword: ${password}`;
                
                navigator.clipboard.writeText(textToCopy).then(() => {
                    const originalIcon = button.innerHTML;
                    button.innerHTML = '<i class="bi bi-check2"></i>';
                    button.classList.remove('btn-outline-primary');
                    button.classList.add('btn-success');
                    
                    setTimeout(() => {
                        button.innerHTML = originalIcon;
                        button.classList.add('btn-outline-primary');
                        button.classList.remove('btn-success');
                    }, 2000);
                });
            });
        });


    // Add password form submission
    addPasswordForm.addEventListener('submit', function(e) {
        e.preventDefault();
        const website = document.getElementById('website').value;
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;

        fetch('/add_password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ website, username, password })
        })
        .then(response => response.json())
        .then(data => {
            if (data.message) {
                loadPasswords();
                var addPasswordModal = bootstrap.Modal.getInstance(document.getElementById('addPasswordModal'));
                addPasswordModal.hide();
                addPasswordForm.reset();
            }
        })
        .catch(error => console.error('Error:', error));
    });

    // Generate password
    generatePasswordBtn.addEventListener('click', function() {
        fetch('/generate_password?length=16')
            .then(response => response.json())
            .then(data => {
                passwordInput.value = data.password;
            });
    });

    // Toggle password visibility in add password form
    togglePasswordBtn.addEventListener('click', function() {
        const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
        passwordInput.setAttribute('type', type);
        togglePasswordBtn.querySelector('i').classList.toggle('bi-eye');
        togglePasswordBtn.querySelector('i').classList.toggle('bi-eye-slash');
    });

    // Add these functions to your existing dashboard.js

// Function to handle edit button click
// Edit password
document.querySelectorAll('.edit-password').forEach(button => {
    button.addEventListener('click', function() {
        const row = this.closest('tr');
        const id = row.dataset.id;
        const website = row.querySelector('td:nth-child(1)').textContent;
        const username = row.querySelector('td:nth-child(2)').textContent;
        const password = row.querySelector('.password-cell').dataset.password;

        // Populate the edit modal
        document.getElementById('edit_id').value = id;
        document.getElementById('edit_website').value = website;
        document.getElementById('edit_username').value = username;
        document.getElementById('edit_password').value = password;

        // Show the modal
        const editModal = new bootstrap.Modal(document.getElementById('editPasswordModal'));
        editModal.show();
    });
});


// Function to handle delete button click
// Delete password
document.querySelectorAll('.delete-password').forEach(button => {
    button.addEventListener('click', function() {
        if (confirm('Are you sure you want to delete this password? This action cannot be undone.')) {
            const row = this.closest('tr');
            const id = row.dataset.id;

            fetch('/delete_password', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ id: id })
            })
            .then(response => response.json())
            .then(data => {
                if (data.message) {
                    // Show success message
                    const alert = document.createElement('div');
                    alert.className = 'alert alert-success alert-dismissible fade show';
                    alert.innerHTML = `
                        ${data.message}
                        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                    `;
                    passwordTable.parentNode.insertBefore(alert, passwordTable);
                    
                    // Reload passwords after a short delay
                    setTimeout(loadPasswords, 500);
                } else {
                    throw new Error(data.error || 'Failed to delete password');
                }
            })
            .catch(error => {
                console.error('Error:', error);
                const alert = document.createElement('div');
                alert.className = 'alert alert-danger alert-dismissible fade show';
                alert.innerHTML = `
                    Error: ${error.message}
                    <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
                `;
                passwordTable.parentNode.insertBefore(alert, passwordTable);
            });
        }
    });
});
}


// Add edit form submission
// Edit form submission
document.getElementById('editPasswordForm')?.addEventListener('submit', function(e) {
    e.preventDefault();
    
    const id = document.getElementById('edit_id').value;
    const website = document.getElementById('edit_website').value;
    const username = document.getElementById('edit_username').value;
    const password = document.getElementById('edit_password').value;

    fetch('/update_password', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({ 
            id: id,
            website: website,
            username: username,
            password: password
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.message) {
            // Close modal
            const editModal = bootstrap.Modal.getInstance(document.getElementById('editPasswordModal'));
            editModal.hide();
            
            // Show success message
            const alert = document.createElement('div');
            alert.className = 'alert alert-success alert-dismissible fade show';
            alert.innerHTML = `
                ${data.message}
                <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
            `;
            passwordTable.parentNode.insertBefore(alert, passwordTable);
            
            // Reload passwords
            loadPasswords();
        } else {
            throw new Error(data.error || 'Failed to update password');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        const alert = document.createElement('div');
        alert.className = 'alert alert-danger alert-dismissible fade show';
        alert.innerHTML = `
            Error: ${error.message}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        document.querySelector('#editPasswordModal .modal-body').prepend(alert);
    });
});

// Add toggle password visibility for edit form
document.getElementById('toggleEditPassword').addEventListener('click', function() {
    const passwordInput = document.getElementById('edit_password');
    const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
    passwordInput.setAttribute('type', type);
    this.querySelector('i').classList.toggle('bi-eye');
    this.querySelector('i').classList.toggle('bi-eye-slash');
});

// Add generate password for edit form
document.getElementById('generateEditPasswordBtn').addEventListener('click', function() {
    fetch('/generate_password?length=16')
        .then(response => response.json())
        .then(data => {
            document.getElementById('edit_password').value = data.password;
        });
});
 // Initial load of passwords
 loadPasswords();
});