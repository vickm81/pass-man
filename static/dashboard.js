document.addEventListener('DOMContentLoaded', function() {
    // CSRF token from meta tag or form
    const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || 
                     document.getElementById('csrf_token')?.value;

    // DOM elements
    const passwordTable = document.getElementById('passwordTable');
    const addPasswordForm = document.getElementById('addPasswordForm');
    const generatePasswordBtn = document.getElementById('generatePasswordBtn');
    const togglePasswordBtn = document.getElementById('togglePassword');
    const toggleEditPassword = document.getElementById('toggleEditPassword');
    const passwordInput = document.getElementById('password');
    const passwordEditInput = document.getElementById('edit_password');
    
    // Request flag
    let isLoadingPasswords = false;

    // Safe HTML rendering
    function escapeHtml(unsafe) {
        return unsafe?.toString()
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;") || '';
    }

    // Load passwords securely
    function loadPasswords() {
        if (isLoadingPasswords) return;
        
        isLoadingPasswords = true;
        passwordTable.classList.add('loading');
        
        fetch('/get_passwords', {
            headers: {
                'Accept': 'text/html',
                'X-Requested-With': 'XMLHttpRequest'
            },
            credentials: 'same-origin'
        })
        .then(response => {
            if (!response.ok) throw new Error('Network response was not ok');
            return response.text();
        })
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
        })
        .finally(() => {
            isLoadingPasswords = false;
        });
    }

    // Setup password table interactions
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

        // Copy password to clipboard
        document.querySelectorAll('.copy-password').forEach(button => {
            button.addEventListener('click', function() {
                const password = this.dataset.password;
                navigator.clipboard.writeText(password).then(() => {
                    const originalText = this.innerHTML;
                    this.innerHTML = '<i class="bi bi-check"></i> Copied!';
                    setTimeout(() => {
                        this.innerHTML = originalText;
                    }, 2000);
                }).catch(err => {
                    console.error('Could not copy text: ', err);
                });
            });
        });

        // Edit password
        document.querySelectorAll('.edit-password').forEach(button => {
            button.addEventListener('click', function() {
                const row = this.closest('tr');
                const id = row.dataset.id;
                const website = row.querySelector('td:nth-child(1)').textContent;
                const username = row.querySelector('td:nth-child(2)').textContent;
                const password = row.querySelector('.password-cell').dataset.password;

                document.getElementById('edit_id').value = escapeHtml(id);
                document.getElementById('edit_website').value = escapeHtml(website);
                document.getElementById('edit_username').value = escapeHtml(username);
                document.getElementById('edit_password').value = escapeHtml(password);

                new bootstrap.Modal(document.getElementById('editPasswordModal')).show();
            });
        });

        // Delete password
        document.querySelectorAll('.delete-password').forEach(button => {
            button.addEventListener('click', function() {
                const row = this.closest('tr');
                const id = row.dataset.id;
                const website = row.querySelector('td:nth-child(1)').textContent;
                const username = row.querySelector('td:nth-child(2)').textContent;

                
                // Populate delete modal
                document.getElementById('delete_id').value = escapeHtml(id);

                document.getElementById('delete_username').textContent = escapeHtml(username);
                document.getElementById('delete_website').textContent = escapeHtml(website);
                
                // Show confirmation modal
                new bootstrap.Modal(document.getElementById('deletePasswordModal')).show();
            });
        });
    }

    // Add password form submission
    addPasswordForm?.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const submitButton = this.querySelector('button[type="submit"]');
        submitButton.disabled = true;
        
        const formData = {
            website: document.getElementById('website').value,
            username: document.getElementById('username').value,
            password: document.getElementById('password').value
        };

        fetch('/add_password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify(formData),
            credentials: 'same-origin'
        })
        .then(response => {
            if (!response.ok) throw new Error('Network response was not ok');
            return response.json();
        })
        .then(data => {
            if (data.error) throw new Error(data.error);
            
            loadPasswords();
            bootstrap.Modal.getInstance(document.getElementById('addPasswordModal')).hide();
            this.reset();
        })
        .catch(error => {
            console.error('Error:', error);
            const errorElement = document.getElementById('addFormError');
            errorElement.textContent = `Error: ${escapeHtml(error.message)}`;
            errorElement.classList.remove('d-none');
        })
        .finally(() => {
            submitButton.disabled = false;
        });
    });

    // Generate password
    generatePasswordBtn?.addEventListener('click', function() {
        fetch('/generate_password?length=16', {
            credentials: 'same-origin'
        })
        .then(response => {
            if (!response.ok) throw new Error('Network response was not ok');
            return response.json();
        })
        .then(data => {
            passwordInput.value = data.password;
        })
        .catch(error => console.error('Error:', error));
    });

    generateEditPasswordBtn?.addEventListener('click', function() {
        fetch('/generate_password?length=16', {
            credentials: 'same-origin'
        })
        .then(response => {
            if (!response.ok) throw new Error('Network response was not ok');
            return response.json();
        })
        .then(data => {
            passwordEditInput.value = data.password;
        })
        .catch(error => console.error('Error:', error));
    });
    
    // Toggle password visibility
    togglePasswordBtn?.addEventListener('click', function() {
        const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
        passwordInput.setAttribute('type', type);
        this.querySelector('i').classList.toggle('bi-eye');
        this.querySelector('i').classList.toggle('bi-eye-slash');
    });

    toggleEditPassword?.addEventListener('click', function() {
        const type = passwordEditInput.getAttribute('type') === 'password' ? 'text' : 'password';
        passwordEditInput.setAttribute('type', type);
        this.querySelector('i').classList.toggle('bi-eye');
        this.querySelector('i').classList.toggle('bi-eye-slash');
    });

    // Edit form submission
    document.getElementById('editPasswordForm')?.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const submitButton = this.querySelector('button[type="submit"]');
        submitButton.disabled = true;
        
        const formData = {
            id: document.getElementById('edit_id').value,
            website: document.getElementById('edit_website').value,
            username: document.getElementById('edit_username').value,
            password: document.getElementById('edit_password').value
        };

        fetch('/update_password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify(formData),
            credentials: 'same-origin'
        })
        .then(response => {
            if (!response.ok) throw new Error('Network response was not ok');
            return response.json();
        })
        .then(data => {
            if (data.error) throw new Error(data.error);
            
            bootstrap.Modal.getInstance(document.getElementById('editPasswordModal')).hide();
            showAlert('success', data.message || 'Password updated successfully');
            loadPasswords();
        })
        .catch(error => {
            console.error('Error:', error);
            const errorElement = document.getElementById('editFormError');
            errorElement.textContent = `Error: ${escapeHtml(error.message)}`;
            errorElement.classList.remove('d-none');
        })
        .finally(() => {
            submitButton.disabled = false;
        });
    });

    // Delete form submission
    document.getElementById('deletePasswordForm')?.addEventListener('submit', function(e) {
        e.preventDefault();
        
        const submitButton = this.querySelector('button[type="submit"]');
        submitButton.disabled = true;
        
        const formData = {
            id: document.getElementById('delete_id').value
        };

        fetch('/delete_password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': csrfToken
            },
            body: JSON.stringify(formData),
            credentials: 'same-origin'
        })
        .then(response => {
            if (!response.ok) throw new Error('Network response was not ok');
            return response.json();
        })
        .then(data => {
            if (data.error) throw new Error(data.error);
            
            bootstrap.Modal.getInstance(document.getElementById('deletePasswordModal')).hide();
            showAlert('success', data.message || 'Password deleted successfully');
            loadPasswords();
        })
        .catch(error => {
            console.error('Error:', error);
            const errorElement = document.getElementById('deleteFormError');
            errorElement.textContent = `Error: ${escapeHtml(error.message)}`;
            errorElement.classList.remove('d-none');
        })
        .finally(() => {
            submitButton.disabled = false;
        });
    });

    // Helper function to show alerts
    function showAlert(type, message) {
        const alert = document.createElement('div');
        alert.className = `alert alert-${type} alert-dismissible fade show`;
        alert.innerHTML = `
            ${escapeHtml(message)}
            <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        `;
        passwordTable.parentNode.insertBefore(alert, passwordTable);
    }

    // Initial load
    loadPasswords();
});