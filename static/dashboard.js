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
            });
    }

    // Setup interactions for password table (toggle and copy)
    function setupPasswordTableInteractions() {
        const passwordCells = document.querySelectorAll('.password-cell');
        const toggleButtons = document.querySelectorAll('.toggle-password');
        const copyButtons = document.querySelectorAll('.copy-credentials');

        // Toggle password visibility
        toggleButtons.forEach((button, index) => {
            button.addEventListener('click', function() {
                const passwordCell = passwordCells[index];
                const isHidden = passwordCell.textContent.trim() === '••••••••';
                
                if (isHidden) {
                    passwordCell.textContent = passwordCell.dataset.password;
                    button.querySelector('i').classList.remove('bi-eye');
                    button.querySelector('i').classList.add('bi-eye-slash');
                } else {
                    passwordCell.textContent = '••••••••';
                    button.querySelector('i').classList.add('bi-eye');
                    button.querySelector('i').classList.remove('bi-eye-slash');
                }
            });
        });

        // Copy credentials to clipboard
        copyButtons.forEach((button) => {
            button.addEventListener('click', function() {
                const row = button.closest('tr');
                const website = row.querySelector('td:first-child').textContent;
                const username = row.querySelector('td:nth-child(2)').textContent;
                const password = row.querySelector('.password-cell').dataset.password;

                const combinedText = `Website: ${website}\nUsername: ${username}\nPassword: ${password}`;
                
                navigator.clipboard.writeText(combinedText).then(() => {
                    button.innerHTML = '<i class="bi bi-clipboard-check"></i>';
                    setTimeout(() => {
                        button.innerHTML = '<i class="bi bi-clipboard"></i>';
                    }, 2000);
                });
            });
        });
    }

    // Initial load of passwords
    loadPasswords();

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
});