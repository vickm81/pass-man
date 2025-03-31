       // Theme switching logic
       const themeSwitch = document.getElementById('themeSwitch');
       const htmlTag = document.documentElement;
       themeIcon = document.getElementById('theme-icon')

       // Check for saved theme preference or system preference
       const savedTheme = localStorage.getItem('theme');
       const systemPrefersDark = window.matchMedia('(prefers-color-scheme: dark)');

        function updateThemeIcon() {
            const isDark = document.documentElement.getAttribute('data-bs-theme') === 'dark';
            themeIcon.classList.toggle('bi-moon-fill', isDark);
            themeIcon.classList.toggle('bi-sun-fill', !isDark);
        }

       // Set initial theme
       function setInitialTheme() {
           let theme;
           if (savedTheme) {
               theme = savedTheme;
           } else if (systemPrefersDark.matches) {
               theme = 'dark';
           } else {
               theme = 'light';
           }

           htmlTag.setAttribute('data-bs-theme', theme);
           themeSwitch.checked = theme === 'dark';
           updateThemeIcon();
       }

       // Initial theme setup
       setInitialTheme();

       // Theme toggle event listener
       themeSwitch.addEventListener('change', () => {
           const newTheme = themeSwitch.checked ? 'dark' : 'light';
           htmlTag.setAttribute('data-bs-theme', newTheme);
           localStorage.setItem('theme', newTheme);
           updateThemeIcon();
       });

       // Listen for system theme changes
       systemPrefersDark.addListener((e) => {
           if (!localStorage.getItem('theme')) {
               htmlTag.setAttribute('data-bs-theme', e.matches ? 'dark' : 'light');
               themeSwitch.checked = e.matches;
           }
       });