/**
 * AVAGuard — Super Admin Dashboard Logic
 * Template: dashboard/admin.html
 * =========================================================
 */

function toggleDarkMode() {
    document.body.classList.toggle('light-mode');
    const isDark = !document.body.classList.contains('light-mode');
    localStorage.setItem('avaguard-dark-mode', isDark);
    const toggleText = document.getElementById('darkModeToggle');
    if (toggleText) {
        // Find the span inside the button
        const span = toggleText.querySelector('span') || toggleText;
        span.textContent = isDark ? 'Dark Mode' : 'Light Mode';
    }
}

// Load dark mode preference
if (localStorage.getItem('avaguard-dark-mode') === 'false') {
    document.body.classList.add('light-mode');
}

function editUser(userId) {
    window.location.href = `/admin/users/${userId}/edit/`;
}

function resetPassword(userId) {
    if (confirm('Send password reset email to this user?')) {
        const csrfToken = window.AVA ? window.AVA.csrfToken : '';
        fetch(`/admin/users/${userId}/reset-password/`, {
            method: 'POST',
            headers: {
                'X-CSRFToken': csrfToken,
                'Content-Type': 'application/json'
            }
        }).then(r => r.json()).then(data => {
            alert(data.message || 'Password reset email sent!');
        });
    }
}

function toggleUserStatus(userId) {
    if (confirm('Toggle user active status?')) {
        const csrfToken = window.AVA ? window.AVA.csrfToken : '';
        fetch(`/admin/users/${userId}/toggle-status/`, {
            method: 'POST',
            headers: {
                'X-CSRFToken': csrfToken,
                'Content-Type': 'application/json'
            }
        }).then(() => window.location.reload());
    }
}
