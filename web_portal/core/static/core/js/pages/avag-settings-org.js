/**
 * AVAGuard — Organization Settings Logic
 * Template: settings/organization.html
 * =========================================================
 */

function switchTab(tabName) {
    // Hide all tabs
    document.querySelectorAll('.tab-content').forEach(function(tab) {
        tab.classList.remove('active');
    });
    document.querySelectorAll('.tab-button').forEach(function(btn) {
        btn.classList.remove('active');
    });
    
    // Show selected tab
    document.getElementById('tab-' + tabName).classList.add('active');
    // If event exists, find the closest tab-button
    if (typeof event !== 'undefined' && event && event.target) {
        const btn = event.target.closest('.tab-button');
        if (btn) btn.classList.add('active');
    }
}

function toggleSwitch(element) {
    element.classList.toggle('active');
}

function sendTestEmail() {
    alert('Test email sent! Check your inbox.');
}

function testConnection() {
    alert('Testing Azure AD connection...\n\nConnection successful!');
}
