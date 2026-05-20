/**
 * AVAGuard - Side Drawer Component
 * 
 * Slide-out panel for detailed views (User Management, etc.)
 * Right-side drawer following AWS/Azure patterns
 */

const AVAGuardDrawer = (function () {
    'use strict';

    let drawerContainer = null;
    let activeDrawer = null;
    let onSaveCallback = null;
    let onCloseCallback = null;

    // Initialize drawer container
    function init() {
        if (drawerContainer) return;

        drawerContainer = document.createElement('div');
        drawerContainer.id = 'ava-drawer-container';
        drawerContainer.innerHTML = `
            <div class="ava-drawer-overlay" id="avaDrawerOverlay"></div>
            <div class="ava-drawer" id="avaDrawer" role="dialog" aria-modal="true">
                <div class="ava-drawer-header" id="avaDrawerHeader">
                    <div class="ava-drawer-avatar" id="avaDrawerAvatar"></div>
                    <div class="ava-drawer-user-info">
                        <h2 class="ava-drawer-title" id="avaDrawerTitle"></h2>
                        <span class="ava-drawer-subtitle" id="avaDrawerSubtitle"></span>
                    </div>
                    <button class="ava-drawer-close" id="avaDrawerClose" aria-label="Close">&times;</button>
                </div>
                <div class="ava-drawer-body" id="avaDrawerBody"></div>
                <div class="ava-drawer-footer" id="avaDrawerFooter">
                    <button class="btn btn-secondary" id="avaDrawerCancel">Cancel</button>
                    <button class="btn btn-primary" id="avaDrawerSave">Save Changes</button>
                </div>
            </div>
        `;
        document.body.appendChild(drawerContainer);

        // Event listeners
        document.getElementById('avaDrawerOverlay').addEventListener('click', close);
        document.getElementById('avaDrawerClose').addEventListener('click', close);
        document.getElementById('avaDrawerCancel').addEventListener('click', close);
        document.getElementById('avaDrawerSave').addEventListener('click', save);

        // Keyboard events
        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape' && activeDrawer) {
                close();
            }
        });
    }

    // Show drawer
    function show() {
        drawerContainer.classList.add('visible');
        document.body.style.overflow = 'hidden';
    }

    // Close drawer
    function close() {
        drawerContainer.classList.remove('visible');
        document.body.style.overflow = '';
        if (onCloseCallback) onCloseCallback();
        activeDrawer = null;
        onSaveCallback = null;
        onCloseCallback = null;
    }

    // Save and close
    function save() {
        if (onSaveCallback) {
            const result = onSaveCallback();
            // If callback returns false, don't close
            if (result === false) return;
        }
        close();
    }

    /**
     * Open User Management Drawer
     * @param {Object} user - User data
     * @param {Function} onSave - Callback with updated data
     */
    function openUserDrawer(user, onSave) {
        init();

        activeDrawer = user;
        onSaveCallback = function () {
            // Gather form data
            const formData = {
                id: user.id,
                first_name: document.getElementById('drawerFirstName').value,
                last_name: document.getElementById('drawerLastName').value,
                email: document.getElementById('drawerEmail').value,
                department: document.getElementById('drawerDepartment').value,
                role: document.getElementById('drawerRole').value,
                mfa_enabled: document.getElementById('drawer2FA').checked,
                is_active: document.getElementById('drawerActive').checked,
                new_password: document.getElementById('drawerNewPassword').value,
                force_password_change: document.getElementById('drawerForceChange').checked,
                expires_at: document.getElementById('drawerExpiry').value || null
            };

            if (onSave) return onSave(formData);
        };

        // Set header
        const initials = (user.first_name?.charAt(0) || '') + (user.last_name?.charAt(0) || '') || user.email?.charAt(0).toUpperCase();
        document.getElementById('avaDrawerAvatar').textContent = initials;
        document.getElementById('avaDrawerTitle').textContent = user.full_name || user.email;
        document.getElementById('avaDrawerSubtitle').textContent = user.role_display || user.role;

        // Build body content
        document.getElementById('avaDrawerBody').innerHTML = `
            <!-- General Details Section -->
            <div class="drawer-section">
                <h4 class="drawer-section-title">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/>
                        <circle cx="9" cy="7" r="4"/>
                    </svg>
                    General Details
                </h4>
                <div class="drawer-form-row">
                    <div class="drawer-form-group">
                        <label for="drawerFirstName">First Name</label>
                        <input type="text" id="drawerFirstName" value="${user.first_name || ''}" class="drawer-input">
                    </div>
                    <div class="drawer-form-group">
                        <label for="drawerLastName">Last Name</label>
                        <input type="text" id="drawerLastName" value="${user.last_name || ''}" class="drawer-input">
                    </div>
                </div>
                <div class="drawer-form-group">
                    <label for="drawerEmail">Email Address</label>
                    <input type="email" id="drawerEmail" value="${user.email || ''}" class="drawer-input">
                </div>
                <div class="drawer-form-row">
                    <div class="drawer-form-group">
                        <label for="drawerDepartment">Department</label>
                        <input type="text" id="drawerDepartment" value="${user.department || ''}" class="drawer-input">
                    </div>
                    <div class="drawer-form-group">
                        <label for="drawerRole">Role</label>
                        <select id="drawerRole" class="drawer-input">
                            <option value="VIEWER" ${user.role === 'VIEWER' ? 'selected' : ''}>Viewer</option>
                            <option value="AUDITOR" ${user.role === 'AUDITOR' ? 'selected' : ''}>Auditor</option>
                            <option value="IT_ADMIN" ${user.role === 'IT_ADMIN' ? 'selected' : ''}>IT Admin</option>
                            <option value="SUPER_ADMIN" ${user.role === 'SUPER_ADMIN' ? 'selected' : ''}>Super Admin</option>
                        </select>
                    </div>
                </div>
            </div>
            
            <!-- Security Controls Section -->
            <div class="drawer-section">
                <h4 class="drawer-section-title">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/>
                    </svg>
                    Security Controls
                </h4>
                <div class="drawer-control-row">
                    <div class="drawer-control-info">
                        <span class="drawer-control-label">Two-Factor Authentication</span>
                        <span class="drawer-control-desc">Require 2FA for this user</span>
                    </div>
                    <label class="drawer-toggle">
                        <input type="checkbox" id="drawer2FA" ${user.mfa_enabled ? 'checked' : ''}>
                        <span class="drawer-toggle-slider"></span>
                    </label>
                </div>
                <div class="drawer-control-row">
                    <div class="drawer-control-info">
                        <span class="drawer-control-label">Account Status</span>
                        <span class="drawer-control-desc">Enable or suspend this account</span>
                    </div>
                    <label class="drawer-toggle">
                        <input type="checkbox" id="drawerActive" ${user.is_active ? 'checked' : ''}>
                        <span class="drawer-toggle-slider"></span>
                    </label>
                </div>
                <div class="drawer-form-group" style="margin-top: 16px;">
                    <label for="drawerExpiry">Account Expiry Date</label>
                    <input type="date" id="drawerExpiry" value="${user.expires_at ? user.expires_at.split('T')[0] : ''}" class="drawer-input">
                    <span class="drawer-help-text">Leave empty for no expiration</span>
                </div>
            </div>
            
            <!-- Password Management Section -->
            <div class="drawer-section">
                <h4 class="drawer-section-title">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <rect width="18" height="11" x="3" y="11" rx="2" ry="2"/>
                        <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
                    </svg>
                    Password Management
                </h4>
                <div class="drawer-form-group">
                    <label for="drawerNewPassword">Set New Password</label>
                    <div class="drawer-input-with-action">
                        <input type="text" id="drawerNewPassword" placeholder="Leave empty to keep current" class="drawer-input">
                        <button type="button" class="drawer-copy-btn" onclick="copyPassword()" title="Copy to clipboard">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                <rect width="14" height="14" x="8" y="8" rx="2" ry="2"/>
                                <path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2"/>
                            </svg>
                        </button>
                    </div>
                </div>
                <div class="drawer-checkbox-row">
                    <label class="drawer-checkbox">
                        <input type="checkbox" id="drawerForceChange" ${user.password_change_required ? 'checked' : ''}>
                        <span class="drawer-checkbox-mark"></span>
                        <span>Force user to change password on next login</span>
                    </label>
                </div>
            </div>
            
            <!-- Security Score Section -->
            <div class="drawer-section drawer-section-muted">
                <div class="drawer-security-score">
                    <span class="drawer-score-label">Security Score:</span>
                    <span class="drawer-score-badge ${user.security_score || 'green'}">
                        <span class="drawer-score-dot"></span>
                        ${user.security_score === 'green' ? 'Secure' : user.security_score === 'yellow' ? 'Moderate' : 'At Risk'}
                    </span>
                </div>
                <p class="drawer-score-info">
                    ${user.security_score === 'green'
                ? '2FA enabled and password recently changed.'
                : user.security_score === 'yellow'
                    ? 'Consider enabling 2FA for enhanced security.'
                    : '2FA disabled and password may be outdated.'}
                </p>
            </div>
        `;

        show();
    }

    /**
     * Set loading state on save button
     */
    function setLoading(loading) {
        const saveBtn = document.getElementById('avaDrawerSave');
        if (loading) {
            saveBtn.disabled = true;
            saveBtn.innerHTML = '<span class="spinner-small"></span> Saving...';
        } else {
            saveBtn.disabled = false;
            saveBtn.innerHTML = 'Save Changes';
        }
    }

    /**
     * Show error message in drawer
     */
    function showError(message) {
        const body = document.getElementById('avaDrawerBody');
        const existingError = body.querySelector('.drawer-error');
        if (existingError) existingError.remove();

        const errorDiv = document.createElement('div');
        errorDiv.className = 'drawer-error';
        errorDiv.innerHTML = `
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <circle cx="12" cy="12" r="10"/><path d="m15 9-6 6"/><path d="m9 9 6 6"/>
            </svg>
            ${message}
        `;
        body.insertBefore(errorDiv, body.firstChild);
    }

    return {
        openUserDrawer,
        close,
        setLoading,
        showError
    };
})();

// Helper function for password copy
function copyPassword() {
    const input = document.getElementById('drawerNewPassword');
    if (input.value) {
        navigator.clipboard.writeText(input.value).then(() => {
            AVAGuardToast.show('Password copied to clipboard', 'success');
        });
    }
}

// Expose globally
window.Drawer = AVAGuardDrawer;
