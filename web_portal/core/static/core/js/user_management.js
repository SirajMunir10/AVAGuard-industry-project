/**
 * AVAGuard - User Management Module (Phase 2 — Hardened)
 *
 * Enterprise-grade side-drawer with:
 * - Sudo-mode re-authentication dialog
 * - RBAC-aware action controls
 * - Focus trap and keyboard navigation (WCAG 2.1)
 * - No Optimistic UI — updates only after server confirmation
 */

// ==========================================
// Core State
// ==========================================
const AVAGuard = window.AVAGuard || {};

AVAGuard.UserManagement = {
    selectedUsers: new Set(),
    currentFilter: 'all',
    searchQuery: '',
    searchTimeout: null,
    expiryUserId: null,
    csrfToken: null,
    drawerOpen: false,
    currentDrawerUser: null,
};

// ==========================================
// Initialization
// ==========================================
document.addEventListener('DOMContentLoaded', function () {
    var UM = AVAGuard.UserManagement;
    // CSRF token with multiple fallback strategies
    UM.csrfToken = document.querySelector('[name=csrfmiddlewaretoken]')?.value
        || document.querySelector('meta[name="csrf-token"]')?.content
        || (typeof csrfToken !== 'undefined' ? csrfToken : '')
        || getCookie('csrftoken');

    // Search input
    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
        searchInput.addEventListener('input', handleSearchInput);
        searchInput.addEventListener('keydown', function (e) {
            if (e.key === 'Escape') clearSearch();
        });
    }

    // Close dropdowns on outside click
    document.addEventListener('click', function (e) {
        if (!e.target.closest('.actions-dropdown')) {
            closeAllDropdowns();
        }
    });

    // Global keyboard handler
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') {
            if (UM.drawerOpen) {
                closeDrawer();
            }
            document.querySelectorAll('.modal.active').forEach(function (modal) {
                modal.classList.remove('active');
            });
            document.querySelectorAll('.ava-sudo-overlay.active').forEach(function (overlay) {
                overlay.classList.remove('active');
            });
            document.body.style.overflow = '';
        }
    });

    // Support deep-linking to edit user (from Dashboard)
    const urlParams = new URLSearchParams(window.location.search);
    const editUserId = urlParams.get('edit_user');
    if (editUserId) {
        // Use timeout to ensure all components are ready
        setTimeout(() => openDrawer(editUserId), 300);
    }
});

// ==========================================
// Side-Drawer
// ==========================================
function openDrawer(userId) {
    const UM = AVAGuard.UserManagement;
    const drawer = document.getElementById('userDrawer');
    const overlay = document.getElementById('drawerOverlay');

    if (!drawer || !overlay) return;

    // Fetch user details from API
    fetch(`/api/users/${userId}/details/`, {
        headers: { 'X-Requested-With': 'XMLHttpRequest' },
    })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (!data.success) {
                showToast(data.errors?.__all__?.[0] || 'Failed to load user', 'error');
                return;
            }

            UM.currentDrawerUser = data.user;
            renderDrawerContent(data.user);

            drawer.classList.add('open');
            overlay.classList.add('active');
            UM.drawerOpen = true;
            document.body.style.overflow = 'hidden';

            // Focus trap — focus the close button
            var closeBtn = drawer.querySelector('.drawer-close');
            if (closeBtn) closeBtn.focus();
        })
        .catch(function (err) {
            console.error('Drawer Error:', err);
            // If it's a 500 error, the JSON parsing might fail, so we provide a clear fallback
            showToast('System error loading user details. Please try again later.', 'error');
        });
}

function closeDrawer() {
    var UM = AVAGuard.UserManagement;
    var drawer = document.getElementById('userDrawer');
    var overlay = document.getElementById('drawerOverlay');

    if (drawer) drawer.classList.remove('open');
    if (overlay) overlay.classList.remove('active');
    UM.drawerOpen = false;
    UM.currentDrawerUser = null;
    document.body.style.overflow = '';
}

function renderDrawerContent(user) {
    var drawer = document.getElementById('userDrawer');
    if (!drawer) return;

    var canEdit = user.can_edit;
    var scoreClass = user.security_score === 'green' ? 'score-green' :
        user.security_score === 'yellow' ? 'score-yellow' : 'score-red';

    var html = '';

    // Header
    html += '<div class="drawer-header">';
    html += '<div class="drawer-header-content">';
    html += '<div class="drawer-avatar">' + (user.first_name || user.email)[0].toUpperCase() + '</div>';
    html += '<div class="drawer-header-info">';
    html += '<h3 class="drawer-title">' + escapeHtml(user.full_name) + '</h3>';
    html += '<span class="drawer-subtitle">' + escapeHtml(user.email) + '</span>';
    html += '</div>';
    html += '</div>';
    html += '<button class="drawer-close" onclick="closeDrawer()" aria-label="Close drawer">&times;</button>';
    html += '</div>';

    // Status bar
    html += '<div class="drawer-status-bar">';
    html += '<span class="status-badge ' + (user.is_active ? 'active' : 'inactive') + '">';
    html += user.is_active ? '● Active' : '○ Inactive';
    html += '</span>';
    html += '<span class="security-score ' + scoreClass + '">Security: ' + user.security_score.toUpperCase() + '</span>';
    html += '<span class="role-badge">' + escapeHtml(user.role_display) + '</span>';
    html += '</div>';

    // Section: Account Overview (read-only metadata)
    html += '<div class="drawer-section">';
    html += '<h4 class="drawer-section-title"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg> Account Overview</h4>';
    html += '<div class="drawer-field-group">';
    html += '<div class="drawer-field"><label class="drawer-field-label">Created</label><span class="drawer-field-value">' + (user.created_at ? new Date(user.created_at).toLocaleDateString() : '—') + '</span></div>';
    html += '<div class="drawer-field"><label class="drawer-field-label">Last Login</label><span class="drawer-field-value">' + (user.last_login ? new Date(user.last_login).toLocaleDateString() + ' ' + new Date(user.last_login).toLocaleTimeString() : 'Never') + '</span></div>';
    html += '<div class="drawer-field"><label class="drawer-field-label">Role</label><span class="drawer-field-value">' + escapeHtml(user.role_display) + '</span></div>';
    html += '</div>';
    html += '</div>';

    // Section: Edit Details
    html += '<div class="drawer-section">';
    html += '<h4 class="drawer-section-title"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg> Edit Details</h4>';
    html += '<div class="drawer-field-group">';
    html += drawerField('First Name', 'first_name', user.first_name, canEdit);
    html += drawerField('Last Name', 'last_name', user.last_name, canEdit);
    html += drawerField('Department', 'department', user.department || '', canEdit);
    html += drawerRoleField(user.role, canEdit);
    html += '</div>';

    if (canEdit) {
        html += '<button class="drawer-btn drawer-btn-primary" onclick="saveDrawerDetails()" id="btnSaveDetails">';
        html += 'Save Changes</button>';
    }
    html += '</div>';

    // Section: Security Controls
    html += '<div class="drawer-section">';
    html += '<h4 class="drawer-section-title"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10"/></svg> Security Controls</h4>';

    // ── Authentication Methods (restructured) ──

    // Overall MFA Status
    html += '<div class="drawer-control-row">';
    html += '<div class="drawer-control-info">';
    html += '<span class="drawer-control-label">MFA Status</span>';
    html += '<span class="drawer-control-value">';
    if (user.totp_configured || user.mfa_enabled) {
        html += '<span class="mfa-badge totp">Active</span>';
    } else {
        html += '<span class="mfa-badge off">Disabled</span>';
    }
    html += '</span>';
    html += '</div>';
    html += '</div>';

    // Authenticator App (TOTP)
    html += '<div class="drawer-control-row">';
    html += '<div class="drawer-control-info">';
    html += '<span class="drawer-control-label">Authenticator App (TOTP)</span>';
    html += '<span class="drawer-control-value">';
    if (user.totp_configured) {
        html += '<span style="color: var(--accent-success);">Configured</span>';
    } else {
        html += '<span style="color: var(--text-secondary);">Not Configured</span>';
    }
    html += '</span>';
    html += '</div>';
    if (canEdit && user.totp_configured) {
        html += '<button class="drawer-btn drawer-btn-danger drawer-btn-sm" ';
        html += 'onclick="resetUser2FA(\'' + user.id + '\')" title="Reset TOTP — forces re-setup on next login">';
        html += 'Reset TOTP</button>';
    }
    html += '</div>';

    // Email OTP
    html += '<div class="drawer-control-row">';
    html += '<div class="drawer-control-info">';
    html += '<span class="drawer-control-label">Email OTP</span>';
    html += '<span class="drawer-control-value">';
    if (user.mfa_enabled) {
        html += '<span style="color: var(--accent-success);">Enabled</span>';
    } else {
        html += '<span style="color: var(--text-secondary);">Disabled</span>';
    }
    html += '</span>';
    html += '</div>';
    if (canEdit) {
        var email2faStatus = user.mfa_enabled ? 'disable' : 'enable';
        var email2faBtnClass = user.mfa_enabled ? 'drawer-btn-danger' : 'drawer-btn-success';
        var email2faBtnText = user.mfa_enabled ? 'Disable' : 'Enable';
        html += '<button class="drawer-btn ' + email2faBtnClass + ' drawer-btn-sm" ';
        html += 'onclick="toggleEmail2FA(\'' + user.id + '\', \'' + email2faStatus + '\')">';
        html += email2faBtnText + '</button>';
    }
    html += '</div>';

    // Force Password Reset
    if (canEdit) {
        html += '<div class="drawer-control-row">';
        html += '<div class="drawer-control-info">';
        html += '<span class="drawer-control-label">Password Status</span>';
        html += '<span class="drawer-control-value">';
        html += user.password_change_required
            ? '<span style="color: var(--accent-warning);">Reset pending</span>'
            : '<span style="color: var(--accent-success);">Current</span>';
        html += '</span>';
        html += '</div>';
        html += '<div style="display:flex; gap:8px;">';
        html += '<button class="drawer-btn drawer-btn-warning drawer-btn-sm" ';
        html += 'onclick="forcePasswordReset(\'' + user.id + '\')">';
        html += '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg> Force Reset</button>';
        html += '<button class="drawer-btn drawer-btn-danger drawer-btn-sm" ';
        html += 'onclick="invalidateSessions(\'' + user.id + '\')" title="Invalidate all active sessions for this user">';
        html += '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M18.36 6.64a9 9 0 1 1-12.73 0"/><line x1="12" y1="2" x2="12" y2="12"/></svg> Kill Sessions</button>';
        html += '</div>';
        html += '</div>';
    }

    // Account Expiry
    html += '<div class="drawer-control-row" style="flex-direction: column; align-items: stretch; gap: 12px;">';
    html += '<div style="display: flex; justify-content: space-between; align-items: center;">';
    html += '<div class="drawer-control-info">';
    html += '<span class="drawer-control-label">Account Expiry</span>';
    html += '<span class="drawer-control-value">';
    if (user.expires_at) {
        var d = new Date(user.expires_at);
        html += d.toLocaleDateString() + (user.is_expired ? ' <span style="color:var(--error-color)">(EXPIRED)</span>' : '');
    } else {
        html += 'Never';
    }
    html += '</span>';
    html += '</div>';
    if (canEdit) {
        html += '<button class="drawer-btn drawer-btn-outline drawer-btn-sm" ';
        html += 'onclick="openExpiryModal(\'' + user.id + '\', \'' + escapeHtml(user.email) + '\', \'' + (user.expires_at ? user.expires_at.split('T')[0] : '') + '\')">';
        html += '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="4" width="18" height="18" rx="2" ry="2"/><line x1="16" y1="2" x2="16" y2="6"/><line x1="8" y1="2" x2="8" y2="6"/><line x1="3" y1="10" x2="21" y2="10"/></svg> Set Expiry</button>';
    }
    html += '</div>';
    
    // Extension Request
    if (user.extension_requested) {
        html += '<div style="background: rgba(255, 255, 255, 0.05); padding: 12px; border-radius: 6px; border-left: 3px solid var(--warning-color);">';
        html += '<div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">';
        html += '<span style="font-size: 12px; font-weight: 600; color: var(--text-secondary);">Extension Request</span>';
        var statusColor = user.extension_request_status === 'PENDING' ? 'var(--warning-color)' : (user.extension_request_status === 'APPROVED' ? 'var(--success-color)' : 'var(--error-color)');
        html += '<span style="font-size: 11px; font-weight: 600; padding: 2px 6px; border-radius: 4px; background: ' + statusColor + '22; color: ' + statusColor + ';">' + user.extension_request_status + '</span>';
        html += '</div>';
        html += '<p style="font-size: 13px; color: var(--text-primary); margin: 0; white-space: pre-wrap;">' + escapeHtml(user.extension_request_message) + '</p>';
        html += '</div>';
    }
    html += '</div>';

    // Toggle Account Status
    if (canEdit) {
        html += '<div class="drawer-control-row drawer-control-destructive">';
        html += '<div class="drawer-control-info">';
        html += '<span class="drawer-control-label">Account Status</span>';
        html += '<span class="drawer-control-value">' + (user.is_active ? 'Active' : 'Disabled') + '</span>';
        html += '</div>';
        html += '<button class="drawer-btn ' + (user.is_active ? 'drawer-btn-danger' : 'drawer-btn-success') + ' drawer-btn-sm" ';
        html += 'onclick="toggleUserStatus(\'' + user.id + '\', ' + user.is_active + ')">';
        if (user.is_active) {
            html += '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg> Disable User';
        } else {
            html += '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg> Enable User';
        }
        html += '</button>';
        html += '</div>';
    }

    html += '</div>';

    // Footer: timestamps (compact, replaces old metadata section)
    html += '<div class="drawer-section" style="padding-top: 8px; border-top: 1px solid var(--border-color, #2a2a4a);">';
    html += '<div style="display: flex; justify-content: space-between; font-size: 11px; color: var(--text-secondary, #a0a0c0);">';
    html += '<span>Created: ' + new Date(user.created_at).toLocaleDateString() + '</span>';
    html += '<span>Updated: ' + new Date(user.updated_at).toLocaleDateString() + '</span>';
    html += '</div>';
    html += '</div>';

    var body = drawer.querySelector('.drawer-body');
    if (body) body.innerHTML = html;
}

function drawerField(label, name, value, editable) {
    var html = '<div class="drawer-field">';
    html += '<label class="drawer-field-label">' + label + '</label>';
    if (editable) {
        html += '<input type="text" class="drawer-field-input" id="drawer_' + name + '" ';
        html += 'value="' + escapeHtml(value) + '" />';
    } else {
        html += '<span class="drawer-field-value">' + escapeHtml(value || '—') + '</span>';
    }
    html += '</div>';
    return html;
}

function drawerRoleField(currentRole, editable) {
    var roles = [
        ['VIEWER', 'Viewer'],
        ['AUDITOR', 'Auditor'],
        ['IT_ADMIN', 'IT Administrator'],
        ['SUPER_ADMIN', 'Super Administrator'],
    ];

    var html = '<div class="drawer-field">';
    html += '<label class="drawer-field-label">Role</label>';
    if (editable) {
        html += '<select class="drawer-field-input" id="drawer_role">';
        roles.forEach(function (r) {
            html += '<option value="' + r[0] + '"' + (r[0] === currentRole ? ' selected' : '') + '>';
            html += r[1] + '</option>';
        });
        html += '</select>';
    } else {
        var display = roles.find(function (r) { return r[0] === currentRole; });
        html += '<span class="drawer-field-value">' + (display ? display[1] : currentRole) + '</span>';
    }
    html += '</div>';
    return html;
}

function saveDrawerDetails() {
    var UM = AVAGuard.UserManagement;
    var user = UM.currentDrawerUser;
    if (!user) return;

    var payload = {
        first_name: document.getElementById('drawer_first_name')?.value || '',
        last_name: document.getElementById('drawer_last_name')?.value || '',
        department: document.getElementById('drawer_department')?.value || '',
        role: document.getElementById('drawer_role')?.value || user.role,
        updated_at: user.updated_at,
    };

    var btn = document.getElementById('btnSaveDetails');
    if (btn) { btn.disabled = true; btn.textContent = 'Saving...'; }

    fetch('/api/users/' + user.id + '/update-info/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': UM.csrfToken,
        },
        body: JSON.stringify(payload),
    })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (btn) { btn.disabled = false; btn.textContent = 'Save Changes'; }

            if (data.success) {
                showToast(data.message, 'success');
                // Update the local timestamp for optimistic locking
                if (data.updated_at) user.updated_at = data.updated_at;
                // Update the table row name in-place
                var row = document.querySelector('tr[data-user-id="' + user.id + '"]');
                if (row) {
                    var nameEl = row.querySelector('.user-name');
                    var fn = document.getElementById('drawer_first_name')?.value || '';
                    var ln = document.getElementById('drawer_last_name')?.value || '';
                    if (nameEl) nameEl.textContent = (fn + ' ' + ln).trim() || user.email;
                }
            } else if (data.conflict) {
                showToast('This user was modified by someone else. Please refresh.', 'error');
            } else if (data.sudo_required) {
                openSudoDialog(function () { saveDrawerDetails(); });
            } else {
                var msg = data.errors?.__all__?.[0] || data.errors?.role?.[0] || 'Update failed';
                showToast(msg, 'error');
            }
        })
        .catch(function () {
            if (btn) { btn.disabled = false; btn.textContent = 'Save Changes'; }
            showToast('Network error.', 'error');
        });
}

// ==========================================
// Sudo-Mode Dialog
// ==========================================
function openSudoDialog(onSuccess) {
    // Create overlay if it doesn't exist
    var existing = document.getElementById('sudoOverlay');
    if (existing) existing.remove();

    var overlay = document.createElement('div');
    overlay.id = 'sudoOverlay';
    overlay.className = 'ava-sudo-overlay active';
    overlay.setAttribute('role', 'dialog');
    overlay.setAttribute('aria-modal', 'true');
    overlay.setAttribute('aria-label', 'Re-authentication required');

    overlay.innerHTML =
        '<div class="ava-sudo-dialog">' +
        '<h3>🔒 Confirm Your Identity</h3>' +
        '<p>This action requires re-authentication.</p>' +
        '<div class="sudo-form-group">' +
        '<label for="sudoPassword">Your Password</label>' +
        '<input type="password" id="sudoPassword" autocomplete="current-password" />' +
        '</div>' +
        '<div class="sudo-error" id="sudoError"></div>' +
        '<div class="sudo-actions">' +
        '<button class="drawer-btn drawer-btn-primary" id="sudoConfirmBtn" onclick="confirmSudo()">Confirm</button>' +
        '<button class="drawer-btn drawer-btn-outline" onclick="closeSudoDialog()">Cancel</button>' +
        '</div>' +
        '</div>';

    document.body.appendChild(overlay);

    // Store the callback
    AVAGuard.UserManagement._sudoCallback = onSuccess;

    // Focus the password field
    setTimeout(function () {
        var input = document.getElementById('sudoPassword');
        if (input) input.focus();
    }, 100);

    // Enter key handler
    var pwInput = overlay.querySelector('#sudoPassword');
    if (pwInput) {
        pwInput.addEventListener('keydown', function (e) {
            if (e.key === 'Enter') confirmSudo();
        });
    }
}

function closeSudoDialog() {
    var overlay = document.getElementById('sudoOverlay');
    if (overlay) overlay.remove();
    // NOTE: Do NOT null _sudoCallback here — confirmSudo() needs it after the dialog closes
}

function confirmSudo() {
    var UM = AVAGuard.UserManagement;
    var password = document.getElementById('sudoPassword')?.value;
    var errorDiv = document.getElementById('sudoError');
    var btn = document.getElementById('sudoConfirmBtn');

    if (!password) {
        if (errorDiv) errorDiv.textContent = 'Password is required.';
        return;
    }

    if (btn) { btn.disabled = true; btn.textContent = 'Verifying...'; }

    fetch('/auth/sudo/confirm/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
            'X-CSRFToken': UM.csrfToken,
        },
        body: 'password=' + encodeURIComponent(password),
    })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            if (data.success) {
                // Save callback BEFORE closing dialog (which removes DOM)
                var callback = UM._sudoCallback;
                UM._sudoCallback = null;
                closeSudoDialog();
                showToast('Identity confirmed. Proceeding...', 'success');
                // Execute the stored callback after a brief delay
                if (callback) {
                    setTimeout(callback, 300);
                }
            } else {
                if (errorDiv) errorDiv.textContent = data.errors?.password?.[0] || 'Incorrect password.';
                if (btn) { btn.disabled = false; btn.textContent = 'Confirm'; }
            }
        })
        .catch(function () {
            if (errorDiv) errorDiv.textContent = 'Network error.';
            if (btn) { btn.disabled = false; btn.textContent = 'Confirm'; }
        });
}

// ==========================================
// Admin 2FA Reset (with sudo)
// ==========================================
function resetUser2FA(userId) {
    openSudoDialog(function () {
        var UM = AVAGuard.UserManagement;
        showLoading(true);

        fetch('/api/users/' + userId + '/reset-2fa/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': UM.csrfToken,
            },
        })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                showLoading(false);
                if (data.success) {
                    showToast(data.message, 'success');
                    closeDrawer();
                    setTimeout(function () { location.reload(); }, 1200);
                } else {
                    showToast(data.errors?.__all__?.[0] || 'Failed to reset 2FA', 'error');
                }
            })
            .catch(function () {
                showLoading(false);
                showToast('Network error.', 'error');
            });
    });
}

// ==========================================
// Search & Filter
// ==========================================
function handleSearchInput(e) {
    var query = e.target.value.trim();
    var container = document.getElementById('searchContainer');

    if (query) {
        container.classList.add('has-value');
    } else {
        container.classList.remove('has-value');
    }

    clearTimeout(AVAGuard.UserManagement.searchTimeout);
    AVAGuard.UserManagement.searchTimeout = setTimeout(function () {
        AVAGuard.UserManagement.searchQuery = query;
        filterTable();
    }, 300);
}

function clearSearch() {
    var searchInput = document.getElementById('searchInput');
    var container = document.getElementById('searchContainer');

    searchInput.value = '';
    container.classList.remove('has-value');
    AVAGuard.UserManagement.searchQuery = '';
    filterTable();
    searchInput.focus();
}

function setFilter(filter) {
    document.querySelectorAll('.status-toggle button').forEach(function (btn) {
        btn.classList.remove('active');
    });
    var filterId = 'filter' + filter.charAt(0).toUpperCase() + filter.slice(1);
    var el = document.getElementById(filterId);
    if (el) el.classList.add('active');

    AVAGuard.UserManagement.currentFilter = filter;
    filterTable();
}

function filterTable() {
    var tbody = document.getElementById('usersTableBody');
    if (!tbody) return;
    var rows = tbody.querySelectorAll('tr[data-user-id]');
    var query = AVAGuard.UserManagement.searchQuery.toLowerCase();
    var filter = AVAGuard.UserManagement.currentFilter;
    
    var visibleCount = 0;

    rows.forEach(function (row) {
        var name = row.querySelector('.user-name')?.textContent.toLowerCase() || '';
        var email = row.querySelector('.user-email')?.textContent.toLowerCase() || '';
        var isActive = row.querySelector('.user-status.active') !== null;
        
        var matchesSearch = !query || name.includes(query) || email.includes(query);
        var matchesFilter = true;
        
        // Status Filter (All/Active/Disabled)
        if (filter === 'active') matchesFilter = isActive;
        else if (filter === 'disabled') matchesFilter = !isActive;

        if (matchesSearch && matchesFilter) {
            row.style.display = '';
            visibleCount++;
        } else {
            row.style.display = 'none';
        }
    });

    var emptyRow = tbody.querySelector('tr:not([data-user-id])');
    if (emptyRow) {
        emptyRow.style.display = visibleCount === 0 ? '' : 'none';
    }

    // Update pagination items if visible count changed
    const tableId = 'usersTable';
    const pagination = window[`AVA_PAGINATION_${tableId}`];
    if (pagination) {
        pagination.rows = Array.from(tbody.querySelectorAll('tr[data-user-id]')).filter(r => r.style.display !== 'none');
        pagination.totalItems = pagination.rows.length;
        pagination.currentPage = 1;
        pagination.updateTotalPages();
        pagination.render();
        // Controls are re-rendered inside render() when totalPages changes,
        // but call once to ensure UI updates.
        pagination.renderControls();
    }
}

// ==========================================
// Existing Actions (Hardened)
// ==========================================
function toggleUserStatus(userId, currentlyActive) {
    closeAllDropdowns();

    var action = currentlyActive ? 'deactivate' : 'activate';

    if (currentlyActive) {
        // Deactivation requires sudo
        openSudoDialog(function () {
            _performToggleStatus(userId);
        });
    } else {
        _performToggleStatus(userId);
    }
}

function _performToggleStatus(userId) {
    var UM = AVAGuard.UserManagement;
    showLoading(true);

    fetch('/api/users/' + userId + '/toggle-status/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': UM.csrfToken,
        },
    })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            showLoading(false);
            if (data.success) {
                var message = data.message;
                if (data.sessions_revoked > 0) {
                    message += ' (' + data.sessions_revoked + ' sessions revoked)';
                }
                showToast(message, 'success');
                closeDrawer();
                // Update the table row in-place (no reload)
                _updateTableRow(userId, { is_active: data.is_active, security_score: data.security_score });
            } else if (data.sudo_required) {
                openSudoDialog(function () { _performToggleStatus(userId); });
            } else {
                showToast(data.errors?.__all__?.[0] || 'Failed to update status', 'error');
            }
        })
        .catch(function () {
            showLoading(false);
            showToast('Network error.', 'error');
        });
}

function forcePasswordReset(userId) {
    closeAllDropdowns();

    openSudoDialog(function () {
        var UM = AVAGuard.UserManagement;
        showLoading(true);

        fetch('/api/users/' + userId + '/force-reset/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': UM.csrfToken,
            },
        })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                showLoading(false);
                if (data.success) {
                    showToast(data.message, 'success');
                    closeDrawer();
                    // Show temp password modal to admin
                    if (data.temp_password) {
                        _showTempPasswordModal(data.temp_password, UM.currentDrawerUser?.email || '');
                    }
                } else if (data.sudo_required) {
                    openSudoDialog(function () { forcePasswordReset(userId); });
                } else {
                    showToast(data.errors?.__all__?.[0] || 'Failed to force password reset', 'error');
                }
            })
            .catch(function () {
                showLoading(false);
                showToast('Network error.', 'error');
            });
    });
}

// Show the one-time temporary password to the admin in a modal
function _showTempPasswordModal(tempPassword, userEmail) {
    var existing = document.getElementById('tempPasswordModal');
    if (existing) existing.remove();

    var overlay = document.createElement('div');
    overlay.id = 'tempPasswordModal';
    overlay.className = 'ava-sudo-overlay active';
    overlay.innerHTML =
        '<div class="ava-sudo-dialog" style="max-width:440px;">' +
        '<h3 style="margin-bottom:16px;">\uD83D\uDD10 Temporary Password Generated</h3>' +
        '<p style="color:#a0a0c0; font-size:13px; margin-bottom:16px;">A temporary password has been generated for <strong style="color:#fff;">' + escapeHtml(userEmail) + '</strong>. Share it securely with the user. They will be required to change it on their next login.</p>' +
        '<div style="background:#252550; border:1px solid #00d4ff44; border-radius:8px; padding:14px 18px; margin-bottom:20px; display:flex; align-items:center; justify-content:space-between;">' +
        '<code id="tempPwdValue" style="color:#00d4ff; font-size:16px; font-weight:600; letter-spacing:1px; user-select:all;">' + escapeHtml(tempPassword) + '</code>' +
        '<button onclick="_copyTempPassword()" class="drawer-btn drawer-btn-outline drawer-btn-sm" style="margin-left:12px;">Copy</button>' +
        '</div>' +
        '<div style="background:rgba(255,217,61,0.08); border:1px solid rgba(255,217,61,0.2); border-radius:8px; padding:10px 14px; margin-bottom:20px;">' +
        '<p style="color:#ffd93d; font-size:12px; margin:0;"><strong>Warning:</strong> This password will not be shown again. Store it securely before closing.</p>' +
        '</div>' +
        '<div class="sudo-actions">' +
        '<button class="drawer-btn drawer-btn-primary" onclick="_closeTempPasswordModal()">Done</button>' +
        '</div>' +
        '</div>';

    document.body.appendChild(overlay);
}

function _copyTempPassword() {
    var el = document.getElementById('tempPwdValue');
    if (el) {
        navigator.clipboard.writeText(el.textContent).then(function () {
            showToast('Password copied to clipboard', 'success');
        }).catch(function () {
            showToast('Copy failed — please select and copy manually', 'error');
        });
    }
}

function _closeTempPasswordModal() {
    var modal = document.getElementById('tempPasswordModal');
    if (modal) modal.remove();
}

function invalidateSessions(userId) {
    closeAllDropdowns();

    var UM = AVAGuard.UserManagement;

    openSudoDialog(function () {
        showLoading(true);
        fetch('/api/users/' + userId + '/invalidate-sessions/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': UM.csrfToken,
            },
        })
            .then(function (r) { return r.json(); })
            .then(function (data) {
                showLoading(false);
                if (data.success) {
                    showToast(data.message, 'success');
                    // No reload needed — sessions are server-side
                } else if (data.sudo_required) {
                    showToast('Sudo confirmation expired. Try again.', 'error');
                } else {
                    showToast(data.errors?.__all__?.[0] || 'Failed', 'error');
                }
            })
            .catch(function () {
                showLoading(false);
                showToast('Network error.', 'error');
            });
    });
}

function toggleEmail2FA(userId, action) {
    var UM = AVAGuard.UserManagement;
    showLoading(true);

    fetch('/api/users/' + userId + '/toggle-2fa/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': UM.csrfToken,
        }
    })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            showLoading(false);
            if (data.success) {
                showToast(data.message, 'success');
                // Refresh the drawer to reflect MFA change
                if (UM.currentDrawerUser) {
                    UM.currentDrawerUser.mfa_enabled = data.mfa_enabled;
                    renderDrawerContent(UM.currentDrawerUser);
                }
                _updateTableRow(userId, { mfa_enabled: data.mfa_enabled });
            } else {
                showToast(data.errors?.__all__?.[0] || 'Failed', 'error');
            }
        })
        .catch(function () {
            showLoading(false);
            showToast('Network error.', 'error');
        });
}

function toggle2FA(userId, checkbox) {
    var originalState = !checkbox.checked;
    var UM = AVAGuard.UserManagement;
    showLoading(true);

    fetch('/api/users/' + userId + '/toggle-2fa/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': UM.csrfToken,
        },
    })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            showLoading(false);
            if (data.success) {
                showToast(data.message, 'success');
                checkbox.checked = data.mfa_enabled;
            } else {
                showToast(data.errors?.__all__?.[0] || 'Failed', 'error');
                checkbox.checked = originalState;
            }
        })
        .catch(function () {
            showLoading(false);
            showToast('Network error.', 'error');
            checkbox.checked = originalState;
        });
}

// ==========================================
// Modal & Dropdown Management
// ==========================================
function openModal(id) {
    document.getElementById(id).classList.add('active');
    document.body.style.overflow = 'hidden';
}

function closeModal(id) {
    document.getElementById(id).classList.remove('active');
    document.body.style.overflow = '';
}

function openRoleModal(userId, email, currentRole) {
    document.getElementById('editUserId').value = userId;
    document.getElementById('editUserEmail').textContent = 'Editing: ' + email;
    document.getElementById('editRole').value = currentRole;
    openModal('editRoleModal');
}

function openExpiryModal(userId, email, currentExpiry) {
    AVAGuard.UserManagement.expiryUserId = userId;
    document.getElementById('expiryUserEmail').textContent = 'Setting expiry for: ' + email;
    document.getElementById('expiryDate').value = currentExpiry || '';
    // Close drawer first so modal renders on top (z-index layering fix)
    closeDrawer();
    setTimeout(function () { openModal('expiryModal'); }, 350);
}

function toggleActionsMenu(button) {
    var dropdown = button.closest('.actions-dropdown');
    var wasOpen = dropdown.classList.contains('open');
    closeAllDropdowns();
    if (!wasOpen) dropdown.classList.add('open');
}

function closeAllDropdowns() {
    document.querySelectorAll('.actions-dropdown.open').forEach(function (dd) {
        dd.classList.remove('open');
    });
}

// ==========================================
// Expiry Actions
// ==========================================
function setExpiry() {
    var UM = AVAGuard.UserManagement;
    var userId = UM.expiryUserId;
    var expiryDate = document.getElementById('expiryDate').value;

    if (!expiryDate) {
        showToast('Please select an expiry date', 'error');
        return;
    }

    var expiresAt = new Date(expiryDate + 'T23:59:59').toISOString();

    showLoading(true);
    closeModal('expiryModal');

    fetch('/api/users/' + userId + '/set-expiry/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': UM.csrfToken,
        },
        body: JSON.stringify({ expires_at: expiresAt }),
    })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            showLoading(false);
            if (data.success) {
                showToast(data.message, 'success');
                // No page reload — toast persists
            } else {
                showToast(data.errors?.__all__?.[0] || 'Failed', 'error');
            }
        })
        .catch(function () {
            showLoading(false);
            showToast('Network error.', 'error');
        });
}

function clearExpiry() {
    var UM = AVAGuard.UserManagement;
    var userId = UM.expiryUserId;

    showLoading(true);
    closeModal('expiryModal');

    fetch('/api/users/' + userId + '/set-expiry/', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-CSRFToken': UM.csrfToken,
        },
        body: JSON.stringify({ expires_at: null }),
    })
        .then(function (r) { return r.json(); })
        .then(function (data) {
            showLoading(false);
            if (data.success) {
                showToast('Account expiry removed', 'success');
                // No page reload — toast persists
            } else {
                showToast(data.errors?.__all__?.[0] || 'Failed', 'error');
            }
        })
        .catch(function () {
            showLoading(false);
            showToast('Network error.', 'error');
        });
}

// ==========================================
// Bulk Actions
// ==========================================
function toggleSelectAll() {
    var selectAllCheckbox = document.getElementById('selectAll');
    var checkboxes = document.querySelectorAll('.user-checkbox');

    checkboxes.forEach(function (cb) {
        var row = cb.closest('tr');
        if (row.style.display !== 'none') {
            cb.checked = selectAllCheckbox.checked;
        }
    });
    updateBulkBar();
}

function updateBulkBar() {
    var checkboxes = document.querySelectorAll('.user-checkbox:checked');
    var bulkBar = document.getElementById('bulkActionsBar');
    var countSpan = document.getElementById('selectedCount');

    AVAGuard.UserManagement.selectedUsers.clear();
    checkboxes.forEach(function (cb) {
        AVAGuard.UserManagement.selectedUsers.add(cb.value);
    });

    if (countSpan) countSpan.textContent = AVAGuard.UserManagement.selectedUsers.size;

    if (AVAGuard.UserManagement.selectedUsers.size > 0) {
        if (bulkBar) bulkBar.classList.add('visible');
    } else {
        if (bulkBar) bulkBar.classList.remove('visible');
    }
}

function bulkAction(action) {
    var UM = AVAGuard.UserManagement;
    if (UM.selectedUsers.size === 0) {
        showToast('No users selected', 'error');
        return;
    }

    var count = UM.selectedUsers.size;
    var actionDisplay = action.replace('_', ' ');
    var confirmMsg = 'Are you sure you want to <strong>' + actionDisplay + '</strong> the selected ' + count + ' users?';

    modalSystem.confirm({
        title: 'Confirm Bulk Action',
        message: confirmMsg,
        confirmText: 'Confirm',
        cancelText: 'Cancel',
        onConfirm: function () {
            showLoading(true);

            fetch('/api/users/bulk-action/', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': UM.csrfToken,
                },
                body: JSON.stringify({
                    user_ids: Array.from(UM.selectedUsers),
                    action: action,
                }),
            })
                .then(function (r) { return r.json(); })
                .then(function (data) {
                    showLoading(false);
                    if (data.success) {
                        var msg = data.message;
                        if (data.skipped > 0) msg += ' (' + data.skipped + ' skipped due to insufficient privileges)';
                        showToast(msg, 'success');
                        UM.selectedUsers.clear();
                        setTimeout(function () { location.reload(); }, 1000);
                    } else {
                        showToast(data.errors?.__all__?.[0] || 'Bulk action failed', 'error');
                    }
                })
                .catch(function () {
                    showLoading(false);
                    showToast('Network error.', 'error');
                });
        }
    });
}

// ==========================================
// DOM Update Helper (avoids location.reload)
// ==========================================
function _updateTableRow(userId, updates) {
    var row = document.querySelector('tr[data-user-id="' + userId + '"]');
    if (!row) return;

    // Update status badge
    if (updates.is_active !== undefined) {
        var statusCell = row.querySelector('.user-status');
        if (statusCell) {
            if (updates.is_active) {
                statusCell.className = 'user-status active';
                statusCell.innerHTML = '<span class="status-dot"></span> Active';
            } else {
                statusCell.className = 'user-status disabled';
                statusCell.innerHTML = '<span class="status-dot"></span> Disabled';
            }
        }
        row.dataset.userActive = updates.is_active ? 'true' : 'false';
    }

    // Update security score badge
    if (updates.security_score) {
        var scoreBadge = row.querySelector('.security-badge');
        if (scoreBadge) {
            scoreBadge.className = 'security-badge ' + updates.security_score;
            var scoreText = updates.security_score === 'green' ? 'Secure' :
                updates.security_score === 'yellow' ? 'Moderate' : 'At Risk';
            scoreBadge.innerHTML = '<span class="dot"></span>' + scoreText;
        }
    }

    // Update MFA badge
    if (updates.mfa_enabled !== undefined) {
        var mfaCell = row.querySelector('.mfa-badge');
        if (mfaCell) {
            if (updates.mfa_enabled) {
                mfaCell.className = 'mfa-badge email';
                mfaCell.innerHTML = 'Enabled';
            } else {
                mfaCell.className = 'mfa-badge off';
                mfaCell.innerHTML = 'Off';
            }
        }
    }
}

// ==========================================
// Utilities
// ==========================================
function showLoading(show) {
    var overlay = document.getElementById('loadingOverlay');
    if (overlay) overlay.classList.toggle('visible', show);
}

function showToast(message, type) {
    // Re-entrancy guard: prevents recursive stack overflow at any entry point
    if (window.__avaToastLock) return;

    type = type || 'info';

    try {
        window.__avaToastLock = true;

        var ToastSystem = window.Toast || (window.parent && window.parent.Toast);
        
        if (ToastSystem && typeof ToastSystem.show === 'function') {
            // Primary path: use the global Toast system
            ToastSystem.show(message, type);
        } else {
            // Fallback: log to console, never use alert() (would block event loop)
            console.warn('[AVAGuard] Toast system not available. Falling back to DOM notification.', message);
            // Append a non-blocking DOM notification as last resort
            var fb = document.createElement('div');
            fb.style.cssText =
                'position:fixed;bottom:24px;right:24px;background:#1a1a2e;' +
                'color:#fff;padding:14px 20px;border-radius:10px;z-index:99999;' +
                'font-size:14px;box-shadow:0 8px 30px rgba(0,0,0,.4);max-width:320px;';
            fb.textContent = message;
            document.body.appendChild(fb);
            setTimeout(function () {
                if (fb && fb.parentNode) fb.parentNode.removeChild(fb);
            }, 4000);
        }
    } catch (err) {
        // If the Toast system itself throws, log it — never re-throw or re-enter
        console.error('[AVAGuard] Toast error (suppressed to prevent recursion):', err);
    } finally {
        // Always release the lock after a safety window
        setTimeout(function () { window.__avaToastLock = false; }, 500);
    }
}

function escapeHtml(str) {
    if (!str) return '';
    var div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}

function getCookie(name) {
    var value = '; ' + document.cookie;
    var parts = value.split('; ' + name + '=');
    if (parts.length === 2) return parts.pop().split(';').shift();
    return '';
}

// Expose globally
window.AVAGuard = AVAGuard;

// Initialize Pagination for Users Table
document.addEventListener('DOMContentLoaded', function() {
    if (document.getElementById('usersTable')) {
        window.initPagination('usersTable', 'paginationContainer', 10);
        
        // Apply filters from URL on load (must happen after pagination init)
        if (typeof filterTable === 'function') {
            filterTable();
        }
    }
});
