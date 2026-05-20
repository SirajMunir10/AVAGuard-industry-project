/**
 * AVAGuard — Active Sessions Management Logic
 * Template: admin/sessions.html
 * =========================================================
 */

let selectedSessions = new Set();

// Date range toggle
function toggleCustomDates(select) {
    const customDates = document.getElementById('customDates');
    if (customDates) {
        customDates.style.display = select.value === 'custom' ? 'flex' : 'none';
    }
}

// Initialize custom date visibility
document.addEventListener('DOMContentLoaded', function() {
    const dateRange = document.querySelector('select[name="date_range"]');
    if (dateRange && dateRange.value === 'custom') {
        const customDates = document.getElementById('customDates');
        if (customDates) customDates.style.display = 'flex';
    }
});

// Selection functions
function toggleSelectAll() {
    const selectAll = document.getElementById('selectAll');
    if (!selectAll) return;
    
    document.querySelectorAll('#sessionsTable .session-checkbox').forEach(cb => {
        cb.checked = selectAll.checked;
    });
    updateBulkBar();
}

function updateBulkBar() {
    const checkboxes = document.querySelectorAll('#sessionsTable .session-checkbox:checked');
    selectedSessions.clear();
    checkboxes.forEach(cb => selectedSessions.add(cb.value));
    
    const countEl = document.getElementById('selectedCount');
    const bulkBar = document.getElementById('bulkBar');
    
    if (countEl) countEl.textContent = selectedSessions.size;
    if (bulkBar) bulkBar.classList.toggle('visible', selectedSessions.size > 0);
}

// Revoke single session with modal
function revokeSession(row) {
    const sessionId = row.dataset.sessionId;
    const userName = row.dataset.userName;
    const userEmail = row.dataset.userEmail;
    const deviceName = row.dataset.deviceName;
    const ipAddress = row.dataset.ipAddress;
    
    if (window.Modal && typeof window.Modal.confirmRevoke === 'function') {
        window.Modal.confirmRevoke({
            userName: userName,
            userEmail: userEmail,
            deviceName: deviceName,
            ipAddress: ipAddress,
            onConfirm: function() {
                performRevoke([sessionId]);
            }
        });
    } else {
        if (confirm(`Revoke session for ${userEmail}?`)) {
            performRevoke([sessionId]);
        }
    }
}

// Bulk revoke
function bulkRevoke() {
    if (selectedSessions.size === 0) {
        if (window.Toast && window.Toast.warning) {
            window.Toast.warning('No sessions selected');
        }
        return;
    }
    
    if (window.Modal && typeof window.Modal.confirmBulk === 'function') {
        window.Modal.confirmBulk({
            action: 'Revoke',
            count: selectedSessions.size,
            onConfirm: function() {
                performRevoke(Array.from(selectedSessions));
            }
        });
    } else {
        if (confirm(`Revoke ${selectedSessions.size} sessions?`)) {
            performRevoke(Array.from(selectedSessions));
        }
    }
}

// Revoke all sessions
function revokeAllSessions() {
    // totalCount is passed via window.AVA bridge in template
    const totalCount = window.AVA && window.AVA.totalSessionsCount ? window.AVA.totalSessionsCount : 0;
    if (totalCount === 0) return;
    
    if (window.Modal && typeof window.Modal.confirm === 'function') {
        window.Modal.confirm({
            title: 'Revoke All Sessions',
            icon: 'danger',
            message: `
                <p>Are you sure you want to revoke <strong>ALL ${totalCount} active sessions</strong>?</p>
                <p class="ava-modal-warning">All users will be immediately logged out of their desktop apps.</p>
            `,
            confirmText: 'Revoke All',
            confirmClass: 'btn-danger',
            onConfirm: function() {
                performRevoke('all');
            }
        });
    } else {
        if (confirm(`Are you sure you want to revoke ALL ${totalCount} active sessions?`)) {
            performRevoke('all');
        }
    }
}

// Perform the actual revocation
function performRevoke(sessionIds) {
    const csrfToken = window.AVA ? window.AVA.csrfToken : '';
    
    // Create form submission
    const form = document.createElement('form');
    form.method = 'POST';
    form.innerHTML = `<input type="hidden" name="csrfmiddlewaretoken" value="${csrfToken}">
                      <input type="hidden" name="action" value="revoke">`;
    
    if (sessionIds === 'all') {
        form.innerHTML += '<input type="hidden" name="revoke_all" value="true">';
    } else if (Array.isArray(sessionIds)) {
        sessionIds.forEach(id => {
            form.innerHTML += `<input type="hidden" name="session_ids" value="${id}">`;
        });
    } else {
        form.innerHTML += `<input type="hidden" name="session_id" value="${sessionIds}">`;
    }
    
    document.body.appendChild(form);
    form.submit();
}
