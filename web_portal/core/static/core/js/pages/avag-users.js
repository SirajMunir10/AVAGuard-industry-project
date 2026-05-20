/**
 * AVAGuard — Users Management Page Logic
 * Template: admin/users.html
 * =========================================================
 */

// Toast compatibility shim (inline JS uses Toast.success/error/warning)
var Toast = {
    success: function(msg) { showToast(msg, 'success'); },
    error: function(msg) { showToast(msg, 'error'); },
    warning: function(msg) { showToast(msg, 'info'); },
    info: function(msg) { showToast(msg, 'info'); }
};

// Modal compatibility shim
var Modal = {
    confirmBulk: function(opts) {
        if (confirm(opts.action + ' ' + opts.count + ' users?')) {
            opts.onConfirm();
        }
    }
};


/**
 * Sorts the users table and updates UI.
 */
let currentSortCol = -1;
let currentSortDir = true; // true = asc, false = desc

function sortTable(colIndex, type, headerEl) {
    const tableId = 'usersTable'; // Assuming this is the table ID or logic needs to find it
    const pagination = window.AVA_PAGINATION_usersTable;
    if (!pagination) {
        console.warn('Pagination instance not found for usersTable');
        return;
    }

    // Toggle direction if same column
    if (currentSortCol === colIndex) {
        currentSortDir = !currentSortDir;
    } else {
        currentSortCol = colIndex;
        currentSortDir = true;
    }

    // Update Header UI
    document.querySelectorAll('.sortable-header').forEach(h => {
        h.classList.remove('asc', 'desc');
    });
    headerEl.classList.add(currentSortDir ? 'asc' : 'desc');

    // Execute sort
    pagination.sort(colIndex, type, currentSortDir);
}



// Open User Management Drawer (Phase 2 — API-based)
function openUserDrawer(row) {
    var userId = row.dataset.userId;
    openDrawer(userId);
}

// Initialize
document.addEventListener('DOMContentLoaded', function() {
    // Check URL parameters for auto-open
    const urlParams = new URLSearchParams(window.location.search);
    if (urlParams.get('add_user') === 'true') {
        // Clear param without reloading
        const url = new URL(window.location.href);
        url.searchParams.delete('add_user');
        window.history.replaceState({}, '', url);
        
        setTimeout(() => {
            if (typeof openCreateUserDrawer === 'function') openCreateUserDrawer();
        }, 100);
    }

    // Escape key to close modals
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            document.querySelectorAll('.modal.active').forEach(m => m.classList.remove('active'));
            if (typeof closeCreateUserDrawer === 'function') closeCreateUserDrawer();
            document.body.style.overflow = '';
        }
    });
});

function openCreateUserDrawer() {
    document.getElementById('createUserOverlay').classList.add('active');
    document.getElementById('createUserDrawer').classList.add('open');
    document.body.style.overflow = 'hidden';
}

function closeCreateUserDrawer() {
    document.getElementById('createUserOverlay').classList.remove('active');
    document.getElementById('createUserDrawer').classList.remove('open');
    document.body.style.overflow = '';
}
