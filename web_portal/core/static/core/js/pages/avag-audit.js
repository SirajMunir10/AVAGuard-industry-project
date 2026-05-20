/**
 * AVAGuard — Audit Logs Page Logic
 * Template: admin/audit_logs.html
 * =========================================================
 */

// Filter users dropdown based on role selection
function filterUsersByRole() {
    const role = document.getElementById('roleFilter').value;
    const userSelect = document.getElementById('userFilter');
    if (!userSelect) return;
    
    const options = userSelect.querySelectorAll('option');
    const currentVal = userSelect.value;
    let foundCurrent = false;

    options.forEach(opt => {
        if (opt.value === "") return;
        if (role === "" || opt.getAttribute('data-role') === role) {
            opt.style.display = "";
            if (opt.value === currentVal) foundCurrent = true;
        } else {
            opt.style.display = "none";
        }
    });

    if (!foundCurrent && role !== "") {
        userSelect.value = "";
    }
}

function toggleCustomDates(select) {
    const customDates = document.getElementById('customDates');
    if (customDates) {
        customDates.style.display = select.value === 'custom' ? 'flex' : 'none';
    }
}

// Global sorting state for Audit Logs
let auditSortCol = -1;
let auditSortDir = true;

function sortAuditLogs(colIndex, type, headerEl) {
    const pagination = window.AVA_PAGINATION_auditLogsTable;
    if (!pagination) return;

    if (auditSortCol === colIndex) {
        auditSortDir = !auditSortDir;
    } else {
        auditSortCol = colIndex;
        auditSortDir = true;
    }

    document.querySelectorAll('.sortable-header').forEach(h => h.classList.remove('asc', 'desc'));
    headerEl.classList.add(auditSortDir ? 'asc' : 'desc');

    pagination.sort(colIndex, type, auditSortDir);
}

document.addEventListener('DOMContentLoaded', function() {
    filterUsersByRole();
    
    // Initialize Pagination for Audit Logs Table (local page only since server uses keyset)
    if (document.getElementById('auditLogsTable')) {
        window.initPagination('auditLogsTable', 'auditPaginationContainer', 25);
    }
});
