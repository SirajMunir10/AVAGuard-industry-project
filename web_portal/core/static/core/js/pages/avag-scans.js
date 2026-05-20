/**
 * AVAGuard — Scans Index Logic
 * Template: scans/index.html
 * =========================================================
 */

let selectedScans = new Set();

function toggleSelectAll() {
    const selectAll = document.getElementById('selectAll');
    if (!selectAll) return;
    document.querySelectorAll('.scan-checkbox').forEach(cb => {
        cb.checked = selectAll.checked;
    });
    updateCompareButton();
}

function updateCompareButton() {
    const checkboxes = document.querySelectorAll('.scan-checkbox:checked');
    selectedScans.clear();
    checkboxes.forEach(cb => selectedScans.add(cb.value));
    
    const btn = document.getElementById('compareBtn');
    if (!btn) return;
    
    if (selectedScans.size === 2) {
        btn.disabled = false;
        btn.style.opacity = '1';
        btn.textContent = 'Compare 2 Scans';
    } else {
        btn.disabled = true;
        btn.style.opacity = '0.5';
        btn.innerHTML = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" x2="18" y1="20" y2="10"/><line x1="12" x2="12" y1="20" y2="4"/><line x1="6" x2="6" y1="20" y2="14"/></svg> Compare Selected (${selectedScans.size}/2)`;
    }
}

function compareScans() {
    if (selectedScans.size !== 2) {
        if (typeof window.Toast !== 'undefined' && window.Toast.warning) {
            window.Toast.warning('Please select exactly 2 scans to compare');
        } else {
            alert('Please select exactly 2 scans to compare');
        }
        return;
    }
    const ids = Array.from(selectedScans);
    window.location.href = '/scans/compare/?scan_a=' + ids[0] + '&scan_b=' + ids[1];
}

// Global sorting state for Scans
let scanSortCol = -1;
let scanSortDir = true;

function sortScans(colIndex, type, headerEl) {
    const pagination = window.AVA_PAGINATION_scansTable;
    if (!pagination) return;

    if (scanSortCol === colIndex) {
        scanSortDir = !scanSortDir;
    } else {
        scanSortCol = colIndex;
        scanSortDir = true;
    }

    document.querySelectorAll('.sortable-header').forEach(h => h.classList.remove('asc', 'desc'));
    headerEl.classList.add(scanSortDir ? 'asc' : 'desc');

    pagination.sort(colIndex, type, scanSortDir);
}

document.addEventListener('DOMContentLoaded', function() {
    // Apply data-width to progress bars
    document.querySelectorAll('.score-bar-fill').forEach(function(bar) {
        var w = bar.getAttribute('data-width');
        if (w) bar.style.width = w + '%';
    });
});
