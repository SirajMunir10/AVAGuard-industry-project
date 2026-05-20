/**
 * AVAGuard — Reports Logic
 * Template: reports/index.html
 * =========================================================
 */

function showScheduleModal() {
    if (typeof window.Modal !== 'undefined' && window.Modal.alert) {
        window.Modal.alert({
            title: 'Schedule Automated Reports',
            icon: 'info',
            message: `
                <div style="text-align: left;">
                    <p style="margin-bottom: 16px;">Automated report scheduling allows you to:</p>
                    <ul style="margin: 0 0 16px 20px; color: var(--text-secondary); line-height: 1.8;">
                        <li>Schedule weekly or monthly compliance summaries</li>
                        <li>Automatically email reports to stakeholders</li>
                        <li>Set up custom report triggers based on thresholds</li>
                    </ul>
                    <div style="background: rgba(0, 212, 255, 0.1); border: 1px solid rgba(0, 212, 255, 0.2); border-radius: 8px; padding: 12px;">
                        <p style="font-size: 13px; color: var(--accent-primary); margin: 0;">
                            <strong>Coming Soon:</strong> This feature will be available in a future release.
                        </p>
                    </div>
                </div>
            `
        });
    } else {
        alert("Automated report scheduling is coming soon in a future release!");
    }
}

// Global sorting state for Reports
let reportSortCol = -1;
let reportSortDir = true;

function sortReports(colIndex, type, headerEl) {
    const pagination = window.AVA_PAGINATION_reportsTable;
    if (!pagination) return;

    if (reportSortCol === colIndex) {
        reportSortDir = !reportSortDir;
    } else {
        reportSortCol = colIndex;
        reportSortDir = true;
    }

    document.querySelectorAll('.sortable-header').forEach(h => h.classList.remove('asc', 'desc'));
    headerEl.classList.add(reportSortDir ? 'asc' : 'desc');

    pagination.sort(colIndex, type, reportSortDir);
}
