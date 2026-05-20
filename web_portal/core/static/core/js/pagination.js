/**
 * AVAGuard - Client-Side Pagination System
 * Handles table pagination without page reloads.
 */

class AVAPagination {
    constructor(options) {
        this.tableId = options.tableId;
        this.containerId = options.containerId;
        this.itemsPerPage = options.itemsPerPage || 10;
        this.currentPage = 1;
        this.table = document.querySelector(`#${this.tableId}`);
        this.tbody = this.table.querySelector('tbody');
        this.rows = Array.from(this.tbody.querySelectorAll('tr:not(.empty-state-row)'));
        this.totalItems = this.rows.length;
        
        if (this.totalItems > 0) {
            this.init();
        }
    }

    init() {
        this.updateTotalPages();
        this.render();
        this.renderControls();
    }

    updateTotalPages() {
        this.totalPages = Math.ceil(this.totalItems / this.itemsPerPage);
        if (this.currentPage > this.totalPages) {
            this.currentPage = this.totalPages || 1;
        }
    }

    render() {
        const start = (this.currentPage - 1) * this.itemsPerPage;
        const end = start + this.itemsPerPage;

        this.rows.forEach((row, index) => {
            if (index >= start && index < end) {
                row.style.display = '';
            } else {
                row.style.display = 'none';
            }
        });
    }

    renderControls() {
        const container = document.querySelector(`#${this.containerId}`);
        if (!container) return;

        let html = `
            <div class="pagination-controls" style="display: flex; justify-content: flex-end; align-items: center; gap: 24px; padding: 16px 0; border-top: 1px solid var(--avag-border-color);">
                <div class="pagination-size-selector" style="display: flex; align-items: center; gap: 8px; font-size: 13px; color: var(--avag-text-secondary);">
                    <label>Show</label>
                    <select onchange="window.AVA_PAGINATION_${this.tableId}.setItemsPerPage(this.value)" style="padding: 4px 8px; border-radius: 4px; background: var(--avag-bg-input); border: 1px solid var(--avag-border-color); color: var(--avag-text-primary);">
                        <option value="10" ${this.itemsPerPage === 10 ? 'selected' : ''}>10</option>
                        <option value="25" ${this.itemsPerPage === 25 ? 'selected' : ''}>25</option>
                        <option value="50" ${this.itemsPerPage === 50 ? 'selected' : ''}>50</option>
                        <option value="100" ${this.itemsPerPage === 100 ? 'selected' : ''}>100</option>
                    </select>
                    <span>per page</span>
                </div>

                <div class="pagination-jump" style="display: flex; align-items: center; gap: 8px; font-size: 13px; color: var(--avag-text-secondary);">
                    <span>Go to page</span>
                    <input type="number" 
                           min="1" 
                           max="${this.totalPages}" 
                           value="${this.currentPage}" 
                           onchange="window.AVA_PAGINATION_${this.tableId}.goToPage(this.value)"
                           style="width: 50px; padding: 4px 8px; border-radius: 4px; background: var(--avag-bg-input); border: 1px solid var(--avag-border-color); color: var(--avag-text-primary); text-align: center;">
                </div>
                
                <div class="pagination-navigation" style="display: flex; align-items: center; gap: 12px;">
                    <button class="pagination-btn ${this.currentPage === 1 ? 'disabled' : ''}" 
                            onclick="window.AVA_PAGINATION_${this.tableId}.goToPage(${this.currentPage - 1})"
                            ${this.currentPage === 1 ? 'disabled' : ''}
                            style="padding: 6px 12px; border-radius: 6px; background: var(--avag-bg-input); border: 1px solid var(--avag-border-color); color: var(--avag-text-primary); cursor: pointer; font-size: 13px;">
                        Previous
                    </button>
                    <div class="pagination-info" style="font-size: 13px; color: var(--avag-text-secondary); font-weight: 500;">
                        Page ${this.currentPage} of ${this.totalPages || 1}
                    </div>
                    <button class="pagination-btn ${this.currentPage === this.totalPages || this.totalPages === 0 ? 'disabled' : ''}" 
                            onclick="window.AVA_PAGINATION_${this.tableId}.goToPage(${this.currentPage + 1})"
                            ${this.currentPage === this.totalPages || this.totalPages === 0 ? 'disabled' : ''}
                            style="padding: 6px 12px; border-radius: 6px; background: var(--avag-bg-input); border: 1px solid var(--avag-border-color); color: var(--avag-text-primary); cursor: pointer; font-size: 13px;">
                        Next
                    </button>
                </div>
            </div>
        `;

        container.innerHTML = html;
    }

    goToPage(page) {
        if (page < 1 || page > this.totalPages) return;
        this.currentPage = page;
        this.render();
        this.renderControls();
    }

    setItemsPerPage(size) {
        this.itemsPerPage = parseInt(size);
        this.currentPage = 1;
        this.updateTotalPages();
        this.render();
        this.renderControls();
    }

    /**
     * Sorts the entire dataset (this.rows) by a specific column.
     * @param {number} columnIndex - The 0-based index of the column to sort by.
     * @param {string} type - The data type: 'text', 'number', or 'date'.
     * @param {boolean} isAscending - Sorting direction.
     */
    sort(columnIndex, type = 'text', isAscending = true) {
        this.rows.sort((a, b) => {
            const cellA = a.cells[columnIndex];
            const cellB = b.cells[columnIndex];

            // Prefer data-sort-value attribute if present (used for dates with human-readable display)
            let valA = cellA.dataset.sortValue !== undefined
                ? cellA.dataset.sortValue
                : cellA.innerText.trim();
            let valB = cellB.dataset.sortValue !== undefined
                ? cellB.dataset.sortValue
                : cellB.innerText.trim();

            // Special handling for status badges
            if (!cellA.dataset.sortValue && cellA.querySelector('.status-badge')) {
                valA = cellA.querySelector('.status-badge').innerText.trim();
                valB = cellB.querySelector('.status-badge').innerText.trim();
            }

            if (type === 'number') {
                valA = parseFloat(String(valA).replace(/[^0-9.-]+/g, '')) || 0;
                valB = parseFloat(String(valB).replace(/[^0-9.-]+/g, '')) || 0;
            } else if (type === 'date') {
                valA = new Date(valA).getTime() || 0;
                valB = new Date(valB).getTime() || 0;
            } else {
                valA = String(valA).toLowerCase();
                valB = String(valB).toLowerCase();
            }

            if (valA < valB) return isAscending ? -1 : 1;
            if (valA > valB) return isAscending ? 1 : -1;
            return 0;
        });

        this.currentPage = 1;
        
        // Re-append sorted rows to DOM to reflect new order
        this.rows.forEach(row => this.tbody.appendChild(row));
        
        this.render();
        this.renderControls();
    }
}

// Global initialization helper
window.initPagination = (tableId, containerId, itemsPerPage) => {
    window[`AVA_PAGINATION_${tableId}`] = new AVAPagination({
        tableId: tableId,
        containerId: containerId,
        itemsPerPage: itemsPerPage
    });
};
