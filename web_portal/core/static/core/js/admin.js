/**
 * AVAGuard Admin JavaScript
 * Admin-specific functionality: modals, filters, user management
 */

(function () {
    'use strict';

    /**
     * Initialize modal functionality
     */
    function initModals() {
        // Open modal buttons
        document.querySelectorAll('[data-modal-open]').forEach(function (btn) {
            btn.addEventListener('click', function () {
                const modalId = this.getAttribute('data-modal-open');
                const modal = document.getElementById(modalId);
                if (modal) {
                    modal.classList.add('active');
                    document.body.style.overflow = 'hidden';
                }
            });
        });

        // Close modal buttons
        document.querySelectorAll('[data-modal-close]').forEach(function (btn) {
            btn.addEventListener('click', function () {
                const modal = this.closest('.modal');
                if (modal) {
                    modal.classList.remove('active');
                    document.body.style.overflow = '';
                }
            });
        });

        // Close on backdrop click
        document.querySelectorAll('.modal').forEach(function (modal) {
            modal.addEventListener('click', function (e) {
                if (e.target === this) {
                    this.classList.remove('active');
                    document.body.style.overflow = '';
                }
            });
        });

        // Close on Escape key
        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape') {
                document.querySelectorAll('.modal.active').forEach(function (modal) {
                    modal.classList.remove('active');
                    document.body.style.overflow = '';
                });
            }
        });
    }

    /**
     * Initialize table filters
     */
    function initTableFilters() {
        const filterInputs = document.querySelectorAll('[data-filter-table]');

        filterInputs.forEach(function (input) {
            const tableId = input.getAttribute('data-filter-table');
            const table = document.getElementById(tableId);

            if (!table) return;

            input.addEventListener('input', AVAGuard.debounce(function () {
                const searchTerm = this.value.toLowerCase();
                const rows = table.querySelectorAll('tbody tr');

                rows.forEach(function (row) {
                    const text = row.textContent.toLowerCase();
                    row.style.display = text.includes(searchTerm) ? '' : 'none';
                });
            }, 300));
        });
    }

    /**
     * Initialize role filter for audit logs
     */
    function initRoleFilter() {
        const roleFilter = document.getElementById('role-filter');
        if (!roleFilter) return;

        roleFilter.addEventListener('change', function () {
            const selectedRole = this.value;
            const rows = document.querySelectorAll('.data-table tbody tr');

            rows.forEach(function (row) {
                const roleCell = row.querySelector('td:nth-child(3)');
                if (roleCell) {
                    const role = roleCell.textContent.trim();
                    if (selectedRole === '' || role.includes(selectedRole)) {
                        row.style.display = '';
                    } else {
                        row.style.display = 'none';
                    }
                }
            });
        });
    }

    /**
     * Initialize user edit functionality
     */
    function initUserEdit() {
        document.querySelectorAll('.edit-user-btn').forEach(function (btn) {
            btn.addEventListener('click', function () {
                const userId = this.getAttribute('data-user-id');
                const userName = this.getAttribute('data-user-name');
                const userEmail = this.getAttribute('data-user-email');
                const userRole = this.getAttribute('data-user-role');

                // Populate form
                const form = document.getElementById('editUserForm');
                if (form) {
                    form.querySelector('[name="user_id"]').value = userId || '';
                    form.querySelector('[name="name"]').value = userName || '';
                    form.querySelector('[name="email"]').value = userEmail || '';
                    form.querySelector('[name="role"]').value = userRole || '';
                }

                // Open modal
                const modal = document.getElementById('editUserModal');
                if (modal) {
                    modal.classList.add('active');
                }
            });
        });
    }

    /**
     * Initialize confirmation dialogs
     */
    function initConfirmations() {
        document.querySelectorAll('[data-confirm]').forEach(function (btn) {
            btn.addEventListener('click', function (e) {
                const message = this.getAttribute('data-confirm');
                if (!confirm(message)) {
                    e.preventDefault();
                }
            });
        });
    }

    /**
     * Initialize date range picker
     */
    function initDateRangePicker() {
        const dateInputs = document.querySelectorAll('.date-range-picker');
        dateInputs.forEach(function (input) {
            // Auto-submit on change
            input.addEventListener('change', function () {
                const form = this.closest('form');
                if (form) form.submit();
            });
        });
    }

    /**
     * Initialize select auto-submit
     */
    function initAutoSubmitSelects() {
        document.querySelectorAll('select[data-auto-submit]').forEach(function (select) {
            select.addEventListener('change', function () {
                const form = this.closest('form');
                if (form) form.submit();
            });
        });
    }

    /**
     * Initialize everything on DOM ready
     */
    document.addEventListener('DOMContentLoaded', function () {
        initModals();
        initTableFilters();
        initRoleFilter();
        initUserEdit();
        initConfirmations();
        initDateRangePicker();
        initAutoSubmitSelects();
    });

    // Expose admin functions globally
    window.AVAGuardAdmin = {
        initModals: initModals,
        initTableFilters: initTableFilters,
        initRoleFilter: initRoleFilter
    };

})();
