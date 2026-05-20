/**
 * AVAGuard - Modal Dialog System
 * 
 * Professional confirmation dialogs replacing browser confirm()
 * Follows enterprise patterns (AWS/Azure style)
 */

const AVAGuardModal = (function () {
    'use strict';

    let modalContainer = null;
    let activeModal = null;

    // Initialize modal container
    function init() {
        if (modalContainer) return;

        modalContainer = document.createElement('div');
        modalContainer.id = 'ava-modal-container';
        modalContainer.innerHTML = `
            <div class="ava-modal-overlay" id="avaModalOverlay"></div>
            <div class="ava-modal" id="avaModal" role="dialog" aria-modal="true">
                <div class="ava-modal-header">
                    <div class="ava-modal-icon" id="avaModalIcon"></div>
                    <h3 class="ava-modal-title" id="avaModalTitle"></h3>
                    <button class="ava-modal-close" id="avaModalClose" aria-label="Close">&times;</button>
                </div>
                <div class="ava-modal-body" id="avaModalBody"></div>
                <div class="ava-modal-footer" id="avaModalFooter"></div>
            </div>
        `;
        document.body.appendChild(modalContainer);

        // Event listeners
        document.getElementById('avaModalOverlay').addEventListener('click', close);
        document.getElementById('avaModalClose').addEventListener('click', close);

        // Keyboard events
        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape' && activeModal) {
                close();
            }
        });
    }

    // Show modal
    function show() {
        modalContainer.classList.add('visible');
        document.body.style.overflow = 'hidden';
        // Focus first button
        const firstBtn = modalContainer.querySelector('.ava-modal-footer button');
        if (firstBtn) firstBtn.focus();
    }

    // Close modal
    function close() {
        modalContainer.classList.remove('visible');
        document.body.style.overflow = '';
        if (activeModal && activeModal.onClose) {
            activeModal.onClose();
        }
        activeModal = null;
    }

    // Icon templates
    const icons = {
        warning: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>
            <path d="M12 9v4"/><path d="M12 17h.01"/>
        </svg>`,
        danger: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/><path d="m15 9-6 6"/><path d="m9 9 6 6"/>
        </svg>`,
        success: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>
            <polyline points="22 4 12 14.01 9 11.01"/>
        </svg>`,
        info: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/>
        </svg>`,
        user: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2"/>
            <circle cx="9" cy="7" r="4"/>
        </svg>`,
        session: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <rect width="20" height="14" x="2" y="3" rx="2"/>
            <line x1="8" x2="16" y1="21" y2="21"/><line x1="12" x2="12" y1="17" y2="21"/>
        </svg>`
    };

    /**
     * Confirm Dialog
     * @param {Object} options
     * @param {string} options.title - Dialog title
     * @param {string} options.message - HTML message content
     * @param {string} options.icon - Icon type: warning, danger, success, info, user, session
     * @param {string} options.confirmText - Confirm button text
     * @param {string} options.cancelText - Cancel button text
     * @param {string} options.confirmClass - CSS class for confirm button
     * @param {Function} options.onConfirm - Callback on confirm
     * @param {Function} options.onCancel - Callback on cancel
     */
    function confirm(options) {
        init();

        const defaults = {
            title: 'Confirm Action',
            message: 'Are you sure you want to proceed?',
            icon: 'warning',
            confirmText: 'Confirm',
            cancelText: 'Cancel',
            confirmClass: 'btn-primary',
            onConfirm: null,
            onCancel: null
        };

        const opts = { ...defaults, ...options };
        activeModal = opts;

        // Set content
        document.getElementById('avaModalIcon').innerHTML = icons[opts.icon] || icons.info;
        document.getElementById('avaModalIcon').className = 'ava-modal-icon ' + opts.icon;
        document.getElementById('avaModalTitle').textContent = opts.title;
        document.getElementById('avaModalBody').innerHTML = opts.message;

        // Set footer buttons
        document.getElementById('avaModalFooter').innerHTML = `
            <button class="btn btn-secondary" id="avaModalCancel">${opts.cancelText}</button>
            <button class="btn ${opts.confirmClass}" id="avaModalConfirm">${opts.confirmText}</button>
        `;

        // Button handlers
        document.getElementById('avaModalCancel').onclick = function () {
            if (opts.onCancel) opts.onCancel();
            close();
        };

        document.getElementById('avaModalConfirm').onclick = function () {
            if (opts.onConfirm) opts.onConfirm();
            close();
        };

        show();
    }

    /**
     * Alert Dialog (single button)
     */
    function alert(options) {
        init();

        const defaults = {
            title: 'Notice',
            message: '',
            icon: 'info',
            buttonText: 'OK',
            onClose: null
        };

        const opts = { ...defaults, ...options };
        activeModal = opts;

        document.getElementById('avaModalIcon').innerHTML = icons[opts.icon] || icons.info;
        document.getElementById('avaModalIcon').className = 'ava-modal-icon ' + opts.icon;
        document.getElementById('avaModalTitle').textContent = opts.title;
        document.getElementById('avaModalBody').innerHTML = opts.message;

        document.getElementById('avaModalFooter').innerHTML = `
            <button class="btn btn-primary" id="avaModalOk">${opts.buttonText}</button>
        `;

        document.getElementById('avaModalOk').onclick = close;

        show();
    }

    /**
     * Delete Confirmation (pre-styled for destructive actions)
     */
    function confirmDelete(options) {
        return confirm({
            icon: 'danger',
            confirmClass: 'btn-danger',
            confirmText: 'Delete',
            ...options
        });
    }

    /**
     * Session Revoke Confirmation (specialized for session revocation)
     */
    function confirmRevoke(options) {
        const { userName, userEmail, deviceName, ipAddress, onConfirm, onCancel } = options;

        return confirm({
            title: 'Revoke Session',
            icon: 'session',
            message: `
                <p style="margin-bottom: 16px;">Are you sure you want to revoke this session?</p>
                <div class="ava-modal-details">
                    <div class="detail-row">
                        <span class="detail-icon">👤</span>
                        <span class="detail-text">${userName || userEmail}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-icon">🖥️</span>
                        <span class="detail-text">${deviceName || 'Unknown Device'}</span>
                    </div>
                    <div class="detail-row">
                        <span class="detail-icon">🌐</span>
                        <span class="detail-text">${ipAddress || 'Unknown IP'}</span>
                    </div>
                </div>
                <p class="ava-modal-warning">This will immediately log them out.</p>
            `,
            confirmText: 'Revoke Session',
            confirmClass: 'btn-danger',
            onConfirm,
            onCancel
        });
    }

    /**
     * Bulk Action Confirmation
     */
    function confirmBulk(options) {
        const { action, count, onConfirm, onCancel } = options;

        return confirm({
            title: `Bulk ${action}`,
            icon: 'warning',
            message: `
                <p>You are about to <strong>${action.toLowerCase()}</strong> 
                <strong>${count}</strong> item${count !== 1 ? 's' : ''}.</p>
                <p class="ava-modal-warning">This action cannot be undone.</p>
            `,
            confirmText: `${action} ${count} Items`,
            confirmClass: action.toLowerCase().includes('delete') || action.toLowerCase().includes('revoke')
                ? 'btn-danger' : 'btn-primary',
            onConfirm,
            onCancel
        });
    }

    return {
        confirm,
        alert,
        confirmDelete,
        confirmRevoke,
        confirmBulk,
        close
    };
})();

// Also expose as window.Modal for convenience
window.Modal = AVAGuardModal;
