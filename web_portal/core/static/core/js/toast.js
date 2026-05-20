/**
 * AVAGuard - Toast Notification System (Enhanced)
 *
 * Non-blocking notifications with:
 *  - Animated countdown timer bar
 *  - ARIA live region & keyboard dismiss (Escape)
 *  - Stacked multi-toast support (newest on top)
 *  - Duplicate-message suppression within 2 s window
 */

const AVAGuardToast = (function () {
    'use strict';

    let container = null;
    const recentMessages = new Map(); // message → timestamp (dedup window)

    function init() {
        if (container) return;

        container = document.createElement('div');
        container.id = 'ava-toast-container';
        container.className = 'ava-toast-container';
        container.setAttribute('role', 'status');
        container.setAttribute('aria-live', 'polite');
        container.setAttribute('aria-atomic', 'false');
        document.body.appendChild(container);

        // Global keyboard handler — Escape dismisses the newest toast
        document.addEventListener('keydown', function (e) {
            if (e.key === 'Escape' && container && container.lastElementChild) {
                dismiss(container.lastElementChild);
            }
        });
    }

    /**
     * Show toast notification
     * @param {string} message  - Message to display
     * @param {string} type     - 'success' | 'error' | 'warning' | 'info'
     * @param {number} duration - Auto-dismiss in ms (default 5000, 0 = sticky)
     */
    function show(message, type, duration) {
        type = type || 'info';
        duration = (typeof duration === 'number') ? duration : 5000;

        init();

        // ── Duplicate suppression (2 s window) ──
        var now = Date.now();
        var dedupKey = type + ':' + message;
        if (recentMessages.has(dedupKey) && now - recentMessages.get(dedupKey) < 2000) {
            return null; // silently drop duplicate
        }
        recentMessages.set(dedupKey, now);
        // Prune old entries
        recentMessages.forEach(function (ts, k) {
            if (now - ts > 5000) recentMessages.delete(k);
        });

        var icons = {
            success: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">' +
                '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/>' +
                '<polyline points="22 4 12 14.01 9 11.01"/></svg>',
            error: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">' +
                '<circle cx="12" cy="12" r="10"/><path d="m15 9-6 6"/><path d="m9 9 6 6"/></svg>',
            warning: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">' +
                '<path d="m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3Z"/>' +
                '<path d="M12 9v4"/><path d="M12 17h.01"/></svg>',
            info: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">' +
                '<circle cx="12" cy="12" r="10"/><path d="M12 16v-4"/><path d="M12 8h.01"/></svg>'
        };

        var toast = document.createElement('div');
        toast.className = 'ava-toast ava-toast-' + type;
        toast.setAttribute('role', 'alert');
        toast.setAttribute('tabindex', '-1');

        // Build inner HTML — icon, message, close, timer bar
        toast.innerHTML =
            '<div class="ava-toast-icon">' + (icons[type] || icons.info) + '</div>' +
            '<div class="ava-toast-message">' + message + '</div>' +
            '<button class="ava-toast-close" aria-label="Dismiss">&times;</button>' +
            (duration > 0
                ? '<div class="ava-toast-timer"><div class="ava-toast-timer-bar" style="animation-duration:' + duration + 'ms"></div></div>'
                : '');

        // Insert at end (CSS flex-direction: column-reverse puts newest on bottom visually → we use column so newest is at bottom of DOM but renders at bottom of screen)
        container.appendChild(toast);

        // Trigger slide-in animation
        requestAnimationFrame(function () {
            toast.classList.add('visible');
        });

        // Close button
        toast.querySelector('.ava-toast-close').onclick = function () { dismiss(toast); };

        // Auto dismiss
        if (duration > 0) {
            setTimeout(function () { dismiss(toast); }, duration);
        }

        return toast;
    }

    function dismiss(toast) {
        if (!toast || toast._dismissing) return;
        toast._dismissing = true;
        toast.classList.remove('visible');
        toast.classList.add('hiding');
        setTimeout(function () {
            if (toast.parentNode) {
                toast.parentNode.removeChild(toast);
            }
        }, 300);
    }

    // Convenience methods
    function success(message, duration) { return show(message, 'success', duration); }
    function error(message, duration) { return show(message, 'error', duration); }
    function warning(message, duration) { return show(message, 'warning', duration); }
    function info(message, duration) { return show(message, 'info', duration); }

    return { show: show, success: success, error: error, warning: warning, info: info };
})();

// Expose globally
window.Toast = AVAGuardToast;
console.log('[AVAGuard] Toast system initialized.');
