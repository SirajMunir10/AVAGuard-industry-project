/**
 * AVAGuard — User Intelligence Page Logic
 * Template: admin/user_sessions_detail.html
 */

(function () {
    'use strict';

    // ── Tab Switching ─────────────────────────────────────────────────────
    function switchTab(tabId) {
        document.querySelectorAll('.intel-tab').forEach(t => t.classList.remove('active'));
        document.querySelectorAll('.intel-panel').forEach(p => p.classList.remove('active'));

        const btn = document.querySelector(`.intel-tab[data-tab="${tabId}"]`);
        const panel = document.getElementById(`panel-${tabId}`);
        if (btn) btn.classList.add('active');
        if (panel) panel.classList.add('active');

        // Persist in URL without reload
        try {
            const url = new URL(window.location.href);
            url.searchParams.set('tab', tabId);
            window.history.replaceState(null, '', url.toString());
        } catch (_) {}
    }

    // Restore tab from URL on load
    function restoreTab() {
        try {
            const params = new URLSearchParams(window.location.search);
            const tab = params.get('tab');
            if (tab && document.getElementById(`panel-${tab}`)) {
                switchTab(tab);
                return;
            }
        } catch (_) {}
        // Default to first tab
        const first = document.querySelector('.intel-tab');
        if (first) switchTab(first.dataset.tab);
    }

    // ── Action Badge Classifier ───────────────────────────────────────────
    function classifyAction(action) {
        if (!action) return 'info';
        const a = action.toUpperCase();
        if (a.includes('FAIL') || a.includes('LOCK') || a.includes('REVOKE')) return 'fail';
        if (a.includes('WARN') || a.includes('BYPASS') || a.includes('STALE')) return 'warn';
        if (a.includes('LOGIN') || a.includes('CREATED') || a.includes('AUTHORIZ') || a.includes('SETUP')) return 'success';
        return 'info';
    }

    // ── Audit event class classifier ─────────────────────────────────────
    function classifyEvent(action) {
        if (!action) return '';
        const a = action.toUpperCase();
        if (a.includes('FAIL') || a.includes('LOCK') || a.includes('REVOKE')) return 'failed';
        if (a.includes('WARN') || a.includes('BYPASS')) return 'warning';
        return '';
    }

    // ── Expose globally for inline onclick handlers ───────────────────────
    window.IntelPage = {
        switchTab,
        classifyAction,
        classifyEvent,
    };

    // ── Init ──────────────────────────────────────────────────────────────
    document.addEventListener('DOMContentLoaded', function () {
        restoreTab();

        // Decorate action badges in the audit table
        document.querySelectorAll('[data-action-badge]').forEach(el => {
            const cls = classifyAction(el.dataset.actionBadge);
            el.classList.add('action-badge', cls);
        });

        // Decorate audit timeline events
        document.querySelectorAll('[data-audit-event]').forEach(el => {
            const cls = classifyEvent(el.dataset.auditEvent);
            if (cls) el.classList.add(cls);
        });
    });
}());
