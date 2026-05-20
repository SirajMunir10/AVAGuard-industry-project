/**
 * AVAGuard - Theme Toggle (Light / Dark)
 *
 * CRITICAL: This script MUST be loaded synchronously in <head> BEFORE
 * any stylesheets to prevent a Flash of Wrong Theme (FOWT).
 *
 * It reads localStorage('avag-theme') and applies data-theme to <html>
 * immediately, before the first paint.
 */

(function () {
    'use strict';

    var STORAGE_KEY = 'avag-theme';
    var DEFAULT_THEME = 'dark';

    // ── Apply saved theme SYNCHRONOUSLY (before first paint) ──
    var saved = null;
    try {
        saved = localStorage.getItem(STORAGE_KEY);
    } catch (e) { /* private browsing — ignore */ }

    var theme = (saved === 'light' || saved === 'dark') ? saved : DEFAULT_THEME;
    document.documentElement.setAttribute('data-theme', theme);

    // ── Toggle function (called by the navbar button) ──
    window.AVAToggleTheme = function () {
        var current = document.documentElement.getAttribute('data-theme') || DEFAULT_THEME;
        var next = (current === 'dark') ? 'light' : 'dark';

        document.documentElement.setAttribute('data-theme', next);

        try {
            localStorage.setItem(STORAGE_KEY, next);
        } catch (e) { /* ignore */ }

        // Update toggle button icons
        updateToggleButton(next);

        // Dispatch custom event so Chart.js and other components can re-render
        window.dispatchEvent(new CustomEvent('avag-theme-changed', { detail: { theme: next } }));
    };

    function updateToggleButton(theme) {
        var btn = document.getElementById('avag-theme-toggle');
        if (!btn) return;

        var sunIcon = '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="5"/><line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/><line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/></svg>';
        var moonIcon = '<svg xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>';

        // Sun icon in dark mode (click to go light), Moon icon in light mode (click to go dark)
        btn.innerHTML = (theme === 'dark') ? sunIcon : moonIcon;
        btn.title = (theme === 'dark') ? 'Switch to Light Mode' : 'Switch to Dark Mode';
    }

    // ── Initialize button icon once DOM is ready ──
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function () {
            updateToggleButton(document.documentElement.getAttribute('data-theme') || DEFAULT_THEME);
        });
    } else {
        updateToggleButton(theme);
    }
})();
