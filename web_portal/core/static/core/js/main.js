/**
 * AVAGuard Main JavaScript
 * Core functionality for sidebar, navigation, and global utilities
 */

(function() {
    'use strict';

    // Constants
    const STORAGE_KEY = 'avaguard_sidebar_collapsed';
    const MOBILE_BREAKPOINT = 991;

    /**
     * Initialize sidebar functionality
     */
    function initSidebar() {
        const sidebar = document.getElementById('sidebar');
        const toggle = document.getElementById('sidebarToggle');

        if (!sidebar || !toggle) return;

        // Load saved state
        const isCollapsed = localStorage.getItem(STORAGE_KEY) === 'true';
        if (isCollapsed) {
            sidebar.classList.add('collapsed');
        }

        // Toggle handler
        toggle.addEventListener('click', function() {
            sidebar.classList.toggle('collapsed');
            const nowCollapsed = sidebar.classList.contains('collapsed');
            localStorage.setItem(STORAGE_KEY, nowCollapsed);
        });

        // Handle responsive collapse
        function handleResize() {
            if (window.innerWidth <= MOBILE_BREAKPOINT) {
                sidebar.classList.add('collapsed');
            }
        }

        // Initial check
        handleResize();
        
        // Listen for resize
        window.addEventListener('resize', handleResize);

        // Mobile Menu Button Logic
        const mobileMenuBtn = document.getElementById('mobileMenuBtn');
        if (mobileMenuBtn) {
            mobileMenuBtn.addEventListener('click', function() {
                sidebar.classList.toggle('mobile-open');
            });
        }
    }

    /**
     * Initialize tooltips for collapsed sidebar
     */
    function initTooltips() {
        const navItems = document.querySelectorAll('.nav-item[data-tooltip]');
        navItems.forEach(function(item) {
            item.addEventListener('mouseenter', function() {
                const sidebar = document.getElementById('sidebar');
                if (sidebar && sidebar.classList.contains('collapsed')) {
                    // Show tooltip
                    const tooltip = this.getAttribute('data-tooltip');
                    this.setAttribute('title', tooltip);
                }
            });
        });
    }

    /**
     * Initialize message auto-dismiss
     */
    function initMessages() {
        const messages = document.querySelectorAll('.message');
        messages.forEach(function(msg) {
            setTimeout(function() {
                msg.style.opacity = '0';
                msg.style.transform = 'translateY(-10px)';
                setTimeout(function() {
                    msg.remove();
                }, 300);
            }, 5000);
        });
    }

    /**
     * Format date utility
     */
    function formatDate(date, format) {
        const d = new Date(date);
        const options = { year: 'numeric', month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' };
        return d.toLocaleDateString('en-US', options);
    }

    /**
     * Debounce utility
     */
    function debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = function() {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }

    /**
     * Toggle custom date inputs visibility
     */
    function toggleCustomDates(select) {
        const container = document.getElementById('customDates');
        if (!container) return;
        
        if (select.value === 'custom') {
            container.style.display = 'flex';
        } else {
            container.style.display = 'none';
            // Auto-submit for non-custom ranges
            select.form.submit();
        }
    }

    /**
     * Initialize everything on DOM ready
     */
    document.addEventListener('DOMContentLoaded', function() {
        initSidebar();
        initTooltips();
        initMessages();
    });

    // Expose utilities globally
    window.AVAGuard = {
        formatDate: formatDate,
        debounce: debounce,
        toggleCustomDates: toggleCustomDates
    };

    // Also expose to global scope for easy access in inline onchange
    window.toggleCustomDates = toggleCustomDates;

})();
