/**
 * AVAGuard Dashboard JavaScript
 * Chart initialization and dashboard-specific functionality
 */

(function () {
    'use strict';

    /**
     * Get computed CSS variable
     */
    function getCSSVar(name, fallback) {
        var val = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
        return val || fallback;
    }

    /**
     * Default chart configuration (dynamic based on CSS vars)
     */
    function getChartDefaults() {
        return {
            colors: {
                primary: getCSSVar('--avag-accent-primary', '#00d4ff'),
                success: getCSSVar('--avag-accent-success', '#00ff88'),
                warning: getCSSVar('--avag-accent-warning', '#ffd93d'),
                danger: getCSSVar('--avag-accent-danger', '#ff6b6b'),
                grid: getCSSVar('--avag-border-color', 'rgba(255, 255, 255, 0.05)'),
                text: getCSSVar('--avag-text-secondary', '#a0a0c0')
            }
        };
    }

    // Keep track of active chart instances
    const activeCharts = [];

    /**
     * Update all active charts when theme changes
     */
    window.addEventListener('avag-theme-changed', function() {
        const defaults = getChartDefaults();
        activeCharts.forEach(function(chart) {
            // Update grid and text colors for axes
            if (chart.options.scales) {
                if (chart.options.scales.x) {
                    if (chart.options.scales.x.grid) chart.options.scales.x.grid.color = defaults.colors.grid;
                    if (chart.options.scales.x.ticks) chart.options.scales.x.ticks.color = defaults.colors.text;
                }
                if (chart.options.scales.y) {
                    if (chart.options.scales.y.grid) chart.options.scales.y.grid.color = defaults.colors.grid;
                    if (chart.options.scales.y.ticks) chart.options.scales.y.ticks.color = defaults.colors.text;
                }
            }
            // Update legend text color
            if (chart.options.plugins && chart.options.plugins.legend && chart.options.plugins.legend.labels) {
                chart.options.plugins.legend.labels.color = defaults.colors.text;
            }
            chart.update();
        });
    });

    /**
     * Initialize compliance trend chart
     * @param {string} canvasId - Canvas element ID
     * @param {Array} labels - Chart labels
     * @param {Array} data - Chart data
     */
    function initTrendChart(canvasId, labels, data) {
        const ctx = document.getElementById(canvasId);
        if (!ctx) return null;

        // Fallback data
        labels = labels || ["Week 1", "Week 2", "Week 3", "Week 4"];
        data = data || [75, 78, 82, 85];
        
        const defaults = getChartDefaults();

        const chart = new Chart(ctx.getContext('2d'), {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Compliance Score',
                    data: data,
                    borderColor: defaults.colors.primary,
                    backgroundColor: 'rgba(0, 212, 255, 0.1)',
                    fill: true,
                    tension: 0.4,
                    pointRadius: 4,
                    pointBackgroundColor: defaults.colors.primary
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        max: 100,
                        grid: {
                            color: defaults.colors.grid
                        },
                        ticks: {
                            color: defaults.colors.text,
                            callback: function (value) {
                                return value + '%';
                            }
                        }
                    },
                    x: {
                        grid: {
                            display: false
                        },
                        ticks: {
                            color: defaults.colors.text
                        }
                    }
                }
            }
        });
        activeCharts.push(chart);
        return chart;
    }

    /**
     * Initialize status distribution doughnut chart
     * @param {string} canvasId - Canvas element ID
     * @param {number} passed - Passed count
     * @param {number} failed - Failed count
     * @param {number} warning - Warning count
     */
    function initStatusChart(canvasId, passed, failed, warning) {
        const ctx = document.getElementById(canvasId);
        if (!ctx) return null;

        // Fallback data
        passed = passed || 70;
        failed = failed || 20;
        warning = warning || 10;
        
        const defaults = getChartDefaults();

        const chart = new Chart(ctx.getContext('2d'), {
            type: 'doughnut',
            data: {
                labels: ['Passed', 'Failed', 'Warning'],
                datasets: [{
                    data: [passed, failed, warning],
                    backgroundColor: [
                        defaults.colors.success,
                        defaults.colors.danger,
                        defaults.colors.warning
                    ],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '70%',
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: defaults.colors.text,
                            padding: 20,
                            usePointStyle: true
                        }
                    }
                }
            }
        });
        activeCharts.push(chart);
        return chart;
    }

    /**
     * Initialize bar chart for role distribution
     * @param {string} canvasId - Canvas element ID
     * @param {Object} data - Chart data {labels, values}
     */
    function initBarChart(canvasId, data) {
        const ctx = document.getElementById(canvasId);
        if (!ctx) return null;

        data = data || {
            labels: ['Super Admin', 'IT Admin', 'Auditor', 'Viewer'],
            values: [1, 2, 3, 5]
        };
        
        const defaults = getChartDefaults();

        const chart = new Chart(ctx.getContext('2d'), {
            type: 'bar',
            data: {
                labels: data.labels,
                datasets: [{
                    label: 'Users',
                    data: data.values,
                    backgroundColor: defaults.colors.primary,
                    borderRadius: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: {
                            color: defaults.colors.grid
                        },
                        ticks: {
                            color: defaults.colors.text,
                            stepSize: 1
                        }
                    },
                    x: {
                        grid: {
                            display: false
                        },
                        ticks: {
                            color: defaults.colors.text
                        }
                    }
                }
            }
        });
        activeCharts.push(chart);
        return chart;
    }

    /**
     * Parse JSON safely with fallback
     * @param {string} jsonString - JSON string to parse
     * @param {*} fallback - Fallback value
     */
    function parseJSON(jsonString, fallback) {
        try {
            if (jsonString && jsonString !== '') {
                return JSON.parse(jsonString);
            }
        } catch (e) {
            console.log('JSON parse error, using fallback');
        }
        return fallback;
    }

    // Expose chart functions globally
    window.AVAGuardCharts = {
        initTrendChart: initTrendChart,
        initStatusChart: initStatusChart,
        initBarChart: initBarChart,
        parseJSON: parseJSON,
        getDefaults: getChartDefaults,
        activeCharts: activeCharts
    };

})();
