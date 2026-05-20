/**
 * AVAGuard — IT Dashboard Logic
 * Template: dashboard/it.html
 * =========================================================
 */

document.addEventListener('DOMContentLoaded', function () {
    if (!window.AVA) return;
    
    var chartLabels = window.AVA.chartLabels ? JSON.parse(window.AVA.chartLabels) : [];
    var chartData = window.AVA.chartData ? JSON.parse(window.AVA.chartData) : [];
    var ctx = document.getElementById('complianceChart');
    if (ctx && typeof Chart !== 'undefined') {
        new Chart(ctx.getContext('2d'), {
            type: 'line',
            data: {
                labels: chartLabels,
                datasets: [{
                    label: 'Compliance Score',
                    data: chartData,
                    borderColor: '#00d4ff',
                    backgroundColor: 'rgba(0, 212, 255, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4,
                    pointRadius: 0,
                    pointHoverRadius: 6,
                    pointHoverBackgroundColor: '#00d4ff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: {
                        grid: { color: 'rgba(42, 42, 74, 0.3)' },
                        ticks: { color: '#888', maxTicksLimit: 7 }
                    },
                    y: {
                        min: 0, max: 100,
                        grid: { color: 'rgba(42, 42, 74, 0.3)' },
                        ticks: { color: '#888', callback: function(v) { return v + '%'; } }
                    }
                }
            }
        });
    }

    // Apply data-width to progress bars
    document.querySelectorAll('.score-bar-fill').forEach(function(bar) {
        var w = bar.getAttribute('data-width');
        if (w) bar.style.width = w + '%';
    });
});
