/**
 * AVAGuard — Dashboard Index Logic
 * Template: dashboard/index.html
 * =========================================================
 */

document.addEventListener('DOMContentLoaded', function () {
    if (!window.AVA) return;
    
    // Data from Django template via bridge
    var trendLabels = AVAGuardCharts.parseJSON(window.AVA.trendLabels, ["Week 1", "Week 2", "Week 3", "Week 4"]);
    var trendData = AVAGuardCharts.parseJSON(window.AVA.trendData, [75, 78, 82, 85]);
    var statsPassed = Number(window.AVA.statsPassed || 70);
    var statsFailed = Number(window.AVA.statsFailed || 20);
    var statsWarning = Number(window.AVA.statsWarning || 10);

    // Initialize charts using library functions
    AVAGuardCharts.initTrendChart('trendChart', trendLabels, trendData);
    AVAGuardCharts.initStatusChart('statusChart', statsPassed, statsFailed, statsWarning);

    // Apply data-width to progress bars
    document.querySelectorAll('.score-bar-fill').forEach(function(bar) {
        var w = bar.getAttribute('data-width');
        if (w) bar.style.width = w + '%';
    });
});
