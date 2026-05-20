import os

CSS_FILES = {
    'auth.css': '''
/* === RESPONSIVE === */
@media (max-width: 767px) {
    /* Below 768px (mobile) */
    .avag-auth-body { padding: 16px; }
    .avag-auth-card { padding: 30px 24px; width: 100%; max-width: 100%; margin: 0; box-sizing: border-box; }
    .avag-auth-form-actions { flex-direction: column; }
    .avag-auth-btn-secondary { width: 100%; text-align: center; margin-top: 12px; }
    .avag-auth-qr-wrapper img { width: 160px; height: 160px; }
    .avag-auth-logo h1 { font-size: 24px; }
}

@media (min-width: 768px) and (max-width: 1023px) {
    /* 768px to 1024px (tablet) */
    .avag-auth-card { width: 400px; }
}

@media (min-width: 1536px) {
    /* 1536px and above (large screens) */
    .avag-auth-card { transform: scale(1.1); }
}
''',
    
    'main.css': '''
/* === RESPONSIVE === */
@media (max-width: 767px) {
    /* Below 768px (mobile) */
    .app-container { flex-direction: column; }
    .sidebar { width: 100%; height: auto; position: static; transform: none; display: none; }
    .sidebar.mobile-open { display: flex; flex-direction: column; }
    .main-content { margin-left: 0; width: 100%; padding: 16px; padding-top: 70px; }
    
    /* Top navbar stacks or compresses */
    .top-navbar { width: 100%; left: 0; border-radius: 0; padding: 10px 16px; flex-wrap: wrap; }
    .user-profile { margin-left: auto; }
    .search-bar { display: none; /* Hide search on mobile for space */ }
    
    /* Hamburger menu button for mobile */
    .mobile-menu-btn { display: flex; align-items: center; justify-content: center; background: none; border: none; color: var(--avag-text-primary); cursor: pointer; padding: 8px; margin-right: 12px; }
    
    /* Stat grids 1-col */
    .stats-grid, .avag-metrics-grid { grid-template-columns: 1fr; }
    .charts-grid { grid-template-columns: 1fr; }
    
    /* Containers */
    .dashboard-layout { grid-template-columns: 1fr; }
}

@media (min-width: 768px) and (max-width: 1023px) {
    /* 768px to 1024px (tablet) */
    .sidebar { width: var(--sidebar-collapsed-width); }
    .sidebar .logo-text, .sidebar .nav-text { display: none; }
    .main-content { margin-left: var(--sidebar-collapsed-width); width: calc(100% - var(--sidebar-collapsed-width)); padding: 24px; }
    .top-navbar { left: var(--sidebar-collapsed-width); width: calc(100% - var(--sidebar-collapsed-width)); }
    
    .stats-grid, .avag-metrics-grid { grid-template-columns: 1fr 1fr; }
    .dashboard-layout { grid-template-columns: 1fr; }
}

@media (min-width: 1024px) and (max-width: 1279px) {
    /* 1024px to 1280px (small laptop) */
    .stats-grid, .avag-metrics-grid { grid-template-columns: repeat(3, 1fr); }
}

@media (min-width: 1536px) {
    /* 1536px and above (large screens) */
    .main-content { 
        display: flex; 
        flex-direction: column; 
        align-items: center; 
    }
    .main-content > * {
        width: 100%;
        max-width: var(--max-content-width);
    }
}
''',

    'components.css': '''
/* === RESPONSIVE === */
@media (max-width: 767px) {
    /* Below 768px (mobile) */
    .avag-modal-content { width: 100%; max-width: 100%; height: 100%; max-height: 100%; border-radius: 0; padding: 20px; overflow-y: auto; }
    .avag-modal { padding: 0; }
    
    /* Tables convert to horizontal scroll */
    .table-container { overflow-x: auto; -webkit-overflow-scrolling: touch; }
    .data-table { min-width: 600px; }
    
    .avag-grid-half { grid-template-columns: 1fr !important; }
}

@media (min-width: 768px) and (max-width: 1023px) {
    /* 768px to 1024px (tablet) */
    .avag-modal-content { width: 90%; }
    .table-container { overflow-x: auto; }
}
''',

    'pages/avag-dashboard-admin.css': '''
/* === RESPONSIVE === */
@media (max-width: 767px) {
    /* Below 768px (mobile) */
    .avag-dashboard-header { flex-direction: column; align-items: flex-start; gap: 16px; }
    .avag-dashboard-actions { width: 100%; justify-content: space-between; }
    .avag-dashboard-layout { grid-template-columns: 1fr; }
    .avag-metrics-grid { grid-template-columns: 1fr; }
    
    /* Dashboard Tabs */
    .dashboard-tabs { flex-direction: column; gap: 8px; border-bottom: none; }
    .dashboard-tabs button { width: 100%; text-align: left; }
    
    .chart-card { padding: 16px; margin-bottom: 16px; }
}

@media (min-width: 768px) and (max-width: 1023px) {
    /* 768px to 1024px (tablet) */
    .avag-dashboard-layout { grid-template-columns: 1fr; }
    .avag-metrics-grid { grid-template-columns: 1fr 1fr; }
    .dashboard-tabs { overflow-x: auto; white-space: nowrap; padding-bottom: 12px; }
}
''',

    'pages/avag-users.css': '''
/* === RESPONSIVE === */
@media (max-width: 767px) {
    .avag-users-header { flex-direction: column; align-items: flex-start; gap: 16px; }
    .avag-users-actions { width: 100%; justify-content: space-between; flex-wrap: wrap; }
    .avag-users-table-container { overflow-x: auto; }
    .avag-users-table { min-width: 700px; }
}
''',

    'pages/avag-sessions.css': '''
/* === RESPONSIVE === */
@media (max-width: 767px) {
    .avag-sessions-header { flex-direction: column; align-items: flex-start; gap: 16px; }
    .avag-session-list { flex-direction: column; }
    .avag-session-card { width: 100%; }
    .avag-session-header { flex-direction: column; gap: 8px; align-items: flex-start; }
}
''',

    'pages/avag-audit.css': '''
/* === RESPONSIVE === */
@media (max-width: 767px) {
    .avag-audit-header { flex-direction: column; align-items: flex-start; gap: 16px; }
    .avag-audit-filters { flex-direction: column; width: 100%; }
    .avag-search-input, .avag-select { width: 100%; }
    .avag-audit-table-container { overflow-x: auto; }
    .avag-audit-table { min-width: 800px; }
}
'''
}

BASE_DIR = r"c:\AVA\web_portal\core\static\core\css"

for filename, content in CSS_FILES.items():
    filepath = os.path.join(BASE_DIR, filename)
    if os.path.exists(filepath):
        # Clean up existing responsive block if any
        with open(filepath, 'r', encoding='utf-8') as f:
            old_content = f.read()
        
        if "/* ── Responsive ── */" in old_content:
            old_content = old_content.split("/* ── Responsive ── */")[0]
        elif "/* === RESPONSIVE === */" in old_content:
            old_content = old_content.split("/* === RESPONSIVE === */")[0]
            
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(old_content.strip() + "\n\n" + content.strip() + "\n")
        print(f"Updated {filename}")
    else:
        print(f"File not found: {filepath}")

