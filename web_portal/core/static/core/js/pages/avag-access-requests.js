/**
 * AVAGuard — Access Requests Logic
 * Template: admin/access_requests.html
 * =========================================================
 */

function approveRequest(reqId) {
    if (confirm('Approve access for 24 hours?')) {
        var form = document.getElementById('approveForm');
        if (form) {
            form.action = '/admin/access-requests/' + reqId + '/approve/';
            form.submit();
        }
    }
}

function denyRequest(reqId) {
    var modal = document.getElementById('denyModal');
    var form = document.getElementById('denyForm');
    if (modal && form) {
        form.action = '/admin/access-requests/' + reqId + '/deny/';
        modal.style.display = 'flex';
        document.body.style.overflow = 'hidden';
    }
}

function closeDenyModal() {
    var modal = document.getElementById('denyModal');
    if (modal) {
        modal.style.display = 'none';
        document.body.style.overflow = '';
    }
}
