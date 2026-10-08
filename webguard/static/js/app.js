/**
 * WeeShark - Client-Side App Logic (app.js)
 */

document.addEventListener('DOMContentLoaded', () => {
    // Auto-fade flash alerts after 6 seconds
    const alerts = document.querySelectorAll('.alert-box');
    alerts.forEach(alert => {
        setTimeout(() => {
            alert.style.transition = 'opacity 0.4s ease';
            alert.style.opacity = '0';
            setTimeout(() => alert.remove(), 400);
        }, 6000);
    });
});
