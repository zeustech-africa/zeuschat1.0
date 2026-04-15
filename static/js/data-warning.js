// Data usage warning for mobile users
(function() {
  function isMeteredConnection() {
    if (!navigator.connection) return false;
    const conn = navigator.connection;
    return conn.saveData === true ||
      conn.type === 'cellular' ||
      (conn.effectiveType && (conn.effectiveType.indexOf('2g') !== -1 || conn.effectiveType === '3g'));
  }

  function showWarning() {
    if (!isMeteredConnection()) return;
    if (sessionStorage.getItem('dataWarningShown')) return;

    const warning = document.createElement('div');
    warning.id = 'data-warning';
    warning.innerHTML =
      '<span>You are on a limited network. Video quality was adjusted to save data.</span>' +
      '<button id="close-data-warning" aria-label="Dismiss data warning">x</button>';

    Object.assign(warning.style, {
      position: 'fixed',
      bottom: '20px',
      left: '20px',
      right: '20px',
      background: '#FF9800',
      color: '#FFFFFF',
      padding: '12px 16px',
      borderRadius: '12px',
      zIndex: '10000',
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center',
      fontSize: '14px',
      gap: '12px'
    });

    document.body.appendChild(warning);

    const closeButton = document.getElementById('close-data-warning');
    if (closeButton) {
      Object.assign(closeButton.style, {
        border: 'none',
        background: 'transparent',
        color: '#FFFFFF',
        fontSize: '16px',
        cursor: 'pointer',
        lineHeight: '1'
      });
      closeButton.onclick = function() {
        warning.remove();
      };
    }

    sessionStorage.setItem('dataWarningShown', 'true');
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', showWarning);
  } else {
    showWarning();
  }
})();
