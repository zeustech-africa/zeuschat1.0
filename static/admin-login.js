(function () {
  const form = document.getElementById('admin-login-form');
  const errorBox = document.getElementById('login-error');

  if (!form) return;

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    errorBox.textContent = '';
    errorBox.style.display = 'none';

    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;

    try {
      const response = await fetch('/admin/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      });
      const data = await response.json();
      if (response.ok && data.success) {
        window.location.href = '/admin/dashboard';
        return;
      }
      errorBox.textContent = data.error || 'Login failed';
      errorBox.style.display = 'block';
    } catch (_err) {
      errorBox.textContent = 'Network error. Please retry.';
      errorBox.style.display = 'block';
    }
  });
})();
