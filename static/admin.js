let currentTab = 'overview';
let selectedUser = null;

function qs(id) {
  return document.getElementById(id);
}

function showTab(tabName) {
  currentTab = tabName;
  document.querySelectorAll('[data-tab-target]').forEach((el) => {
    el.classList.toggle('hidden', el.dataset.tabTarget !== tabName);
  });
  document.querySelectorAll('.nav-item').forEach((el) => {
    el.classList.toggle('active', el.dataset.tab === tabName);
  });

  if (tabName === 'users') loadUsers();
  if (tabName === 'payments') loadPayments();
  if (tabName === 'messages') loadMessageUsers();
}

async function authCheck() {
  const response = await fetch('/admin/api/me');
  if (!response.ok) {
    window.location.href = '/admin/login';
    return false;
  }
  const data = await response.json();
  qs('admin-role').textContent = data.admin.role;
  return true;
}

async function loadStats() {
  const response = await fetch('/admin/api/stats');
  if (!response.ok) return;
  const data = await response.json();
  if (!data.success) return;

  qs('stat-pending').textContent = data.stats.pending_approvals;
  qs('stat-active').textContent = data.stats.active_users;
  qs('stat-payments').textContent = data.stats.pending_payments;
  qs('stat-revenue').textContent = `R${Number(data.stats.revenue_today).toFixed(2)}`;

  const rows = data.recent_activities.map((a) => (
    `<tr><td>${a.action}</td><td>${a.admin || '-'}</td><td>${a.target_user || '-'}</td><td>${a.timestamp}</td></tr>`
  )).join('');
  qs('activity-body').innerHTML = rows || '<tr><td colspan="4">No activity</td></tr>';
}

function statusBadge(status) {
  return `<span class="badge ${status}">${status}</span>`;
}

async function loadUsers() {
  const status = qs('filter-status').value;
  const search = encodeURIComponent(qs('filter-search').value.trim());
  const response = await fetch(`/admin/api/users?status=${encodeURIComponent(status)}&search=${search}`);
  if (!response.ok) return;
  const data = await response.json();
  if (!data.success) return;

  const rows = data.users.map((u) => {
    const approveBtn = u.approval_status === 'pending' ? `<button class="btn ok" onclick="approveUser(${u.id})">Approve</button>` : '';
    const rejectBtn = u.approval_status === 'pending' ? `<button class="btn no" onclick="rejectUser(${u.id})">Reject</button>` : '';
    return `<tr>
      <td>${u.zeus_pin}</td>
      <td>${u.full_name}</td>
      <td>${u.email}</td>
      <td>${statusBadge(u.approval_status)}</td>
      <td>${new Date(u.registered_at).toLocaleString()}</td>
      <td>${approveBtn} ${rejectBtn}</td>
    </tr>`;
  }).join('');

  qs('users-body').innerHTML = rows || '<tr><td colspan="6">No users found</td></tr>';
}

async function approveUser(userId) {
  const response = await fetch(`/admin/api/users/${userId}/approve`, { method: 'PUT' });
  if (response.ok) {
    await loadStats();
    await loadUsers();
  }
}

async function rejectUser(userId) {
  const reason = prompt('Rejection reason:');
  if (!reason) return;
  const response = await fetch(`/admin/api/users/${userId}/reject`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ rejection_reason: reason }),
  });
  if (response.ok) {
    await loadStats();
    await loadUsers();
  }
}

async function loadPayments() {
  const response = await fetch('/admin/api/payments/pending');
  if (!response.ok) return;
  const data = await response.json();
  if (!data.success) return;

  const rows = data.payments.map((p) => `
    <tr>
      <td>${p.payment_id}</td>
      <td>${p.user_name} (${p.user_pin})</td>
      <td>${p.payment_type}</td>
      <td>${p.currency} ${p.amount}</td>
      <td>${new Date(p.created_at).toLocaleString()}</td>
      <td>
        <button class="btn ok" onclick="approvePayment(${p.payment_id})">Approve</button>
        <button class="btn no" onclick="rejectPayment(${p.payment_id})">Reject</button>
      </td>
    </tr>
  `).join('');

  qs('payments-body').innerHTML = rows || '<tr><td colspan="6">No pending payments</td></tr>';
}

async function approvePayment(paymentId) {
  const response = await fetch(`/admin/api/payments/${paymentId}/approve`, { method: 'PUT' });
  if (response.ok) {
    await loadStats();
    await loadPayments();
  }
}

async function rejectPayment(paymentId) {
  const reason = prompt('Rejection reason:');
  if (!reason) return;
  const response = await fetch(`/admin/api/payments/${paymentId}/reject`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reason }),
  });
  if (response.ok) {
    await loadStats();
    await loadPayments();
  }
}

async function loadMessageUsers() {
  const response = await fetch('/admin/api/messages/users');
  if (!response.ok) return;
  const data = await response.json();
  if (!data.success) return;

  const html = data.users.map((u) => (`
    <div class="user-item" onclick="selectMessageUser(${u.user_id}, '${String(u.full_name).replace(/'/g, "&#39;")}')">
      <strong>${u.full_name}</strong><br>
      <small>${u.zeus_pin}</small>
      ${u.unread_count ? `<span class="badge pending">${u.unread_count}</span>` : ''}
    </div>
  `)).join('');

  qs('message-users').innerHTML = html || '<div class="user-item">No conversations</div>';
}

async function selectMessageUser(userId, name) {
  selectedUser = { userId, name };
  qs('chat-target').textContent = `Chat with ${name}`;

  const response = await fetch(`/admin/api/messages/${userId}`);
  if (!response.ok) return;
  const data = await response.json();
  if (!data.success) return;

  const rows = data.messages.map((m) => (`
    <div class="msg ${m.is_from_admin ? 'admin' : 'user'}">
      ${m.message}
      <small>${new Date(m.created_at).toLocaleString()}</small>
    </div>
  `)).join('');
  qs('chat-log').innerHTML = rows || '<div>No messages</div>';
  qs('chat-log').scrollTop = qs('chat-log').scrollHeight;
}

async function sendAdminMessage() {
  if (!selectedUser) return;
  const message = qs('chat-input').value.trim();
  if (!message) return;

  const response = await fetch('/admin/api/messages/send', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ user_id: selectedUser.userId, message }),
  });

  if (response.ok) {
    qs('chat-input').value = '';
    await selectMessageUser(selectedUser.userId, selectedUser.name);
  }
}

async function adminLogout() {
  await fetch('/admin/api/logout', { method: 'POST' });
  window.location.href = '/admin/login';
}

window.addEventListener('DOMContentLoaded', async () => {
  const isValid = await authCheck();
  if (!isValid) return;

  document.querySelectorAll('.nav-item').forEach((btn) => {
    btn.addEventListener('click', () => showTab(btn.dataset.tab));
  });
  qs('filter-status').addEventListener('change', loadUsers);
  qs('filter-search').addEventListener('input', () => {
    clearTimeout(window.__userFilterTimer);
    window.__userFilterTimer = setTimeout(loadUsers, 300);
  });
  qs('chat-send').addEventListener('click', sendAdminMessage);
  qs('logout-btn').addEventListener('click', adminLogout);

  await loadStats();
  setInterval(loadStats, 30000);
});
