-- ============================================
-- ZEUSCHAT ADMIN CONTROL ROOM MIGRATION
-- Non-breaking migration: adds tables and indexes only.
-- ============================================

CREATE TABLE IF NOT EXISTS user_approvals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL UNIQUE,
  status TEXT NOT NULL DEFAULT 'pending',
  reviewed_by INTEGER,
  reviewed_at TIMESTAMP,
  rejection_reason TEXT,
  notes TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS admin_users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  email TEXT UNIQUE NOT NULL,
  role TEXT NOT NULL DEFAULT 'moderator',
  permissions TEXT,
  last_login TIMESTAMP,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS admin_messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  admin_id INTEGER,
  message TEXT NOT NULL,
  is_from_admin INTEGER DEFAULT 0,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  read_at TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (admin_id) REFERENCES admin_users(id)
);

CREATE TABLE IF NOT EXISTS one_off_payments (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  payment_type TEXT NOT NULL,
  amount REAL NOT NULL,
  currency TEXT DEFAULT 'ZAR',
  payfast_payment_id TEXT,
  payfast_token TEXT,
  status TEXT NOT NULL DEFAULT 'pending_approval',
  approved_by INTEGER,
  approved_at TIMESTAMP,
  rejection_reason TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (approved_by) REFERENCES admin_users(id)
);

CREATE TABLE IF NOT EXISTS user_unlocks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL,
  feature_name TEXT NOT NULL,
  unlock_type TEXT NOT NULL,
  payment_id INTEGER,
  expires_at TIMESTAMP,
  granted_by INTEGER,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id),
  FOREIGN KEY (payment_id) REFERENCES one_off_payments(id),
  FOREIGN KEY (granted_by) REFERENCES admin_users(id),
  UNIQUE(user_id, feature_name)
);

CREATE TABLE IF NOT EXISTS admin_audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_id INTEGER,
  action TEXT NOT NULL,
  target_user_id INTEGER,
  target_payment_id INTEGER,
  details TEXT,
  ip_address TEXT,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (admin_id) REFERENCES admin_users(id)
);

CREATE INDEX IF NOT EXISTS idx_user_approvals_status ON user_approvals(status);
CREATE INDEX IF NOT EXISTS idx_user_approvals_user_id ON user_approvals(user_id);
CREATE INDEX IF NOT EXISTS idx_admin_messages_user_id ON admin_messages(user_id);
CREATE INDEX IF NOT EXISTS idx_one_off_payments_status ON one_off_payments(status);
CREATE INDEX IF NOT EXISTS idx_user_unlocks_user_id ON user_unlocks(user_id);
CREATE INDEX IF NOT EXISTS idx_admin_audit_log_created_at ON admin_audit_log(created_at);

INSERT OR IGNORE INTO user_approvals (user_id, status, reviewed_at)
SELECT id, 'approved', CURRENT_TIMESTAMP FROM users;
