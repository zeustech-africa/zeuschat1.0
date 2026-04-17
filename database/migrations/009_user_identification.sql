-- ============================================
-- AUDIT 5: USER IDENTIFICATION + ADMIN ACTIONS
-- SQLite-compatible migration
-- ============================================

CREATE TABLE IF NOT EXISTS user_identification (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    full_name TEXT NOT NULL,
    date_of_birth TEXT,
    id_type TEXT NOT NULL,
    id_number TEXT,
    id_document_front TEXT,
    id_document_back TEXT,
    selfie_with_id TEXT,
    address TEXT,
    phone_number TEXT,
    email TEXT,
    verification_status TEXT DEFAULT 'pending',
    verified_by INTEGER,
    verified_at TIMESTAMP,
    rejection_reason TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (verified_by) REFERENCES admin_users(id)
);

CREATE TABLE IF NOT EXISTS user_full_profile (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    zeus_pin TEXT,
    registration_ip TEXT,
    last_login_ip TEXT,
    device_info TEXT,
    browser_info TEXT,
    account_status TEXT DEFAULT 'active',
    suspended_by INTEGER,
    suspended_at TIMESTAMP,
    suspension_reason TEXT,
    deleted_by INTEGER,
    deleted_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (suspended_by) REFERENCES admin_users(id),
    FOREIGN KEY (deleted_by) REFERENCES admin_users(id)
);

CREATE TABLE IF NOT EXISTS admin_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    admin_id INTEGER,
    action_type TEXT NOT NULL,
    target_user_id INTEGER,
    target_type TEXT,
    target_id INTEGER,
    details TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (admin_id) REFERENCES admin_users(id),
    FOREIGN KEY (target_user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_user_identification_user_id ON user_identification(user_id);
CREATE INDEX IF NOT EXISTS idx_user_identification_verification_status ON user_identification(verification_status);
CREATE INDEX IF NOT EXISTS idx_user_full_profile_user_id ON user_full_profile(user_id);
CREATE INDEX IF NOT EXISTS idx_user_full_profile_zeus_pin ON user_full_profile(zeus_pin);
CREATE INDEX IF NOT EXISTS idx_admin_actions_admin_id ON admin_actions(admin_id);
CREATE INDEX IF NOT EXISTS idx_admin_actions_target_user_id ON admin_actions(target_user_id);
CREATE INDEX IF NOT EXISTS idx_admin_actions_created_at ON admin_actions(created_at);
