-- Create users table if it doesn't exist
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    zeus_pin TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0,
    is_verified INTEGER DEFAULT 0,
    full_name TEXT,
    email TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Delete existing superadmin to avoid conflicts
DELETE FROM users WHERE zeus_pin = 'superadmin';

-- Insert new admin user
INSERT INTO users (zeus_pin, password, is_admin, is_verified, full_name, email)
VALUES ('superadmin', 'admin123', 1, 1, 'Super Administrator', 'admin@zeuschat.com');

-- Also add alternate admin credentials
INSERT OR IGNORE INTO users (zeus_pin, password, is_admin, is_verified, full_name)
VALUES ('admin', 'admin123', 1, 1, 'Admin User');

-- Make sure any existing user can become admin
UPDATE users SET is_admin = 1 WHERE zeus_pin = 'superadmin' OR zeus_pin = 'admin';
