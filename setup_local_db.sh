#!/bin/bash

echo "========================================="
echo "ZEUSCHAT LOCAL DATABASE SETUP"
echo "========================================="

# Database file location
DB_FILE="zeuschat_local.db"

# Remove existing database if it exists
if [ -f "$DB_FILE" ]; then
    echo "Removing existing database..."
    rm -f "$DB_FILE"
fi

echo "Creating fresh database at: $DB_FILE"
echo ""

# Create tables and insert admin user
sqlite3 "$DB_FILE" << 'SQL_END'

-- USERS TABLE
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    zeus_pin TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    is_admin INTEGER DEFAULT 0,
    is_verified INTEGER DEFAULT 0,
    full_name TEXT,
    email TEXT,
    phone TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    is_active INTEGER DEFAULT 1
);

-- ADMIN USERS TABLE
CREATE TABLE admin_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL DEFAULT 'moderator',
    permissions TEXT,
    last_login TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- USER APPROVALS TABLE
CREATE TABLE user_approvals (
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

-- KYC DOCUMENTS TABLE
CREATE TABLE kyc_documents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    id_document_path TEXT NOT NULL,
    selfie_path TEXT NOT NULL,
    document_type TEXT NOT NULL,
    face_match_score REAL,
    auto_verified INTEGER DEFAULT 0,
    admin_review_status TEXT DEFAULT 'pending',
    admin_review_notes TEXT,
    reviewed_by INTEGER,
    reviewed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- ADMIN MESSAGES TABLE
CREATE TABLE admin_messages (
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

-- SUBSCRIPTIONS TABLE
CREATE TABLE subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    tier TEXT NOT NULL DEFAULT 'free',
    status TEXT NOT NULL DEFAULT 'active',
    current_period_start TIMESTAMP,
    current_period_end TIMESTAMP,
    cancelled_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- ONE OFF PAYMENTS TABLE
CREATE TABLE one_off_payments (
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
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- USER UNLOCKS TABLE
CREATE TABLE user_unlocks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    feature_name TEXT NOT NULL,
    unlock_type TEXT NOT NULL,
    payment_id INTEGER,
    expires_at TIMESTAMP,
    granted_by INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (payment_id) REFERENCES one_off_payments(id)
);

-- PROFILE PICTURE LOCKS TABLE
CREATE TABLE profile_picture_locks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    is_locked INTEGER DEFAULT 1,
    remaining_changes INTEGER DEFAULT 0,
    subscription_tier TEXT DEFAULT 'free',
    last_change_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- SUBSCRIPTION FEATURES TABLE
CREATE TABLE subscription_features (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tier TEXT NOT NULL,
    feature_name TEXT NOT NULL,
    is_enabled INTEGER DEFAULT 1,
    UNIQUE(tier, feature_name)
);

-- USER FEEDBACK TABLE
CREATE TABLE user_feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    feedback_type TEXT NOT NULL,
    message TEXT NOT NULL,
    contact_email TEXT,
    status TEXT DEFAULT 'pending',
    admin_notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    resolved_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- PUSH SUBSCRIPTIONS TABLE
CREATE TABLE push_subscriptions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    endpoint TEXT NOT NULL UNIQUE,
    keys_auth TEXT NOT NULL,
    keys_p256dh TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- ADMIN AUDIT LOG TABLE
CREATE TABLE admin_audit_log (
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

-- GHOST COMMUNITY POSTS TABLE
CREATE TABLE ghost_posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    zeus_pin TEXT NOT NULL,
    content_type TEXT NOT NULL,
    media_url TEXT,
    text_content TEXT,
    hashtags TEXT,
    is_paid INTEGER DEFAULT 0,
    price REAL,
    status TEXT DEFAULT 'pending',
    likes_count INTEGER DEFAULT 0,
    comments_count INTEGER DEFAULT 0,
    shares_count INTEGER DEFAULT 0,
    views_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP DEFAULT (datetime('now', '+24 hours')),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- GHOST MARKET LISTINGS TABLE
CREATE TABLE ghost_listings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    seller_id INTEGER NOT NULL,
    zeus_pin TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    price REAL NOT NULL,
    currency TEXT DEFAULT 'ZT',
    condition TEXT DEFAULT 'used',
    category TEXT,
    location TEXT,
    images TEXT,
    status TEXT DEFAULT 'pending',
    views_count INTEGER DEFAULT 0,
    saves_count INTEGER DEFAULT 0,
    messages_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (seller_id) REFERENCES users(id)
);

-- GHOST LIKES TABLE
CREATE TABLE ghost_likes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES ghost_posts(id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    UNIQUE(post_id, user_id)
);

-- GHOST COMMENTS TABLE
CREATE TABLE ghost_comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    zeus_pin TEXT NOT NULL,
    comment_text TEXT NOT NULL,
    likes_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES ghost_posts(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- GHOST FOLLOWS TABLE
CREATE TABLE ghost_follows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    follower_id INTEGER NOT NULL,
    following_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (follower_id) REFERENCES users(id),
    FOREIGN KEY (following_id) REFERENCES users(id),
    UNIQUE(follower_id, following_id)
);

-- GHOST HASHTAGS TABLE
CREATE TABLE ghost_hashtags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    post_count INTEGER DEFAULT 0,
    view_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- INSERT DEFAULT SUBSCRIPTION FEATURES
INSERT OR IGNORE INTO subscription_features (tier, feature_name, is_enabled) VALUES
    ('free', 'basic_messaging', 1),
    ('free', 'ghost_community_view', 1),
    ('free', 'ghost_market_view', 1),
    ('premium', 'unlimited_wallpapers', 1),
    ('premium', 'custom_theme', 1),
    ('premium', 'advanced_analytics', 1),
    ('premium', 'priority_support', 1);

-- INSERT ADMIN USER INTO USERS TABLE
INSERT OR REPLACE INTO users (zeus_pin, password, is_admin, is_verified, full_name, email)
VALUES ('superadmin', 'ZeusAdmin2026Secure!', 1, 1, 'Super Administrator', 'admin@zeustechafrica.com');

-- INSERT ADMIN USER INTO ADMIN_USERS TABLE
INSERT OR REPLACE INTO admin_users (username, password_hash, email, role)
VALUES ('superadmin', 'ZeusAdmin2026Secure!', 'admin@zeustechafrica.com', 'super_admin');

-- VERIFY
SELECT '✅ Admin user created: superadmin / ZeusAdmin2026Secure!' as status;
SELECT '✅ Total tables created: ' || (SELECT COUNT(*) FROM sqlite_master WHERE type='table') as info;

SQL_END

echo ""
echo "========================================="
echo "DATABASE SETUP COMPLETE"
echo "========================================="
echo ""
echo "📁 Database: $DB_FILE"
echo ""
echo "👤 Admin Credentials:"
echo "   Username: superadmin"
echo "   Password: ZeusAdmin2026Secure!"
echo ""
echo "========================================="
echo "NEXT STEPS:"
echo "1. Start your server: python3 app.py"
echo "2. Go to: http://localhost:5000/admin_control"
echo "3. Login with credentials above"
echo "========================================="
