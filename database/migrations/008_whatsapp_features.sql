-- ============================================
-- WHATSAPP FEATURES FOR ZEUSCHAT
-- Migration 008: Priority 1, 2, and 3 Features
-- SQLite-compatible (no UUID, no ARRAY, no INTERVAL)
-- ============================================

-- ============================================
-- 1. MESSAGE FEATURES
-- ============================================

-- Starred messages
CREATE TABLE IF NOT EXISTS starred_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    chat_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(message_id, user_id)
);

-- Pinned messages (per chat)
CREATE TABLE IF NOT EXISTS pinned_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER NOT NULL,
    chat_id INTEGER NOT NULL,
    pinned_by INTEGER NOT NULL,
    pinned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (pinned_by) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(chat_id, message_id)
);

-- Message reactions (emoji reactions)
CREATE TABLE IF NOT EXISTS message_reactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    reaction_emoji TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(message_id, user_id)
);

-- ============================================
-- 2. BUSINESS TOOLS
-- ============================================

-- Quick replies templates
CREATE TABLE IF NOT EXISTS quick_replies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    shortcut TEXT,
    category TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Away messages
CREATE TABLE IF NOT EXISTS away_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    is_enabled INTEGER DEFAULT 0,
    message TEXT NOT NULL,
    start_time TEXT,
    end_time TEXT,
    days_of_week TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Greeting messages
CREATE TABLE IF NOT EXISTS greeting_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    is_enabled INTEGER DEFAULT 0,
    message TEXT NOT NULL,
    send_to_new_chats_only INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Labels for chats
CREATE TABLE IF NOT EXISTS chat_labels (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    color TEXT DEFAULT '#667781',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, name)
);

CREATE TABLE IF NOT EXISTS chat_label_assignments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id INTEGER NOT NULL,
    label_id INTEGER NOT NULL,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (label_id) REFERENCES chat_labels(id) ON DELETE CASCADE,
    UNIQUE(chat_id, label_id)
);

-- ============================================
-- 3. STATISTICS DASHBOARD
-- ============================================

CREATE TABLE IF NOT EXISTS message_stats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    date TEXT DEFAULT (date('now')),
    messages_sent INTEGER DEFAULT 0,
    messages_received INTEGER DEFAULT 0,
    messages_delivered INTEGER DEFAULT 0,
    messages_read INTEGER DEFAULT 0,
    response_time_seconds INTEGER DEFAULT 0,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(user_id, date)
);

-- ============================================
-- 4. READ RECEIPTS TOGGLE
-- ============================================

ALTER TABLE users ADD COLUMN read_receipts_enabled INTEGER DEFAULT 1;

-- ============================================
-- 5. CHAT WALLPAPERS
-- ============================================

CREATE TABLE IF NOT EXISTS user_wallpapers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    wallpaper_url TEXT,
    wallpaper_type TEXT DEFAULT 'solid',
    wallpaper_color TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS chat_wallpapers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    wallpaper_url TEXT,
    wallpaper_type TEXT DEFAULT 'solid',
    wallpaper_color TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(chat_id, user_id)
);

CREATE TABLE IF NOT EXISTS wallpaper_change_usage (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    change_count INTEGER DEFAULT 0,
    last_changed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ============================================
-- 6. AUTO-DOWNLOAD RULES
-- ============================================

ALTER TABLE users ADD COLUMN auto_download_photos TEXT DEFAULT 'wifi';
ALTER TABLE users ADD COLUMN auto_download_videos TEXT DEFAULT 'never';
ALTER TABLE users ADD COLUMN auto_download_documents TEXT DEFAULT 'wifi';
ALTER TABLE users ADD COLUMN low_data_mode INTEGER DEFAULT 0;

-- ============================================
-- 7. THEMES
-- ============================================

ALTER TABLE users ADD COLUMN theme_preference TEXT DEFAULT 'light';
ALTER TABLE users ADD COLUMN font_scale REAL DEFAULT 1.0;

-- ============================================
-- 8. CUSTOM NOTIFICATION TONES
-- ============================================

ALTER TABLE users ADD COLUMN notification_tone TEXT DEFAULT 'default';
ALTER TABLE users ADD COLUMN group_notification_tone TEXT DEFAULT 'default';

-- ============================================
-- 9. TWO-STEP VERIFICATION
-- ============================================

ALTER TABLE users ADD COLUMN two_step_verified INTEGER DEFAULT 0;
ALTER TABLE users ADD COLUMN two_step_pin TEXT;
ALTER TABLE users ADD COLUMN two_step_email TEXT;
ALTER TABLE users ADD COLUMN two_step_verified_at TIMESTAMP;

-- ============================================
-- 10. ENCRYPTED BACKUPS
-- ============================================

CREATE TABLE IF NOT EXISTS encrypted_backups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    backup_url TEXT NOT NULL,
    backup_key TEXT NOT NULL,
    backup_size INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP DEFAULT (datetime('now', '+30 days')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ============================================
-- 11. BROADCAST LISTS
-- ============================================

CREATE TABLE IF NOT EXISTS broadcast_lists (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    recipient_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS broadcast_list_recipients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    broadcast_list_id INTEGER NOT NULL,
    contact_id INTEGER NOT NULL,
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (broadcast_list_id) REFERENCES broadcast_lists(id) ON DELETE CASCADE,
    FOREIGN KEY (contact_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(broadcast_list_id, contact_id)
);

-- ============================================
-- 12. GROUP ANNOUNCEMENTS
-- ============================================

ALTER TABLE groups ADD COLUMN announcements_enabled INTEGER DEFAULT 0;
ALTER TABLE groups ADD COLUMN only_admins_can_send INTEGER DEFAULT 0;

CREATE TABLE IF NOT EXISTS group_announcements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER NOT NULL,
    admin_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    sent_to_all INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (admin_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ============================================
-- 13. GIF & STICKER SUPPORT
-- ============================================

CREATE TABLE IF NOT EXISTS favorite_gifs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    gif_url TEXT NOT NULL,
    gif_id TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS favorite_stickers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    sticker_url TEXT NOT NULL,
    sticker_pack_id TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- ============================================
-- INDEXES FOR PERFORMANCE
-- ============================================

CREATE INDEX IF NOT EXISTS idx_starred_messages_user_id ON starred_messages(user_id);
CREATE INDEX IF NOT EXISTS idx_starred_messages_chat_id ON starred_messages(chat_id);
CREATE INDEX IF NOT EXISTS idx_pinned_messages_chat_id ON pinned_messages(chat_id);
CREATE INDEX IF NOT EXISTS idx_message_reactions_message_id ON message_reactions(message_id);
CREATE INDEX IF NOT EXISTS idx_quick_replies_user_id ON quick_replies(user_id);
CREATE INDEX IF NOT EXISTS idx_chat_labels_user_id ON chat_labels(user_id);
CREATE INDEX IF NOT EXISTS idx_chat_label_assignments_chat_id ON chat_label_assignments(chat_id);
CREATE INDEX IF NOT EXISTS idx_message_stats_user_id_date ON message_stats(user_id, date);
CREATE INDEX IF NOT EXISTS idx_broadcast_lists_user_id ON broadcast_lists(user_id);
CREATE INDEX IF NOT EXISTS idx_encrypted_backups_user_id ON encrypted_backups(user_id);
CREATE INDEX IF NOT EXISTS idx_favorite_gifs_user_id ON favorite_gifs(user_id);
CREATE INDEX IF NOT EXISTS idx_favorite_stickers_user_id ON favorite_stickers(user_id);
