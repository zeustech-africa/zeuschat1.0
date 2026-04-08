CREATE TABLE IF NOT EXISTS ghost_posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    content TEXT,
    media_url TEXT,
    media_type TEXT,
    is_paid INTEGER DEFAULT 0,
    price REAL DEFAULT 0,
    preview_text TEXT,
    status TEXT DEFAULT 'pending_ai',
    ai_approved INTEGER DEFAULT 0,
    ai_confidence REAL,
    ai_flags TEXT,
    upvotes INTEGER DEFAULT 0,
    downvotes INTEGER DEFAULT 0,
    comment_count INTEGER DEFAULT 0,
    view_count INTEGER DEFAULT 0,
    paid_view_count INTEGER DEFAULT 0,
    total_earnings REAL DEFAULT 0,
    report_count INTEGER DEFAULT 0,
    is_flagged INTEGER DEFAULT 0,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS ghost_purchases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    buyer_id INTEGER NOT NULL,
    amount_paid REAL NOT NULL,
    creator_earnings REAL NOT NULL,
    zeuschat_commission REAL NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES ghost_posts(id),
    FOREIGN KEY (buyer_id) REFERENCES users(id),
    UNIQUE(post_id, buyer_id)
);

CREATE TABLE IF NOT EXISTS ghost_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    reporter_id INTEGER NOT NULL,
    reason TEXT NOT NULL,
    details TEXT,
    status TEXT DEFAULT 'pending',
    resolved_by INTEGER,
    resolved_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES ghost_posts(id),
    FOREIGN KEY (reporter_id) REFERENCES users(id),
    FOREIGN KEY (resolved_by) REFERENCES admin_users(id)
);

CREATE TABLE IF NOT EXISTS creator_wallets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    balance REAL DEFAULT 0,
    total_earned REAL DEFAULT 0,
    total_withdrawn REAL DEFAULT 0,
    pending_payout REAL DEFAULT 0,
    last_withdrawal TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS creator_earnings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    week_start DATE NOT NULL,
    week_end DATE NOT NULL,
    total_revenue REAL DEFAULT 0,
    zeuschat_commission REAL DEFAULT 0,
    creator_payout REAL DEFAULT 0,
    is_paid INTEGER DEFAULT 0,
    paid_at TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    UNIQUE(user_id, week_start, week_end)
);

CREATE TABLE IF NOT EXISTS moderation_queue (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    content_text TEXT,
    media_url TEXT,
    ai_score REAL,
    ai_flags TEXT,
    status TEXT DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES ghost_posts(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS ghost_comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    parent_comment_id INTEGER,
    content TEXT NOT NULL,
    upvotes INTEGER DEFAULT 0,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES ghost_posts(id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (parent_comment_id) REFERENCES ghost_comments(id)
);

CREATE TABLE IF NOT EXISTS ghost_votes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER,
    comment_id INTEGER,
    user_id INTEGER NOT NULL,
    vote_type INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES ghost_posts(id),
    FOREIGN KEY (comment_id) REFERENCES ghost_comments(id),
    FOREIGN KEY (user_id) REFERENCES users(id),
    UNIQUE(post_id, user_id),
    UNIQUE(comment_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_ghost_posts_expires ON ghost_posts(expires_at);
CREATE INDEX IF NOT EXISTS idx_ghost_posts_status ON ghost_posts(status);
CREATE INDEX IF NOT EXISTS idx_ghost_posts_created ON ghost_posts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ghost_purchases_buyer ON ghost_purchases(buyer_id);
CREATE INDEX IF NOT EXISTS idx_ghost_reports_status ON ghost_reports(status);
CREATE INDEX IF NOT EXISTS idx_moderation_queue_status ON moderation_queue(status);
CREATE INDEX IF NOT EXISTS idx_ghost_comments_post ON ghost_comments(post_id, created_at ASC);
CREATE INDEX IF NOT EXISTS idx_ghost_votes_post ON ghost_votes(post_id);
