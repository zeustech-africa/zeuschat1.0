CREATE TABLE IF NOT EXISTS ghost_post_shares (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES ghost_posts(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(post_id, user_id)
);

CREATE TABLE IF NOT EXISTS ghost_post_views (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    post_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES ghost_posts(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(post_id, user_id)
);

CREATE TABLE IF NOT EXISTS ghost_follows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    follower_id INTEGER NOT NULL,
    following_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (follower_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (following_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(follower_id, following_id)
);

ALTER TABLE ghost_posts ADD COLUMN hashtags TEXT;
ALTER TABLE ghost_posts ADD COLUMN media_duration INTEGER;
ALTER TABLE ghost_posts ADD COLUMN updated_at TIMESTAMP;

UPDATE ghost_posts
SET updated_at = COALESCE(updated_at, created_at)
WHERE updated_at IS NULL;

CREATE TABLE IF NOT EXISTS ghost_listing_saves (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    listing_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (listing_id) REFERENCES ghost_market_items(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(listing_id, user_id)
);

CREATE TABLE IF NOT EXISTS ghost_listing_views (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    listing_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (listing_id) REFERENCES ghost_market_items(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(listing_id, user_id)
);

CREATE TABLE IF NOT EXISTS ghost_listing_inquiries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    listing_id INTEGER NOT NULL,
    buyer_id INTEGER NOT NULL,
    seller_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    seller_reply TEXT,
    is_read INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    replied_at TIMESTAMP,
    FOREIGN KEY (listing_id) REFERENCES ghost_market_items(id) ON DELETE CASCADE,
    FOREIGN KEY (buyer_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (seller_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ghost_seller_analytics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    seller_id INTEGER NOT NULL,
    date DATE DEFAULT CURRENT_DATE,
    listing_views INTEGER DEFAULT 0,
    listing_saves INTEGER DEFAULT 0,
    messages_received INTEGER DEFAULT 0,
    items_sold INTEGER DEFAULT 0,
    revenue REAL DEFAULT 0,
    FOREIGN KEY (seller_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(seller_id, date)
);

ALTER TABLE ghost_market_items ADD COLUMN location TEXT;
ALTER TABLE ghost_market_items ADD COLUMN sold_at TIMESTAMP;

CREATE INDEX IF NOT EXISTS idx_ghost_post_shares_post ON ghost_post_shares(post_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ghost_post_views_post ON ghost_post_views(post_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ghost_follows_following ON ghost_follows(following_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ghost_listing_saves_listing ON ghost_listing_saves(listing_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ghost_listing_views_listing ON ghost_listing_views(listing_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ghost_listing_inquiries_seller ON ghost_listing_inquiries(seller_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ghost_listing_inquiries_listing ON ghost_listing_inquiries(listing_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ghost_seller_analytics_seller_date ON ghost_seller_analytics(seller_id, date DESC);