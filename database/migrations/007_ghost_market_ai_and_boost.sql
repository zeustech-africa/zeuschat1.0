ALTER TABLE ghost_market_items ADD COLUMN is_boosted INTEGER DEFAULT 0;
ALTER TABLE ghost_market_items ADD COLUMN boost_expires_at TIMESTAMP;
ALTER TABLE ghost_market_items ADD COLUMN updated_at TIMESTAMP;

UPDATE ghost_market_items
SET updated_at = COALESCE(updated_at, created_at)
WHERE updated_at IS NULL;

CREATE TABLE IF NOT EXISTS ghost_listing_auto_replies (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    listing_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    buyer_question TEXT,
    auto_reply_text TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (listing_id) REFERENCES ghost_market_items(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ghost_market_ai_drafts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    source_filename TEXT,
    generated_title TEXT,
    generated_description TEXT,
    suggested_price REAL,
    category TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ghost_seller_ratings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    seller_id INTEGER NOT NULL,
    buyer_id INTEGER NOT NULL,
    listing_id INTEGER NOT NULL,
    rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
    review TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (seller_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (buyer_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (listing_id) REFERENCES ghost_market_items(id) ON DELETE CASCADE,
    UNIQUE(buyer_id, listing_id)
);

CREATE INDEX IF NOT EXISTS idx_ghost_market_items_boost ON ghost_market_items(is_boosted, boost_expires_at);
CREATE INDEX IF NOT EXISTS idx_ghost_listing_auto_replies_listing ON ghost_listing_auto_replies(listing_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ghost_market_ai_drafts_user ON ghost_market_ai_drafts(user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ghost_seller_ratings_seller ON ghost_seller_ratings(seller_id, created_at DESC);
