CREATE TABLE IF NOT EXISTS ghost_market_sellers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE,
    application_status TEXT DEFAULT 'pending',
    store_name TEXT,
    store_description TEXT,
    approved_by INTEGER,
    approved_at TIMESTAMP,
    rejection_reason TEXT,
    total_sales INTEGER DEFAULT 0,
    total_earnings REAL DEFAULT 0,
    rating REAL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (approved_by) REFERENCES admin_users(id)
);

CREATE TABLE IF NOT EXISTS ghost_market_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    seller_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    price REAL NOT NULL,
    currency TEXT DEFAULT 'ZAR',
    images TEXT,
    category TEXT,
    condition TEXT,
    status TEXT DEFAULT 'pending_approval',
    admin_notes TEXT,
    approved_by INTEGER,
    approved_at TIMESTAMP,
    rejection_reason TEXT,
    view_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP,
    FOREIGN KEY (seller_id) REFERENCES ghost_market_sellers(user_id),
    FOREIGN KEY (approved_by) REFERENCES admin_users(id)
);

CREATE TABLE IF NOT EXISTS ghost_market_orders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id INTEGER NOT NULL,
    buyer_id INTEGER NOT NULL,
    seller_id INTEGER NOT NULL,
    amount REAL NOT NULL,
    status TEXT DEFAULT 'pending_payment',
    pudo_locker_location TEXT,
    pudo_pickup_code TEXT,
    buyer_pin_half TEXT,
    seller_pin_half TEXT,
    tracking_number TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    paid_at TIMESTAMP,
    shipped_at TIMESTAMP,
    delivered_at TIMESTAMP,
    completed_at TIMESTAMP,
    cancelled_at TIMESTAMP,
    FOREIGN KEY (item_id) REFERENCES ghost_market_items(id),
    FOREIGN KEY (buyer_id) REFERENCES users(id),
    FOREIGN KEY (seller_id) REFERENCES ghost_market_sellers(user_id)
);

CREATE TABLE IF NOT EXISTS ghost_market_escrow (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL,
    amount REAL NOT NULL,
    status TEXT DEFAULT 'held',
    held_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    released_at TIMESTAMP,
    refunded_at TIMESTAMP,
    FOREIGN KEY (order_id) REFERENCES ghost_market_orders(id)
);

CREATE TABLE IF NOT EXISTS ghost_market_disputes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id INTEGER NOT NULL,
    raised_by INTEGER NOT NULL,
    reason TEXT NOT NULL,
    evidence TEXT,
    status TEXT DEFAULT 'open',
    resolution TEXT,
    resolved_by INTEGER,
    resolved_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (order_id) REFERENCES ghost_market_orders(id),
    FOREIGN KEY (raised_by) REFERENCES users(id),
    FOREIGN KEY (resolved_by) REFERENCES admin_users(id)
);

CREATE TABLE IF NOT EXISTS ghost_market_reviews (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id INTEGER NOT NULL,
    buyer_id INTEGER NOT NULL,
    seller_id INTEGER NOT NULL,
    rating INTEGER NOT NULL CHECK (rating >= 1 AND rating <= 5),
    comment TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (item_id) REFERENCES ghost_market_items(id),
    FOREIGN KEY (buyer_id) REFERENCES users(id),
    FOREIGN KEY (seller_id) REFERENCES ghost_market_sellers(user_id),
    UNIQUE(item_id, buyer_id)
);
