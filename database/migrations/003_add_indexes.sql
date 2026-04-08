CREATE INDEX IF NOT EXISTS idx_user_approvals_status ON user_approvals(status);
CREATE INDEX IF NOT EXISTS idx_user_approvals_user_id ON user_approvals(user_id);
CREATE INDEX IF NOT EXISTS idx_admin_messages_user_id ON admin_messages(user_id);
CREATE INDEX IF NOT EXISTS idx_one_off_payments_status ON one_off_payments(status);
CREATE INDEX IF NOT EXISTS idx_user_unlocks_user_id ON user_unlocks(user_id);
CREATE INDEX IF NOT EXISTS idx_admin_audit_log_created_at ON admin_audit_log(created_at);
CREATE INDEX IF NOT EXISTS idx_kyc_documents_review_status ON kyc_documents(admin_review_status);
CREATE INDEX IF NOT EXISTS idx_profile_pic_payments_status ON profile_pic_payments(status);
CREATE INDEX IF NOT EXISTS idx_profile_picture_locks_user_id ON profile_picture_locks(user_id);
CREATE INDEX IF NOT EXISTS idx_subscriptions_user_id ON subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_subscriptions_status ON subscriptions(status);
CREATE INDEX IF NOT EXISTS idx_subscription_payments_subscription_id ON subscription_payments(subscription_id);
CREATE INDEX IF NOT EXISTS idx_user_feedback_status ON user_feedback(status);
CREATE INDEX IF NOT EXISTS idx_user_feedback_user_id ON user_feedback(user_id);

CREATE INDEX IF NOT EXISTS idx_message_queue_status ON message_queue(queue_status);
CREATE INDEX IF NOT EXISTS idx_message_queue_next_retry ON message_queue(next_retry_at);
CREATE INDEX IF NOT EXISTS idx_message_queue_user_id ON message_queue(user_id);

CREATE INDEX IF NOT EXISTS idx_messages_sender_receiver ON messages(sender_id, receiver_id);
CREATE INDEX IF NOT EXISTS idx_messages_timestamp_desc ON messages(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_messages_is_read ON messages(viewed_at);

CREATE INDEX IF NOT EXISTS idx_contacts_user_contact ON contacts(user_id, contact_user_id);
CREATE INDEX IF NOT EXISTS idx_contacts_status ON contacts(status);
CREATE INDEX IF NOT EXISTS idx_contact_requests_receiver_pending ON contacts(contact_user_id, status);
CREATE INDEX IF NOT EXISTS idx_contact_requests_sender ON contacts(user_id);

CREATE INDEX IF NOT EXISTS idx_users_zeus_pin ON users(zeus_pin);
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);
CREATE INDEX IF NOT EXISTS idx_subscriptions_user_tier ON subscriptions(user_id, tier);
CREATE INDEX IF NOT EXISTS idx_push_subscriptions_user ON push_subscriptions(user_id);

CREATE INDEX IF NOT EXISTS idx_gmi_status ON ghost_market_items(status);
CREATE INDEX IF NOT EXISTS idx_gmi_category ON ghost_market_items(category);
CREATE INDEX IF NOT EXISTS idx_gmo_status ON ghost_market_orders(status);
CREATE INDEX IF NOT EXISTS idx_gmo_buyer ON ghost_market_orders(buyer_id);
CREATE INDEX IF NOT EXISTS idx_gmo_seller ON ghost_market_orders(seller_id);
CREATE INDEX IF NOT EXISTS idx_gmi_seller_status ON ghost_market_items(seller_id, status);
CREATE INDEX IF NOT EXISTS idx_gmi_approved ON ghost_market_items(status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_gmo_buyer_status ON ghost_market_orders(buyer_id, status);
CREATE INDEX IF NOT EXISTS idx_gmo_seller_status ON ghost_market_orders(seller_id, status);
