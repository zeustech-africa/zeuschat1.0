# ============================================
# ZEUSCHAT CLEAN APP.PY
# Working admin login only
# ============================================

from flask import Flask, request, jsonify, session, render_template, redirect, url_for
import sqlite3
import os

app = Flask(__name__)

# ============================================
# LOGIN REQUIRED DECORATOR
# ============================================
from functools import wraps

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session and 'admin_id' not in session:
            return jsonify({'success': False, 'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function

app.secret_key = 'zeuschat_secret_key_2024'

# Database helper
def get_db():
    db_path = os.path.join(os.path.dirname(__file__), 'zeuschat_local.db')
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

# ============================================
# TEST ROUTES
# ============================================

@app.route('/test', methods=['GET'])
def test():
    return jsonify({'status': 'ok', 'message': 'Server is running!'})

@app.route('/admin/test', methods=['GET', 'POST'])
def admin_test():
    if request.method == 'POST':
        return jsonify({'success': True, 'message': 'POST works!', 'received': request.get_json()})
    return jsonify({'success': True, 'message': 'GET works!'})

# ============================================
# ADMIN LOGIN ROUTES
# ============================================

@app.route('/admin/login')
def admin_login_page():
    return render_template('admin/login.html')

@app.route('/admin/api/login', methods=['POST'])
def admin_api_login():
    try:
        data = request.get_json()
        print(f"Login attempt: {data}")
        
        if not data:
            return jsonify({'error': 'No JSON data'}), 400
        
        username = data.get('username')
        password = data.get('password')
        
        if username == 'superadmin' and password == 'ZeusAdmin2026Secure!':
            session['admin_id'] = 1
            session['admin_username'] = username
            return jsonify({'success': True, 'redirect': '/admin/dashboard'})
        else:
            return jsonify({'success': False, 'error': 'Invalid credentials'}), 401
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_id' not in session:
        return redirect('/admin/login')
    return render_template('admin/dashboard.html')

# ============================================
# MAIN ENTRY
# ============================================

if __name__ == '__main__':
    print("=" * 50)
    print("🚀 ZEUSCHAT SERVER STARTING")
    print("=" * 50)
    print("📍 Test: http://localhost:5000/test")
    print("📍 Admin Login: http://localhost:5000/admin/login")
    print("=" * 50)
    app.run(host='0.0.0.0', port=5000, debug=True)


# ============================================
# GHOST COMMUNITY - FOR YOU FEED
# ============================================

@app.route('/api/ghost/feed/foryou', methods=['GET'])
@login_required
def ghost_foryou_feed():
    """For You feed - Algorithm-based content recommendation"""
    try:
        user_id = session.get('user_id')
        limit = request.args.get('limit', 20, type=int)
        offset = request.args.get('offset', 0, type=int)
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Algorithm: engagement score based on watch time, likes, shares
        cursor.execute('''
            SELECT p.*, u.zeus_pin,
                   COALESCE(l.is_liked, 0) as is_liked_by_user,
                   COALESCE(f.is_following, 0) as is_following_user,
                   (COALESCE(p.watch_time_total, 0) * 0.35 +
                    COALESCE(p.completion_count, 0) * 0.20 +
                    COALESCE(p.replay_count, 0) * 0.15 +
                    COALESCE(p.likes_count, 0) * 0.10 +
                    COALESCE(p.shares_count, 0) * 0.08) as algorithm_score
            FROM ghost_posts p
            JOIN users u ON u.id = p.user_id
            LEFT JOIN (
                SELECT 1 as is_liked, post_id FROM ghost_likes WHERE user_id = ?
            ) l ON l.post_id = p.id
            LEFT JOIN (
                SELECT 1 as is_following, following_id FROM ghost_follows WHERE follower_id = ?
            ) f ON f.following_id = p.user_id
            WHERE p.status = 'approved'
            AND p.expires_at > datetime('now')
            ORDER BY algorithm_score DESC
            LIMIT ? OFFSET ?
        ''', (user_id, user_id, limit, offset))
        
        posts = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return jsonify({'success': True, 'posts': posts, 'hasMore': len(posts) == limit})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================
# GHOST COMMUNITY - FOLLOWING FEED
# ============================================

@app.route('/api/ghost/feed/following', methods=['GET'])
@login_required
def ghost_following_feed():
    """Following feed - Posts from users you follow"""
    try:
        user_id = session.get('user_id')
        limit = request.args.get('limit', 20, type=int)
        offset = request.args.get('offset', 0, type=int)
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT p.*, u.zeus_pin,
                   COALESCE(l.is_liked, 0) as is_liked_by_user,
                   1 as is_following_user
            FROM ghost_posts p
            JOIN users u ON u.id = p.user_id
            JOIN ghost_follows f ON f.following_id = p.user_id
            LEFT JOIN (
                SELECT 1 as is_liked, post_id FROM ghost_likes WHERE user_id = ?
            ) l ON l.post_id = p.id
            WHERE p.status = 'approved'
            AND p.expires_at > datetime('now')
            AND f.follower_id = ?
            ORDER BY p.created_at DESC
            LIMIT ? OFFSET ?
        ''', (user_id, user_id, limit, offset))
        
        posts = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return jsonify({'success': True, 'posts': posts, 'hasMore': len(posts) == limit})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================
# GHOST COMMUNITY - TRENDING FEED
# ============================================

@app.route('/api/ghost/feed/trending', methods=['GET'])
@login_required
def ghost_trending_feed():
    """Trending feed - Most engaged posts in last 24 hours"""
    try:
        user_id = session.get('user_id')
        limit = request.args.get('limit', 20, type=int)
        offset = request.args.get('offset', 0, type=int)
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT p.*, u.zeus_pin,
                   COALESCE(l.is_liked, 0) as is_liked_by_user,
                   COALESCE(f.is_following, 0) as is_following_user,
                   ((p.likes_count + p.comments_count + p.shares_count) * 1.0 / NULLIF(p.views_count, 1)) as engagement_rate
            FROM ghost_posts p
            JOIN users u ON u.id = p.user_id
            LEFT JOIN (
                SELECT 1 as is_liked, post_id FROM ghost_likes WHERE user_id = ?
            ) l ON l.post_id = p.id
            LEFT JOIN (
                SELECT 1 as is_following, following_id FROM ghost_follows WHERE follower_id = ?
            ) f ON f.following_id = p.user_id
            WHERE p.status = 'approved'
            AND p.expires_at > datetime('now')
            AND p.created_at > datetime('now', '-24 hours')
            ORDER BY engagement_rate DESC
            LIMIT ? OFFSET ?
        ''', (user_id, user_id, limit, offset))
        
        posts = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return jsonify({'success': True, 'posts': posts, 'hasMore': len(posts) == limit})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================
# GHOST COMMUNITY - CREATE POST
# ============================================

@app.route('/api/ghost/post/create', methods=['POST'])
@login_required
def ghost_create_post():
    """Create a new post (video, image, or text)"""
    try:
        user_id = session.get('user_id')
        zeus_pin = session.get('zeus_pin')
        data = request.get_json()
        
        content_type = data.get('content_type', 'text')
        text_content = data.get('text_content', '')
        hashtags = data.get('hashtags', [])
        is_paid = data.get('is_paid', False)
        price = data.get('price', 0)
        media_url = data.get('media_url', None)
        
        # Limit hashtags to 5
        if len(hashtags) > 5:
            return jsonify({'success': False, 'error': 'Maximum 5 hashtags allowed'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO ghost_posts (user_id, zeus_pin, content_type, text_content, hashtags, is_paid, price, media_url)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, zeus_pin, content_type, text_content, ','.join(hashtags), is_paid, price, media_url))
        
        post_id = cursor.lastrowid
        
        # Process hashtags
        for tag in hashtags:
            tag_lower = tag.lower().strip()
            cursor.execute('INSERT OR IGNORE INTO ghost_hashtags (name) VALUES (?)', (tag_lower,))
            cursor.execute('UPDATE ghost_hashtags SET post_count = post_count + 1 WHERE name = ?', (tag_lower,))
            cursor.execute('SELECT id FROM ghost_hashtags WHERE name = ?', (tag_lower,))
            hashtag_id = cursor.fetchone()[0]
            cursor.execute('INSERT INTO ghost_post_hashtags (post_id, hashtag_id) VALUES (?, ?)', (post_id, hashtag_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'post_id': post_id, 'status': 'pending'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================
# GHOST COMMUNITY - LIKE/UNLIKE POST
# ============================================

@app.route('/api/ghost/post/<int:post_id>/like', methods=['POST'])
@login_required
def ghost_toggle_like(post_id):
    """Toggle like on a post (like if not liked, unlike if already liked)"""
    try:
        user_id = session.get('user_id')
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Check if post exists
        cursor.execute('SELECT id, likes_count FROM ghost_posts WHERE id = ?', (post_id,))
        post = cursor.fetchone()
        if not post:
            conn.close()
            return jsonify({'success': False, 'error': 'Post not found'}), 404
        
        # Check if already liked
        cursor.execute('SELECT id FROM ghost_likes WHERE post_id = ? AND user_id = ?', (post_id, user_id))
        existing = cursor.fetchone()
        
        if existing:
            # Unlike: remove the like
            cursor.execute('DELETE FROM ghost_likes WHERE post_id = ? AND user_id = ?', (post_id, user_id))
            cursor.execute('UPDATE ghost_posts SET likes_count = likes_count - 1 WHERE id = ?', (post_id,))
            conn.commit()
            action = 'unliked'
        else:
            # Like: add the like
            cursor.execute('INSERT INTO ghost_likes (post_id, user_id) VALUES (?, ?)', (post_id, user_id))
            cursor.execute('UPDATE ghost_posts SET likes_count = likes_count + 1 WHERE id = ?', (post_id,))
            conn.commit()
            action = 'liked'
        
        # Get updated count
        cursor.execute('SELECT likes_count FROM ghost_posts WHERE id = ?', (post_id,))
        new_count = cursor.fetchone()[0]
        
        conn.close()
        
        return jsonify({'success': True, 'action': action, 'likes_count': new_count})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================
# GHOST COMMUNITY - ADD COMMENT
# ============================================

@app.route('/api/ghost/post/<int:post_id>/comment', methods=['POST'])
@login_required
def ghost_add_comment(post_id):
    """Add a comment to a post"""
    try:
        user_id = session.get('user_id')
        zeus_pin = session.get('zeus_pin')
        data = request.get_json()
        comment_text = data.get('comment_text', '').strip()
        
        if not comment_text:
            return jsonify({'success': False, 'error': 'Comment cannot be empty'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Check if post exists
        cursor.execute('SELECT id, comments_count FROM ghost_posts WHERE id = ?', (post_id,))
        post = cursor.fetchone()
        if not post:
            conn.close()
            return jsonify({'success': False, 'error': 'Post not found'}), 404
        
        # Add comment (status: pending for auto-scan, will be implemented later)
        cursor.execute('''
            INSERT INTO ghost_comments (post_id, user_id, zeus_pin, comment_text, status)
            VALUES (?, ?, ?, ?, 'approved')
        ''', (post_id, user_id, zeus_pin, comment_text))
        
        comment_id = cursor.lastrowid
        
        # Update comment count on post
        cursor.execute('UPDATE ghost_posts SET comments_count = comments_count + 1 WHERE id = ?', (post_id,))
        
        conn.commit()
        
        # Get the new comment
        cursor.execute('''
            SELECT id, zeus_pin, comment_text, created_at, likes_count
            FROM ghost_comments WHERE id = ?
        ''', (comment_id,))
        comment = dict(cursor.fetchone())
        
        conn.close()
        
        return jsonify({'success': True, 'comment': comment, 'comments_count': post[1] + 1})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================
# GHOST COMMUNITY - GET COMMENTS
# ============================================

@app.route('/api/ghost/post/<int:post_id>/comments', methods=['GET'])
@login_required
def ghost_get_comments(post_id):
    """Get all comments for a post"""
    try:
        limit = request.args.get('limit', 50, type=int)
        offset = request.args.get('offset', 0, type=int)
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, zeus_pin, comment_text, created_at, likes_count
            FROM ghost_comments
            WHERE post_id = ? AND status = 'approved'
            ORDER BY created_at DESC
            LIMIT ? OFFSET ?
        ''', (post_id, limit, offset))
        
        comments = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return jsonify({'success': True, 'comments': comments})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================
# GHOST COMMUNITY - SHARE/REPOST POST
# ============================================

@app.route('/api/ghost/post/<int:post_id>/share', methods=['POST'])
@login_required
def ghost_share_post(post_id):
    """Share/repost a post to user's own feed (free posts only)"""
    try:
        user_id = session.get('user_id')
        zeus_pin = session.get('zeus_pin')
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Get original post
        cursor.execute('''
            SELECT id, user_id, zeus_pin, content_type, media_url, text_content, 
                   hashtags, is_paid, price, created_at
            FROM ghost_posts WHERE id = ?
        ''', (post_id,))
        original = cursor.fetchone()
        
        if not original:
            conn.close()
            return jsonify({'success': False, 'error': 'Post not found'}), 404
        
        # Check if paid content - cannot share
        if original['is_paid'] == 1:
            conn.close()
            return jsonify({'success': False, 'error': 'Paid content cannot be shared'}), 403
        
        # Check if user is trying to share their own post
        if original['user_id'] == user_id:
            conn.close()
            return jsonify({'success': False, 'error': 'You cannot share your own post'}), 403
        
        # Create repost (copy as new post in user's feed)
        repost_text = f"Reposted from @{original['zeus_pin']}: {original['text_content']}"
        
        cursor.execute('''
            INSERT INTO ghost_posts (user_id, zeus_pin, content_type, media_url, text_content, 
                                     hashtags, is_paid, price, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'approved', datetime('now'))
        ''', (user_id, zeus_pin, original['content_type'], original['media_url'], 
              repost_text, original['hashtags'], 0, 0))
        
        repost_id = cursor.lastrowid
        
        # Record the share
        cursor.execute('''
            INSERT INTO ghost_shares (original_post_id, shared_by_user_id, new_post_id)
            VALUES (?, ?, ?)
        ''', (post_id, user_id, repost_id))
        
        # Increment share count on original post
        cursor.execute('UPDATE ghost_posts SET shares_count = shares_count + 1 WHERE id = ?', (post_id,))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'repost_id': repost_id, 'message': 'Post shared to your feed'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================
# GHOST COMMUNITY - FOLLOW/UNFOLLOW USER
# ============================================

@app.route('/api/ghost/user/<string:target_zeus_pin>/follow', methods=['POST'])
@login_required
def ghost_toggle_follow(target_zeus_pin):
    """Follow or unfollow a user"""
    try:
        follower_id = session.get('user_id')
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Get the target user's ID
        cursor.execute('SELECT id FROM users WHERE zeus_pin = ?', (target_zeus_pin,))
        target = cursor.fetchone()
        
        if not target:
            conn.close()
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        target_id = target['id']
        
        # Don't allow following yourself
        if follower_id == target_id:
            conn.close()
            return jsonify({'success': False, 'error': 'You cannot follow yourself'}), 400
        
        # Check if already following
        cursor.execute('''
            SELECT id FROM ghost_follows WHERE follower_id = ? AND following_id = ?
        ''', (follower_id, target_id))
        existing = cursor.fetchone()
        
        if existing:
            # Unfollow
            cursor.execute('DELETE FROM ghost_follows WHERE follower_id = ? AND following_id = ?', (follower_id, target_id))
            conn.commit()
            action = 'unfollowed'
            message = f'You unfollowed {target_zeus_pin}'
        else:
            # Follow
            cursor.execute('INSERT INTO ghost_follows (follower_id, following_id) VALUES (?, ?)', (follower_id, target_id))
            conn.commit()
            action = 'followed'
            message = f'You are now following {target_zeus_pin}'
        
        conn.close()
        
        return jsonify({'success': True, 'action': action, 'message': message})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================
# GHOST COMMUNITY - RECORD VIEW & WATCH TIME
# ============================================

@app.route('/api/ghost/post/<int:post_id>/view', methods=['POST'])
@login_required
def ghost_record_view(post_id):
    """Record a view with watch time for algorithm"""
    try:
        user_id = session.get('user_id')
        data = request.get_json()
        
        watch_time_seconds = data.get('watch_time_seconds', 0)
        completed = data.get('completed', False)
        replay_count = data.get('replay_count', 0)
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Check if post exists
        cursor.execute('SELECT id FROM ghost_posts WHERE id = ?', (post_id,))
        if not cursor.fetchone():
            conn.close()
            return jsonify({'success': False, 'error': 'Post not found'}), 404
        
        # Check if user already viewed this post
        cursor.execute('SELECT id, watch_time_seconds, replay_count FROM ghost_views WHERE post_id = ? AND user_id = ?', (post_id, user_id))
        existing = cursor.fetchone()
        
        if existing:
            # Update existing view with cumulative data
            new_watch_time = existing['watch_time_seconds'] + watch_time_seconds
            new_replay_count = existing['replay_count'] + replay_count
            
            cursor.execute('''
                UPDATE ghost_views 
                SET watch_time_seconds = ?, completed = ?, replay_count = ?, created_at = CURRENT_TIMESTAMP
                WHERE post_id = ? AND user_id = ?
            ''', (new_watch_time, completed, new_replay_count, post_id, user_id))
        else:
            # Insert new view
            cursor.execute('''
                INSERT INTO ghost_views (post_id, user_id, watch_time_seconds, completed, replay_count)
                VALUES (?, ?, ?, ?, ?)
            ''', (post_id, user_id, watch_time_seconds, completed, replay_count))
        
        # Update post aggregate stats for algorithm
        cursor.execute('''
            UPDATE ghost_posts 
            SET views_count = views_count + 1,
                watch_time_total = watch_time_total + ?,
                completion_count = completion_count + ?,
                replay_count = replay_count + ?
            WHERE id = ?
        ''', (watch_time_seconds, 1 if completed else 0, replay_count, post_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================
# GHOST COMMUNITY - CREATOR ANALYTICS
# ============================================

@app.route('/api/ghost/analytics/creator', methods=['GET'])
@login_required
def ghost_creator_analytics():
    """Get analytics for the logged-in creator"""
    try:
        user_id = session.get('user_id')
        period = request.args.get('period', 'week')  # day, week, month, all
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Date filter based on period
        if period == 'day':
            date_filter = "p.created_at > datetime('now', '-1 day')"
        elif period == 'week':
            date_filter = "p.created_at > datetime('now', '-7 days')"
        elif period == 'month':
            date_filter = "p.created_at > datetime('now', '-30 days')"
        else:
            date_filter = "1=1"
        
        # Get aggregate stats
        cursor.execute(f'''
            SELECT 
                COUNT(*) as total_posts,
                COALESCE(SUM(views_count), 0) as total_views,
                COALESCE(SUM(likes_count), 0) as total_likes,
                COALESCE(SUM(comments_count), 0) as total_comments,
                COALESCE(SUM(shares_count), 0) as total_shares,
                COALESCE(AVG(watch_time_total), 0) as avg_watch_time,
                COALESCE(SUM(CASE WHEN is_paid = 1 THEN price * 0.8 ELSE 0 END), 0) as total_earnings
            FROM ghost_posts p
            WHERE p.user_id = ? AND p.status = 'approved' AND {date_filter}
        ''', (user_id,))
        
        summary = cursor.fetchone()
        
        # Calculate engagement rate
        total_engagement = summary['total_likes'] + summary['total_comments'] + summary['total_shares']
        engagement_rate = (total_engagement / summary['total_views'] * 100) if summary['total_views'] > 0 else 0
        
        # Get top 5 posts by engagement
        cursor.execute(f'''
            SELECT id, text_content, views_count, likes_count, comments_count, shares_count, is_paid, price
            FROM ghost_posts
            WHERE user_id = ? AND status = 'approved' AND {date_filter}
            ORDER BY (likes_count + comments_count + shares_count) DESC
            LIMIT 5
        ''', (user_id,))
        
        top_posts = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        return jsonify({
            'success': True,
            'analytics': {
                'total_posts': summary['total_posts'],
                'total_views': summary['total_views'],
                'total_likes': summary['total_likes'],
                'total_comments': summary['total_comments'],
                'total_shares': summary['total_shares'],
                'total_earnings': round(float(summary['total_earnings']), 2),
                'avg_watch_time': round(float(summary['avg_watch_time']), 1),
                'engagement_rate': round(engagement_rate, 1),
                'top_posts': top_posts
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================
# GHOST MARKET - MARKETPLACE FEED
# ============================================

@app.route('/api/ghost/market/feed', methods=['GET'])
@login_required
def ghost_market_feed():
    """Get marketplace listings grid with filters and sorting"""
    try:
        user_id = session.get('user_id')
        
        # Get query parameters
        category = request.args.get('category', 'all')
        min_price = request.args.get('min_price', type=float)
        max_price = request.args.get('max_price', type=float)
        condition = request.args.get('condition', 'all')
        sort_by = request.args.get('sort_by', 'newest')
        limit = request.args.get('limit', 20, type=int)
        offset = request.args.get('offset', 0, type=int)
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Build the query
        query = '''
            SELECT l.id, l.seller_id, 
                   SUBSTR(l.zeus_pin, 1, 3) || '-****-****' as seller_zeus_pin,
                   l.title, l.description, l.price, l.currency, l.condition, 
                   l.category, l.location, l.images, l.views_count, l.saves_count,
                   l.created_at,
                   COALESCE(s.is_saved, 0) as is_saved_by_user,
                   COALESCE(r.avg_rating, 0) as seller_rating
            FROM ghost_market_listings l
            LEFT JOIN (
                SELECT 1 as is_saved, listing_id FROM ghost_market_saves WHERE user_id = ?
            ) s ON s.listing_id = l.id
            LEFT JOIN (
                SELECT seller_id, AVG(rating) as avg_rating 
                FROM ghost_market_ratings GROUP BY seller_id
            ) r ON r.seller_id = l.seller_id
            WHERE l.status = 'active'
        '''
        
        params = [user_id]
        
        # Apply filters
        if category != 'all':
            query += ' AND l.category = ?'
            params.append(category)
        
        if min_price is not None:
            query += ' AND l.price >= ?'
            params.append(min_price)
        
        if max_price is not None:
            query += ' AND l.price <= ?'
            params.append(max_price)
        
        if condition != 'all':
            query += ' AND l.condition = ?'
            params.append(condition)
        
        # Apply sorting
        if sort_by == 'price_asc':
            query += ' ORDER BY l.price ASC'
        elif sort_by == 'price_desc':
            query += ' ORDER BY l.price DESC'
        elif sort_by == 'most_views':
            query += ' ORDER BY l.views_count DESC'
        else:  # newest
            query += ' ORDER BY l.created_at DESC'
        
        query += ' LIMIT ? OFFSET ?'
        params.extend([limit, offset])
        
        cursor.execute(query, params)
        listings = [dict(row) for row in cursor.fetchall()]
        
        # Parse images JSON
        for listing in listings:
            if listing.get('images'):
                try:
                    import json
                    listing['images'] = json.loads(listing['images'])
                except:
                    listing['images'] = [listing['images']] if listing['images'] else []
            else:
                listing['images'] = []
        
        conn.close()
        
        return jsonify({
            'success': True,
            'listings': listings,
            'hasMore': len(listings) == limit
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================
# GHOST MARKET - CREATE LISTING
# ============================================

@app.route('/api/ghost/market/listing/create', methods=['POST'])
@login_required
def ghost_market_create_listing():
    """Create a new listing (requires admin approval)"""
    try:
        user_id = session.get('user_id')
        zeus_pin = session.get('zeus_pin')
        data = request.get_json()
        
        title = data.get('title', '').strip()
        description = data.get('description', '').strip()
        price = data.get('price', 0)
        currency = data.get('currency', 'ZAR')
        condition = data.get('condition', 'used')
        category = data.get('category', 'Other')
        location = data.get('location', '').strip()
        images = data.get('images', [])
        
        # Validation
        if not title:
            return jsonify({'success': False, 'error': 'Title is required'}), 400
        
        if price <= 0:
            return jsonify({'success': False, 'error': 'Valid price is required'}), 400
        
        if len(images) > 10:
            return jsonify({'success': False, 'error': 'Maximum 10 photos allowed'}), 400
        
        # Convert images list to JSON string
        import json
        images_json = json.dumps(images)
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO ghost_market_listings 
            (seller_id, zeus_pin, title, description, price, currency, 
             condition, category, location, images, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
        ''', (user_id, zeus_pin, title, description, price, currency, 
              condition, category, location, images_json))
        
        listing_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True, 
            'listing_id': listing_id, 
            'message': 'Listing submitted for admin approval',
            'status': 'pending'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================
# GHOST MARKET - SAVE/UNSAVE LISTING
# ============================================

@app.route('/api/ghost/market/listing/<int:listing_id>/save', methods=['POST'])
@login_required
def ghost_market_toggle_save(listing_id):
    """Save or unsave a listing"""
    try:
        user_id = session.get('user_id')
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Check if listing exists and is active
        cursor.execute('SELECT id, saves_count FROM ghost_market_listings WHERE id = ? AND status = ?', (listing_id, 'active'))
        listing = cursor.fetchone()
        
        if not listing:
            conn.close()
            return jsonify({'success': False, 'error': 'Listing not found'}), 404
        
        # Check if already saved
        cursor.execute('SELECT id FROM ghost_market_saves WHERE listing_id = ? AND user_id = ?', (listing_id, user_id))
        existing = cursor.fetchone()
        
        if existing:
            # Unsave
            cursor.execute('DELETE FROM ghost_market_saves WHERE listing_id = ? AND user_id = ?', (listing_id, user_id))
            cursor.execute('UPDATE ghost_market_listings SET saves_count = saves_count - 1 WHERE id = ?', (listing_id,))
            conn.commit()
            action = 'unsaved'
            message = 'Listing removed from saved'
        else:
            # Save
            cursor.execute('INSERT INTO ghost_market_saves (listing_id, user_id) VALUES (?, ?)', (listing_id, user_id))
            cursor.execute('UPDATE ghost_market_listings SET saves_count = saves_count + 1 WHERE id = ?', (listing_id,))
            conn.commit()
            action = 'saved'
            message = 'Listing saved to your bookmarks'
        
        # Get updated count
        cursor.execute('SELECT saves_count FROM ghost_market_listings WHERE id = ?', (listing_id,))
        new_count = cursor.fetchone()['saves_count']
        
        conn.close()
        
        return jsonify({
            'success': True, 
            'action': action, 
            'message': message,
            'saves_count': new_count
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================
# GHOST MARKET - INQUIRE TO SELLER
# ============================================

@app.route('/api/ghost/market/listing/<int:listing_id>/inquire', methods=['POST'])
@login_required
def ghost_market_inquire(listing_id):
    """Send a message to the seller about a listing"""
    try:
        buyer_id = session.get('user_id')
        buyer_zeus_pin = session.get('zeus_pin')
        data = request.get_json()
        message = data.get('message', '').strip()
        
        if not message:
            return jsonify({'success': False, 'error': 'Message cannot be empty'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Get listing details and seller
        cursor.execute('''
            SELECT l.id, l.title, l.seller_id, l.zeus_pin as seller_zeus_pin,
                   SUBSTR(l.zeus_pin, 1, 3) || '-****-****' as masked_seller_pin
            FROM ghost_market_listings l
            WHERE l.id = ? AND l.status = 'active'
        ''', (listing_id,))
        listing = cursor.fetchone()
        
        if not listing:
            conn.close()
            return jsonify({'success': False, 'error': 'Listing not found'}), 404
        
        seller_id = listing['seller_id']
        
        # Don't allow inquiring on your own listing
        if buyer_id == seller_id:
            conn.close()
            return jsonify({'success': False, 'error': 'You cannot inquire on your own listing'}), 400
        
        # Record the inquiry
        cursor.execute('''
            INSERT INTO ghost_market_inquiries (listing_id, buyer_id, seller_id, message)
            VALUES (?, ?, ?, ?)
        ''', (listing_id, buyer_id, seller_id, message))
        
        # Increment messages count on listing
        cursor.execute('''
            UPDATE ghost_market_listings SET messages_count = messages_count + 1 WHERE id = ?
        ''', (listing_id,))
        
        conn.commit()
        inquiry_id = cursor.lastrowid
        
        # Create a chat message in the main messaging system
        # This creates a thread between buyer and seller
        chat_thread_id = f"market_{listing_id}_{min(buyer_id, seller_id)}_{max(buyer_id, seller_id)}"
        
        # Insert into messages table (assuming it exists)
        cursor.execute('''
            INSERT OR IGNORE INTO messages (thread_id, sender_id, receiver_id, content, created_at)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (chat_thread_id, buyer_id, seller_id, f"[Ghost Market] Regarding: {listing['title']}\n\n{message}"))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'inquiry_id': inquiry_id,
            'message': 'Your inquiry has been sent to the seller',
            'seller': listing['masked_seller_pin']
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================
# GHOST MARKET - MARK LISTING AS SOLD
# ============================================

@app.route('/api/ghost/market/listing/<int:listing_id>/mark-sold', methods=['POST'])
@login_required
def ghost_market_mark_sold(listing_id):
    """Mark a listing as sold (seller only)"""
    try:
        user_id = session.get('user_id')
        data = request.get_json()
        buyer_zeus_pin = data.get('buyer_zeus_pin', '').strip()
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Get listing and verify ownership
        cursor.execute('''
            SELECT id, seller_id, title, price FROM ghost_market_listings 
            WHERE id = ? AND status = 'active'
        ''', (listing_id,))
        listing = cursor.fetchone()
        
        if not listing:
            conn.close()
            return jsonify({'success': False, 'error': 'Listing not found'}), 404
        
        if listing['seller_id'] != user_id:
            conn.close()
            return jsonify({'success': False, 'error': 'You can only mark your own listings as sold'}), 403
        
        # Mark as sold
        cursor.execute('''
            UPDATE ghost_market_listings 
            SET status = 'sold', sold_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (listing_id,))
        
        # Update seller analytics (daily stats)
        cursor.execute('''
            INSERT INTO ghost_market_seller_stats (seller_id, date, items_sold, revenue)
            VALUES (?, DATE('now'), 1, ?)
            ON CONFLICT(seller_id, date) DO UPDATE SET
                items_sold = items_sold + 1,
                revenue = revenue + ?
        ''', (user_id, listing['price'], listing['price']))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': f'Listing "{listing["title"]}" marked as sold',
            'listing_id': listing_id
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================
# GHOST MARKET - ADD/GET SELLER RATINGS
# ============================================

@app.route('/api/ghost/market/seller/<int:seller_id>/rate', methods=['POST'])
@login_required
def ghost_market_rate_seller(seller_id):
    """Rate a seller after a transaction (buyer only)"""
    try:
        buyer_id = session.get('user_id')
        data = request.get_json()
        
        listing_id = data.get('listing_id')
        rating = data.get('rating', 0)
        review = data.get('review', '').strip()
        
        if not listing_id:
            return jsonify({'success': False, 'error': 'Listing ID is required'}), 400
        
        if rating < 1 or rating > 5:
            return jsonify({'success': False, 'error': 'Rating must be between 1 and 5'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Verify the listing was sold to this buyer
        cursor.execute('''
            SELECT id, seller_id FROM ghost_market_listings 
            WHERE id = ? AND status = 'sold'
        ''', (listing_id,))
        listing = cursor.fetchone()
        
        if not listing:
            conn.close()
            return jsonify({'success': False, 'error': 'Listing not found or not sold'}), 404
        
        if listing['seller_id'] != seller_id:
            conn.close()
            return jsonify({'success': False, 'error': 'Invalid seller for this listing'}), 400
        
        # Check if already rated
        cursor.execute('SELECT id FROM ghost_market_ratings WHERE listing_id = ? AND buyer_id = ?', (listing_id, buyer_id))
        existing = cursor.fetchone()
        
        if existing:
            conn.close()
            return jsonify({'success': False, 'error': 'You have already rated this transaction'}), 400
        
        # Add rating
        cursor.execute('''
            INSERT INTO ghost_market_ratings (seller_id, buyer_id, listing_id, rating, review)
            VALUES (?, ?, ?, ?, ?)
        ''', (seller_id, buyer_id, listing_id, rating, review))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Thank you for your rating!',
            'rating': rating
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/ghost/market/seller/<int:seller_id>/ratings', methods=['GET'])
@login_required
def ghost_market_get_seller_ratings(seller_id):
    """Get all ratings for a seller"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Get average rating and count
        cursor.execute('''
            SELECT 
                COALESCE(AVG(rating), 0) as average_rating,
                COUNT(*) as total_ratings,
                SUM(CASE WHEN rating = 5 THEN 1 ELSE 0 END) as five_star,
                SUM(CASE WHEN rating = 4 THEN 1 ELSE 0 END) as four_star,
                SUM(CASE WHEN rating = 3 THEN 1 ELSE 0 END) as three_star,
                SUM(CASE WHEN rating = 2 THEN 1 ELSE 0 END) as two_star,
                SUM(CASE WHEN rating = 1 THEN 1 ELSE 0 END) as one_star
            FROM ghost_market_ratings
            WHERE seller_id = ?
        ''', (seller_id,))
        stats = cursor.fetchone()
        
        # Get individual ratings with buyer info (masked)
        cursor.execute('''
            SELECT r.rating, r.review, r.created_at,
                   SUBSTR(u.zeus_pin, 1, 3) || '-****-****' as buyer_zeus_pin
            FROM ghost_market_ratings r
            JOIN users u ON u.id = r.buyer_id
            WHERE r.seller_id = ?
            ORDER BY r.created_at DESC
            LIMIT 20
        ''', (seller_id,))
        ratings = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        return jsonify({
            'success': True,
            'seller_id': seller_id,
            'average_rating': round(float(stats['average_rating']), 1),
            'total_ratings': stats['total_ratings'],
            'rating_breakdown': {
                '5': stats['five_star'],
                '4': stats['four_star'],
                '3': stats['three_star'],
                '2': stats['two_star'],
                '1': stats['one_star']
            },
            'ratings': ratings
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================
# GHOST MARKET - SELLER ANALYTICS DASHBOARD
# ============================================

@app.route('/api/ghost/market/seller/analytics', methods=['GET'])
@login_required
def ghost_market_seller_analytics():
    """Get analytics dashboard for the seller"""
    try:
        user_id = session.get('user_id')
        period = request.args.get('period', 'week')  # day, week, month, all
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Date filter
        if period == 'day':
            date_filter = "created_at > datetime('now', '-1 day')"
        elif period == 'week':
            date_filter = "created_at > datetime('now', '-7 days')"
        elif period == 'month':
            date_filter = "created_at > datetime('now', '-30 days')"
        else:
            date_filter = "1=1"
        
        # Get listing stats
        cursor.execute(f'''
            SELECT 
                COUNT(*) as total_listings,
                SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active_listings,
                SUM(CASE WHEN status = 'sold' THEN 1 ELSE 0 END) as sold_listings,
                SUM(views_count) as total_views,
                SUM(saves_count) as total_saves,
                SUM(messages_count) as total_messages
            FROM ghost_market_listings
            WHERE seller_id = ? AND {date_filter}
        ''', (user_id,))
        
        listing_stats = cursor.fetchone()
        
        # Get revenue from sold items
        cursor.execute(f'''
            SELECT 
                COALESCE(SUM(price), 0) as total_revenue,
                COUNT(*) as items_sold
            FROM ghost_market_listings
            WHERE seller_id = ? AND status = 'sold' AND {date_filter}
        ''', (user_id,))
        
        revenue_stats = cursor.fetchone()
        
        # Get daily breakdown for chart
        cursor.execute('''
            SELECT 
                DATE(created_at) as date,
                COUNT(*) as listings_created,
                SUM(views_count) as views,
                SUM(saves_count) as saves
            FROM ghost_market_listings
            WHERE seller_id = ? AND created_at > datetime('now', '-30 days')
            GROUP BY DATE(created_at)
            ORDER BY date DESC
            LIMIT 30
        ''', (user_id,))
        
        daily_breakdown = [dict(row) for row in cursor.fetchall()]
        
        # Get top performing listings
        cursor.execute('''
            SELECT id, title, price, views_count, saves_count, messages_count, 
                   CASE WHEN status = 'sold' THEN 1 ELSE 0 END as is_sold
            FROM ghost_market_listings
            WHERE seller_id = ?
            ORDER BY views_count DESC
            LIMIT 5
        ''', (user_id,))
        
        top_listings = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        # Calculate average rating
        avg_rating = 0
        try:
            conn2 = get_db()
            cursor2 = conn2.cursor()
            cursor2.execute('SELECT AVG(rating) as avg FROM ghost_market_ratings WHERE seller_id = ?', (user_id,))
            avg_row = cursor2.fetchone()
            avg_rating = round(float(avg_row['avg']), 1) if avg_row and avg_row['avg'] else 0
            conn2.close()
        except:
            pass
        
        return jsonify({
            'success': True,
            'analytics': {
                'period': period,
                'listings': {
                    'total': listing_stats['total_listings'] or 0,
                    'active': listing_stats['active_listings'] or 0,
                    'sold': listing_stats['sold_listings'] or 0
                },
                'engagement': {
                    'total_views': listing_stats['total_views'] or 0,
                    'total_saves': listing_stats['total_saves'] or 0,
                    'total_messages': listing_stats['total_messages'] or 0
                },
                'revenue': {
                    'total': float(revenue_stats['total_revenue'] or 0),
                    'items_sold': revenue_stats['items_sold'] or 0
                },
                'average_rating': avg_rating,
                'daily_breakdown': daily_breakdown,
                'top_listings': top_listings
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================
# WHATSAPP FEATURES - THEME SETTINGS
# ============================================

@app.route('/api/whatsapp/settings/theme', methods=['GET'])
@login_required
def whatsapp_get_theme():
    """Get user's theme preference"""
    try:
        user_id = session.get('user_id')
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT theme, font_scale FROM whatsapp_user_settings WHERE user_id = ?
        ''', (user_id,))
        settings = cursor.fetchone()
        conn.close()
        
        if settings:
            theme = settings['theme']
            font_scale = settings['font_scale']
        else:
            theme = 'light'
            font_scale = 1.0
        
        return jsonify({
            'success': True,
            'theme': theme,
            'fontScale': font_scale
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/whatsapp/settings/theme', methods=['PUT'])
@login_required
def whatsapp_update_theme():
    """Update user's theme preference"""
    try:
        user_id = session.get('user_id')
        data = request.get_json()
        
        theme = data.get('theme', 'light')
        font_scale = data.get('fontScale', 1.0)
        
        # Validate theme
        if theme not in ['light', 'dark', 'system']:
            theme = 'light'
        
        # Validate font scale
        if font_scale < 0.8 or font_scale > 1.6:
            font_scale = 1.0
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO whatsapp_user_settings (user_id, theme, font_scale, updated_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id) DO UPDATE SET
                theme = excluded.theme,
                font_scale = excluded.font_scale,
                updated_at = CURRENT_TIMESTAMP
        ''', (user_id, theme, font_scale))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Theme updated successfully',
            'theme': theme,
            'fontScale': font_scale
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================
# WHATSAPP FEATURES - WALLPAPER SETTINGS
# ============================================

@app.route('/api/whatsapp/settings/wallpaper', methods=['GET'])
@login_required
def whatsapp_get_wallpaper():
    """Get user's wallpaper preference"""
    try:
        user_id = session.get('user_id')
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT wallpaper_url, wallpaper_color FROM whatsapp_user_settings WHERE user_id = ?
        ''', (user_id,))
        settings = cursor.fetchone()
        conn.close()
        
        if settings:
            return jsonify({
                'success': True,
                'wallpaper_url': settings['wallpaper_url'],
                'wallpaper_color': settings['wallpaper_color']
            })
        else:
            return jsonify({
                'success': True,
                'wallpaper_url': None,
                'wallpaper_color': None
            })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/whatsapp/settings/wallpaper', methods=['PUT'])
@login_required
def whatsapp_update_wallpaper():
    """Update user's wallpaper preference"""
    try:
        user_id = session.get('user_id')
        data = request.get_json()
        
        wallpaper_url = data.get('wallpaper_url')
        wallpaper_color = data.get('wallpaper_color')
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Check if user is subscriber for unlimited changes
        cursor.execute('SELECT subscription_tier FROM profile_picture_locks WHERE user_id = ?', (user_id,))
        sub = cursor.fetchone()
        is_subscriber = sub and sub['subscription_tier'] == 'premium'
        
        if not is_subscriber:
            # Check wallpaper change count for free users
            cursor.execute('''
                SELECT wallpaper_change_count FROM whatsapp_user_settings WHERE user_id = ?
            ''', (user_id,))
            settings = cursor.fetchone()
            
            change_count = settings['wallpaper_change_count'] if settings else 0
            
            if change_count >= 1:
                conn.close()
                return jsonify({
                    'success': False, 
                    'error': 'Free users can only change wallpaper once. Upgrade to premium for unlimited changes.'
                }), 403
        
        # Update wallpaper
        cursor.execute('''
            INSERT INTO whatsapp_user_settings (user_id, wallpaper_url, wallpaper_color, updated_at, wallpaper_change_count)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP, COALESCE((SELECT wallpaper_change_count + 1 FROM whatsapp_user_settings WHERE user_id = ?), 1))
            ON CONFLICT(user_id) DO UPDATE SET
                wallpaper_url = COALESCE(excluded.wallpaper_url, wallpaper_url),
                wallpaper_color = COALESCE(excluded.wallpaper_color, wallpaper_color),
                wallpaper_change_count = wallpaper_change_count + 1,
                updated_at = CURRENT_TIMESTAMP
        ''', (user_id, wallpaper_url, wallpaper_color, user_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Wallpaper updated successfully'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/whatsapp/settings/wallpaper', methods=['DELETE'])
@login_required
def whatsapp_remove_wallpaper():
    """Remove user's wallpaper (reset to default)"""
    try:
        user_id = session.get('user_id')
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE whatsapp_user_settings 
            SET wallpaper_url = NULL, wallpaper_color = NULL, updated_at = CURRENT_TIMESTAMP
            WHERE user_id = ?
        ''', (user_id,))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Wallpaper removed, default restored'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================
# WHATSAPP FEATURES - QUICK REPLIES CRUD
# ============================================

@app.route('/api/whatsapp/quick-replies', methods=['GET'])
@login_required
def whatsapp_get_quick_replies():
    """Get all quick replies for the user"""
    try:
        user_id = session.get('user_id')
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, title, content, shortcut, category, created_at
            FROM whatsapp_quick_replies
            WHERE user_id = ?
            ORDER BY title ASC
        ''', (user_id,))
        
        replies = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return jsonify({
            'success': True,
            'quick_replies': replies
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/whatsapp/quick-replies', methods=['POST'])
@login_required
def whatsapp_create_quick_reply():
    """Create a new quick reply template"""
    try:
        user_id = session.get('user_id')
        data = request.get_json()
        
        title = data.get('title', '').strip()
        content = data.get('content', '').strip()
        shortcut = data.get('shortcut', '').strip()
        category = data.get('category', '').strip()
        
        if not title or not content:
            return jsonify({'success': False, 'error': 'Title and content are required'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO whatsapp_quick_replies (user_id, title, content, shortcut, category)
            VALUES (?, ?, ?, ?, ?)
        ''', (user_id, title, content, shortcut if shortcut else None, category if category else None))
        
        reply_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Quick reply created successfully',
            'id': reply_id
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/whatsapp/quick-replies/<int:reply_id>', methods=['PUT'])
@login_required
def whatsapp_update_quick_reply(reply_id):
    """Update an existing quick reply"""
    try:
        user_id = session.get('user_id')
        data = request.get_json()
        
        title = data.get('title', '').strip()
        content = data.get('content', '').strip()
        shortcut = data.get('shortcut', '').strip()
        category = data.get('category', '').strip()
        
        if not title or not content:
            return jsonify({'success': False, 'error': 'Title and content are required'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Verify ownership
        cursor.execute('SELECT id FROM whatsapp_quick_replies WHERE id = ? AND user_id = ?', (reply_id, user_id))
        if not cursor.fetchone():
            conn.close()
            return jsonify({'success': False, 'error': 'Quick reply not found'}), 404
        
        cursor.execute('''
            UPDATE whatsapp_quick_replies 
            SET title = ?, content = ?, shortcut = ?, category = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ? AND user_id = ?
        ''', (title, content, shortcut if shortcut else None, category if category else None, reply_id, user_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Quick reply updated successfully'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/whatsapp/quick-replies/<int:reply_id>', methods=['DELETE'])
@login_required
def whatsapp_delete_quick_reply(reply_id):
    """Delete a quick reply"""
    try:
        user_id = session.get('user_id')
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Verify ownership
        cursor.execute('SELECT id FROM whatsapp_quick_replies WHERE id = ? AND user_id = ?', (reply_id, user_id))
        if not cursor.fetchone():
            conn.close()
            return jsonify({'success': False, 'error': 'Quick reply not found'}), 404
        
        cursor.execute('DELETE FROM whatsapp_quick_replies WHERE id = ? AND user_id = ?', (reply_id, user_id))
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Quick reply deleted successfully'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================
# WHATSAPP FEATURES - AWAY MESSAGES
# ============================================

@app.route('/api/whatsapp/away-message', methods=['GET'])
@login_required
def whatsapp_get_away_message():
    """Get user's away message settings"""
    try:
        user_id = session.get('user_id')
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT is_enabled, message, start_time, end_time, days_of_week
            FROM whatsapp_away_messages
            WHERE user_id = ?
        ''', (user_id,))
        settings = cursor.fetchone()
        conn.close()
        
        if settings:
            return jsonify({
                'success': True,
                'is_enabled': bool(settings['is_enabled']),
                'message': settings['message'],
                'start_time': settings['start_time'],
                'end_time': settings['end_time'],
                'days_of_week': settings['days_of_week'].split(',') if settings['days_of_week'] else []
            })
        else:
            return jsonify({
                'success': True,
                'is_enabled': False,
                'message': "I'm currently away. Will respond when I return.",
                'start_time': None,
                'end_time': None,
                'days_of_week': []
            })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/whatsapp/away-message', methods=['PUT'])
@login_required
def whatsapp_update_away_message():
    """Update user's away message settings"""
    try:
        user_id = session.get('user_id')
        data = request.get_json()
        
        is_enabled = data.get('is_enabled', False)
        message = data.get('message', '').strip()
        start_time = data.get('start_time')
        end_time = data.get('end_time')
        days_of_week = data.get('days_of_week', [])
        
        if is_enabled and not message:
            return jsonify({'success': False, 'error': 'Message is required when away message is enabled'}), 400
        
        # Convert days_of_week list to comma-separated string
        days_str = ','.join(days_of_week) if days_of_week else None
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO whatsapp_away_messages (user_id, is_enabled, message, start_time, end_time, days_of_week, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id) DO UPDATE SET
                is_enabled = excluded.is_enabled,
                message = excluded.message,
                start_time = excluded.start_time,
                end_time = excluded.end_time,
                days_of_week = excluded.days_of_week,
                updated_at = CURRENT_TIMESTAMP
        ''', (user_id, 1 if is_enabled else 0, message, start_time, end_time, days_str))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Away message settings updated successfully'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================
# WHATSAPP FEATURES - AUTO-DOWNLOAD RULES
# ============================================

@app.route('/api/whatsapp/settings/auto-download', methods=['GET'])
@login_required
def whatsapp_get_auto_download():
    """Get user's auto-download settings"""
    try:
        user_id = session.get('user_id')
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT auto_download_photos, auto_download_videos, auto_download_documents, low_data_mode
            FROM whatsapp_user_settings
            WHERE user_id = ?
        ''', (user_id,))
        settings = cursor.fetchone()
        conn.close()
        
        if settings:
            return jsonify({
                'success': True,
                'photos': settings['auto_download_photos'],
                'videos': settings['auto_download_videos'],
                'documents': settings['auto_download_documents'],
                'low_data_mode': bool(settings['low_data_mode'])
            })
        else:
            # Default settings
            return jsonify({
                'success': True,
                'photos': 'wifi',
                'videos': 'never',
                'documents': 'wifi',
                'low_data_mode': False
            })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/whatsapp/settings/auto-download', methods=['PUT'])
@login_required
def whatsapp_update_auto_download():
    """Update user's auto-download settings"""
    try:
        user_id = session.get('user_id')
        data = request.get_json()
        
        photos = data.get('photos', 'wifi')
        videos = data.get('videos', 'never')
        documents = data.get('documents', 'wifi')
        low_data_mode = data.get('low_data_mode', False)
        
        # Validate options
        valid_options = ['wifi', 'never', 'always']
        if photos not in valid_options:
            photos = 'wifi'
        if videos not in valid_options:
            videos = 'never'
        if documents not in valid_options:
            documents = 'wifi'
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO whatsapp_user_settings (user_id, auto_download_photos, auto_download_videos, auto_download_documents, low_data_mode, updated_at)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            ON CONFLICT(user_id) DO UPDATE SET
                auto_download_photos = excluded.auto_download_photos,
                auto_download_videos = excluded.auto_download_videos,
                auto_download_documents = excluded.auto_download_documents,
                low_data_mode = excluded.low_data_mode,
                updated_at = CURRENT_TIMESTAMP
        ''', (user_id, photos, videos, documents, 1 if low_data_mode else 0))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Auto-download settings updated successfully'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================
# ESCROW PAYMENT SYSTEM API
# ============================================

import secrets

@app.route('/api/escrow/initiate', methods=['POST'])
@login_required
def escrow_initiate():
    """Buyer initiates escrow for a listing"""
    try:
        buyer_id = session.get('user_id')
        data = request.get_json()
        
        listing_id = data.get('listing_id')
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Get listing details
        cursor.execute('''
            SELECT id, title, price, seller_id, zeus_pin 
            FROM ghost_market_listings 
            WHERE id = ? AND status = 'active'
        ''', (listing_id,))
        listing = cursor.fetchone()
        
        if not listing:
            conn.close()
            return jsonify({'success': False, 'error': 'Listing not found'}), 404
        
        if listing['seller_id'] == buyer_id:
            conn.close()
            return jsonify({'success': False, 'error': 'Cannot buy your own item'}), 400
        
        # Generate unique transaction ID
        transaction_id = f"ESC-{secrets.token_hex(8).upper()}"
        
        # Create escrow transaction
        cursor.execute('''
            INSERT INTO escrow_transactions 
            (transaction_id, listing_id, buyer_id, seller_id, amount, status)
            VALUES (?, ?, ?, ?, ?, 'pending_payment')
        ''', (transaction_id, listing_id, buyer_id, listing['seller_id'], listing['price']))
        
        # Update listing status
        cursor.execute('UPDATE ghost_market_listings SET status = ? WHERE id = ?', ('pending_payment', listing_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'transaction_id': transaction_id,
            'amount': listing['price'],
            'message': 'Escrow created. Complete payment to secure item.'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/escrow/confirm-payment', methods=['POST'])
@login_required
def escrow_confirm_payment():
    """Confirm payment received"""
    try:
        user_id = session.get('user_id')
        data = request.get_json()
        
        transaction_id = data.get('transaction_id')
        payment_reference = data.get('payment_reference')
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE escrow_transactions 
            SET status = 'paid', payment_reference = ?, paid_at = CURRENT_TIMESTAMP
            WHERE transaction_id = ? AND buyer_id = ? AND status = 'pending_payment'
        ''', (payment_reference, transaction_id, user_id))
        
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({'success': False, 'error': 'Transaction not found or invalid status'}), 404
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Payment confirmed'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/escrow/mark-shipped', methods=['POST'])
@login_required
def escrow_mark_shipped():
    """Seller marks item as shipped"""
    try:
        user_id = session.get('user_id')
        data = request.get_json()
        
        transaction_id = data.get('transaction_id')
        tracking_number = data.get('tracking_number')
        carrier = data.get('carrier')
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE escrow_transactions 
            SET status = 'shipped', shipping_tracking = ?, shipping_carrier = ?, shipped_at = CURRENT_TIMESTAMP
            WHERE transaction_id = ? AND seller_id = ? AND status = 'paid'
        ''', (tracking_number, carrier, transaction_id, user_id))
        
        if cursor.rowcount == 0:
            conn.close()
            return jsonify({'success': False, 'error': 'Transaction not found or invalid status'}), 404
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Item marked as shipped'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/escrow/confirm-delivery', methods=['POST'])
@login_required
def escrow_confirm_delivery():
    """Buyer confirms delivery - releases funds to seller"""
    try:
        user_id = session.get('user_id')
        data = request.get_json()
        
        transaction_id = data.get('transaction_id')
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Get transaction details
        cursor.execute('''
            SELECT seller_id, amount FROM escrow_transactions 
            WHERE transaction_id = ? AND buyer_id = ? AND status = 'shipped'
        ''', (transaction_id, user_id))
        transaction = cursor.fetchone()
        
        if not transaction:
            conn.close()
            return jsonify({'success': False, 'error': 'Transaction not found or invalid status'}), 404
        
        # Update transaction
        cursor.execute('''
            UPDATE escrow_transactions 
            SET status = 'completed', buyer_confirmed = 1, delivered_at = CURRENT_TIMESTAMP, completed_at = CURRENT_TIMESTAMP
            WHERE transaction_id = ?
        ''', (transaction_id,))
        
        # Add funds to seller's wallet
        cursor.execute('''
            INSERT INTO seller_wallets (user_id, balance, total_earned)
            VALUES (?, ?, ?)
            ON CONFLICT(user_id) DO UPDATE SET
                balance = balance + ?,
                total_earned = total_earned + ?
        ''', (transaction['seller_id'], transaction['amount'], transaction['amount'], transaction['amount'], transaction['amount']))
        
        # Update listing as sold
        cursor.execute('''
            UPDATE ghost_market_listings 
            SET status = 'sold', sold_at = CURRENT_TIMESTAMP
            WHERE id = (SELECT listing_id FROM escrow_transactions WHERE transaction_id = ?)
        ''', (transaction_id,))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Delivery confirmed. Funds released to seller.'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================
# CREATOR TIPPING SYSTEM (R5 - R50)
# ============================================

@app.route('/api/ghost/post/<int:post_id>/tip', methods=['POST'])
@login_required
def ghost_tip_creator(post_id):
    """Tip a creator for their content (R5 - R50)"""
    try:
        tipper_id = session.get('user_id')
        data = request.get_json()
        
        amount = data.get('amount', 0)
        message = data.get('message', '').strip()
        
        # Validate amount (R5 - R50)
        if amount < 5 or amount > 50:
            return jsonify({'success': False, 'error': 'Tip amount must be between R5 and R50'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Get post and creator info
        cursor.execute('''
            SELECT id, user_id as creator_id, zeus_pin, title, is_paid
            FROM ghost_posts 
            WHERE id = ? AND status = 'approved'
        ''', (post_id,))
        post = cursor.fetchone()
        
        if not post:
            conn.close()
            return jsonify({'success': False, 'error': 'Post not found'}), 404
        
        if post['creator_id'] == tipper_id:
            conn.close()
            return jsonify({'success': False, 'error': 'You cannot tip your own content'}), 400
        
        # Create tip record
        cursor.execute('''
            INSERT INTO creator_tips (post_id, tipper_id, creator_id, amount, message, status)
            VALUES (?, ?, ?, ?, ?, 'pending')
        ''', (post_id, tipper_id, post['creator_id'], amount, message))
        
        tip_id = cursor.lastrowid
        
        # Create escrow for tip
        transaction_id = f"TIP-{secrets.token_hex(8).upper()}"
        cursor.execute('''
            INSERT INTO escrow_transactions 
            (transaction_id, listing_id, buyer_id, seller_id, amount, status)
            VALUES (?, ?, ?, ?, ?, 'pending_payment')
        ''', (transaction_id, post_id, tipper_id, post['creator_id'], amount))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'tip_id': tip_id,
            'transaction_id': transaction_id,
            'amount': amount,
            'message': f'Tip of R{amount} created. Complete payment to send to creator.'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/ghost/creator/earnings', methods=['GET'])
@login_required
def ghost_creator_earnings():
    """Get creator's total earnings from tips and paid content"""
    try:
        user_id = session.get('user_id')
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Get tips received (80% to creator)
        cursor.execute('''
            SELECT 
                COUNT(*) as total_tips,
                COALESCE(SUM(amount), 0) as total_tip_amount,
                COALESCE(SUM(amount * 0.8), 0) as creator_tip_earnings
            FROM creator_tips
            WHERE creator_id = ? AND status = 'completed'
        ''', (user_id,))
        tips = cursor.fetchone()
        
        # Get paid content earnings (80% to creator)
        cursor.execute('''
            SELECT 
                COUNT(*) as total_paid_views,
                COALESCE(SUM(price), 0) as total_paid_amount,
                COALESCE(SUM(price * 0.8), 0) as creator_content_earnings
            FROM ghost_posts
            WHERE user_id = ? AND is_paid = 1 AND status = 'approved'
        ''', (user_id,))
        paid_content = cursor.fetchone()
        
        # Get wallet balance
        cursor.execute('''
            SELECT balance, pending_balance, total_earned, total_withdrawn
            FROM seller_wallets WHERE user_id = ?
        ''', (user_id,))
        wallet = cursor.fetchone()
        
        conn.close()
        
        total_earnings = (tips['creator_tip_earnings'] or 0) + (paid_content['creator_content_earnings'] or 0)
        
        return jsonify({
            'success': True,
            'earnings': {
                'tips': {
                    'count': tips['total_tips'] or 0,
                    'total_amount': float(tips['total_tip_amount'] or 0),
                    'creator_share': float(tips['creator_tip_earnings'] or 0)
                },
                'paid_content': {
                    'views': paid_content['total_paid_views'] or 0,
                    'total_amount': float(paid_content['total_paid_amount'] or 0),
                    'creator_share': float(paid_content['creator_content_earnings'] or 0)
                },
                'total_earnings': float(total_earnings),
                'wallet_balance': float(wallet['balance'] or 0) if wallet else 0,
                'pending_balance': float(wallet['pending_balance'] or 0) if wallet else 0,
                'total_withdrawn': float(wallet['total_withdrawn'] or 0) if wallet else 0
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/ghost/creator/withdraw', methods=['POST'])
@login_required
def ghost_creator_withdraw():
    """Request withdrawal from creator wallet"""
    try:
        user_id = session.get('user_id')
        data = request.get_json()
        
        amount = data.get('amount', 0)
        bank_name = data.get('bank_name')
        account_number = data.get('account_number')
        account_holder = data.get('account_holder')
        branch_code = data.get('branch_code')
        
        if amount < 100:
            return jsonify({'success': False, 'error': 'Minimum withdrawal amount is R100'}), 400
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Check wallet balance
        cursor.execute('SELECT balance FROM seller_wallets WHERE user_id = ?', (user_id,))
        wallet = cursor.fetchone()
        
        if not wallet or wallet['balance'] < amount:
            conn.close()
            return jsonify({'success': False, 'error': 'Insufficient balance'}), 400
        
        # Create withdrawal request
        cursor.execute('''
            INSERT INTO withdrawal_requests 
            (user_id, amount, bank_name, account_number, account_holder, branch_code, status)
            VALUES (?, ?, ?, ?, ?, ?, 'pending')
        ''', (user_id, amount, bank_name, account_number, account_holder, branch_code))
        
        # Update wallet balance
        cursor.execute('''
            UPDATE seller_wallets 
            SET balance = balance - ?, total_withdrawn = total_withdrawn + ?
            WHERE user_id = ?
        ''', (amount, amount, user_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': f'Withdrawal request of R{amount} submitted for processing'
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================
# SELLER PROFILE SUMMARY (AI-GENERATED)
# ============================================

@app.route('/api/ghost/market/seller/<int:seller_id>/profile-summary', methods=['GET'])
@login_required
def ghost_market_seller_profile_summary(seller_id):
    """Get AI-generated seller profile summary"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Get seller's listing history
        cursor.execute('''
            SELECT 
                COUNT(*) as total_listings,
                SUM(CASE WHEN status = 'sold' THEN 1 ELSE 0 END) as items_sold,
                AVG(price) as avg_price,
                AVG(views_count) as avg_views,
                AVG(saves_count) as avg_saves,
                MIN(created_at) as first_listing,
                MAX(created_at) as last_listing
            FROM ghost_market_listings
            WHERE seller_id = ? AND status IN ('active', 'sold')
        ''', (seller_id,))
        stats = cursor.fetchone()
        
        # Get average rating
        cursor.execute('''
            SELECT AVG(rating) as avg_rating, COUNT(*) as rating_count
            FROM ghost_market_ratings
            WHERE seller_id = ?
        ''', (seller_id,))
        rating = cursor.fetchone()
        
        # Get top categories
        cursor.execute('''
            SELECT category, COUNT(*) as count
            FROM ghost_market_listings
            WHERE seller_id = ? AND status IN ('active', 'sold')
            GROUP BY category
            ORDER BY count DESC
            LIMIT 3
        ''', (seller_id,))
        top_categories = [dict(row) for row in cursor.fetchall()]
        
        # Get seller zeus_pin (masked)
        cursor.execute('SELECT zeus_pin FROM users WHERE id = ?', (seller_id,))
        user = cursor.fetchone()
        
        conn.close()
        
        # Generate AI summary text
        items_sold = stats['items_sold'] or 0
        total_listings = stats['total_listings'] or 0
        avg_rating = round(float(rating['avg_rating'] or 0), 1)
        rating_count = rating['rating_count'] or 0
        
        if items_sold == 0 and total_listings == 0:
            summary = "New seller on Ghost Market. No transaction history yet."
        elif items_sold == 0 and total_listings > 0:
            summary = f"Active seller with {total_listings} listings. Waiting for first sale."
        elif items_sold > 0 and rating_count == 0:
            summary = f"Seller has successfully sold {items_sold} item(s). No ratings yet."
        elif avg_rating >= 4.5:
            summary = f"Top-rated seller! {items_sold} item(s) sold with {rating_count} reviews averaging {avg_rating} stars. Highly recommended."
        elif avg_rating >= 3.5:
            summary = f"Good seller with {items_sold} item(s) sold. {rating_count} reviews average {avg_rating} stars."
        else:
            summary = f"Seller has completed {items_sold} sale(s). {rating_count} reviews average {avg_rating} stars."
        
        # Add category expertise
        if top_categories:
            categories_str = ", ".join([c['category'] for c in top_categories[:2]])
            summary += f" Specializes in {categories_str}."
        
        # Add response time estimate
        summary += " Typically responds within 24 hours."
        
        return jsonify({
            'success': True,
            'seller_id': seller_id,
            'seller_zeus_pin': user['zeus_pin'][:3] + '-****-****' if user else 'Unknown',
            'summary': summary,
            'stats': {
                'total_listings': total_listings,
                'items_sold': items_sold,
                'avg_price': round(float(stats['avg_price'] or 0), 2),
                'avg_views': round(float(stats['avg_views'] or 0), 1),
                'avg_saves': round(float(stats['avg_saves'] or 0), 1),
                'member_since': stats['first_listing'].split(' ')[0] if stats['first_listing'] else 'Unknown'
            },
            'rating': {
                'average': avg_rating,
                'count': rating_count
            },
            'top_categories': top_categories
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/ghost/market/seller/<int:seller_id>/listing-history', methods=['GET'])
@login_required
def ghost_market_seller_listing_history(seller_id):
    """Get seller's listing history (past sold items)"""
    try:
        limit = request.args.get('limit', 20, type=int)
        offset = request.args.get('offset', 0, type=int)
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT id, title, price, images, condition, category,
                   created_at, sold_at, views_count, saves_count
            FROM ghost_market_listings
            WHERE seller_id = ? AND status = 'sold'
            ORDER BY sold_at DESC
            LIMIT ? OFFSET ?
        ''', (seller_id, limit, offset))
        
        listings = [dict(row) for row in cursor.fetchall()]
        
        # Parse images JSON
        for listing in listings:
            if listing.get('images'):
                try:
                    import json
                    listing['images'] = json.loads(listing['images'])
                except:
                    listing['images'] = [listing['images']] if listing['images'] else []
            else:
                listing['images'] = []
        
        conn.close()
        
        return jsonify({
            'success': True,
            'listings': listings,
            'hasMore': len(listings) == limit
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================
# ADMIN CONTROL SYSTEM
# ============================================

# Admin decorator
def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function


# ============================================
# ADMIN - FLAGGED CONTENT (Posts & Comments)
# ============================================

@app.route('/api/admin/flagged/posts', methods=['GET'])
@admin_required
def admin_get_flagged_posts():
    """Get posts flagged by system for review"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Get posts that need admin review (status = 'flagged' or created recently with violations)
        cursor.execute('''
            SELECT p.id, p.user_id, u.zeus_pin, p.content_type, p.text_content, 
                   p.media_url, p.created_at, p.status, p.report_count,
                   COUNT(DISTINCT r.id) as report_count,
                   GROUP_CONCAT(DISTINCT r.reason) as report_reasons
            FROM ghost_posts p
            JOIN users u ON u.id = p.user_id
            LEFT JOIN ghost_reports r ON r.post_id = p.id
            WHERE p.status IN ('pending', 'flagged')
            GROUP BY p.id
            ORDER BY p.created_at DESC
        ''')
        
        posts = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return jsonify({'success': True, 'posts': posts})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/admin/flagged/comments', methods=['GET'])
@admin_required
def admin_get_flagged_comments():
    """Get comments flagged by system for review"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT c.id, c.post_id, c.user_id, u.zeus_pin, c.comment_text, 
                   c.created_at, c.status, c.report_count
            FROM ghost_comments c
            JOIN users u ON u.id = c.user_id
            WHERE c.status IN ('pending', 'flagged')
            ORDER BY c.created_at DESC
        ''')
        
        comments = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return jsonify({'success': True, 'comments': comments})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/admin/content/<string:type>/<int:content_id>/approve', methods=['POST'])
@admin_required
def admin_approve_content(type, content_id):
    """Approve flagged content (post or comment)"""
    try:
        admin_id = session.get('admin_id')
        data = request.get_json()
        notes = data.get('notes', '')
        
        conn = get_db()
        cursor = conn.cursor()
        
        if type == 'post':
            cursor.execute('''
                UPDATE ghost_posts SET status = 'approved', admin_notes = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (notes, content_id))
        elif type == 'comment':
            cursor.execute('''
                UPDATE ghost_comments SET status = 'approved', admin_notes = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (notes, content_id))
        else:
            conn.close()
            return jsonify({'success': False, 'error': 'Invalid content type'}), 400
        
        # Log admin action
        cursor.execute('''
            INSERT INTO admin_actions (admin_id, action_type, target_type, target_id, details)
            VALUES (?, 'approve', ?, ?, ?)
        ''', (admin_id, type, content_id, f'Approved by admin. Notes: {notes}'))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': f'{type.capitalize()} approved successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/admin/content/<string:type>/<int:content_id>/reject', methods=['POST'])
@admin_required
def admin_reject_content(type, content_id):
    """Reject flagged content (post or comment)"""
    try:
        admin_id = session.get('admin_id')
        data = request.get_json()
        reason = data.get('reason', '')
        
        conn = get_db()
        cursor = conn.cursor()
        
        if type == 'post':
            cursor.execute('''
                UPDATE ghost_posts SET status = 'rejected', rejection_reason = ?, admin_notes = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (reason, reason, content_id))
            
            # Get user_id to notify
            cursor.execute('SELECT user_id, text_content FROM ghost_posts WHERE id = ?', (content_id,))
            post = cursor.fetchone()
            
        elif type == 'comment':
            cursor.execute('''
                UPDATE ghost_comments SET status = 'rejected', rejection_reason = ?, admin_notes = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (reason, reason, content_id))
        else:
            conn.close()
            return jsonify({'success': False, 'error': 'Invalid content type'}), 400
        
        # Log admin action
        cursor.execute('''
            INSERT INTO admin_actions (admin_id, action_type, target_type, target_id, details)
            VALUES (?, 'reject', ?, ?, ?)
        ''', (admin_id, type, content_id, f'Rejected. Reason: {reason}'))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': f'{type.capitalize()} rejected'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================
# ADMIN - USER MANAGEMENT
# ============================================

@app.route('/api/admin/users', methods=['GET'])
@admin_required
def admin_get_all_users():
    """Get all users with their details"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT u.id, u.zeus_pin, u.full_name, u.email, u.created_at, u.is_verified, 
                   u.is_active, u.last_login,
                   COALESCE(w.balance, 0) as wallet_balance,
                   COALESCE(p.post_count, 0) as post_count,
                   COALESCE(l.listing_count, 0) as listing_count
            FROM users u
            LEFT JOIN seller_wallets w ON w.user_id = u.id
            LEFT JOIN (SELECT user_id, COUNT(*) as post_count FROM ghost_posts GROUP BY user_id) p ON p.user_id = u.id
            LEFT JOIN (SELECT seller_id, COUNT(*) as listing_count FROM ghost_market_listings GROUP BY seller_id) l ON l.seller_id = u.id
            ORDER BY u.created_at DESC
        ''')
        
        users = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return jsonify({'success': True, 'users': users})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/admin/users/<int:user_id>', methods=['GET'])
@admin_required
def admin_get_user_detail(user_id):
    """Get detailed user information including KYC"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # Get user basic info
        cursor.execute('''
            SELECT u.id, u.zeus_pin, u.full_name, u.email, u.phone, u.created_at, 
                   u.is_verified, u.is_active, u.last_login,
                   ui.id_type, ui.id_number, ui.id_document_front, ui.id_document_back, 
                   ui.selfie_with_id, ui.verification_status
            FROM users u
            LEFT JOIN user_identification ui ON ui.user_id = u.id
            WHERE u.id = ?
        ''', (user_id,))
        user = cursor.fetchone()
        
        if not user:
            conn.close()
            return jsonify({'success': False, 'error': 'User not found'}), 404
        
        # Get user's posts
        cursor.execute('''
            SELECT id, content_type, text_content, created_at, status, views_count, likes_count
            FROM ghost_posts WHERE user_id = ? ORDER BY created_at DESC LIMIT 10
        ''', (user_id,))
        posts = [dict(row) for row in cursor.fetchall()]
        
        # Get user's listings
        cursor.execute('''
            SELECT id, title, price, status, views_count, saves_count, created_at
            FROM ghost_market_listings WHERE seller_id = ? ORDER BY created_at DESC LIMIT 10
        ''', (user_id,))
        listings = [dict(row) for row in cursor.fetchall()]
        
        # Get user's transactions
        cursor.execute('''
            SELECT transaction_id, amount, status, created_at, completed_at
            FROM escrow_transactions WHERE buyer_id = ? OR seller_id = ?
            ORDER BY created_at DESC LIMIT 10
        ''', (user_id, user_id))
        transactions = [dict(row) for row in cursor.fetchall()]
        
        conn.close()
        
        return jsonify({
            'success': True,
            'user': dict(user),
            'posts': posts,
            'listings': listings,
            'transactions': transactions
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/admin/users/<int:user_id>/suspend', methods=['POST'])
@admin_required
def admin_suspend_user(user_id):
    """Suspend a user account"""
    try:
        admin_id = session.get('admin_id')
        data = request.get_json()
        reason = data.get('reason', '')
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE users SET is_active = 0, suspended_at = CURRENT_TIMESTAMP, suspension_reason = ?
            WHERE id = ?
        ''', (reason, user_id))
        
        # Log admin action
        cursor.execute('''
            INSERT INTO admin_actions (admin_id, action_type, target_user_id, details)
            VALUES (?, 'suspend_user', ?, ?)
        ''', (admin_id, user_id, f'User suspended. Reason: {reason}'))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'User suspended successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/admin/users/<int:user_id>/reactivate', methods=['POST'])
@admin_required
def admin_reactivate_user(user_id):
    """Reactivate a suspended user account"""
    try:
        admin_id = session.get('admin_id')
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE users SET is_active = 1, suspended_at = NULL, suspension_reason = NULL
            WHERE id = ?
        ''', (user_id,))
        
        # Log admin action
        cursor.execute('''
            INSERT INTO admin_actions (admin_id, action_type, target_user_id, details)
            VALUES (?, 'reactivate_user', ?, 'User account reactivated')
        ''', (admin_id, user_id))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'User reactivated successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/admin/users/<int:user_id>/delete', methods=['DELETE'])
@admin_required
def admin_delete_user(user_id):
    """Permanently delete a user account"""
    try:
        admin_id = session.get('admin_id')
        data = request.get_json()
        reason = data.get('reason', '')
        
        conn = get_db()
        cursor = conn.cursor()
        
        # Soft delete - mark as deleted
        cursor.execute('''
            UPDATE users SET is_active = 0, deleted_at = CURRENT_TIMESTAMP, deletion_reason = ?
            WHERE id = ?
        ''', (reason, user_id))
        
        # Log admin action
        cursor.execute('''
            INSERT INTO admin_actions (admin_id, action_type, target_user_id, details)
            VALUES (?, 'delete_user', ?, ?)
        ''', (admin_id, user_id, f'User deleted. Reason: {reason}'))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'User deleted successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================
# ADMIN - ESCROW DISPUTE RESOLUTION
# ============================================

@app.route('/api/admin/escrow/disputes', methods=['GET'])
@admin_required
def admin_get_escrow_disputes():
    """Get all disputed escrow transactions"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT e.*, 
                   b.zeus_pin as buyer_pin, s.zeus_pin as seller_pin,
                   l.title as listing_title
            FROM escrow_transactions e
            JOIN users b ON b.id = e.buyer_id
            JOIN users s ON s.id = e.seller_id
            JOIN ghost_market_listings l ON l.id = e.listing_id
            WHERE e.status = 'disputed'
            ORDER BY e.created_at DESC
        ''')
        
        disputes = [dict(row) for row in cursor.fetchall()]
        conn.close()
        
        return jsonify({'success': True, 'disputes': disputes})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/admin/escrow/dispute/<int:transaction_id>/resolve', methods=['POST'])
@admin_required
def admin_resolve_dispute(transaction_id):
    """Resolve an escrow dispute"""
    try:
        admin_id = session.get('admin_id')
        data = request.get_json()
        
        resolution = data.get('resolution')  # 'refund_buyer', 'release_to_seller', 'split'
        admin_notes = data.get('admin_notes', '')
        
        conn = get_db()
        cursor = conn.cursor()
        
        if resolution == 'refund_buyer':
            cursor.execute('''
                UPDATE escrow_transactions 
                SET status = 'refunded', dispute_resolution = ?, dispute_resolved_by = ?, refunded_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (f'Refunded to buyer. {admin_notes}', admin_id, transaction_id))
        elif resolution == 'release_to_seller':
            cursor.execute('''
                UPDATE escrow_transactions 
                SET status = 'completed', dispute_resolution = ?, dispute_resolved_by = ?, completed_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (f'Released to seller. {admin_notes}', admin_id, transaction_id))
            
            # Release funds to seller
            cursor.execute('''
                SELECT seller_id, amount FROM escrow_transactions WHERE id = ?
            ''', (transaction_id,))
            tx = cursor.fetchone()
            if tx:
                cursor.execute('''
                    INSERT INTO seller_wallets (user_id, balance, total_earned)
                    VALUES (?, ?, ?)
                    ON CONFLICT(user_id) DO UPDATE SET
                        balance = balance + ?,
                        total_earned = total_earned + ?
                ''', (tx['seller_id'], tx['amount'], tx['amount'], tx['amount'], tx['amount']))
        else:
            conn.close()
            return jsonify({'success': False, 'error': 'Invalid resolution'}), 400
        
        # Log admin action
        cursor.execute('''
            INSERT INTO admin_actions (admin_id, action_type, target_id, details)
            VALUES (?, 'resolve_dispute', ?, ?)
        ''', (admin_id, transaction_id, f'Dispute resolved: {resolution}. {admin_notes}'))
        
        conn.commit()
        conn.close()
        
        return jsonify({'success': True, 'message': 'Dispute resolved successfully'})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================
# ADMIN - SYSTEM STATISTICS
# ============================================

@app.route('/api/admin/stats', methods=['GET'])
@admin_required
def admin_get_system_stats():
    """Get system-wide statistics"""
    try:
        conn = get_db()
        cursor = conn.cursor()
        
        # User stats
        cursor.execute('SELECT COUNT(*) as total FROM users')
        total_users = cursor.fetchone()['total']
        
        cursor.execute('SELECT COUNT(*) as active FROM users WHERE is_active = 1')
        active_users = cursor.fetchone()['active']
        
        # Content stats
        cursor.execute('SELECT COUNT(*) as total FROM ghost_posts')
        total_posts = cursor.fetchone()['total']
        
        cursor.execute('SELECT COUNT(*) as pending FROM ghost_posts WHERE status = "pending"')
        pending_posts = cursor.fetchone()['pending']
        
        cursor.execute('SELECT COUNT(*) as flagged FROM ghost_posts WHERE status = "flagged"')
        flagged_posts = cursor.fetchone()['flagged']
        
        # Market stats
        cursor.execute('SELECT COUNT(*) as total FROM ghost_market_listings')
        total_listings = cursor.fetchone()['total']
        
        cursor.execute('SELECT COUNT(*) as pending FROM ghost_market_listings WHERE status = "pending"')
        pending_listings = cursor.fetchone()['pending']
        
        # Financial stats
        cursor.execute('SELECT COALESCE(SUM(amount), 0) as total_volume FROM escrow_transactions WHERE status = "completed"')
        total_volume = cursor.fetchone()['total_volume']
        
        cursor.execute('SELECT COALESCE(SUM(balance), 0) as total_balance FROM seller_wallets')
        total_wallet_balance = cursor.fetchone()['total_balance']
        
        conn.close()
        
        return jsonify({
            'success': True,
            'stats': {
                'users': {
                    'total': total_users,
                    'active': active_users
                },
                'content': {
                    'total_posts': total_posts,
                    'pending_posts': pending_posts,
                    'flagged_posts': flagged_posts,
                    'total_listings': total_listings,
                    'pending_listings': pending_listings
                },
                'financial': {
                    'total_escrow_volume': float(total_volume),
                    'total_wallet_balance': float(total_wallet_balance)
                }
            }
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# ============================================
# ADMIN - ADMIN ACTION LOGS
# ============================================

@app.route('/api/admin/actions/logs', methods=['GET'])
@admin_required
def admin_get_action_logs():
    """Get admin action logs"""
    try:
        limit = request.args.get('limit', 50, type=int)
        offset = request.args.get('offset', 0, type=int)
        
        conn = get_db()
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT a.*, u.zeus_pin as admin_pin,
                   tu.zeus_pin as target_user_pin
            FROM admin_actions a
            LEFT JOIN users u ON u.id = a.admin_id
            LEFT JOIN users tu ON tu.id = a.target_user_id
            ORDER BY a.created_at DESC
            LIMIT ? OFFSET ?
        ''', (limit, offset))
        
        logs = [dict(row) for row in cursor.fetchall()]
        
        # Get total count
        cursor.execute('SELECT COUNT(*) as total FROM admin_actions')
        total = cursor.fetchone()['total']
        
        conn.close()
        
        return jsonify({
            'success': True,
            'logs': logs,
            'total': total,
            'hasMore': len(logs) == limit
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500

# ============================================
# ADMIN REQUIRED DECORATOR
# ============================================

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            return jsonify({'success': False, 'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function


# ============================================
# STATIC FILE ROUTES
# ============================================

@app.route('/')
def index():
    return send_file('index.html')

@app.route('/<path:filename>.html')
def serve_html(filename):
    try:
        return send_file(f'{filename}.html')
    except:
        return jsonify({'error': 'Page not found'}), 404

