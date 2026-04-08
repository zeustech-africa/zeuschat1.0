let currentFeed = [];
let currentPostIdForPay = null;
let isLoading = false;
let hasMore = true;
let page = 1;
let csrfToken = null;

async function ensureCsrfToken(forceRefresh = false) {
    if (csrfToken && !forceRefresh) return csrfToken;
    const response = await window.fetch('/api/csrf-token', { method: 'GET', credentials: 'include' });
    const data = await response.json();
    csrfToken = data.csrf_token || null;
    return csrfToken;
}

async function apiFetch(url, options = {}) {
    const requestOptions = { ...options };
    const method = (requestOptions.method || 'GET').toUpperCase();
    requestOptions.method = method;
    requestOptions.credentials = requestOptions.credentials || 'include';
    requestOptions.headers = { ...(requestOptions.headers || {}) };

    if (!['GET', 'HEAD', 'OPTIONS'].includes(method)) {
        const token = await ensureCsrfToken();
        if (token) requestOptions.headers['X-CSRF-Token'] = token;
    }

    return window.fetch(url, requestOptions);
}

async function loadFeed(reset = false) {
    if (isLoading) return;
    if (reset) {
        page = 1;
        hasMore = true;
        currentFeed = [];
        document.getElementById('feedContainer').innerHTML = '<div id="postsLoader" style="text-align:center;padding:40px;color:#D4AF37;">Loading...</div>';
    }
    if (!hasMore) return;

    isLoading = true;
    try {
        const response = await apiFetch(`/api/ghost/feed?page=${page}&limit=10`);
        const data = await response.json();

        if (!response.ok || !data.success) {
            const message = data.error || 'Failed to load feed';
            document.getElementById('feedContainer').innerHTML = `<div id="postsLoader" style="text-align:center;padding:40px;color:#ef4444;">${escapeHtml(message)}</div>`;
            return;
        }

        if ((data.posts || []).length < 10) hasMore = false;
        currentFeed = [...currentFeed, ...(data.posts || [])];
        renderFeed(data.posts || [], page > 1);
        page += 1;
    } finally {
        isLoading = false;
    }
}

function renderFeed(posts, append = true) {
    const container = document.getElementById('feedContainer');
    if (!append) container.innerHTML = '';

    const html = posts.map((post) => {
        const commentsPreview = renderComments(post.comments || []);
        return `
        <div class="post-card" data-post-id="${post.id}" data-is-paid="${post.is_paid}" data-price="${post.price}">
            ${post.report_count >= 3 ? '<div class="report-flag">⚠️ Content under review</div>' : ''}
            <button class="report-btn" onclick="reportPost(${post.id})">🚩</button>

            <div class="media-container" id="media-${post.id}">
                ${renderMedia(post)}
                ${post.is_paid && !post.user_purchased && post.user_id !== getCurrentUserId() ? `
                    <div class="paid-overlay">
                        <div class="price-tag">💰 R${post.price} to Unlock</div>
                        <button class="unlock-btn" onclick="event.stopPropagation(); showPayModal(${post.id}, ${post.price})">Unlock →</button>
                    </div>
                ` : ''}
            </div>

            <div class="post-info">
                <div class="post-title">${escapeHtml(post.title || '')}</div>
                <div>${escapeHtml(post.content || '')}</div>
                <div class="post-stats">
                    <span>👻 ${escapeHtml(post.anonymous_id || 'Anonymous')}</span>
                    <span>⏱️ ${getTimeRemaining(post.expires_at)}</span>
                    <span>👁️ ${post.view_count || 0} views</span>
                </div>

                <div class="action-buttons">
                    <button class="action-btn ${post.user_upvoted ? 'active' : ''}" onclick="votePost(${post.id}, 1)">👍 <span id="upvotes-${post.id}">${post.upvotes || 0}</span></button>
                    <button class="action-btn ${post.user_downvoted ? 'active' : ''}" onclick="votePost(${post.id}, -1)">👎 <span id="downvotes-${post.id}">${post.downvotes || 0}</span></button>
                    <button class="action-btn" onclick="toggleComments(${post.id})">💬 <span id="comment-count-${post.id}">${post.comment_count || 0}</span></button>
                    <button class="action-btn" onclick="sharePost(${post.id})">↗️ Share</button>
                </div>

                <div id="comments-section-${post.id}" class="comments-section hidden">
                    ${commentsPreview}
                    <div class="comment-input" style="display:flex; gap:8px; margin-top:8px;">
                        <input type="text" id="comment-input-${post.id}" placeholder="Write a comment..." style="width:80%; padding:8px; border-radius:20px; border:1px solid #444; background:#111; color:#fff;">
                        <button class="secondary-action" style="padding:8px 12px;" onclick="addComment(${post.id})">Post</button>
                    </div>
                </div>
            </div>
        </div>`;
    }).join('');

    container.insertAdjacentHTML('beforeend', html);
}

function renderMedia(post) {
    if (!post.media_url) {
        return '<div style="padding:40px; text-align:center; color:#bbb;">📝 Text Post</div>';
    }

    const blurClass = (post.is_paid && !post.user_purchased && post.user_id !== getCurrentUserId()) ? 'blurred-preview' : '';

    if (post.media_type === 'video') {
        return `<video class="${blurClass}" controls playsinline>
                    <source src="${post.media_url}" type="video/mp4">
                </video>`;
    }
    return `<img src="${post.media_url}" class="${blurClass}" alt="Ghost media">`;
}

function showPayModal(postId, price) {
    currentPostIdForPay = postId;
    document.getElementById('payModalTitle').textContent = 'Locked Content';
    document.getElementById('payModalPrice').textContent = `Price: R${price}`;
    document.getElementById('payModal').classList.remove('hidden');
}

async function votePost(postId, voteType) {
    const response = await apiFetch('/api/ghost/vote', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ post_id: postId, vote_type: voteType }),
    });
    const data = await response.json();
    if (response.ok && data.success) {
        document.getElementById(`upvotes-${postId}`).innerText = data.upvotes;
        document.getElementById(`downvotes-${postId}`).innerText = data.downvotes;
        return;
    }
    alert(data.error || 'Failed to vote');
}

async function reportPost(postId) {
    const reason = prompt('Why are you reporting this post?');
    if (!reason) return;

    const details = prompt('Additional details (optional):') || '';
    const response = await apiFetch('/api/ghost/report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ post_id: postId, reason, details }),
    });
    const data = await response.json();
    alert(data.message || data.error || 'Report submitted.');
}

async function toggleComments(postId) {
    const section = document.getElementById(`comments-section-${postId}`);
    if (!section) return;

    if (!section.classList.contains('hidden')) {
        section.classList.add('hidden');
        return;
    }

    const response = await apiFetch(`/api/ghost/comments/${postId}`);
    const data = await response.json();
    if (response.ok && data.success) {
        section.innerHTML = renderComments(data.comments || []) + `
            <div class="comment-input" style="display:flex; gap:8px; margin-top:8px;">
                <input type="text" id="comment-input-${postId}" placeholder="Write a comment..." style="width:80%; padding:8px; border-radius:20px; border:1px solid #444; background:#111; color:#fff;">
                <button class="secondary-action" style="padding:8px 12px;" onclick="addComment(${postId})">Post</button>
            </div>`;
        section.classList.remove('hidden');
        return;
    }
    alert(data.error || 'Failed to load comments');
}

async function addComment(postId) {
    const input = document.getElementById(`comment-input-${postId}`);
    if (!input) return;
    const content = input.value.trim();
    if (!content) return;

    const response = await apiFetch('/api/ghost/comment', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ post_id: postId, content }),
    });
    const data = await response.json();
    if (response.ok && data.success) {
        input.value = '';
        const countEl = document.getElementById(`comment-count-${postId}`);
        if (countEl) countEl.textContent = String((Number(countEl.textContent || '0') || 0) + 1);
        await toggleComments(postId);
        await toggleComments(postId);
        return;
    }
    alert(data.error || 'Failed to comment');
}

function renderComments(comments) {
    if (!comments.length) return '<div class="empty-state">No comments yet. Be the first!</div>';

    return comments.map((c) => `
        <div class="comment ${c.parent_comment_id ? 'reply' : ''}">
            <strong>👻 ${escapeHtml(c.anonymous_id || 'Anonymous')}</strong>
            <p>${escapeHtml(c.content || '')}</p>
            <small>👍 ${c.upvotes || 0}</small>
        </div>
    `).join('');
}

function getCurrentUserId() {
    const raw = sessionStorage.getItem('user_id');
    return raw ? Number(raw) : null;
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text || '';
    return div.innerHTML;
}

function getTimeRemaining(expiresAt) {
    const diff = new Date(expiresAt) - new Date();
    if (Number.isNaN(diff) || diff <= 0) return 'Expired';
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
    return `${hours}h ${minutes}m remaining`;
}

function sharePost(postId) {
    const shareUrl = `${window.location.origin}/ghost-ultimate#post-${postId}`;
    if (navigator.share) {
        navigator.share({ title: 'Ghost Community Post', url: shareUrl }).catch(() => {});
    } else {
        navigator.clipboard.writeText(shareUrl).then(() => alert('Post link copied!')).catch(() => alert(shareUrl));
    }
}

function bindModalActions() {
    document.getElementById('confirmPayBtn')?.addEventListener('click', async () => {
        if (!currentPostIdForPay) return;
        const response = await apiFetch('/api/ghost/pay', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ post_id: currentPostIdForPay }),
        });
        const data = await response.json();
        if (response.ok && data.success) {
            alert('Payment successful! Content unlocked.');
            document.getElementById('payModal').classList.add('hidden');
            loadFeed(true);
            return;
        }
        alert(data.error || 'Payment failed');
    });

    document.getElementById('cancelPayBtn')?.addEventListener('click', () => {
        document.getElementById('payModal').classList.add('hidden');
    });

    document.getElementById('createPostBtn')?.addEventListener('click', () => {
        document.getElementById('createPostModal').classList.remove('hidden');
    });

    document.getElementById('cancelPostBtn')?.addEventListener('click', () => {
        document.getElementById('createPostModal').classList.add('hidden');
    });

    document.getElementById('submitPostBtn')?.addEventListener('click', async () => {
        const title = document.getElementById('postTitle').value.trim();
        const content = document.getElementById('postContent').value.trim();
        const isPaid = document.querySelector('input[name="paidType"]:checked')?.value === 'paid';
        const price = isPaid ? document.getElementById('postPrice').value : '0';
        const previewText = isPaid ? document.getElementById('previewText').value.trim() : '';
        const mediaFile = document.getElementById('postMedia').files[0];

        if (!title) {
            alert('Title is required');
            return;
        }

        const formData = new FormData();
        formData.append('title', title);
        formData.append('content', content);
        formData.append('is_paid', isPaid ? 'true' : 'false');
        formData.append('price', price);
        formData.append('preview_text', previewText);
        if (mediaFile) formData.append('media', mediaFile);

        const response = await apiFetch('/api/ghost/create', {
            method: 'POST',
            body: formData,
        });
        const data = await response.json();
        if (response.ok && data.success) {
            alert('Post created! It will appear after AI review.');
            document.getElementById('createPostModal').classList.add('hidden');
            document.getElementById('postTitle').value = '';
            document.getElementById('postContent').value = '';
            document.getElementById('postMedia').value = '';
            document.getElementById('previewText').value = '';
            loadFeed(true);
            return;
        }
        alert(data.error || 'Failed to create post');
    });

    document.querySelectorAll('input[name="paidType"]').forEach((radio) => {
        radio.addEventListener('change', (event) => {
            const isPaid = event.target.value === 'paid';
            document.getElementById('priceGroup').classList.toggle('hidden', !isPaid);
            document.getElementById('previewGroup').classList.toggle('hidden', !isPaid);
        });
    });
}

function bindInfiniteScroll() {
    let scrollTimeout;
    document.querySelector('.feed-container')?.addEventListener('scroll', () => {
        clearTimeout(scrollTimeout);
        scrollTimeout = setTimeout(() => {
            const container = document.querySelector('.feed-container');
            if (!container) return;
            if (container.scrollTop + container.clientHeight >= container.scrollHeight - 500) {
                loadFeed();
            }
        }, 100);
    });
}

function bindMobileNav() {
    document.querySelectorAll('.nav-item-mobile').forEach((item) => {
        item.addEventListener('click', () => {
            const page = item.dataset.page;
            const pages = {
                chat: '/chat.html',
                ghost: '/ghost-ultimate',
                market: '/ghost-market',
                profile: '/profile.html',
                settings: '/settings.html',
            };
            if (pages[page]) window.location.href = pages[page];
        });
    });
}

window.addEventListener('DOMContentLoaded', async () => {
    await ensureCsrfToken();
    bindModalActions();
    bindInfiniteScroll();
    bindMobileNav();
    loadFeed(true);
});
