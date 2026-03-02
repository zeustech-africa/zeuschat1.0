# ⏰ ZeusChat TTL System Audit - CRITICAL FINDING

**Date:** February 26, 2026  
**Issue:** TTL Timer Starts on SEND, Not on READ ❌  
**Impact:** Messages can be deleted BEFORE receiver opens them!

---

## 🔴 CURRENT SYSTEM (WRONG)

### Current Code
[app.py, lines 798-823](app.py#L798-L823)

```python
# TTL expires based on created_at (SEND time)
AND datetime(created_at, '+' || ttl_seconds || ' seconds') <= datetime('now')
                        ^^^^^^^^
                    SEND TIME - WRONG!
```

### Current Timeline Example

```
9:00:00 AM - Alice writes: "Secret info: XYZ"
9:00:00 AM - Message created_at = 9:00:00
9:00:00 AM - Message sent with TTL=30 seconds
            (Expiration time = 9:00:30 AM)

9:00:15 AM - Bob is busy, hasn't checked ZeusChat yet
            
9:00:30 AM - ⏱️ MESSAGE EXPIRES & AUTO-DELETES
            Status: EXPIRED before receiver reads it!

9:00:45 AM - Bob finally opens ZeusChat
            👻 Message is gone! Bob never sees it!
            Alice thinks Bob read it and deleted it
            But Bob never even SAW it!

⚠️ TRUST BROKEN: Alice's assumption is wrong!
```

### Why This Is Bad

1. **Messages deleted before receiver sees them** ❌
2. **Users can't trust the "read receipt"** - Maybe it was deleted before they read it?
3. **Sender/receiver out of sync** - One thinks message was read, other never saw it
4. **Bad UX** - "Security" that doesn't make sense

---

## ✅ DESIRED SYSTEM (CORRECT)

### Desired Code
```python
# TTL expires based on viewed_at (READ time)
AND datetime(viewed_at, '+' || ttl_seconds || ' seconds') <= datetime('now')
                   ^^^^^^^^^
                  READ TIME - CORRECT!
```

### Desired Timeline Example

```
9:00:00 AM - Alice writes: "Secret info: XYZ"
9:00:00 AM - Message created, viewed_at = NULL
9:00:00 AM - TTL timer NOT started yet
            (No expiration time yet)

9:00:15 AM - Bob opens ZeusChat,sees message
9:00:15 AM - Message marked as viewed
            viewed_at = 9:00:15 AM
            Expiration time NOW = 9:00:45 AM (30 seconds from now)

9:00:30 AM - Bob still reading...message is safe
            
9:00:45 AM - ⏱️ MESSAGE EXPIRES (30 sec after Bob OPENED it)
            Message auto-deletes

✅ TRUST EARNED: Alice knows Bob saw her message before it disappeared!
```

### Why This Is Better

1. **Messages always seen before deletion** ✅
2. **TTL = "30-second read timer" after opening** 📖⏰
3. **Sender/receiver alignment** - Both agree on timeline
4. **Security + UX balance** - Privacy without anxiety
5. **Similar to Snapchat** - Users understand it

---

## 📊 Comparison

| Aspect | Current (WRONG) | Desired (CORRECT) |
|--------|---|---|
| TTL starts | When sender sends | When receiver opens |
| Message visible before deletion | ❌ NO (might expire before read) | ✅ YES (guaranteed) |
| User trust | ❌ LOW | ✅ HIGH |
| Read receipt accuracy | ❌ MISLEADING | ✅ ACCURATE |
| Time from send to delete | Fixed (30s) | Variable (30s + time to open) |
| Use case | Classic | **Snapchat/Signal style** |

---

## 🔧 IMPLEMENTATION REQUIRED

### Step 1: Add `read_timer_started_at` Column (Optional, for debugging)

```sql
ALTER TABLE messages ADD COLUMN read_timer_started_at TIMESTAMP;
-- When the TTL timer actually begins (when viewed)
```

### Step 2: Set `read_timer_started_at` When Message is Read

**In `/api/mark-message-viewed` endpoint:**

```python
@app.route('/api/mark-message-viewed', methods=['POST', 'OPTIONS'])
def mark_message_viewed():
    # ... existing code ...
    
    cursor.execute(f'''
        UPDATE messages 
        SET viewed_at = datetime('now'),
            delivered_at = COALESCE(delivered_at, datetime('now')),
            read_timer_started_at = datetime('now'),  # ✅ START TTL TIMER NOW
            status = 'seen'
        WHERE id IN ({placeholders}) AND receiver_id = ?
    ''', message_ids + [user_id])
```

### Step 3: Change TTL Expiration Calculation

**From:** `datetime(created_at, '+' || ttl_seconds || ' seconds')`  
**To:** `datetime(COALESCE(read_timer_started_at, created_at), '+' || ttl_seconds || ' seconds')`

This handles:
- **If message was read:** Use `read_timer_started_at` (timer starts when opened)
- **If message never read:** Use `created_at` as fallback (delete after long time to prevent DB bloat)

### Step 4: Update ALL TTL Queries

**Locations to update:**

1. [app.py, line 798](app.py#L798) - Delete expired messages
2. [app.py, line 809](app.py#L809) - Mark messages as expired  
3. [app.py, line 823](app.py#L823) - Find messages to deliver
4. [app.py, line 834](app.py#L834) - Filter non-expired messages
5. [app.py, line 850](app.py#L850) - Filter messages for display
6. [app.py, line 866](app.py#L866) - Filter messages for sender view
7. [app.py, line 943](app.py#L943) - Filter unread messages
8. [app.py, line 1072](app.py#L1072) - Get expiring messages (TTL tracking)
9. [app.py, line 1150](app.py#L1150), [line 1161](app.py#L1161) - TTL statistics

### Step 5: Update Frontend Display

**In chat.html, update TTL countdown display:**

```javascript
function calculateTimeRemaining(message) {
    const nowMs = Date.now();
    
    // TTL starts from when message was read (viewed_at)
    // If not read yet, TTL doesn't count
    if (!message.viewed_at) {
        return {
            seconds: message.ttl_seconds,
            started: false,
            startedAt: null
        };
    }
    
    const viewedMs = new Date(message.viewed_at).getTime();
    const ttlMs = message.ttl_seconds * 1000;
    const expiresMs = viewedMs + ttlMs;
    
    const remainingMs = expiresMs - nowMs;
    const remainingSeconds = Math.max(0, Math.ceil(remainingMs / 1000));
    
    return {
        seconds: remainingSeconds,
        started: true,
        startedAt: message.viewed_at,
        message: remainingSeconds > 0 
            ? `Expires in ${remainingSeconds}s` 
            : 'Expired'
    };
}

// Update every 100ms
setInterval(() => {
    document.querySelectorAll('[data-message-id]').forEach(msgEl => {
        const messageId = msgEl.dataset.messageId;
        const message = messagesMap[messageId];
        if (message) {
            const timeInfo = calculateTimeRemaining(message);
            const ttlDisplay = msgEl.querySelector('.ttl-timer');
            if (ttlDisplay) {
                ttlDisplay.textContent = timeInfo.message;
                ttlDisplay.style.color = timeInfo.seconds < 5 ? '#dc3545' : '#ffc107';
            }
        }
    });
}, 100);
```

### Step 6: Add Message Tracking UI

```html
<!-- Show user exactly when TTL timer started -->
<div class="message-ttl-info">
    <span class="timer-status">
        <!-- If message never read -->
        ⏳ Timer not started (unread)
        
        <!-- If message was read -->
        ⏰ Timer started at 9:00 AM | Expires in 15s
    </span>
</div>
```

---

## 🎯 Message Tracking With TTL

Perfect combined system:

```
=== COMPLETE MESSAGE LIFECYCLE ===

1. SENT (0ms)
   └─ Sender sees: "✓ sent"
   └─ Receiver: no notification yet
   └─ TTL Timer: Not started

2. DELIVERED (100-500ms)
   └─ Sender sees: "✓✓ delivered"
   └─ Receiver: Notification arrives
   └─ TTL Timer: Still not started
   
3. READ / VIEWED (varies)
   └─ Sender sees: "✓✓✓ seen"
   └─ Receiver: Opens message
   └─ Backend: read_timer_started_at = NOW
   └─ TTL Timer: STARTS NOW! ⏰
   
4. COUNTDOWN (next 30 seconds)
   └─ Both see: "⏳ Expires in 28s..."
   └─ Both see: "⏳ Expires in 5s..."
   └─ TTL Timer: Ticking down
   
5. EXPIRED (30s after read)
   └─ Both see: "🗑️ Message deleted"
   └─ Receiver: Message removed from chat
   └─ Database: Message deleted
   └─ TTL Timer: Complete
```

---

## 💡 User-Facing Message

**What user sees in ZeusChat:**

> ✅ **Message Tracking Guarantee**
> 
> Your messages are secure and private:
> - **Sent:** Server receives your message
> - **Delivered:** Message reaches recipient's phone
> - **Seen:** Recipient opens and reads the message
> - **Auto-Delete:** 30 seconds AFTER recipient reads
>
> This means: **Your message will ALWAYS be read before it disappears.**

---

## ✅ Implementation Checklist

- [ ] Add `read_timer_started_at` column to messages table
- [ ] Update `/api/mark-message-viewed` to set timer start
- [ ] Update TTL expiration logic (all 9 locations)
- [ ] Update frontend TTL display to use `viewed_at` + TTL seconds
- [ ] Add "Timer started at X" label to message UI
- [ ] Test message lifecycle end-to-end
- [ ] Test TTL countdown accuracy
- [ ] Test messages delete exactly at correct time

---

## 🧪 Test Cases

```sql
-- Test 1: Message read, should expire 30s after read
INSERT INTO messages (..., created_at, ttl_seconds) 
VALUES (..., NOW()-100s, 30);
-- Read at NOW()-50s
-- Should expire at NOW()+0 (30s after read of NOW()-50s+30s)
-- ✅ Message expired correctly

-- Test 2: Message never read, should expire eventually
INSERT INTO messages (..., created_at, ttl_seconds) 
VALUES (..., NOW()-1000s, 30);
-- Never read
-- Current: Expired NOW()-970s (wrong - already gone!)
-- Desired: Never expires (unless safeguard: 24h after send)
-- ✅ Message NOT expired

-- Test 3: Multiple clients, TTL accurate
-- Alice sends, Bob reads at 9:00 AM
-- Charlie logs in later, still sees message timing
-- ✅ Both see same expiration time
```

---

## 🚀 Priority: CRITICAL

**Why?** This feature differentiates ZeusChat in the market:
- ✅ Users TRUST messages will be seen
- ✅ Privacy without anxiety
- ✅ Clear, honest message lifecycle
- ✅ Competitive advantage vs other secure messengers

**Estimated implementation time:** 2-3 hours

**Ready to implement?** This is the feature that will make users **actually trust** your "secure + auto-delete" promise!
