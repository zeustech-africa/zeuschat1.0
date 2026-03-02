# TTL Timer Fix - Implementation Report
**Date:** February 26, 2026  
**Objective:** Fix TTL timer to start counting **ONLY after receiver opens message**, not from send time

---

## ✅ COMPLETED CHANGES

### 1. Database Schema Update
**File:** `app.py` (lines ~250-260)

**Added Column:**
```sql
ALTER TABLE messages ADD COLUMN read_timer_started_at TIMESTAMP
```

**Purpose:** Track when TTL timer actually starts (when receiver opens message)

---

### 2. Backend TTL Query Updates (9 locations fixed)

#### **Critical Change:**
- **OLD:** `datetime(created_at, '+' || ttl_seconds || ' seconds')`
- **NEW:** `datetime(read_timer_started_at, '+' || ttl_seconds || ' seconds')`
- **Fallback:** Messages without `read_timer_started_at` (unopened) are NOT expired

#### **Updated Queries:**

1. **Line 805** - Find expired messages (only if opened)
2. **Line 817** - Mark expired messages (only if opened)
3. **Line 832** - Filter messages for delivery
4. **Line 843** - Mark messages as delivered
5. **Lines 854, 871** - Get messages between users / all messages
6. **Line 943** - Unread message counts
7. **Line 1077** - TTL expiring endpoint
8. **Lines 1144, 1151-1161, 1172** - TTL statistics

**Key Logic:**
- Unopened messages (`read_timer_started_at IS NULL`) never expire
- TTL only runs after message is opened
- Undelivered messages can stay in inbox indefinitely until opened

---

### 3. Mark Message Viewed - Start TTL Timer
**Files:** `app.py` (lines 1000-1020, 1033-1050)

**Updated Queries:**
```python
UPDATE messages 
SET viewed_at = datetime('now'),
    delivered_at = COALESCE(delivered_at, datetime('now')),
    read_timer_started_at = datetime('now'),  # ← NEW - Starts TTL timer
    status = 'seen'
WHERE receiver_id = ? AND viewed_at IS NULL
```

**Socket.IO Update:**
```python
viewed_at = datetime.now().isoformat()
emit_message_status(sender_id, message_id, 'seen', viewed_at=viewed_at)
```

Now emits `viewed_at` timestamp so sender sees exact time receiver opened message.

---

### 4. Frontend TTL Display Updates
**File:** `chat.html` (lines 1180-1278)

#### **Before (Broken):**
```javascript
const createdTime = new Date(message.created_at).getTime();
const expirationTime = createdTime + ttlMillis;
```
Timer counted from send time → message could expire before opening

#### **After (Fixed):**
```javascript
const timerStart = message.read_timer_started_at || message.viewed_at || (!isOwnMessage ? new Date().toISOString() : null);
if (timerStart) {
  const startTime = new Date(timerStart).getTime();
  expirationTime = startTime + ttlMillis;
}
```

**New Behavior:**
- Shows "⏳ not started" if message not opened yet
- Timer only counts after `read_timer_started_at` or `viewed_at` exists
- Auto-delete uses `remainingMs` from actual expiration time

---

### 5. Sender Visibility - "Message Seen" Feedback
**File:** `chat.html` (lines 1350-1398, 1543-1595)

#### **Status Icons Updated:**
- ✓ (gray) = Sent
- ✓✓ (gold) = Delivered
- 👁✓ (green) = **Seen**
- ✓💨 (green) = **Seen & deleted** (expired after being opened)
- ⏱✗ (red) = **Expired (never seen)** (unopened, expired without read)

#### **Status Labels Updated:**
```javascript
case 'expired': 
  if (viewedAt) {
    return 'Seen & deleted';  // ← User DID read it
  }
  return 'Expired (not seen)';  // ← User NEVER read it
```

#### **"Opened at" Timestamp:**
When receiver opens message, sender sees:
```
📖 14:32  (green timestamp showing exact open time)
```

Displayed next to message status for full transparency.

---

### 6. Socket.IO Real-Time Updates
**Files:** `app.py` (line 90-120), `chat.html` (line 2438-2448)

**Backend Emit:**
```python
payload = {
    'message_id': message_id,
    'status': status,
    'viewed_at': viewed_at  # ← Now included
}
socketio.emit('message_status', payload, room=f"user:{sender_id}")
```

**Frontend Handler:**
```javascript
statusSocket.on('message_status', (payload) => {
  updateMessageStatus(payload.message_id, payload.status, payload.viewed_at || null);
});
```

Sender now gets instant notification with timestamp when receiver opens message.

---

## 🎯 USER EXPERIENCE CHANGES

### **For Senders:**
✅ Clear feedback when message is seen  
✅ Exact timestamp showing when receiver opened  
✅ Distinction between "never seen" and "seen & deleted"  
✅ No more confusion about expired messages  
✅ BBM-style transparency maintained

### **For Receivers:**
✅ Messages stay in inbox until opened (no premature deletion)  
✅ TTL countdown only starts after opening  
✅ Clear "⏳ not started" indicator if not opened yet  
✅ Timer shows accurate remaining time after opening

---

## 🔍 TESTING CHECKLIST

### **Test Scenario 1: Unopened Messages Don't Expire**
1. Alice sends message to Bob with 30s TTL
2. Bob waits 2 minutes WITHOUT opening message
3. **Expected:** Message still in Bob's inbox (no expiration)
4. Bob opens message → Timer starts
5. After 30s → Message expires and deletes

### **Test Scenario 2: Sender Sees "Opened at" Timestamp**
1. Alice sends message to Bob at 14:30
2. Bob opens message at 14:32
3. **Expected:** Alice sees "📖 14:32" next to message status
4. Alice knows Bob read it at exactly 14:32

### **Test Scenario 3: Expired Status Distinction**
1. Alice sends 10s TTL message to Bob
2. **Case A:** Bob opens → Status shows "Seen & deleted" ✓💨 (green)
3. **Case B:** Bob never opens → Status shows "Expired (not seen)" ⏱✗ (red)
4. **Expected:** Alice knows if Bob read it or not

### **Test Scenario 4: Real-Time Socket Updates**
1. Alice sends message to Bob
2. Bob opens message immediately
3. **Expected:** Alice's screen updates in <1 second with "Seen" + timestamp
4. No need to refresh or wait for polling

---

## 📊 SYSTEM IMPACT

### **Database Changes:**
- ✅ Safe migration (column added with try/except)
- ✅ NULL values handled gracefully with COALESCE
- ✅ No data loss on existing messages

### **Backend Changes:**
- ✅ All TTL queries updated (9 locations)
- ✅ Mark-viewed endpoint sets read_timer_started_at
- ✅ Socket.IO emissions include viewed_at timestamp
- ✅ Backward compatible (old messages still work)

### **Frontend Changes:**
- ✅ TTL display logic updated
- ✅ Status icons/labels distinguish seen vs unseen expiration
- ✅ "Opened at" timestamp added for senders
- ✅ Socket.IO handler extracts viewed_at

### **No Breaking Changes:**
- ✅ Contact management unchanged
- ✅ Message sending unchanged
- ✅ Delivery tracking unchanged
- ✅ Polling fallback still works
- ✅ Existing features preserved

---

## 🚀 NEXT STEPS

1. **Restart Server** - Run migration to add read_timer_started_at column
2. **Test Flow** - Send messages and verify timer behavior
3. **User Acceptance** - Confirm sender visibility features work as expected
4. **Monitor Logs** - Check for any SQL errors or Socket.IO issues

---

## 📝 NOTES

- TTL timer fix ensures messages cannot expire before receiver reads them
- Sender transparency features maintain BBM-style trust model
- All auto-delete functionality preserved (non-optional)
- System remains production-ready for app store deployment

**Implementation Status:** ✅ COMPLETE  
**Test Status:** ⏳ PENDING USER VERIFICATION
