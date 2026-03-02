# ⚡ ZeusChat BBM Features - Quick Reference Guide

## 🎨 Status Colors (Presence Awareness)

### **What Users See**
- Contact's status dot in chat header
- 🟢 Available = Normal notifications
- 🟡 Away = Might be slow to respond  
- 🔴 Busy = Might not reply quickly

### **How to Use**
1. Click 😊 status button in chat header
2. Select: Available, Away, or Busy
3. All contacts see your status instantly
4. Status persists when you come back

### **Technical**
- **API:** POST `/api/bbm-update-status`
- **GET:** `/api/bbm-get-contacts-status`
- **Database:** `users.status_state`, `users.status_message`
- **Real-time:** Socket.IO `contact_status_changed` event

---

## 📳 PING (Tactile Nudge)

### **What It Does**
- Send urgent "get my attention" signal
- Receiver's phone vibrates (different pattern)
- Sender gets confirmation
- More urgent than a text message

### **How to Use**
1. Open chat with a contact
2. Click 📳 PING button in header
3. Receiver's phone vibrates immediately
4. You see: "PING sent to John"

### **Vibration Patterns**
- Standard PING: [100ms vibrate, 50ms pause, 100ms vibrate]
- Urgent PING: [200ms, 100ms, 200ms, 100ms, 200ms]

### **Technical**
- **API:** POST `/api/bbm-send-ping`
- **Database:** `messages.is_ping` flag
- **Real-time:** Socket.IO `ping_incoming` event with vibration pattern
- **Fallback:** No fallback (immediate only)

---

## 🗑️ Delete Everywhere (True Privacy)

### **What It Does**
- Delete message from BOTH devices
- No "(message deleted)" placeholder
- Complete privacy and control
- True BBM-style deletion (not WhatsApp)

### **How to Use**
1. Right-click on ANY message you sent
2. Two options appear:
   - "Delete for me" = just remove from your view
   - "Delete Everywhere (BBM)" = remove from BOTH devices
3. Message vanishes for both
4. Refresh page = still gone

### **Key Difference from WhatsApp**
| Feature | WhatsApp | ZeusChat BBM |
|---------|----------|------------|
| Deletion | Shows "(message deleted)" | Message vanishes completely |
| Privacy | Receiver knows it was deleted | Zero trace |
| Feeling | Awkward | Complete control |

### **Technical**
- **API:** POST `/api/delete-message` with `delete_mode: "delete_everywhere"`
- **Database:** `messages.is_deleted = 1` (soft delete)
- **Query Filter:** `WHERE is_deleted = 0`
- **Real-time:** Socket.IO `message_deleted` event
- **Sync:** Immediate both directions

---

## 🤐 Ignore (Social Grace)

### **What It Does**
- Ignore contact requests silently
- They never know you ignored them
- Request stays "pending" on their end forever
- Perfect for awkward situations

### **How to Use**
1. Get incoming contact request
2. Three buttons:
   - ✅ Accept = become contacts
   - ❌ Decline = reject (they might know)
   - 🤐 Ignore = silently ignore (they NEVER know)
3. Removed from your view
4. Stays pending on their end

### **Why It's Genius**
```
Scenario: Random person sends request

Option 1: Accept
  ❌ Now contacts with random person (awkward)

Option 2: Decline  
  ⚠️ They MIGHT see "request declined" (still awkward)

Option 3: Ignore (🤐)
  ✨ It vanishes from your view
  ✨ THEY still see "pending" (they don't know)
  ✨ They might try again later (no harm)
  ✨ No awkwardness created
```

### **Technical**
- **API:** POST `/api/decline-contact` with `action: "ignore"`
- **Database:** `contacts.status = 'ignored'`
- **Query Logic:** Ignored requests removed from user's view
- **Sender View:** Still shows as "pending" (they don't know)
- **Notifications:** None to sender (silent)

---

## 🔧 Developer Integration Guide

### **Data Models**

**Users Table**
```sql
status_state TEXT DEFAULT 'available'    -- 'available', 'away', 'busy'
status_message TEXT                      -- Custom status text
```

**Messages Table**
```sql
is_ping INTEGER DEFAULT 0                -- 1 if PING message
is_deleted INTEGER DEFAULT 0             -- 1 if deleted everywhere
```

**Contacts Table**
```sql
status values: 'pending', 'accepted', 'blocked', 'ignored'
-- 'ignored' = user 1 ignored request from user 2
```

### **Socket.IO Events**

**Broadcast (Multiple Recipients)**
```python
socketio.emit('contact_status_changed', {
    'user_id': 123,
    'status_state': 'busy',
    'status_message': 'In meeting',
    'timestamp': '2026-02-26T08:00:00'
}, broadcast=True)
```

**Point-to-Point (Single Recipient)**
```python
socketio.emit('ping_incoming', {
    'sender_id': 123,
    'sender_pin': 'ZT-1234-5678',
    'sender_name': 'John',
    'ping_type': 'standard',
    'vibration_pattern': [100, 50, 100],
    'timestamp': '2026-02-26T08:00:00'
}, room=f"user:{receiver_id}")

socketio.emit('message_deleted', {
    'message_id': 456,
    'deleted_by': 123,
    'timestamp': '2026-02-26T08:00:00'
}, room=f"user:{receiver_id}")
```

### **REST API Examples**

**Update User Status**
```bash
curl -X POST http://localhost:5000/api/bbm-update-status \
  -H "Content-Type: application/json" \
  -d '{
    "status_state": "busy",
    "status_message": "In a meeting"
  }'
```

**Send PING**
```bash
curl -X POST http://localhost:5000/api/bbm-send-ping \
  -H "Content-Type: application/json" \
  -d '{
    "receiver_pin": "ZT-1234-5678",
    "ping_type": "standard"
  }'
```

**Delete Message Everywhere**
```bash
curl -X POST http://localhost:5000/api/delete-message \
  -H "Content-Type: application/json" \
  -d '{
    "message_id": 456,
    "delete_mode": "delete_everywhere"
  }'
```

**Ignore Contact Request**
```bash
curl -X POST http://localhost:5000/api/decline-contact \
  -H "Content-Type: application/json" \
  -d '{
    "contact_id": 789,
    "action": "ignore"
  }'
```

### **Frontend JavaScript**

**Update Status**
```javascript
async function updateStatus(statusState) {
  const response = await fetch('/api/bbm-update-status', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      status_state: statusState,
      status_message: ''
    })
  });
  const data = await response.json();
  console.log('Status updated:', data);
}
```

**Send PING**
```javascript
async function sendPing() {
  const response = await fetch('/api/bbm-send-ping', {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      receiver_pin: 'ZT-1234-5678',
      ping_type: 'standard'
    })
  });
  if (navigator.vibrate) {
    navigator.vibrate([100, 50, 100]); // Feedback to sender
  }
}
```

**Listen for PING**
```javascript
statusSocket.on('ping_incoming', (data) => {
  const { sender_name, vibration_pattern } = data;
  
  // Vibrate device
  if (navigator.vibrate && vibration_pattern) {
    navigator.vibrate(vibration_pattern);
  }
  
  // Show notification
  new Notification(`📳 PING from ${sender_name}!`);
  
  // Play sound
  playNotificationSound();
});
```

**Listen for Contact Status Change**
```javascript
statusSocket.on('contact_status_changed', (data) => {
  const { user_id, status_state } = data;
  
  // Update UI indicator
  updateStatusColorIndicator(status_state);
  console.log(`Contact ${user_id} status: ${status_state}`);
});
```

---

## 📊 Database Queries

### **Get User's Current Status**
```sql
SELECT status_state, status_message
FROM users
WHERE id = 123;
```

### **Get All Contacts' Statuses**
```sql
SELECT u.id, u.zeus_pin, u.status_state, u.status_message
FROM users u
JOIN contacts c ON u.id = c.contact_user_id
WHERE c.user_id = 123 AND c.status = 'accepted';
```

### **Get Non-Deleted Messages**
```sql
SELECT * FROM messages
WHERE (sender_id = 123 OR receiver_id = 123)
AND is_deleted = 0
AND status NOT IN ('expired', 'failed')
ORDER BY created_at DESC;
```

### **Check if Contact Ignored**
```sql
SELECT * FROM contacts
WHERE user_id = 456
AND contact_user_id = 123
AND status = 'ignored';
```

---

## 🧪 Testing Checklist

### **Status Colors**
- [ ] Set status to Available → Indicator shows 🟢
- [ ] Change to Busy → Indicator shows 🔴 immediately
- [ ] Refresh page → Status persists
- [ ] Load contact list → See all contacts' statuses
- [ ] Multiple browsers → All see real-time changes

### **PING**
- [ ] Click PING button → Toast shows "PING sent"
- [ ] Check device → Phone vibrates
- [ ] Phone vibrates with correct pattern
- [ ] Different pattern for "urgent" PING
- [ ] Confirmation visible immediately

### **Delete Everywhere**
- [ ] Right-click message → Menu appears with delete options
- [ ] "Delete Everywhere" option highlighted in red
- [ ] Click → Message vanishes from UI
- [ ] Refresh page → Message still gone
- [ ] Other user's message becomes "(message deleted)"

### **Ignore**
- [ ] Receive contact request
- [ ] Three buttons: Accept, Decline, Ignore
- [ ] Click Ignore → Request removed from view
- [ ] Check database → status = 'ignored'
- [ ] Request still shows "pending" for sender

---

## 🚀 Performance Tips

### **Optimization**
- Status updates broadcast to all contacts (OK for typical friend count ~50-100)
- Delete events only emit to 1 recipient (low overhead)
- PINGs immediate, no fallback mechanism (fast)
- Use Socket.IO connection checks before emitting

### **Monitoring**
- Count Socket.IO event emissions per minute
- Monitor API response times (should be <100ms)
- Track database queries for delete filtering
- Watch memory usage (should be stable)

### **Caching**
- Client caches contact status locally
- Refresh on Socket.IO event
- Reload on page refresh (not an issue)
- Status stored in user session storage

---

## 🔐 Security Notes

### **Status Colors**
- Only visible to accepted contacts
- Not visible to blocked/ignored users
- Cleared on logout
- Encrypted in transit (Socket.IO + HTTPS)

### **PING**
- Only sendable to accepted contacts
- Server verifies contact relationship
- Immediate delivery only (no storage)
- Can't PING blocked/ignored users

### **Delete Everywhere**
- User can only delete own messages
- Server verifies ownership before deleting
- Soft delete (not immediately removed)
- Hard delete can happen in background job

### **Ignore**
- User can only ignore inbound requests
- Cannot ignore accepted contacts
- Cannot ignore blocked contacts
- Silently ignores (no notification to sender)

---

## 📱 Mobile Optimization

### **Vibration API**
```javascript
// Check support
if (navigator.vibrate) {
  // Works on most modern phones
  navigator.vibrate([100, 50, 100]);
}

// Does NOT work on iOS/Safari
// Will silently fail (graceful degradation)
```

### **Notification API**
```javascript
if (Notification && Notification.permission === 'granted') {
  new Notification('PING!', {
    body: 'John sent you a PING',
    icon: '/icon.png',
    tag: 'ping-notification'
  });
}
```

### **Touch Events**
- Status picker works with touch
- Right-click works with long-press on mobile
- All buttons tap-friendly (44px minimum)

---

## 🐛 Troubleshooting

| Problem | Solution |
|---------|----------|
| Status not updating | Refresh page, check Socket.IO connection |
| PING not vibrating | Check device vibration enabled, browser supports it |
| Delete not syncing | Verify Socket.IO active, check browser console |
| Ignore button missing | Confirm you're on contact requests page |
| API returns 404 | Ensure server is running, check endpoint name |
| Status picker not showing | Check browser console for errors, try refresh |

---

## 📞 Support Reference

**Full Documentation:** See `BBM_FEATURES_IMPLEMENTATION.md`  
**Executive Summary:** See `BBM_EXECUTIVE_SUMMARY.md`  
**Server:** Running on localhost:5000  
**Database:** zeuschat.db (WAL mode)  

---

*Quick Reference v1.0*  
*Last Updated: February 26, 2026*  
*Status: ✅ Production Ready*
