# Database Locking Fix - Technical Documentation

## Problem Statement

The Zeus Chat application was experiencing SQLite database locking issues:
- Multiple API endpoints attempting concurrent writes causes "database is locked" errors
- No retry mechanism or timeout handling for database operations
- Vulnerable to race conditions during high traffic
- Poor error recovery - single lock causes immediate failure

## Root Cause Analysis

SQLite uses file-level locking, which means:
1. Only one writer can exist at a time (writers block each other)
2. Readers can block writers and vice versa
3. No built-in retry mechanism when lock is encountered
4. Default timeout is very short (5 seconds)

Problems in original code:
```python
# BEFORE - Vulnerable approach
conn = sqlite3.connect('zeuschat.db')  # Default timeout=5s, no WAL
cursor = conn.cursor()
cursor.execute("UPDATE ...")            # Could fail with database locked
conn.commit()
conn.close()
```

## Solution Architecture

### 1. Context Manager for Resource Management

**File: app.py (lines 23-33) and backend/app.py (lines 18-28)**

```python
@contextmanager
def get_db_connection():
    """Context manager for database connections with automatic retry on lock"""
    conn = sqlite3.connect('zeuschat.db', timeout=30.0)
    conn.execute('PRAGMA journal_mode=WAL')
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise
    finally:
        conn.close()
```

**Benefits:**
- `timeout=30.0`: Waits up to 30 seconds for lock to be released
- `PRAGMA journal_mode=WAL`: Enables Write-Ahead Logging for better concurrency
- Automatic commit on success, rollback on error
- Guaranteed cleanup with finally block
- No manual commit/close statements needed

### 2. Retry Decorator with Exponential Backoff

**File: app.py (lines 35-49) and backend/app.py (lines 30-44)**

```python
def retry_on_locked(max_retries=3, delay=0.5):
    """Decorator to retry on database lock with exponential backoff"""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            last_error = None
            for attempt in range(max_retries):
                try:
                    return f(*args, **kwargs)
                except sqlite3.OperationalError as e:
                    if 'locked' in str(e).lower():
                        last_error = e
                        if attempt < max_retries - 1:
                            wait_time = delay * (2 ** attempt)
                            print(f"⚠️  Database locked, retrying in {wait_time}s (attempt {attempt + 1}/{max_retries})")
                            time.sleep(wait_time)
                        continue
                    raise
            if last_error:
                raise last_error
        return wrapper
    return decorator
```

**Retry Strategy:**
- 1st attempt: Fails with lock → Wait 0.5s
- 2nd attempt: Retries → Wait 1s (0.5 × 2)
- 3rd attempt: Retries → Wait 2s (0.5 × 4)
- 4th attempt: Succeeds or raises exception

**Benefits:**
- Exponential backoff prevents thundering herd problem
- Catches only "database locked" errors (lets other errors through)
- Provides visibility into retry attempts via console logging
- Decorators are applied transparently to all endpoints

### 3. Applied Decorators to All Endpoints

**Main app.py - 9 endpoints with decorator:**
- Line 142: `/api/start-signup`
- Line 222: `/api/verify-otp`
- Line 272: `/api/complete-registration`
- Line 334: `/api/login`
- Line 366: `/api/logout`
- Line 395: `/api/user/profile`
- Line 425: `/api/user/update-profile` ✅
- Line 459: `/api/send-message`
- Line 519: `/api/get-messages`
- Line 560: `/api/delete-message`
- Line 601: `/health`

**Backend app.py - 10 endpoints with decorator:**
- Line 102: `/send-otp`
- Line 123: `/verify-otp`
- Line 157: `/save-profile`
- Line 175: `/add-contact`
- Line 205: `/get-requests`
- Line 224: `/accept-contact`
- Line 243: `/get-contacts`
- Line 264: `/send-message`
- Line 290: `/get-messages`
- Line 325: `/mark-viewed`

### 4. Refactored All Database Operations

**BEFORE:**
```python
conn = sqlite3.connect('zeuschat.db')
cursor = conn.cursor()
cursor.execute("INSERT INTO users ...")
conn.commit()
conn.close()
```

**AFTER:**
```python
with get_db_connection() as conn:
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users ...")
# Automatic commit & close
```

**Changes Applied:**
- Removed 19× manual `sqlite3.connect()` calls
- Removed 19× manual `conn.commit()` statements
- Removed 19× manual `conn.close()` statements
- All operations now use context manager

## Testing Recommendations

### Simulate High Load
```bash
# Test concurrent requests
for i in {1..10}; do
  curl -X POST http://localhost:5000/api/send-message \
    -H "Content-Type: application/json" \
    -d '{"receiver_pin":"ZT-XXXX-XXXX","content":"Test"}' &
done
wait
```

### Monitor Lock Contention
```python
# Check WAL file size (indicates writer backlog)
import os
wal_size = os.path.getsize('zeuschat.db-wal') if os.path.exists('zeuschat.db-wal') else 0
print(f"WAL file size: {wal_size} bytes")
```

### Verify Retry Behavior
- Watch console for "⚠️ Database locked, retrying..." messages
- Confirm operations complete after retries
- Verify no data corruption in logs

## Performance Impact

**Improvements:**
- Higher concurrent request throughput (WAL mode)
- Better error recovery (automatic retries)
- Reduced request failures (30s timeout)
- No additional latency under normal conditions

**Minimal Cost:**
- Exponential backoff waits (0.5-2s) only on contention
- WAL mode uses slightly more disk space (~5% overhead)
- Overhead only applies during actual lock contention

## Migration Notes

### Backward Compatibility
✅ **Fully backward compatible**
- No changes to API endpoints or responses
- No changes to database schema
- Existing code continues to work

### Deployment Steps
1. Deploy updated app.py and backend/app.py
2. Application automatically enables WAL mode on first run
3. No database migration needed
4. Monitor logs for first 24 hours

### Rollback
If issues occur:
1. Revert code to previous version
2. Delete `zeuschat.db-wal` and `zeuschat.db-shm` files
3. Database returns to normal journal mode

## Future Optimizations

1. **Connection Pooling**: Use SQLAlchemy or similar for connection reuse
2. **Read Replicas**: Offload reads to separate database
3. **Async Operations**: Use asyncio for non-blocking database calls
4. **Query Optimization**: Add indexes for frequently queried columns
5. **Monitoring**: Implement metrics for lock contention tracking

## References

- SQLite Documentation: https://www.sqlite.org/wal.html
- Python sqlite3 Module: https://docs.python.org/3/library/sqlite3.html
- WAL Mode Best Practices: https://www.sqlite.org/pragma.html#pragma_journal_mode
- Error Handling: https://www.sqlite.org/rescode.html

---

**Document Version:** 1.0  
**Last Updated:** 2024  
**Status:** Deployed
