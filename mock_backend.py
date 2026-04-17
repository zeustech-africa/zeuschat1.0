#!/usr/bin/env python3
"""Lightweight in-memory backend used for integration-style pytest runs."""

from __future__ import annotations

import time
import uuid
from typing import Any

from flask import Flask, jsonify, make_response, request

app = Flask(__name__)


users: dict[str, dict[str, Any]] = {}
sessions: dict[str, str] = {}
contact_requests: dict[str, list[dict[str, Any]]] = {}
contacts: dict[str, set[str]] = {}
messages: list[dict[str, Any]] = []

next_contact_request_id = 1
next_message_id = 1

WAV_BYTES = (
    b"RIFF$\\x00\\x00\\x00WAVEfmt "
    b"\\x10\\x00\\x00\\x00\\x01\\x00\\x01\\x00"
    b"D\\xac\\x00\\x00\\x88X\\x01\\x00\\x02\\x00\\x10\\x00"
    b"data\\x00\\x00\\x00\\x00"
)


def _json() -> dict[str, Any]:
    return request.get_json(silent=True) or {}


def _create_session(pin: str):
    sid = uuid.uuid4().hex
    sessions[sid] = pin
    resp = make_response()
    resp.set_cookie("sid", sid, httponly=True, samesite="Lax")
    return resp


def _current_pin() -> str | None:
    sid = request.cookies.get("sid")
    if not sid:
        return None
    return sessions.get(sid)


def _require_auth():
    pin = _current_pin()
    if not pin:
        return None, (jsonify({"error": "Not authenticated"}), 401)
    return pin, None


def _contact_key(a: str, b: str) -> tuple[str, str]:
    return (a, b) if a < b else (b, a)


def _are_contacts(a: str, b: str) -> bool:
    return b in contacts.get(a, set())


def _expire_messages():
    global messages
    now = time.time()
    kept = []
    for msg in messages:
        start = msg.get("read_timer_started_at")
        ttl = msg.get("ttl", 30)
        if start is not None and (now - start) > ttl:
            continue
        kept.append(msg)
    messages = kept


@app.get("/health")
def health():
    return jsonify({"status": "ok"})


@app.route("/static/notification.wav", methods=["GET", "HEAD"])
def notification_wav():
    resp = make_response(b"" if request.method == "HEAD" else WAV_BYTES)
    resp.headers["Content-Type"] = "audio/wav"
    resp.headers["Content-Length"] = str(len(WAV_BYTES))
    return resp


@app.post("/api/login")
def api_login():
    data = _json()
    pin = (data.get("zeus_pin") or "").strip()
    password = data.get("password") or ""

    user = users.get(pin)
    if not user or user["password"] != password:
        return jsonify({"success": False, "error": "Invalid credentials"}), 401

    resp = _create_session(pin)
    resp.set_data(jsonify({"success": True}).get_data())
    resp.content_type = "application/json"
    return resp


@app.post("/api/complete-registration")
def api_complete_registration():
    data = _json()
    pin = (data.get("zeus_pin") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    full_name = (data.get("full_name") or pin).strip() or pin

    if not pin or not email or not password:
        return jsonify({"success": False, "error": "Missing required fields"}), 400

    if pin in users:
        return jsonify({"success": False, "error": "PIN already exists"}), 409

    users[pin] = {
        "zeus_pin": pin,
        "email": email,
        "password": password,
        "full_name": full_name,
    }
    contacts.setdefault(pin, set())
    contact_requests.setdefault(pin, [])

    resp = _create_session(pin)
    resp.set_data(jsonify({"success": True, "user_id": len(users)}).get_data())
    resp.content_type = "application/json"
    return resp, 201


@app.post("/api/add-contact")
def api_add_contact():
    global next_contact_request_id

    requester, err = _require_auth()
    if err:
        return err

    data = _json()
    target = (data.get("zeus_pin") or "").strip()
    if not target or target not in users:
        return jsonify({"error": "Contact not found"}), 404

    if _are_contacts(requester, target):
        return jsonify({"error": "Already contacts"}), 409

    pending_for_target = contact_requests.setdefault(target, [])
    for row in pending_for_target:
        if row.get("zeus_pin") == requester:
            return jsonify({"error": "Request already pending"}), 409

    pending_for_target.append({
        "contact_id": next_contact_request_id,
        "zeus_pin": requester,
    })
    next_contact_request_id += 1
    return jsonify({"success": True}), 201


@app.get("/api/get-contact-requests")
def api_get_contact_requests():
    target, err = _require_auth()
    if err:
        return err
    return jsonify({"requests": contact_requests.get(target, [])})


@app.post("/api/accept-contact")
def api_accept_contact():
    target, err = _require_auth()
    if err:
        return err

    data = _json()
    contact_id = data.get("contact_id")

    target_requests = contact_requests.setdefault(target, [])
    found = None
    for row in target_requests:
        if row.get("contact_id") == contact_id:
            found = row
            break

    if not found:
        return jsonify({"error": "Request not found"}), 404

    requester = found["zeus_pin"]
    target_requests[:] = [row for row in target_requests if row.get("contact_id") != contact_id]

    contacts.setdefault(target, set()).add(requester)
    contacts.setdefault(requester, set()).add(target)

    return jsonify({"success": True}), 200


@app.post("/api/bbm-send-ping")
def api_send_ping():
    sender, err = _require_auth()
    if err:
        return err

    data = _json()
    receiver = (data.get("receiver_pin") or "").strip()
    if not receiver or receiver not in users:
        return jsonify({"success": False, "error": "Receiver not found"}), 404

    if not _are_contacts(sender, receiver):
        return jsonify({"success": False, "error": "PING only allowed for accepted contacts"}), 403

    return jsonify({"success": True, "ping_id": uuid.uuid4().hex}), 200


@app.post("/api/send-message")
def api_send_message():
    global next_message_id

    sender, err = _require_auth()
    if err:
        return err

    data = _json()
    receiver = (data.get("receiver_pin") or "").strip()
    content = data.get("content") or ""
    ttl = int(data.get("ttl") or 30)

    if not receiver or receiver not in users:
        return jsonify({"success": False, "error": "Receiver not found"}), 404

    if not _are_contacts(sender, receiver):
        return jsonify({"success": False, "error": "Not contacts"}), 403

    msg = {
        "id": next_message_id,
        "sender_pin": sender,
        "receiver_pin": receiver,
        "content": content,
        "ttl": ttl,
        "status": "sent",
        "created_at": time.time(),
        "viewed_at": None,
        "read_timer_started_at": None,
    }
    next_message_id += 1
    messages.append(msg)
    return jsonify({"success": True, "message_id": msg["id"]}), 200


@app.get("/api/get-messages")
def api_get_messages():
    pin, err = _require_auth()
    if err:
        return err

    _expire_messages()

    contact_pin = (request.args.get("contact_pin") or "").strip()
    if not contact_pin:
        return jsonify({"messages": []}), 200

    # Receiver fetching messages from sender upgrades status to delivered.
    for msg in messages:
        if msg["sender_pin"] == contact_pin and msg["receiver_pin"] == pin and msg["status"] == "sent":
            msg["status"] = "delivered"

    convo = [
        {
            "id": msg["id"],
            "sender_pin": msg["sender_pin"],
            "receiver_pin": msg["receiver_pin"],
            "content": msg["content"],
            "status": msg["status"],
            "viewed_at": msg["viewed_at"],
            "read_timer_started_at": msg["read_timer_started_at"],
        }
        for msg in messages
        if (
            (msg["sender_pin"] == pin and msg["receiver_pin"] == contact_pin)
            or (msg["sender_pin"] == contact_pin and msg["receiver_pin"] == pin)
        )
    ]

    return jsonify({"messages": convo}), 200


@app.post("/api/mark-message-viewed")
def api_mark_message_viewed():
    pin, err = _require_auth()
    if err:
        return err

    data = _json()
    ids = set(data.get("message_ids") or [])
    now = time.time()
    marked = 0

    for msg in messages:
        if msg["id"] in ids and msg["receiver_pin"] == pin:
            if msg["viewed_at"] is None:
                msg["viewed_at"] = now
                msg["read_timer_started_at"] = now
            msg["status"] = "seen"
            marked += 1

    return jsonify({"success": True, "marked_count": marked}), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
