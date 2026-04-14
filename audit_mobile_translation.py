#!/usr/bin/env python3
"""Mobile Translation System - Full Audit"""
import requests, time

BASE = 'http://127.0.0.1:5000'
results = []
issues = []

with open('templates/mobile-chat.html', 'r') as f:
    html = f.read()

style_section = html.split('<style>')[1].split('</style>')[0] if '<style>' in html else ''
js_section = html.split('<script>')[1].split('</script>')[0] if '<script>' in html else ''

# === SECTION 1: FILE INTEGRITY ===
css_count = html.count('.voice-translate-btn {')
results.append(('CSS: No duplicate blocks', 'PASS' if css_count == 1 else 'FAIL'))
if css_count != 1:
    issues.append(f'voice-translate-btn CSS appears {css_count}x')

if '<button' not in style_section and '<div' not in style_section:
    results.append(('CSS: No HTML contamination', 'PASS'))
else:
    results.append(('CSS: No HTML contamination', 'FAIL'))
    issues.append('HTML tags inside <style>')

open_divs = html.count('<div')
close_divs = html.count('</div>')
results.append(('HTML: Balanced div tags', 'PASS' if abs(open_divs - close_divs) <= 1 else 'FAIL'))
if abs(open_divs - close_divs) > 1:
    issues.append(f'Unbalanced divs: {open_divs} open vs {close_divs} close')

script_count = html.count('<script>')
script_close = html.count('</script>')
results.append(('HTML: Single script block', 'PASS' if script_count == 1 and script_close == 1 else 'FAIL'))
if script_count != 1:
    issues.append(f'Script blocks: {script_count} open, {script_close} close')

# === SECTION 2: UI ELEMENTS ===
ui_checks = [
    ('Voice translate button HTML', 'voiceTranslateBtn' in html),
    ('Voice translate CSS', '.voice-translate-btn' in style_section),
    ('Recording animation CSS', '.voice-translate-btn.recording' in style_section),
    ('@keyframes pulse', '@keyframes pulse' in style_section),
    ('Translation badge CSS', '.translation-badge' in style_section),
    ('Original tooltip CSS', '.original-text-tooltip' in style_section),
]
for name, test in ui_checks:
    results.append((f'UI: {name}', 'PASS' if test else 'FAIL'))
    if not test:
        issues.append(f'Missing: {name}')

# === SECTION 3: JS FUNCTIONS ===
js_checks = [
    ('loadContacts()', 'function loadContacts()' in js_section),
    ('openChat()', 'function openChat(' in js_section),
    ('closeChat()', 'function closeChat()' in js_section),
    ('loadMessages() + translate', 'function loadMessages(' in js_section and '/api/translate-text' in js_section),
    ('sendMessage() + translate', 'function sendMessage()' in js_section),
    ('escapeHtml()', 'function escapeHtml(' in js_section),
    ('showOriginalMessage()', 'function showOriginalMessage(' in js_section),
    ('showToast()', 'function showToast(' in js_section),
    ('SpeechRecognition setup', 'webkitSpeechRecognition' in js_section),
]
for name, test in js_checks:
    results.append((f'JS: {name}', 'PASS' if test else 'FAIL'))
    if not test:
        issues.append(f'Missing JS: {name}')

# Check no duplicate function defs
for fn in ['loadContacts', 'openChat', 'closeChat', 'loadMessages', 'sendMessage', 'escapeHtml', 'showOriginalMessage', 'showToast']:
    c = js_section.count(f'function {fn}(') + js_section.count(f'function {fn} (')
    results.append((f'JS: {fn} no duplicates', 'PASS' if c == 1 else 'FAIL'))
    if c != 1:
        issues.append(f'{fn} defined {c}x (should be 1)')

# === SECTION 4: TRANSLATION FLOW ===
flow_checks = [
    ('Reads language pref from localStorage', 'zeuschat_language' in js_section),
    ('Auto-translates received messages', 'translate-text' in js_section),
    ('Shows translation badge', 'Translated' in js_section),
    ('Sends target_lang for translation', 'target_lang' in js_section),
    ('12 African lang speech map', all(l in js_section for l in ['en-US', 'xh-ZA', 'zu-ZA', 'af-ZA', 'sw-KE', 'yo-NG', 'ha-NG', 'ig-NG', 'am-ET', 'st-ZA', 'tn-ZA', 'nso-ZA'])),
    ('File sharing intact', 'send-file' in js_section),
    ('Voice notes intact', 'MediaRecorder' in js_section),
    ('Bottom nav intact', 'bottom-nav' in html),
    ('Auth redirect', '/login.html' in js_section),
    ('Enter key sends message', "e.key === 'Enter'" in js_section or 'key === "Enter"' in js_section),
]
for name, test in flow_checks:
    results.append((f'Flow: {name}', 'PASS' if test else 'FAIL'))
    if not test:
        issues.append(f'Missing flow: {name}')

# === SECTION 5: API ENDPOINT TESTS ===
api_tests = [
    ('zu->en Sawubona', {'text': 'Sawubona', 'source_lang': 'zu', 'target_lang': 'en'}, 'hello'),
    ('af->en Goeie more', {'text': 'Goeie more', 'source_lang': 'af', 'target_lang': 'en'}, 'good morning'),
    ('en->zu Hello friend', {'text': 'Hello friend', 'source_lang': 'en', 'target_lang': 'zu'}, None),
    ('xh->en Molo', {'text': 'Molo', 'source_lang': 'xh', 'target_lang': 'en'}, None),
]

for name, payload, expected in api_tests:
    time.sleep(0.5)
    try:
        r = requests.post(f'{BASE}/api/translate-text', json=payload, timeout=15)
        d = r.json()
        t = d.get('translated_text', '')
        if expected:
            ok = r.status_code == 200 and expected in t.lower()
        else:
            ok = r.status_code == 200 and t and t != payload['text'] and 'INVALID' not in t.upper()
        results.append((f'API: {name} -> "{t}"', 'PASS' if ok else 'FAIL'))
        if not ok:
            issues.append(f'{name} got: "{t}"')
    except Exception as e:
        results.append((f'API: {name}', 'FAIL'))
        issues.append(f'{name}: {e}')

# detect-language
time.sleep(0.5)
try:
    r = requests.post(f'{BASE}/api/detect-language', json={'text': 'Ndiyakuthanda'}, timeout=15)
    d = r.json()
    ok = r.status_code == 200 and 'detected_language' in d
    results.append((f'API: detect-language -> {d.get("detected_language","")}', 'PASS' if ok else 'FAIL'))
except Exception as e:
    results.append(('API: detect-language', 'FAIL'))
    issues.append(str(e))

# CSRF exempt test
time.sleep(0.3)
try:
    r = requests.post(f'{BASE}/api/translate-text', json={'text': 'test', 'source_lang': 'en', 'target_lang': 'zu'}, timeout=15)
    results.append(('API: CSRF exempt (no token needed)', 'PASS' if r.status_code == 200 else 'FAIL'))
    if r.status_code != 200:
        issues.append(f'CSRF blocking: status {r.status_code}')
except Exception as e:
    results.append(('API: CSRF exempt', 'FAIL'))
    issues.append(str(e))

# === PRINT REPORT ===
passed = sum(1 for _, s in results if s == 'PASS')
failed = sum(1 for _, s in results if s == 'FAIL')
total = len(results)

print('=' * 64)
print('  ZEUSCHAT MOBILE TRANSLATION SYSTEM - FULL AUDIT REPORT')
print('  Date: 13 April 2026')
print('=' * 64)

sections = {
    'FILE INTEGRITY': ['CSS:', 'HTML:'],
    'UI ELEMENTS': ['UI:'],
    'JS FUNCTIONS': ['JS:'],
    'TRANSLATION FLOW': ['Flow:'],
    'API ENDPOINTS': ['API:'],
}
for section, prefixes in sections.items():
    print(f'\n  --- {section} ---')
    for name, status in results:
        if any(name.startswith(p) for p in prefixes):
            icon = 'PASS' if status == 'PASS' else 'FAIL'
            print(f'  [{icon}] {name}')

print('\n' + '-' * 64)
print(f'  TOTAL: {passed}/{total} passed | {failed} failed')
print('-' * 64)

if issues:
    print('\n  ISSUES FOUND:')
    for i, iss in enumerate(issues, 1):
        print(f'    {i}. {iss}')
else:
    print('\n  NO ISSUES FOUND')

print('\n' + '=' * 64)
if failed == 0:
    print('  VERDICT: ALL CHECKS PASSED - MOBILE TRANSLATION SYSTEM READY')
else:
    print(f'  VERDICT: {failed} ISSUE(S) NEED ATTENTION')
print('=' * 64)
