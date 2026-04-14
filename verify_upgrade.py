#!/usr/bin/env python3
"""Verify mobile translation upgrade: bottom sheet, speak again, pro tier."""

with open('templates/mobile-chat.html', 'r') as f:
    html = f.read()

style = html.split('<style>')[1].split('</style>')[0]
js = html.split('<script>')[1].split('</script>')[0]

results = []
issues = []

# FILE INTEGRITY
results.append(('Single DOCTYPE', 'PASS' if html.count('<!DOCTYPE') == 1 else 'FAIL'))
results.append(('Single <script>', 'PASS' if html.count('<script>') == 1 else 'FAIL'))
results.append(('Single </script>', 'PASS' if html.count('</script>') == 1 else 'FAIL'))
results.append(('No HTML in CSS', 'PASS' if '<button' not in style and '<div' not in style else 'FAIL'))

# BOTTOM SHEET HTML
for elem_id in ['translationModal', 'originalSpokenText', 'editTranslatedText',
                'sendTranslatedBtn', 'speakAgainBtn', 'cancelTranslationBtn', 'proUpgradeHint']:
    results.append((f'HTML: {elem_id}', 'PASS' if f'id="{elem_id}"' in html else 'FAIL'))

results.append(('HTML: bottom-sheet-handle', 'PASS' if 'bottom-sheet-handle' in html else 'FAIL'))
results.append(('HTML: /subscription link', 'PASS' if '/subscription' in html else 'FAIL'))

# BOTTOM SHEET CSS
css_checks = [
    ('.translation-bottom-sheet', '.translation-bottom-sheet {'),
    ('.open animation class', '.translation-bottom-sheet.open'),
    ('.bottom-sheet-handle', '.bottom-sheet-handle'),
    ('.bottom-sheet-header', '.bottom-sheet-header'),
    ('.edit-textarea', '.edit-textarea'),
    ('.btn-send', '.btn-send'),
    ('.btn-speak-again', '.btn-speak-again'),
    ('.btn-cancel', '.btn-cancel'),
    ('.pro-upgrade-hint', '.pro-upgrade-hint'),
    ('z-index 10001', 'z-index: 10001'),
    ('border-radius 28px', 'border-top-left-radius: 28px'),
    ('max-height 85vh', 'max-height: 85vh'),
    ('touch-action pan-y', 'touch-action: pan-y'),
    ('min-height 52px (touch target)', 'min-height: 52px'),
]
for name, check in css_checks:
    results.append((f'CSS: {name}', 'PASS' if check in style else 'FAIL'))

# JS CONFIRMATION SYSTEM
js_funcs = [
    'openTranslationModal', 'closeTranslationModal', 'initSwipeToClose',
    'sendEditedMessage', 'speakAgain', 'sendTranslatedMessage',
    'checkProStatusForTranslation',
]
for fn in js_funcs:
    results.append((f'JS: {fn}()', 'PASS' if f'function {fn}(' in js else 'FAIL'))

# Haptic feedback
results.append(('Haptic: vibrate(50) on open', 'PASS' if 'navigator.vibrate(50)' in js else 'FAIL'))
results.append(('Haptic: vibrate(30) on send', 'PASS' if 'navigator.vibrate(30)' in js else 'FAIL'))
results.append(('Haptic: vibrate(200) on error', 'PASS' if 'navigator.vibrate(200)' in js else 'FAIL'))

# Swipe to close
results.append(('Swipe: touchstart listener', 'PASS' if 'touchstart' in js else 'FAIL'))
results.append(('Swipe: touchmove diff>50', 'PASS' if 'diff > 50' in js else 'FAIL'))

# Auto-focus
results.append(('UX: auto-focus textarea', 'PASS' if 'editTranslatedText' in js and '.focus()' in js else 'FAIL'))

# Voice handler uses modal
results.append(('Voice: opens modal', 'PASS' if 'openTranslationModal(spokenText, englishText)' in js else 'FAIL'))
results.append(('Voice: checks pro status', 'PASS' if 'checkProStatusForTranslation()' in js else 'FAIL'))

# Event listeners
results.append(('Event: sendTranslatedBtn click', 'PASS' if "sendTranslatedBtn" in js and 'sendEditedMessage' in js else 'FAIL'))
results.append(('Event: speakAgainBtn click', 'PASS' if "speakAgainBtn" in js and 'speakAgain' in js else 'FAIL'))
results.append(('Event: cancelTranslationBtn click', 'PASS' if "cancelTranslationBtn" in js and 'closeTranslationModal' in js else 'FAIL'))

# EXISTING FEATURES INTACT
results.append(('Existing: loadContacts', 'PASS' if 'function loadContacts()' in js else 'FAIL'))
results.append(('Existing: sendMessage', 'PASS' if 'function sendMessage()' in js else 'FAIL'))
results.append(('Existing: file sharing', 'PASS' if 'send-file' in js else 'FAIL'))
results.append(('Existing: voice notes', 'PASS' if 'MediaRecorder' in js else 'FAIL'))
results.append(('Existing: 12 lang map', 'PASS' if all(l in js for l in ['xh-ZA','zu-ZA','af-ZA','sw-KE','yo-NG','ha-NG','ig-NG','am-ET','st-ZA','tn-ZA','nso-ZA']) else 'FAIL'))

# REPORT
passed = sum(1 for _, s in results if s == 'PASS')
failed = sum(1 for _, s in results if s == 'FAIL')

print('=' * 64)
print('  MOBILE TRANSLATION UPGRADE - VERIFICATION REPORT')
print('=' * 64)
for name, status in results:
    icon = 'OK' if status == 'PASS' else 'XX'
    print(f'  [{icon}] {name}')
    if status == 'FAIL':
        issues.append(name)
print('-' * 64)
print(f'  {passed}/{len(results)} PASSED | {failed} FAILED')
if issues:
    print('  ISSUES:')
    for i in issues:
        print(f'    - {i}')
else:
    print('  ALL CHECKS PASSED')
print('=' * 64)
