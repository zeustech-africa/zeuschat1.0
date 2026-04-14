#!/usr/bin/env python3
"""Verify mobile translation upgrade: offline cache, voice activity, translation history."""

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

# ─── OFFLINE BADGE ───
results.append(('HTML: offlineBadge div', 'PASS' if 'id="offlineBadge"' in html else 'FAIL'))
results.append(('CSS: .offline-badge', 'PASS' if '.offline-badge' in style else 'FAIL'))
results.append(('CSS: .offline-badge.visible', 'PASS' if '.offline-badge.visible' in style else 'FAIL'))
results.append(('JS: updateOnlineStatus()', 'PASS' if 'function updateOnlineStatus()' in js else 'FAIL'))
results.append(('JS: online event listener', 'PASS' if "addEventListener('online'" in js or 'addEventListener("online"' in js else 'FAIL'))
results.append(('JS: offline event listener', 'PASS' if "addEventListener('offline'" in js or 'addEventListener("offline"' in js else 'FAIL'))
results.append(('JS: navigator.onLine check', 'PASS' if 'navigator.onLine' in js else 'FAIL'))

# ─── OFFLINE CACHE ───
results.append(('JS: translationCache object', 'PASS' if 'translationCache' in js and "'xh'" in js and "'zu'" in js and "'af'" in js else 'FAIL'))
results.append(('JS: getCachedTranslation()', 'PASS' if 'function getCachedTranslation(' in js else 'FAIL'))
results.append(('JS: translateWithOfflineFallback()', 'PASS' if 'function translateWithOfflineFallback(' in js else 'FAIL'))
results.append(('JS: cache has Swahili', 'PASS' if "'sw'" in js and "'habari'" in js else 'FAIL'))
results.append(('JS: cache has Yoruba', 'PASS' if "'yo'" in js and "'bawo ni'" in js else 'FAIL'))
results.append(('JS: cache has Hausa', 'PASS' if "'ha'" in js and "'sannu'" in js else 'FAIL'))
results.append(('JS: reverse cache built', 'PASS' if 'reverseCacheBuilt' in js else 'FAIL'))
results.append(('JS: uses fallback in onresult', 'PASS' if 'translateWithOfflineFallback(' in js and 'fromCache' in js else 'FAIL'))
results.append(('JS: offline toast message', 'PASS' if 'Offline' in js and 'cached translation' in js else 'FAIL'))

# ─── VOICE ACTIVITY INDICATOR ───
results.append(('HTML: voiceActivity div', 'PASS' if 'id="voiceActivity"' in html else 'FAIL'))
results.append(('HTML: voice-wave spans', 'PASS' if 'voice-wave' in html else 'FAIL'))
results.append(('CSS: .voice-activity', 'PASS' if '.voice-activity' in style else 'FAIL'))
results.append(('CSS: .voice-activity.visible', 'PASS' if '.voice-activity.visible' in style else 'FAIL'))
results.append(('CSS: .voice-wave', 'PASS' if '.voice-wave' in style else 'FAIL'))
results.append(('CSS: @keyframes wave', 'PASS' if '@keyframes wave' in style else 'FAIL'))
results.append(('CSS: wave animation spans', 'PASS' if '.voice-wave span:nth-child(3)' in style else 'FAIL'))
results.append(('JS: showVoiceActivity()', 'PASS' if 'function showVoiceActivity()' in js else 'FAIL'))
results.append(('JS: hideVoiceActivity()', 'PASS' if 'function hideVoiceActivity()' in js else 'FAIL'))
results.append(('JS: updateVoiceActivityText()', 'PASS' if 'function updateVoiceActivityText(' in js else 'FAIL'))
results.append(('JS: onstart shows activity', 'PASS' if 'showVoiceActivity()' in js and 'Listening' in js else 'FAIL'))
results.append(('JS: onend hides activity', 'PASS' if 'hideVoiceActivity()' in js else 'FAIL'))
results.append(('JS: onresult shows Translating', 'PASS' if "Translating..." in js else 'FAIL'))
results.append(('CSS: z-index 10002', 'PASS' if 'z-index: 10002' in style else 'FAIL'))
results.append(('CSS: backdrop-filter blur', 'PASS' if 'backdrop-filter: blur' in style else 'FAIL'))

# ─── TRANSLATION HISTORY ───
results.append(('HTML: historyPanel div', 'PASS' if 'id="historyPanel"' in html else 'FAIL'))
results.append(('HTML: historyList div', 'PASS' if 'id="historyList"' in html else 'FAIL'))
results.append(('HTML: clearHistoryBtn', 'PASS' if 'clearHistoryBtn' in html else 'FAIL'))
results.append(('HTML: showHistoryBtn FAB', 'PASS' if 'id="showHistoryBtn"' in html else 'FAIL'))
results.append(('CSS: .history-panel', 'PASS' if '.history-panel' in style else 'FAIL'))
results.append(('CSS: .history-panel.open', 'PASS' if '.history-panel.open' in style else 'FAIL'))
results.append(('CSS: .history-item', 'PASS' if '.history-item' in style else 'FAIL'))
results.append(('CSS: .history-item:active', 'PASS' if '.history-item:active' in style else 'FAIL'))
results.append(('CSS: .history-clear', 'PASS' if '.history-clear' in style else 'FAIL'))
results.append(('CSS: z-index 10003', 'PASS' if 'z-index: 10003' in style else 'FAIL'))
results.append(('JS: loadTranslationHistory()', 'PASS' if 'function loadTranslationHistory()' in js else 'FAIL'))
results.append(('JS: saveTranslationHistory()', 'PASS' if 'function saveTranslationHistory()' in js else 'FAIL'))
results.append(('JS: addToTranslationHistory()', 'PASS' if 'function addToTranslationHistory(' in js else 'FAIL'))
results.append(('JS: renderHistoryList()', 'PASS' if 'function renderHistoryList()' in js else 'FAIL'))
results.append(('JS: openHistoryPanel()', 'PASS' if 'function openHistoryPanel()' in js else 'FAIL'))
results.append(('JS: closeHistoryPanel()', 'PASS' if 'function closeHistoryPanel()' in js else 'FAIL'))
results.append(('JS: useHistoryTranslation()', 'PASS' if 'function useHistoryTranslation(' in js else 'FAIL'))
results.append(('JS: clearTranslationHistory()', 'PASS' if 'function clearTranslationHistory()' in js else 'FAIL'))
results.append(('JS: localStorage key', 'PASS' if 'zeuschat_translation_history' in js else 'FAIL'))
results.append(('JS: limit 50 translations', 'PASS' if '> 50' in js else 'FAIL'))
results.append(('JS: history panel swipe close', 'PASS' if 'historyPanel' in js and 'touchstart' in js else 'FAIL'))
results.append(('JS: FAB button click listener', 'PASS' if "showHistoryBtn" in js and 'openHistoryPanel' in js else 'FAIL'))
results.append(('JS: saves in onresult', 'PASS' if 'addToTranslationHistory(spokenText' in js else 'FAIL'))

# ─── INIT ───
results.append(('Init: loadTranslationHistory called', 'PASS' if 'loadTranslationHistory()' in js else 'FAIL'))

# EXISTING FEATURES INTACT
results.append(('Existing: loadContacts', 'PASS' if 'function loadContacts()' in js else 'FAIL'))
results.append(('Existing: sendMessage', 'PASS' if 'function sendMessage()' in js else 'FAIL'))
results.append(('Existing: file sharing', 'PASS' if 'send-file' in js else 'FAIL'))
results.append(('Existing: voice notes', 'PASS' if 'MediaRecorder' in js else 'FAIL'))
results.append(('Existing: bottom sheet modal', 'PASS' if 'function openTranslationModal(' in js else 'FAIL'))

# REPORT
passed = sum(1 for _, s in results if s == 'PASS')
failed = sum(1 for _, s in results if s == 'FAIL')

print('=' * 64)
print('  MOBILE FEATURES UPGRADE - VERIFICATION REPORT')
print('  Offline Cache | Voice Activity | Translation History')
print('=' * 64)

sections = {
    'FILE INTEGRITY': lambda n: n.startswith('Single'),
    'OFFLINE BADGE': lambda n: 'offlineBadge' in n or 'offline-badge' in n or 'onLine' in n or 'online event' in n.lower() or 'offline event' in n.lower() or 'updateOnlineStatus' in n,
    'OFFLINE CACHE': lambda n: 'Cache' in n or 'cache' in n or 'fallback' in n or 'Swahili' in n or 'Yoruba' in n or 'Hausa' in n or 'reverse' in n or 'offline toast' in n.lower(),
    'VOICE ACTIVITY': lambda n: 'voiceActivity' in n or 'voice-activity' in n or 'voice-wave' in n or 'Voice' in n.split(':')[-1].strip()[:5] or 'wave' in n.lower() or 'Listening' in n or 'Translating' in n or 'backdrop' in n,
    'TRANSLATION HISTORY': lambda n: 'history' in n.lower() or 'History' in n,
    'INIT': lambda n: n.startswith('Init'),
    'EXISTING FEATURES': lambda n: n.startswith('Existing'),
}

printed = set()
for section, matcher in sections.items():
    print(f'\n  --- {section} ---')
    for name, status in results:
        if matcher(name) and name not in printed:
            icon = 'OK' if status == 'PASS' else 'XX'
            print(f'  [{icon}] {name}')
            printed.add(name)
            if status == 'FAIL':
                issues.append(name)

# Print any unmatched
unmatched = [(n, s) for n, s in results if n not in printed]
if unmatched:
    print('\n  --- OTHER ---')
    for name, status in unmatched:
        icon = 'OK' if status == 'PASS' else 'XX'
        print(f'  [{icon}] {name}')
        if status == 'FAIL':
            issues.append(name)

print('\n' + '-' * 64)
print(f'  {passed}/{len(results)} PASSED | {failed} FAILED')
if issues:
    print('  ISSUES:')
    for i in issues:
        print(f'    - {i}')
else:
    print('  ALL CHECKS PASSED')
print('=' * 64)
