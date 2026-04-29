#!/usr/bin/env python3
"""
Cross-Platform Fix Script
Fixes mobile-chat.html to match chat.html for:
1. translation-badge CSS class
2. original-text-tooltip CSS class
3. Auto-translate JS logic
"""

import re

MOBILE_FILE = '/Users/administrator/Desktop/zeuschat/mobile-chat.html'
CHAT_FILE = '/Users/administrator/Desktop/zeuschat/chat.html'

def read_file(path):
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()

def write_file(path, content):
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)

def main():
    mobile = read_file(MOBILE_FILE)
    chat = read_file(CHAT_FILE)
    
    fixes = 0
    
    # ====================================
    # FIX 1: Add translation-badge CSS
    # ====================================
    if '.translation-badge' not in mobile:
        print("FIX 1: Adding .translation-badge CSS to mobile-chat.html...")
        
        # Find the message-translation CSS block in mobile-chat.html
        # Add after .message-translation CSS
        css_block = """
    .translation-badge {
      font-size: 10px;
      color: #D4AF37;
      margin-top: 4px;
      display: flex;
      align-items: center;
      gap: 4px;
      cursor: pointer;
    }
    .original-text-tooltip {
      font-size: 10px;
      color: #888;
      cursor: pointer;
      text-decoration: underline dotted;
      margin-right: 6px;
    }
"""
        # Find the footer CSS to insert before it
        footer_idx = mobile.rfind('.footer')
        if footer_idx > -1:
            # Find the previous CSS closing brace before footer
            prev_brace = mobile.rfind('}', 0, footer_idx)
            if prev_brace > -1:
                insert_pos = prev_brace + 1
                mobile = mobile[:insert_pos] + css_block + mobile[insert_pos:]
                fixes += 1
                print("  ✅ Added translation-badge and original-text-tooltip CSS")
    
    # ====================================
    # FIX 2: Find displayMessage and add auto-translate badge logic
    # ====================================
    if 'autoTranslate' not in mobile and 'userLanguage' in mobile:
        print("FIX 2: Adding auto-translate display logic to mobile-chat.html...")
        
        # Find message HTML template - look for the div that contains message content
        # We need to find where chat.html inserts the badge HTML
        # chat.html line 2890: translationHtml + originalTextHtml
        
        # Find the spot in displayMessage where the message content is rendered
        # Look for where .translate-btn is appended in mobile
        translate_btn_pattern = r'(translateBtn\.setAttribute\([\'"]data-message-text[\'"].*?\))'
        match = re.search(translate_btn_pattern, mobile)
        if match:
            # Add auto-translate logic after this
            auto_translate_js = """
        
        // Auto-translate if user has preferred language
        if (currentUserLang && currentUserLang !== 'en' && message.user_id !== currentUserId) {
          // Check if user has auto-translate enabled
          const autoTier = tierLevel_user >= 1; // free users can auto-translate
          if (autoTier) {
            try {
              const trResp = await fetch('/api/translate-text', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                  text: message.content || '',
                  source_lang: 'en',
                  target_lang: currentUserLang
                })
              });
              const trData = await trResp.json();
              if (trData.translated_text) {
                messageText.textContent = trData.translated_text;
                const badgeHtml = document.createElement('div');
                badgeHtml.className = 'translation-badge';
                badgeHtml.innerHTML = `🌐 Translated to ${currentUserLang.toUpperCase()}`;
                badgeHtml.onclick = function() { alert('🌐 Original message:\\n\\n' + (message.content || '')); };
                messageText.insertAdjacentElement('afterend', badgeHtml);
              }
            } catch(e) {
              console.error('Auto-translate error:', e);
            }
          }
        }
"""
            # Find the line after translateBtn setup and before closing of the displayMessage section
            insert_after = match.end()
            mobile = mobile[:insert_after] + auto_translate_js + mobile[insert_after:]
            fixes += 1
            print("  ✅ Added auto-translate logic to displayMessage()")
    
    # ====================================
    # FIX 3: Add autoTranslate variable and settings check in mobile-chat.html
    # ====================================
    if 'autoTranslate' not in mobile:
        print("FIX 3: Adding autoTranslate variable initialization...")
        # Find the tier level checks in mobile-chat.html
        tier_pattern = r'(tierLevel_user\s*>=\s*TIER_HIERARCHY\.indexOf\(.*?\).*?;)'
        match = re.search(tier_pattern, mobile)
        if match:
            # Find last tier variable and add autoTranslate after it
            all_matches = list(re.finditer(tier_pattern, mobile))
            last_match = all_matches[-1]
            insert_pos = last_match.end()
            auto_translate_var = """
          
          AutoTranslate = tierLevel_user >= TIER_HIERARCHY.indexOf('pro');
"""
            mobile = mobile[:insert_pos] + auto_translate_var + mobile[insert_pos:]
            fixes += 1
            print("  ✅ Added AutoTranslate variable")
    
    # ====================================
    # FIX 4: Fix speakAgain - check if function exists with different name
    # ====================================
    has_speak_func = bool(re.search(r'recordVoice|startRecording|recording.*voice|voice.*record|speak.*again|restartRecord|newRecord', mobile, re.I))
    if not has_speak_func:
        print("FIX 4: Checking speakAgain/voice re-record functionality...")
        # The "Speak Again" is likely part of the voice translation flow
        # Check if there's a re-record option in the voice modal
        if 'startVoiceRecording' in mobile or 'stopVoiceRecording' in mobile:
            print("  ⚠️ Voice recording functions exist, but 'Speak Again' labeled function not found")
        else:
            print("  ℹ️ Voice recording functions may use different naming")
    
    # ====================================
    # Write fixed file
    # ====================================
    if fixes > 0:
        write_file(MOBILE_FILE, mobile)
        print(f"\n✅ Applied {fixes} fixes to mobile-chat.html")
    else:
        print("\nℹ️ No fixes needed - all features already present")
    
    # Verify fixes
    print("\n=== VERIFICATION ===")
    if '.translation-badge' in mobile:
        print("✅ translation-badge CSS present")
    else:
        print("❌ translation-badge CSS still missing")
    if '.original-text-tooltip' in mobile:
        print("✅ original-text-tooltip CSS present")
    else:
        print("❌ original-text-tooltip CSS still missing")
    if 'autoTranslate' in mobile:
        print("✅ autoTranslate logic present")
    else:
        print("❌ autoTranslate logic still missing")

if __name__ == '__main__':
    main()
