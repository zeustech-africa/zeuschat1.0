// User video quality preference
(function() {
  const STORAGE_KEY = 'zeuschat_video_quality';
  const QUALITIES = {
    auto: 'Auto (Based on connection)',
    high: 'High Quality',
    medium: 'Medium Quality',
    low: 'Low Quality',
    off: 'Off (No video)'
  };

  function getPreference() {
    return localStorage.getItem(STORAGE_KEY) || 'auto';
  }

  function setPreference(value) {
    if (QUALITIES[value]) {
      localStorage.setItem(STORAGE_KEY, value);
    }
  }

  function getVideoSource() {
    const pref = getPreference();
    if (pref === 'off') return null;
    if (pref !== 'auto') return '/static/videos/' + pref + '/chat-bg.mp4';

    if (window.ZeusChatVideo && window.ZeusChatVideo.getConnectionType && window.ZeusChatVideo.getVideoSource) {
      return window.ZeusChatVideo.getVideoSource(window.ZeusChatVideo.getConnectionType());
    }

    return '/static/videos/medium/chat-bg.mp4';
  }

  function normalizeUrl(value) {
    try {
      return new URL(value, window.location.origin).pathname;
    } catch (error) {
      return value || '';
    }
  }

  function applyPreference() {
    const video = document.querySelector('.chat-background-video');
    if (!video) return;

    const source = getVideoSource();
    if (source === null) {
      video.style.display = 'none';
      video.pause();
      return;
    }

    video.style.display = 'block';
    const currentPath = normalizeUrl(video.currentSrc || video.src);
    if (currentPath !== source) {
      video.src = source;
      video.load();
      video.play().catch(function(e) {
        console.log('Autoplay prevented:', e);
      });
    }
  }

  function createSettingsUI() {
    const container = document.createElement('div');
    container.className = 'video-quality-settings section';
    container.innerHTML =
      '<div class="section-title">Video Background Quality</div>' +
      '<div id="video-quality-options">' +
      Object.entries(QUALITIES)
        .map(function(entry) {
          const value = entry[0];
          const label = entry[1];
          const checked = getPreference() === value ? 'checked' : '';
          return '<label style="display:block;margin-bottom:8px;">' +
            '<input type="radio" name="video-quality" value="' + value + '" ' + checked + '> ' + label +
            '</label>';
        })
        .join('') +
      '</div>' +
      '<button id="save-video-quality" class="btn" style="margin-top:12px;">Save Video Preference</button>';

    const saveButton = container.querySelector('#save-video-quality');
    if (saveButton) {
      saveButton.onclick = function() {
        const selected = container.querySelector('input[name="video-quality"]:checked');
        if (selected) {
          setPreference(selected.value);
          applyPreference();
        }
      };
    }

    return container;
  }

  function addToSettings() {
    const settings = document.querySelector('.settings-container, #settings-page, .settings-content, .container');
    if (settings && !document.querySelector('.video-quality-settings')) {
      settings.appendChild(createSettingsUI());
    }
  }

  document.addEventListener('DOMContentLoaded', function() {
    applyPreference();
    addToSettings();
  });

  window.ZeusChatVideoPreference = {
    getPreference: getPreference,
    setPreference: setPreference,
    applyPreference: applyPreference
  };
})();
