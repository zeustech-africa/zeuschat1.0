// Connection detection for video quality optimization
(function() {
  function getConnectionType() {
    if (navigator.connection) {
      const conn = navigator.connection;
      if (conn.saveData === true) return 'low';
      if (conn.effectiveType === '4g') return 'high';
      if (conn.effectiveType === '3g') return 'medium';
      if (conn.effectiveType === '2g' || conn.effectiveType === 'slow-2g') return 'low';
      if (typeof conn.downlink === 'number' && conn.downlink >= 5) return 'high';
      if (typeof conn.downlink === 'number' && conn.downlink >= 1.5) return 'medium';
      return 'low';
    }
    return 'medium';
  }

  function getVideoSource(quality) {
    const qualityMap = {
      high: '/static/videos/high/chat-bg.mp4',
      medium: '/static/videos/medium/chat-bg.mp4',
      low: '/static/videos/low/chat-bg.mp4'
    };
    return qualityMap[quality] || qualityMap.medium;
  }

  function normalizeUrl(value) {
    try {
      return new URL(value, window.location.origin).pathname;
    } catch (error) {
      return value || '';
    }
  }

  function setVideoQuality(videoElement) {
    if (!videoElement) return;

    // Respect explicit preference set by user unless set to auto.
    const pref = window.ZeusChatVideoPreference && window.ZeusChatVideoPreference.getPreference
      ? window.ZeusChatVideoPreference.getPreference()
      : 'auto';
    if (pref && pref !== 'auto') return;

    const quality = getConnectionType();
    const source = getVideoSource(quality);
    const currentPath = normalizeUrl(videoElement.currentSrc || videoElement.src);
    if (currentPath !== source) {
      videoElement.src = source;
      videoElement.load();
      videoElement.play().catch(function(e) {
        console.log('Autoplay prevented:', e);
      });
    }
    videoElement.setAttribute('data-quality', quality);
  }

  function initVideoBackground() {
    const video = document.querySelector('.chat-background-video');
    if (video) {
      setVideoQuality(video);
      if (navigator.connection && navigator.connection.addEventListener) {
        navigator.connection.addEventListener('change', function() {
          setVideoQuality(video);
        });
      }
    }
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initVideoBackground);
  } else {
    initVideoBackground();
  }

  window.ZeusChatVideo = { getConnectionType: getConnectionType, getVideoSource: getVideoSource, setVideoQuality: setVideoQuality };
})();
