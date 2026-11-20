document.addEventListener('DOMContentLoaded', () => {
  const urlParams = new URLSearchParams(window.location.search);
  const targetUrl = urlParams.get('url');
  const score = urlParams.get('score');
  
  let reasons = [];
  try {
    reasons = JSON.parse(urlParams.get('reasons') || '[]');
  } catch (e) {
    console.error("Failed to parse reasons");
  }

  if (targetUrl) {
    document.getElementById('target-url').textContent = targetUrl;
  }
  
  if (score) {
    document.getElementById('score-val').textContent = score;
  }
  
  const reasonsList = document.getElementById('reasons-list');
  if (reasons.length > 0) {
    reasons.forEach(r => {
      const li = document.createElement('li');
      li.textContent = r;
      reasonsList.appendChild(li);
    });
  } else {
    reasonsList.innerHTML = "<li>Suspicious patterns detected by AI model.</li>";
  }

  document.getElementById('btn-back').addEventListener('click', () => {
    // Go back or close tab
    if (window.history.length > 1) {
      window.history.back();
    } else {
      window.close();
    }
  });

  document.getElementById('btn-proceed').addEventListener('click', () => {
    // Send message to background to allow this URL temporarily
    chrome.runtime.sendMessage({ action: 'allow_url', url: targetUrl }, (response) => {
      if (response && response.success) {
        // The background script will redirect the tab, but we can also do it here just in case
        window.location.href = targetUrl;
      }
    });
  });
});
