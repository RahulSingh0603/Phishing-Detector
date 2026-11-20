document.addEventListener('DOMContentLoaded', async () => {
  const currentUrlEl = document.getElementById('current-url');
  const statusTextEl = document.getElementById('status-text');
  const riskScoreEl = document.getElementById('risk-score');
  const domFindingsEl = document.getElementById('dom-findings');
  const domStatusTagEl = document.getElementById('dom-status-tag');
  
  chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
    if (tabs.length === 0) return;
    
    const tab = tabs[0];
    try {
      const url = new URL(tab.url);
      currentUrlEl.textContent = url.hostname || tab.url;
    } catch (e) {
      currentUrlEl.textContent = tab.url;
    }
    
    chrome.storage.local.get([tab.id.toString()], (result) => {
      const data = result[tab.id.toString()];
      if (data) {
        updateUI(data);
      } else {
        analyzeUrl(tab.url);
      }
    });
  });

  document.getElementById('scan-btn').addEventListener('click', () => {
    statusTextEl.textContent = "ANALYZING...";
    statusTextEl.className = "status-badge";
    riskScoreEl.textContent = "-- / 100";
    domFindingsEl.innerHTML = '<li class="empty-state">Re-evaluating page forms & structure...</li>';
    
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs.length > 0) analyzeUrl(tabs[0].url);
    });
  });
});

async function analyzeUrl(url) {
  try {
    const response = await fetch('http://127.0.0.1:8000/predict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url })
    });
    const result = await response.json();
    updateUI(result);
  } catch (err) {
    document.getElementById('status-text').textContent = "OFFLINE";
    document.getElementById('status-text').className = "status-badge status-malicious";
  }
}

function updateUI(result) {
  const statusEl = document.getElementById('status-text');
  const scoreEl = document.getElementById('risk-score');
  const domFindingsEl = document.getElementById('dom-findings');
  const domStatusTagEl = document.getElementById('dom-status-tag');
  
  statusEl.textContent = result.status;
  statusEl.className = "status-badge";
  
  if (result.status === 'SAFE') {
    statusEl.classList.add('status-safe');
  } else if (result.status === 'SUSPICIOUS') {
    statusEl.classList.add('status-suspicious');
  } else {
    statusEl.classList.add('status-malicious');
  }
  
  scoreEl.textContent = `${result.risk_score} / 100`;

  // Render DOM & reasons
  domFindingsEl.innerHTML = '';
  const reasons = result.reasons || [];

  if (reasons.length === 0) {
    domFindingsEl.innerHTML = '<li class="empty-state">✓ Form inputs & credentials verified safe</li>';
    domStatusTagEl.textContent = "Verified";
    domStatusTagEl.style.background = "#064e3b";
    domStatusTagEl.style.color = "#34d399";
  } else {
    reasons.forEach(r => {
      const li = document.createElement('li');
      li.textContent = "• " + r;
      if (r.includes('fake') || r.includes('Insecure') || r.includes('External Form') || r.includes('malicious')) {
        li.className = 'danger-item';
      } else {
        li.className = 'warning-item';
      }
      domFindingsEl.appendChild(li);
    });
    domStatusTagEl.textContent = "Alerts Found";
    domStatusTagEl.style.background = "#7f1d1d";
    domStatusTagEl.style.color = "#f87171";
  }
}
