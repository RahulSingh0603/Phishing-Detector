const API_URL = "http://127.0.0.1:8000";

let cache = {}; // in-memory allow cache

// Intercept before navigation commits (Stage 1: URL Pre-Scan)
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;
  
  const url = details.url;
  
  if (url.startsWith('chrome://') || url.startsWith('chrome-extension://') || url.startsWith('http://127.0.0.1')) {
    return;
  }
  
  if (cache[url] === 'ALLOW') return;

  try {
    const response = await fetch(`${API_URL}/predict`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url })
    });
    
    const result = await response.json();
    
    chrome.storage.local.set({ [details.tabId]: result });
    
    if (result.action === 'BLOCK') {
      const warningUrl = chrome.runtime.getURL(`warning.html?url=${encodeURIComponent(url)}&score=${result.risk_score}&reasons=${encodeURIComponent(JSON.stringify(result.reasons))}`);
      chrome.tabs.update(details.tabId, { url: warningUrl });
    }
    
  } catch (err) {
    console.error("PhishGuard Backend not reachable:", err);
  }
});

// Listen for messages from warning page or content scripts (Stage 2: DOM & Form Analysis)
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'allow_url') {
    cache[message.url] = 'ALLOW';
    if (sender.tab) {
        chrome.storage.local.remove(sender.tab.id.toString());
    }
    chrome.tabs.update(sender.tab.id, { url: message.url });
    sendResponse({ success: true });
    return true;
  }

  // Handle live DOM inspection result from content.js
  if (message.action === 'dom_inspection_result' && sender.tab) {
    const tabId = sender.tab.id;
    chrome.storage.local.get([tabId.toString()], (result) => {
      let scanData = result[tabId.toString()] || {
        url: message.url,
        status: "SAFE",
        risk_score: 10,
        reasons: [],
        action: "ALLOW"
      };

      // Combine URL findings with DOM findings
      const combinedReasons = Array.from(new Set([...(scanData.reasons || []), ...message.findings]));
      const newScore = Math.min(100, Math.max(scanData.risk_score || 0, message.domRisk));
      
      let updatedStatus = scanData.status;
      let updatedAction = scanData.action;

      if (message.spoofedBrand || newScore >= 75) {
        updatedStatus = "PHISHING";
        updatedAction = "BLOCK";
      } else if (newScore >= 45) {
        updatedStatus = "SUSPICIOUS";
        updatedAction = "WARN";
      }

      const updatedScan = {
        ...scanData,
        status: updatedStatus,
        risk_score: newScore,
        reasons: combinedReasons,
        action: updatedAction,
        dom_inspected: true,
        spoofed_brand: message.spoofedBrand
      };

      chrome.storage.local.set({ [tabId]: updatedScan });

      // If page turned out to be a fake brand login form, block it immediately
      if (updatedAction === 'BLOCK' && scanData.action !== 'BLOCK') {
        const warningUrl = chrome.runtime.getURL(`warning.html?url=${encodeURIComponent(message.url)}&score=${newScore}&reasons=${encodeURIComponent(JSON.stringify(combinedReasons))}`);
        chrome.tabs.update(tabId, { url: warningUrl });
      }
    });
    sendResponse({ received: true });
    return true;
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.local.remove(tabId.toString());
});
