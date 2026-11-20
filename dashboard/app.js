const API_URL = 'http://127.0.0.1:8000';
let distChart = null;
let riskBarChart = null;

document.addEventListener('DOMContentLoaded', () => {
    // Tab switching logic
    const navButtons = document.querySelectorAll('.nav-btn');
    const tabPanes = document.querySelectorAll('.tab-pane');

    navButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const targetTab = btn.getAttribute('data-tab');
            navButtons.forEach(b => b.classList.remove('active'));
            tabPanes.forEach(p => p.classList.remove('active'));

            btn.classList.add('active');
            const activePane = document.getElementById(`tab-${targetTab}`);
            if (activePane) activePane.classList.add('active');
        });
    });

    // Initial Data Fetch
    fetchStats();
    fetchHistory();
    fetchAcademicMetrics();

    // Poll stats every 5 seconds for live dashboard feeling
    setInterval(fetchStats, 5000);
});

async function fetchStats() {
    try {
        const response = await fetch(`${API_URL}/stats`);
        const stats = await response.json();
        
        document.getElementById('stat-total').textContent = stats.total_scans;
        document.getElementById('stat-safe').textContent = stats.safe;
        document.getElementById('stat-suspicious').textContent = stats.suspicious;
        document.getElementById('stat-malicious').textContent = stats.phishing + stats.malicious;
        document.getElementById('stat-blocked').textContent = stats.blocked;

        updateCharts(stats);
    } catch (error) {
        console.warn('Backend not responding yet on port 8000');
    }
}

async function fetchHistory() {
    try {
        const response = await fetch(`${API_URL}/history?limit=15`);
        const history = await response.json();
        
        const tbody = document.getElementById('history-body');
        tbody.innerHTML = '';
        
        if (history.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" style="text-align:center; color:#64748b; padding:24px;">No threat logs recorded yet. Browse any site or test via API to populate.</td></tr>`;
            return;
        }

        history.forEach(item => {
            const tr = document.createElement('tr');
            const date = new Date(item.timestamp).toLocaleTimeString();
            
            let tagClass = 'tag-safe';
            if (item.status === 'SUSPICIOUS') tagClass = 'tag-suspicious';
            else if (item.status === 'PHISHING' || item.status === 'MALICIOUS') tagClass = 'tag-malicious';
            
            tr.innerHTML = `
                <td style="color: #94a3b8; font-family:'JetBrains Mono';">${date}</td>
                <td style="word-break: break-all; max-width: 380px; font-weight: 500;">${escapeHtml(item.url)}</td>
                <td><span class="table-tag ${tagClass}">${item.status}</span></td>
                <td style="font-family:'JetBrains Mono'; font-weight:700;">${item.risk_score}/100</td>
                <td style="font-family:'JetBrains Mono'; color:#38bdf8;">${(item.confidence * 100).toFixed(0)}%</td>
                <td style="font-weight: 700; color: ${item.action === 'BLOCK' ? '#f43f5e' : '#34d399'}">${item.action}</td>
            `;
            tbody.appendChild(tr);
        });
    } catch (error) {
        console.error('Error fetching history:', error);
    }
}

async function fetchAcademicMetrics() {
    try {
        const res = await fetch('reports/metrics.json');
        if (res.ok) {
            const data = await res.json();
            document.getElementById('kpi-acc').textContent = `${(data.accuracy * 100).toFixed(2)}%`;
            document.getElementById('kpi-auc').textContent = data.roc_auc.toFixed(4);
            document.getElementById('kpi-latency').textContent = `${data.mean_latency_ms} ms`;
        }
    } catch (e) {
        console.log("Static metrics file loaded via default fallbacks.");
    }
}

function updateCharts(stats) {
    const distCtx = document.getElementById('distributionChart').getContext('2d');
    const barCtx = document.getElementById('riskBarChart').getContext('2d');
    
    // Doughnut Chart
    if (distChart) distChart.destroy();
    distChart = new Chart(distCtx, {
        type: 'doughnut',
        data: {
            labels: ['Safe', 'Suspicious', 'Phishing', 'Malicious'],
            datasets: [{
                data: [stats.safe, stats.suspicious, stats.phishing, stats.malicious],
                backgroundColor: ['#10b981', '#f59e0b', '#f43f5e', '#881337'],
                borderColor: '#131b2e',
                borderWidth: 3
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: { color: '#94a3b8', font: { family: 'Plus Jakarta Sans', size: 12 } }
                }
            }
        }
    });

    // Bar Chart
    if (riskBarChart) riskBarChart.destroy();
    riskBarChart = new Chart(barCtx, {
        type: 'bar',
        data: {
            labels: ['Clean/Safe', 'Warning State', 'Critical Risk'],
            datasets: [{
                label: 'Interception Volume',
                data: [stats.safe, stats.suspicious, stats.phishing + stats.malicious],
                backgroundColor: ['#10b981', '#f59e0b', '#f43f5e'],
                borderRadius: 8
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: { ticks: { color: '#94a3b8' }, grid: { display: false } },
                y: { ticks: { color: '#94a3b8' }, grid: { color: 'rgba(255,255,255,0.05)' } }
            },
            plugins: {
                legend: { display: false }
            }
        }
    });
}

function escapeHtml(text) {
    if (!text) return '';
    return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}
