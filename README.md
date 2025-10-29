# firewall-pipeline.
transformer based end to end web application firewall  pipeline   use ai models to detect and block web attacks by learning traffic patterns automatically . it improves security by identifying new and unknown threats without relying on fixing rules.
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Transformer WAF Security Dashboard</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css">
    <style>
        .header-section { padding: 20px 0; background-color: #f8f9fa; border-bottom: 1px solid #e9ecef; }
        .stat-card { border-left: 5px solid; transition: transform 0.2s; }
        .stat-card:hover { transform: translateY(-5px); box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
        
        .card-total { border-color: #007bff; }
        .card-blocked { border-color: #dc3545; }
        .card-allowed { border-color: #28a745; }
        
        .text-malicious { color: #dc3545; font-weight: bold; }
        .text-benign { color: #28a745; }
        
        /* Table enhancements for visual feedback */
        .table-log tbody tr.table-danger { background-color: #f8d7da !important; }
        .table-log tbody tr.table-warning { background-color: #fff3cd !important; } /* For Rate Limit blocks */
        
        .nav-button { margin-left: 10px; }
    </style>
</head>
<body>
    <nav class="navbar navbar-dark bg-dark">
        <div class="container-fluid container">
            <span class="navbar-brand mb-0 h1">
                <i class="fa-solid fa-robot"></i> Transformer WAF | Security Console
            </span>
            <button class="btn btn-outline-light nav-button" onclick="fetchStats(); fetchAndRenderLogs();">
                <i class="fas fa-sync-alt"></i> Refresh
            </button>
        </div>
    </nav>

    <div class="container mt-4">
        
        <div class="header-section mb-4">
            <h2 class="mb-4 text-primary"><i class="fas fa-chart-line"></i> Real-time Traffic Overview</h2>
            <div class="row">
                <div class="col-md-3 mb-3">
                    <div class="card p-3 stat-card card-blocked">
                        <h5 class="card-title text-danger"><i class="fas fa-brain"></i> ML Blocks</h5>
                        <p class="display-6 text-danger" id="blocked-ml-count">0</p>
                    </div>
                </div>
                <div class="col-md-3 mb-3">
                    <div class="card p-3 stat-card" style="border-color: orange;">
                        <h5 class="card-title text-warning"><i class="fas fa-tachometer-alt"></i> Rate Limited</h5>
                        <p class="display-6 text-warning" id="blocked-rate-count">0</p>
                    </div>
                </div>
                <div class="col-md-3 mb-3">
                    <div class="card p-3 stat-card card-allowed">
                        <h5 class="card-title text-success"><i class="fas fa-check-circle"></i> Total Allowed</h5>
                        <p class="display-6 text-success" id="allowed-count">0</p>
                    </div>
                </div>
                <div class="col-md-3 mb-3">
                    <div class="card p-3 stat-card card-total">
                        <h5 class="card-title text-primary"><i class="fas fa-globe"></i> Total Requests</h5>
                        <p class="display-6" id="total-requests">0</p>
                    </div>
                </div>
            </div>
        </div>

        <div class="card mb-4 shadow-sm">
            <div class="card-header bg-dark text-white">
                <h5 class="mb-0"><i class="fas fa-flask"></i> Test WAF Analyzer (ML Threshold: 90%)</h5>
            </div>
            <div class="card-body">
                <div class="input-group mb-3">
                    <input type="text" class="form-control" id="test-payload" placeholder="Enter payload to test (e.g., /login?user=admin' OR '1'='1" />
                    <button class="btn btn-warning" type="button" onclick="sendTestRequest()">Run WAF Check</button>
                </div>
                <div id="test-result-msg" class="alert alert-info mb-0"></div>
            </div>
        </div>

        <h2 class="mt-5 mb-3"><i class="fas fa-chart-pie"></i> Attack Breakdown</h2>
        <div id="attack-breakdown-container" class="alert alert-secondary">
            <p>Top Attacks Detected:</p>
            <ul id="attack-list" class="list-group">
                <li class="list-group-item">Loading...</li>
            </ul>
        </div>

        <h2 class="mt-5 mb-3"><i class="fas fa-list-ul"></i> Recent Activity Logs</h2>
        <div class="table-responsive shadow">
            <table class="table table-striped table-hover table-log">
                <thead class="table-secondary">
                    <tr>
                        <th>Time</th>
                        <th>Req. ID</th>
                        <th>IP Address</th>
                        <th>Summary</th>
                        <th>Attack Type</th>
                        <th>Model Score</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody id="log-table-body">
                    <tr><td colspan="7" class="text-center">Loading live logs...</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
    
    <script>
        const logTableBody = document.getElementById('log-table-body');
        const testPayloadInput = document.getElementById('test-payload');
        const testResultMsg = document.getElementById('test-result-msg');
        
        // Stats elements
        const totalRequests = document.getElementById('total-requests');
        const blockedMlCount = document.getElementById('blocked-ml-count');
        const blockedRateCount = document.getElementById('blocked-rate-count');
        const allowedCount = document.getElementById('allowed-count');
        const attackList = document.getElementById('attack-list');
        
        // --- Core Functions ---

        /** Fetches summary statistics and updates the cards and breakdown list. */
        async function fetchStats() {
            try {
                const response = await fetch('/api/stats');
                const stats = await response.json();
                
                // Update Cards
                totalRequests.textContent = stats.total_requests;
                blockedMlCount.textContent = stats.blocked_ml_count;
                blockedRateCount.textContent = stats.blocked_rate_count;
                allowedCount.textContent = stats.total_requests - stats.total_blocked;
                
                // Update Attack Breakdown List
                attackList.innerHTML = '';
                const breakdown = stats.attack_breakdown;
                if (Object.keys(breakdown).length === 0) {
                    attackList.innerHTML = '<li class="list-group-item">No blocks recorded yet.</li>';
                } else {
                    for (const [type, count] of Object.entries(breakdown).sort(([,a],[,b]) => b-a)) {
                        const listItem = document.createElement('li');
                        listItem.className = 'list-group-item d-flex justify-content-between align-items-center';
                        listItem.innerHTML = `
                            ${type}
                            <span class="badge bg-danger rounded-pill">${count}</span>
                        `;
                        attackList.appendChild(listItem);
                    }
                }
                
            } catch (error) {
                console.error("Error fetching stats:", error);
            }
        }

        /** Fetches and renders the log table. */
        async function fetchAndRenderLogs() {
            try {
                const response = await fetch('/api/logs');
                const logs = await response.json();
                
                logTableBody.innerHTML = ''; // Clear previous logs

                logs.slice(0, 30).forEach(log => {
                    const row = logTableBody.insertRow();
                    
                    // Dynamic row styling based on action type
                    if (log.action === 'BLOCK') {
                        row.classList.add('table-danger');
                    } else if (log.action === 'BLOCKED_RATELIMIT') {
                        row.classList.add('table-warning');
                    }
                    
                    row.insertCell().textContent = new Date(log.timestamp).toLocaleTimeString();
                    row.insertCell().textContent = log.id;
                    row.insertCell().textContent = log.source_ip;
                    row.insertCell().textContent = log.request_summary;
                    
                    // Attack Type Cell
                    const typeCell = row.insertCell();
                    typeCell.textContent = log.attack_type;
                    
                    // Score Cell (N/A for Rate Limit blocks)
                    const scoreCell = row.insertCell();
                    if (log.action === 'BLOCKED_RATELIMIT') {
                        scoreCell.textContent = 'N/A';
                    } else {
                        scoreCell.textContent = log.transformer_score.toFixed(4);
                        scoreCell.classList.add(log.action === 'BLOCK' ? 'text-malicious' : 'text-benign');
                    }
                    
                    // Action Cell
                    const actionCell = row.insertCell();
                    actionCell.textContent = log.action;
                    if (log.action === 'BLOCK') {
                        actionCell.classList.add('text-danger');
                    } else if (log.action === 'BLOCKED_RATELIMIT') {
                        actionCell.classList.add('text-warning');
                    } else {
                        actionCell.classList.add('text-success');
                    }
                });

            } catch (error) {
                console.error("Error fetching WAF logs:", error);
                logTableBody.innerHTML = '<tr><td colspan="7" class="text-center text-danger">Failed to load logs. Check WAF service status.</td></tr>';
            }
        }
        
        /** Sends a mock request to the WAF proxy endpoint for testing. */
        async function sendTestRequest() {
            const payload = testPayloadInput.value;
            if (!payload) {
                testResultMsg.className = 'alert alert-warning mb-0';
                testResultMsg.textContent = "Please enter a payload to test the WAF.";
                return;
            }
            
            testResultMsg.className = 'alert alert-info mb-0';
            testResultMsg.textContent = "Sending mock request to WAF for analysis...";
            
            try {
                // Send the mock request to the proxy endpoint
                const response = await fetch('/waf/proxy/testpath?q=' + encodeURIComponent(payload), {
                    method: 'GET', 
                });

                const data = await response.json();
                
                if (response.status === 403) {
                    testResultMsg.className = 'alert alert-danger mb-0';
                    testResultMsg.innerHTML = `<strong><i class="fas fa-ban"></i> BLOCKED!</strong> Detected Attack: ${data.attack} | Score: ${data.score} | ID: ${data.id}`;
                } else if (response.status === 429) {
                    testResultMsg.className = 'alert alert-warning mb-0';
                    testResultMsg.innerHTML = `<strong><i class="fas fa-clock"></i> BLOCKED!</strong> ${data.message} ID: ${data.id}`;
                } else {
                    testResultMsg.className = 'alert alert-success mb-0';
                    testResultMsg.innerHTML = `<strong><i class="fas fa-thumbs-up"></i> ALLOWED.</strong> Score: ${data.score} | ID: ${data.id}`;
                }

                // Refresh the dashboard data
                setTimeout(() => {
                    fetchAndRenderLogs();
                    fetchStats();
                }, 500);

            } catch (error) {
                console.error("Test request failed:", error);
                testResultMsg.className = 'alert alert-danger mb-0';
                testResultMsg.textContent = `<i class="fas fa-exclamation-triangle"></i> Error: Could not connect to WAF service (Check app.py status).`;
            }
        }

        // Initialize and refresh dashboard data
        document.addEventListener('DOMContentLoaded', () => {
            fetchStats();
            fetchAndRenderLogs();
            // Setup auto-refresh for a powerful, live feel
            setInterval(fetchStats, 5000); 
            setInterval(fetchAndRenderLogs, 10000);
            testResultMsg.textContent = "Enter a mock payload (e.g., a SQL Injection) and click 'Run WAF Check'.";
        });
    </script>
</body>
</html>
