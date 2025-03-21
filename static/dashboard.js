document.addEventListener("DOMContentLoaded", function() {
    loadDashboardData();
});

function loadDashboardData() {
    fetch("/api/dashboard-data")
    .then(response => response.json())
    .then(data => {
        document.getElementById("total-packets").innerText = data.total_packets;
        updateBlockedIPs(data.blocked_ips);
        updateLogEntries(data.logs);
    })
    .catch(error => console.error("Error loading dashboard data:", error));
}

function updateBlockedIPs(blockedIPs) {
    const blockedList = document.getElementById("blocked-ips");
    blockedList.innerHTML = ""; // Clear existing content
    if (blockedIPs.length === 0) {
        blockedList.innerHTML = "<li>No blocked IPs</li>";
    } else {
        blockedIPs.forEach(ip => {
            const li = document.createElement("li");
            li.textContent = ip;
            blockedList.appendChild(li);
        });
    }
}

function updateLogEntries(logs) {
    const logTable = document.getElementById("log-entries");
    logTable.innerHTML = ""; // Clear existing content
    if (logs.length === 0) {
        logTable.innerHTML = "<tr><td colspan='3'>No recent logs</td></tr>";
    } else {
        logs.forEach(log => {
            const row = document.createElement("tr");

            const timestampCell = document.createElement("td");
            timestampCell.textContent = log.timestamp;
            row.appendChild(timestampCell);

            const ipCell = document.createElement("td");
            ipCell.textContent = log.source_ip;
            row.appendChild(ipCell);

            const actionCell = document.createElement("td");
            actionCell.textContent = log.action;
            row.appendChild(actionCell);

            logTable.appendChild(row);
        });
    }
}
