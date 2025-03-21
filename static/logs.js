document.addEventListener("DOMContentLoaded", function() {
    loadLogs();
});

let logsData = [];
let currentPage = 1;
const logsPerPage = 10;

function loadLogs() {
    fetch("/api/get-logs")
    .then(response => response.json())
    .then(data => {
        logsData = data.logs;
        displayLogs();
    })
    .catch(error => console.error("Error fetching logs:", error));
}

function displayLogs() {
    const logsList = document.getElementById("logs-list");
    logsList.innerHTML = "";
    
    let filteredLogs = filterLogs(logsData);
    let start = (currentPage - 1) * logsPerPage;
    let paginatedLogs = filteredLogs.slice(start, start + logsPerPage);
    
    paginatedLogs.forEach(log => {
        let row = document.createElement("tr");
        row.innerHTML = `<td>${log.timestamp}</td><td>${log.ip}</td><td>${log.action}</td>`;
        logsList.appendChild(row);
    });
    updatePagination(filteredLogs.length);
}

function filterLogs(logs) {
    const searchQuery = document.getElementById("search-logs").value.toLowerCase();
    return logs.filter(log => 
        log.ip.includes(searchQuery) || 
        log.action.toLowerCase().includes(searchQuery)
    );
}

document.getElementById("search-logs").addEventListener("input", function() {
    currentPage = 1;
    displayLogs();
});

function updatePagination(totalLogs) {
    const controls = document.getElementById("pagination-controls");
    controls.innerHTML = "";
    
    let totalPages = Math.ceil(totalLogs / logsPerPage);
    for (let i = 1; i <= totalPages; i++) {
        let btn = document.createElement("button");
        btn.textContent = i;
        btn.onclick = function() { 
            currentPage = i;
            displayLogs();
        };
        controls.appendChild(btn);
    }
}

function clearLogs() {
    fetch("/api/clear-logs", { method: "POST" })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            logsData = [];
            displayLogs();
        } else {
            alert("Failed to clear logs.");
        }
    })
    .catch(error => console.error("Error clearing logs:", error));
}
