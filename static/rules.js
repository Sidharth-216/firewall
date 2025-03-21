document.addEventListener("DOMContentLoaded", function() {
    loadRules();
});

function addRule() {
    const ipAddress = document.getElementById("ip-address").value;
    const action = document.getElementById("rule-action").value;
    
    if (!ipAddress) {
        alert("Please enter a valid IP address.");
        return;
    }
    
    fetch("/api/add-rule", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip: ipAddress, action: action })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            loadRules();
        } else {
            alert("Failed to add rule.");
        }
    })
    .catch(error => console.error("Error adding rule:", error));
}

function loadRules() {
    fetch("/api/get-rules")
    .then(response => response.json())
    .then(data => {
        const rulesList = document.getElementById("rules-list");
        rulesList.innerHTML = "";
        data.rules.forEach(rule => {
            let row = document.createElement("tr");
            row.innerHTML = `<td>${rule.ip}</td><td>${rule.action}</td>
                             <td><button onclick="removeRule('${rule.ip}')">Remove</button></td>`;
            rulesList.appendChild(row);
        });
    })
    .catch(error => console.error("Error loading rules:", error));
}

function removeRule(ipAddress) {
    fetch("/api/remove-rule", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip: ipAddress })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            loadRules();
        } else {
            alert("Failed to remove rule.");
        }
    })
    .catch(error => console.error("Error removing rule:", error));
}
