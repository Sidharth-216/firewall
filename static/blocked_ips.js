document.addEventListener("DOMContentLoaded", function() {
    fetchBlockedIPs();
});

function fetchBlockedIPs() {
    fetch("/api/get-blocked-ips")
    .then(response => response.json())
    .then(data => {
        const blockedIPsBody = document.getElementById("blocked-ips-body");
        blockedIPsBody.innerHTML = "";
        data.blocked_ips.forEach(ip => {
            const row = `<tr>
                <td>${ip.address}</td>
                <td>${ip.reason}</td>
                <td><button onclick="unblockIP('${ip.address}')">Unblock</button></td>
            </tr>`;
            blockedIPsBody.innerHTML += row;
        });
    })
    .catch(error => console.error("Error fetching blocked IPs:", error));
}

function addBlockedIP() {
    const ipAddress = document.getElementById("ip-address").value;
    const reason = document.getElementById("reason").value;

    fetch("/api/block-ip", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ address: ipAddress, reason: reason })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert("IP Blocked Successfully!");
            fetchBlockedIPs();
        } else {
            alert("Failed to Block IP.");
        }
    })
    .catch(error => console.error("Error blocking IP:", error));
}

function unblockIP(ipAddress) {
    fetch("/api/unblock-ip", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ address: ipAddress })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert("IP Unblocked Successfully!");
            fetchBlockedIPs();
        } else {
            alert("Failed to Unblock IP.");
        }
    })
    .catch(error => console.error("Error unblocking IP:", error));
}
