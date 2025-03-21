document.addEventListener("DOMContentLoaded", function() {
    loadSettings();
});

function loadSettings() {
    fetch("/api/get-settings")
    .then(response => response.json())
    .then(data => {
        document.getElementById("traffic-threshold").value = data.traffic_threshold;
        document.getElementById("log-retention").value = data.log_retention;
        document.getElementById("auto-block").value = data.auto_block;
    })
    .catch(error => console.error("Error loading settings:", error));
}

function saveSettings() {
    const settings = {
        traffic_threshold: document.getElementById("traffic-threshold").value,
        log_retention: document.getElementById("log-retention").value,
        auto_block: document.getElementById("auto-block").value
    };

    fetch("/api/save-settings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(settings)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            alert("Settings saved successfully!");
        } else {
            alert("Failed to save settings.");
        }
    })
    .catch(error => console.error("Error saving settings:", error));
}
