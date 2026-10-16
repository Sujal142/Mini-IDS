/**
 * Mini Network Intrusion Detection System (IDS) - Dashboard Logic
 * Manages live telemetry polling, Chart.js updates, alert feed, and simulation controls.
 */

let trafficChart = null;
let protocolChart = null;
let pollInterval = null;
let trafficHistory = [];

document.addEventListener("DOMContentLoaded", () => {
  initCharts();
  fetchInitialData();
  startPolling();
});

// Initialize Chart.js Instances
function initCharts() {
  const trafficCtx = document.getElementById("chart-traffic").getContext("2d");
  trafficChart = new Chart(trafficCtx, {
    type: "line",
    data: {
      labels: [],
      datasets: [{
        label: "Packets / Interval",
        data: [],
        borderColor: "#38bdf8",
        backgroundColor: "rgba(56, 189, 248, 0.12)",
        fill: true,
        tension: 0.3,
        borderWidth: 2,
        pointRadius: 2
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: { grid: { color: "#1e293b" }, ticks: { color: "#64748b", font: { size: 10 } } },
        y: { grid: { color: "#1e293b" }, ticks: { color: "#64748b", font: { size: 10 } }, beginAtZero: true }
      },
      plugins: {
        legend: { display: false }
      }
    }
  });

  const protocolCtx = document.getElementById("chart-protocols").getContext("2d");
  protocolChart = new Chart(protocolCtx, {
    type: "doughnut",
    data: {
      labels: ["TCP", "UDP", "DNS", "ICMP", "OTHER"],
      datasets: [{
        data: [1, 1, 1, 0, 0],
        backgroundColor: ["#38bdf8", "#c084fc", "#34d399", "#fbbf24", "#94a3b8"],
        borderColor: "#0f172a",
        borderWidth: 2
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { position: "right", labels: { color: "#94a3b8", font: { size: 11 }, boxWidth: 12 } }
      }
    }
  });
}

function fetchInitialData() {
  updateStatus();
  updateStats();
  loadAlerts();
  loadPackets();
}

function startPolling() {
  if (pollInterval) clearInterval(pollInterval);
  pollInterval = setInterval(() => {
    updateStatus();
    updateStats();
    loadAlerts();
    loadPackets();
  }, 2500);
}

// Fetch and update system status
async function updateStatus() {
  try {
    const res = await fetch("/api/status");
    const data = await res.json();

    const indicator = document.getElementById("status-indicator");
    const statusText = document.getElementById("status-text");
    const modeBadge = document.getElementById("mode-badge");
    const btnSim = document.getElementById("btn-start-sim");
    const btnLive = document.getElementById("btn-start-live");
    const btnStop = document.getElementById("btn-stop");

    if (data.is_running) {
      indicator.className = "h-2.5 w-2.5 rounded-full bg-emerald-400 animate-ping";
      statusText.textContent = `MONITORING (${data.mode})`;
      statusText.className = "font-medium text-emerald-400";
      modeBadge.textContent = data.mode;
      modeBadge.className = "ml-1 text-[10px] px-1.5 py-0.2 rounded bg-emerald-950 text-emerald-400 border border-emerald-800";

      btnSim.classList.add("hidden");
      btnLive.classList.add("hidden");
      btnStop.classList.remove("hidden");
    } else {
      indicator.className = "h-2.5 w-2.5 rounded-full bg-amber-500";
      statusText.textContent = "IDLE (Stopped)";
      statusText.className = "font-medium text-slate-300";
      modeBadge.textContent = "STANDBY";
      modeBadge.className = "ml-1 text-[10px] px-1.5 py-0.2 rounded bg-slate-800 text-slate-400";

      btnSim.classList.remove("hidden");
      btnLive.classList.remove("hidden");
      btnStop.classList.add("hidden");
    }
  } catch (err) {
    console.error("Error fetching status:", err);
  }
}

// Fetch aggregate statistics & update charts
async function updateStats() {
  try {
    const res = await fetch("/api/stats");
    const data = await res.json();

    document.getElementById("stat-total-packets").textContent = data.total_packets || 0;
    document.getElementById("stat-total-alerts").textContent = data.total_alerts || 0;
    document.getElementById("stat-unique-ips").textContent = data.unique_ips || 0;

    const sev = data.severity_distribution || { HIGH: 0, MEDIUM: 0, LOW: 0 };
    document.getElementById("stat-high-alerts").textContent = `${sev.HIGH || 0} High`;
    document.getElementById("stat-med-alerts").textContent = `${sev.MEDIUM || 0} Med`;
    document.getElementById("stat-low-alerts").textContent = `${sev.LOW || 0} Low`;

    // Update Protocol Chart
    if (protocolChart && data.protocol_distribution) {
      const labels = Object.keys(data.protocol_distribution);
      const counts = Object.values(data.protocol_distribution);
      if (labels.length > 0) {
        protocolChart.data.labels = labels;
        protocolChart.data.datasets[0].data = counts;
        protocolChart.update();
      }
    }

    // Update Traffic Time Series
    if (trafficChart) {
      const now = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      trafficHistory.push({ time: now, count: data.total_packets || 0 });
      if (trafficHistory.length > 15) trafficHistory.shift();

      // Compute rate (difference from previous sample)
      const labels = [];
      const rates = [];
      for (let i = 1; i < trafficHistory.length; i++) {
        labels.push(trafficHistory[i].time);
        rates.push(Math.max(0, trafficHistory[i].count - trafficHistory[i - 1].count));
      }

      trafficChart.data.labels = labels;
      trafficChart.data.datasets[0].data = rates;
      trafficChart.update();
    }
  } catch (err) {
    console.error("Error updating stats:", err);
  }
}

// Load and render Alerts table
async function loadAlerts() {
  try {
    const severity = document.getElementById("filter-severity").value;
    const ip = document.getElementById("filter-ip").value;

    let url = `/api/alerts?limit=50`;
    if (severity !== "ALL") url += `&severity=${severity}`;
    if (ip) url += `&src_ip=${encodeURIComponent(ip)}`;

    const res = await fetch(url);
    const data = await res.json();
    const tbody = document.getElementById("alerts-tbody");
    document.getElementById("alert-badge-count").textContent = `${data.count} alerts`;

    if (!data.alerts || data.alerts.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="py-6 text-center text-slate-500">No alerts match current filter.</td></tr>`;
      return;
    }

    tbody.innerHTML = data.alerts.map(a => {
      let sevBadge = "badge-low";
      if (a.severity === "HIGH") sevBadge = "badge-high";
      else if (a.severity === "MEDIUM") sevBadge = "badge-med";

      return `
        <tr class="hover:bg-slate-800/40 transition-colors">
          <td class="py-2.5 px-3 text-slate-400 whitespace-nowrap">${a.timestamp}</td>
          <td class="py-2.5 px-3 whitespace-nowrap">
            <span class="px-2 py-0.5 rounded text-[10px] font-bold ${sevBadge}">${a.severity}</span>
          </td>
          <td class="py-2.5 px-3 text-indigo-300 font-semibold whitespace-nowrap">${a.rule_name}</td>
          <td class="py-2.5 px-3 text-white font-mono whitespace-nowrap">${a.src_ip}</td>
          <td class="py-2.5 px-3 text-slate-300 font-mono whitespace-nowrap">${a.dst_ip || 'N/A'}:${a.dst_port || '*'}</td>
          <td class="py-2.5 px-3 text-slate-300 max-w-xs truncate" title="${a.reason}">
            <div>${a.reason}</div>
            <div class="text-[10px] text-slate-500 font-mono">${a.threshold_info || ''}</div>
          </td>
          <td class="py-2.5 px-3 whitespace-nowrap">
            <span class="text-[10px] px-1.5 py-0.5 rounded ${a.is_simulated ? 'bg-amber-950 text-amber-400 border border-amber-800' : 'bg-blue-950 text-blue-400 border border-blue-800'}">
              ${a.is_simulated ? 'SIMULATED' : 'LIVE'}
            </span>
          </td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    console.error("Error loading alerts:", err);
  }
}

// Load and render Packets table
async function loadPackets() {
  try {
    const proto = document.getElementById("filter-packet-proto").value;
    let url = `/api/packets?limit=50`;
    if (proto !== "ALL") url += `&protocol=${proto}`;

    const res = await fetch(url);
    const data = await res.json();
    const tbody = document.getElementById("packets-tbody");

    if (!data.packets || data.packets.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="py-6 text-center text-slate-500">No packets captured yet.</td></tr>`;
      return;
    }

    tbody.innerHTML = data.packets.map(p => {
      let protoClass = "badge-tcp";
      if (p.protocol === "UDP") protoClass = "badge-udp";
      else if (p.protocol === "DNS") protoClass = "badge-dns";
      else if (p.protocol === "ICMP") protoClass = "badge-icmp";

      return `
        <tr class="hover:bg-slate-800/40 transition-colors">
          <td class="py-2 px-3 text-slate-400 whitespace-nowrap">${p.timestamp}</td>
          <td class="py-2 px-3 text-slate-200 whitespace-nowrap">${p.src_ip}:${p.src_port || '*'}</td>
          <td class="py-2 px-3 text-slate-300 whitespace-nowrap">${p.dst_ip}:${p.dst_port || '*'}</td>
          <td class="py-2 px-3 whitespace-nowrap">
            <span class="badge-proto ${protoClass}">${p.protocol}</span>
          </td>
          <td class="py-2 px-3 text-slate-400 whitespace-nowrap">${p.length} B</td>
          <td class="py-2 px-3 text-amber-300 font-semibold whitespace-nowrap">${p.tcp_flags || '-'}</td>
          <td class="py-2 px-3 text-slate-400 truncate max-w-sm" title="${p.info}">${p.info || ''}</td>
        </tr>
      `;
    }).join("");
  } catch (err) {
    console.error("Error loading packets:", err);
  }
}

// Control Actions
async function startMonitoring(mode) {
  try {
    const res = await fetch("/api/monitor/start", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mode })
    });
    const data = await res.json();
    if (!data.success) {
      alert(`Could not start capture: ${data.message}`);
    }
    updateStatus();
  } catch (err) {
    alert("Network error starting monitoring.");
  }
}

async function stopMonitoring() {
  try {
    await fetch("/api/monitor/stop", { method: "POST" });
    updateStatus();
  } catch (err) {
    alert("Error stopping monitoring.");
  }
}

async function injectScenario(scenario) {
  try {
    const res = await fetch("/api/simulate/attack", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ scenario })
    });
    const data = await res.json();
    if (data.success) {
      setTimeout(() => {
        updateStats();
        loadAlerts();
        loadPackets();
      }, 300);
    }
  } catch (err) {
    alert("Error injecting attack scenario.");
  }
}

function exportAlertsCSV() {
  window.location.href = "/api/export/csv";
}

async function clearData() {
  if (confirm("Are you sure you want to clear all packet and alert logs?")) {
    await fetch("/api/clear", { method: "POST" });
    trafficHistory = [];
    updateStats();
    loadAlerts();
    loadPackets();
  }
}

// Machine Learning Anomaly Predictor
async function evaluateMLFlow() {
  const pkts = parseInt(document.getElementById("ml-pkts").value) || 0;
  const ports = parseInt(document.getElementById("ml-ports").value) || 0;
  const len = parseFloat(document.getElementById("ml-len").value) || 0;
  const syns = parseInt(document.getElementById("ml-syns").value) || 0;

  try {
    const res = await fetch("/api/ml/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        packets_per_window: pkts,
        unique_dst_ports: ports,
        avg_packet_len: len,
        syn_attempt_count: syns
      })
    });
    const data = await res.json();

    const box = document.getElementById("ml-result-box");
    const predLabel = document.getElementById("ml-pred-label");
    const conf = document.getElementById("ml-confidence");
    const status = document.getElementById("ml-model-status");

    box.classList.remove("hidden");
    predLabel.textContent = data.prediction.toUpperCase();
    if (data.is_anomaly) {
      predLabel.className = "font-bold px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/40";
    } else {
      predLabel.className = "font-bold px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-300 border border-emerald-500/40";
    }

    conf.textContent = `${(data.confidence * 100).toFixed(1)}%`;
    status.textContent = `Engine: ${data.model_status}`;
  } catch (err) {
    alert("Failed to evaluate ML flow.");
  }
}
