"""
Flask Web Application & REST API for Mini Network Intrusion Detection System (IDS).

Provides:
- Web Dashboard serving
- Real-time packet and alert querying
- Monitoring start/stop controls (Live / Simulated)
- Attack scenario injection for demonstration
- CSV alert export
- Machine Learning flow classification and metrics
"""

import os
import sys
from pathlib import Path
from flask import Flask, render_template, jsonify, request, Response

# Add current directory to path
BASE_DIR = Path(__file__).resolve().parent
sys.path.append(str(BASE_DIR))

import config
from database.storage import DatabaseManager
from detector.rules import RuleEngine
from detector.traffic_analyzer import TrafficAnalyzer
from detector.packet_capture import PacketCaptureManager, SCAPY_AVAILABLE
from detector.ml_detector import MLAnomalyDetector

# Initialize Flask
app = Flask(__name__, template_folder="templates", static_folder="static")
app.config["SECRET_KEY"] = "mini-ids-educational-secret-key-2026"

# Initialize Core Services
db = DatabaseManager(config.DATABASE_PATH)
rule_engine = RuleEngine(
    port_scan_threshold=config.PORT_SCAN_THRESHOLD,
    port_scan_window_sec=config.PORT_SCAN_WINDOW_SEC,
    request_burst_threshold=config.REQUEST_BURST_THRESHOLD,
    request_burst_window_sec=config.REQUEST_BURST_WINDOW_SEC,
    repeated_conn_threshold=config.REPEATED_CONN_THRESHOLD,
    repeated_conn_window_sec=config.REPEATED_CONN_WINDOW_SEC,
    deduplication_window_sec=config.ALERT_DEDUPLICATION_WINDOW_SEC
)
analyzer = TrafficAnalyzer(db, rule_engine)
capture_manager = PacketCaptureManager(packet_handler=analyzer.process_packet)
ml_detector = MLAnomalyDetector(config.ML_MODEL_PATH, config.ML_METRICS_PATH)


@app.route("/")
def index():
    """Renders the main IDS web dashboard."""
    return render_template("index.html")


@app.route("/api/status", methods=["GET"])
def get_status():
    """Returns current monitor status and interface configuration."""
    return jsonify({
        "status": "RUNNING" if capture_manager.is_running else "STOPPED",
        "mode": capture_manager.mode,
        "is_running": capture_manager.is_running,
        "scapy_available": SCAPY_AVAILABLE,
        "last_error": capture_manager.last_error,
        "thresholds": {
            "port_scan_threshold": rule_engine.port_scan_threshold,
            "port_scan_window_sec": rule_engine.port_scan_window_sec,
            "request_burst_threshold": rule_engine.request_burst_threshold,
            "request_burst_window_sec": rule_engine.request_burst_window_sec,
            "repeated_conn_threshold": rule_engine.repeated_conn_threshold,
            "repeated_conn_window_sec": rule_engine.repeated_conn_window_sec
        }
    })


@app.route("/api/stats", methods=["GET"])
def get_stats():
    """Returns aggregate packet, alert, and protocol statistics."""
    stats = db.get_statistics()
    return jsonify(stats)


@app.route("/api/packets", methods=["GET"])
def get_packets():
    """Retrieves recent captured/simulated packets with optional filters."""
    limit = int(request.args.get("limit", 50))
    src_ip = request.args.get("src_ip")
    protocol = request.args.get("protocol")
    packets = db.get_recent_packets(limit=limit, src_ip=src_ip, protocol=protocol)
    return jsonify({"count": len(packets), "packets": packets})


@app.route("/api/alerts", methods=["GET"])
def get_alerts():
    """Retrieves security alerts with optional filters."""
    limit = int(request.args.get("limit", 50))
    severity = request.args.get("severity")
    category = request.args.get("category")
    src_ip = request.args.get("src_ip")
    alerts = db.get_alerts(limit=limit, severity=severity, category=category, src_ip=src_ip)
    return jsonify({"count": len(alerts), "alerts": alerts})


@app.route("/api/monitor/start", methods=["POST"])
def start_monitor():
    """Starts traffic monitoring (mode: 'live' or 'simulated')."""
    data = request.get_json(silent=True) or {}
    mode = data.get("mode", "simulated").lower()

    if mode == "live":
        success, message = capture_manager.start_live_capture()
    else:
        success, message = capture_manager.start_simulation()

    return jsonify({"success": success, "message": message, "mode": capture_manager.mode})


@app.route("/api/monitor/stop", methods=["POST"])
def stop_monitor():
    """Stops traffic monitoring gracefully."""
    success, message = capture_manager.stop_capture()
    return jsonify({"success": success, "message": message})


@app.route("/api/simulate/attack", methods=["POST"])
def simulate_attack():
    """Injects an educational attack pattern into the packet stream."""
    data = request.get_json(silent=True) or {}
    scenario = data.get("scenario", "port_scan")

    valid_scenarios = ["port_scan", "burst", "malformed", "repeated_syn"]
    if scenario not in valid_scenarios:
        return jsonify({"success": False, "error": f"Invalid scenario. Choose from: {valid_scenarios}"}), 400

    packets = capture_manager.inject_attack_scenario(scenario)
    return jsonify({
        "success": True,
        "scenario": scenario,
        "packets_generated": len(packets),
        "message": f"Successfully injected {scenario} traffic pattern into IDS analyzer."
    })


@app.route("/api/clear", methods=["POST"])
def clear_data():
    """Clears all stored packets and alerts for a fresh demo."""
    analyzer.reset_analyzer()
    return jsonify({"success": True, "message": "All database records and rule states have been cleared."})


@app.route("/api/export/csv", methods=["GET"])
def export_csv():
    """Exports all stored alerts as a downloadable CSV file."""
    csv_data = db.export_alerts_to_csv()
    return Response(
        csv_data,
        mimetype="text/csv",
        headers={"Content-disposition": "attachment; filename=ids_security_alerts.csv"}
    )


@app.route("/api/ml/predict", methods=["POST"])
def ml_predict():
    """Evaluates flow statistics against the ML anomaly model."""
    data = request.get_json(silent=True) or {}
    pkts = int(data.get("packets_per_window", 10))
    ports = int(data.get("unique_dst_ports", 1))
    avg_len = float(data.get("avg_packet_len", 512.0))
    syns = int(data.get("syn_attempt_count", 2))

    result = ml_detector.predict_flow(pkts, ports, avg_len, syns)
    return jsonify(result)


@app.route("/api/ml/metrics", methods=["GET"])
def ml_metrics():
    """Returns ML model training metrics and confusion matrix."""
    return jsonify(ml_detector.get_evaluation_metrics())


if __name__ == "__main__":
    print("=" * 60)
    print(" Mini Network Intrusion Detection System (IDS) Server ")
    print(f" Web Dashboard URL: http://{config.SERVER_HOST}:{config.SERVER_PORT}")
    print("=" * 60)
    app.run(
        host=config.SERVER_HOST,
        port=config.SERVER_PORT,
        debug=config.DEBUG_MODE
    )
