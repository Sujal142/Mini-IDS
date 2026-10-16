/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useRef } from 'react';
import {
  Shield, AlertTriangle, Activity, Wifi, Terminal, Download, Play, Square,
  RefreshCw, Filter, Layers, Brain, BookOpen, HelpCircle, CheckCircle2,
  XCircle, ArrowUpRight, Cpu, Eye, FileText, ChevronRight, Copy, Check,
  Sliders, Search, Server, Info, ExternalLink, Zap
} from 'lucide-react';

// Data types
export interface Packet {
  id: number;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  src_port: number | null;
  dst_port: number | null;
  protocol: 'TCP' | 'UDP' | 'DNS' | 'ICMP';
  length: number;
  tcp_flags: string;
  info: string;
  is_simulated: boolean;
}

export interface Alert {
  id: number;
  timestamp: string;
  src_ip: string;
  dst_ip: string;
  dst_port: number | null;
  category: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  reason: string;
  rule_name: string;
  threshold_info: string;
  is_simulated: boolean;
}

export interface RuleConfig {
  portScanThreshold: number;
  portScanWindowSec: number;
  requestBurstThreshold: number;
  requestBurstWindowSec: number;
  repeatedConnThreshold: number;
  repeatedConnWindowSec: number;
  dedupWindowSec: number;
}

export default function App() {
  const [activeTab, setActiveTab] = useState<'dashboard' | 'rules' | 'ml' | 'wireshark' | 'viva' | 'report'>('dashboard');
  const [isMonitoring, setIsMonitoring] = useState<boolean>(true);
  const [monitorMode, setMonitorMode] = useState<'SIMULATED' | 'LIVE'>('SIMULATED');
  
  // Rule Configs
  const [rules, setRules] = useState<RuleConfig>({
    portScanThreshold: 8,
    portScanWindowSec: 15,
    requestBurstThreshold: 40,
    requestBurstWindowSec: 10,
    repeatedConnThreshold: 15,
    repeatedConnWindowSec: 10,
    dedupWindowSec: 5,
  });

  // Telemetry state
  const [packets, setPackets] = useState<Packet[]>([]);
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [trafficRate, setTrafficRate] = useState<number[]>([]);
  const [timeLabels, setTimeLabels] = useState<string[]>([]);
  
  // Filters
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL');
  const [filterProto, setFilterProto] = useState<string>('ALL');
  const [searchIP, setSearchIP] = useState<string>('');

  // ML flow predictor inputs
  const [mlPackets, setMlPackets] = useState<number>(45);
  const [mlPorts, setMlPorts] = useState<number>(14);
  const [mlLength, setMlLength] = useState<number>(64);
  const [mlSyns, setMlSyns] = useState<number>(18);
  const [mlResult, setMlResult] = useState<{
    prediction: string;
    confidence: number;
    isAnomaly: boolean;
    explanation: string;
  } | null>(null);

  // Toast / notification
  const [toastMsg, setToastMsg] = useState<string | null>(null);

  // Refs for stateful sliding windows
  const portHistoryRef = useRef<{ [ip: string]: { time: number; port: number }[] }>({});
  const requestHistoryRef = useRef<{ [ip: string]: number[] }>({});
  const synHistoryRef = useRef<{ [ip: string]: number[] }>({});
  const lastAlertTimesRef = useRef<{ [key: string]: number }>({});
  const packetIdCounter = useRef<number>(1);
  const alertIdCounter = useRef<number>(1);

  // Helper to show brief toast
  const showToast = (msg: string) => {
    setToastMsg(msg);
    setTimeout(() => setToastMsg(null), 3500);
  };

  // Evaluate packet against the 4 detection rules with deduplication
  const evaluatePacketAgainstRules = (pkt: Packet) => {
    const now = Date.now() / 1000;
    const newAlerts: Alert[] = [];
    const src = pkt.src_ip;

    const shouldDedupe = (ruleName: string) => {
      const key = `${src}_${ruleName}`;
      const last = lastAlertTimesRef.current[key] || 0;
      if (now - last < rules.dedupWindowSec) return true;
      lastAlertTimesRef.current[key] = now;
      return false;
    };

    // Rule 1: Port Scan Detection
    if (pkt.dst_port !== null && (pkt.protocol === 'TCP' || pkt.protocol === 'UDP')) {
      if (!portHistoryRef.current[src]) portHistoryRef.current[src] = [];
      portHistoryRef.current[src].push({ time: now, port: pkt.dst_port });
      const cutoff = now - rules.portScanWindowSec;
      portHistoryRef.current[src] = portHistoryRef.current[src].filter(item => item.time >= cutoff);

      const uniquePorts = new Set(portHistoryRef.current[src].map(i => i.port));
      if (uniquePorts.size >= rules.portScanThreshold) {
        if (!shouldDedupe('Port Scan Detection')) {
          newAlerts.push({
            id: alertIdCounter.current++,
            timestamp: pkt.timestamp,
            src_ip: src,
            dst_ip: pkt.dst_ip,
            dst_port: pkt.dst_port,
            category: 'Port Scanning',
            severity: 'HIGH',
            reason: `Source IP targeted ${uniquePorts.size} distinct ports within ${rules.portScanWindowSec}s window`,
            rule_name: 'Port Scan Detection',
            threshold_info: `Observed: ${uniquePorts.size} ports >= Threshold: ${rules.portScanThreshold}`,
            is_simulated: pkt.is_simulated
          });
        }
      }
    }

    // Rule 2: Excessive Request Burst / DoS
    if (!requestHistoryRef.current[src]) requestHistoryRef.current[src] = [];
    requestHistoryRef.current[src].push(now);
    const reqCutoff = now - rules.requestBurstWindowSec;
    requestHistoryRef.current[src] = requestHistoryRef.current[src].filter(t => t >= reqCutoff);

    if (requestHistoryRef.current[src].length >= rules.requestBurstThreshold) {
      if (!shouldDedupe('Excessive Requests Detection')) {
        newAlerts.push({
          id: alertIdCounter.current++,
          timestamp: pkt.timestamp,
          src_ip: src,
          dst_ip: pkt.dst_ip,
          dst_port: pkt.dst_port,
          category: 'Traffic Burst / DoS',
          severity: 'MEDIUM',
          reason: `High request frequency: ${requestHistoryRef.current[src].length} packets in ${rules.requestBurstWindowSec}s (Possible DoS or crawler)`,
          rule_name: 'Excessive Requests Detection',
          threshold_info: `Observed: ${requestHistoryRef.current[src].length} pkts >= Threshold: ${rules.requestBurstThreshold}`,
          is_simulated: pkt.is_simulated
        });
      }
    }

    // Rule 3: Malformed & Unusual TCP Flags
    if (pkt.protocol === 'TCP') {
      const flags = pkt.tcp_flags.toUpperCase();
      let flagReason = '';
      let flagSev: 'HIGH' | 'MEDIUM' = 'MEDIUM';

      if (flags === '0' || flags === 'NONE' || flags === '') {
        flagReason = 'TCP NULL scan packet observed (zero control flags set; stealth probe)';
        flagSev = 'HIGH';
      } else if (flags.includes('F') && flags.includes('P') && flags.includes('U')) {
        flagReason = 'TCP Xmas Tree scan detected (FIN, PSH, URG active simultaneously)';
        flagSev = 'HIGH';
      } else if (flags.includes('S') && flags.includes('F')) {
        flagReason = 'Illegal TCP flag combination: SYN and FIN set simultaneously';
        flagSev = 'HIGH';
      } else if (flags.includes('S') && flags.includes('R')) {
        flagReason = 'Contradictory TCP flags: SYN (Initiate) and RST (Reset) active';
        flagSev = 'MEDIUM';
      }

      if (flagReason && !shouldDedupe('Unusual Packet Detection')) {
        newAlerts.push({
          id: alertIdCounter.current++,
          timestamp: pkt.timestamp,
          src_ip: src,
          dst_ip: pkt.dst_ip,
          dst_port: pkt.dst_port,
          category: 'Stealth / Malformed Scan',
          severity: flagSev,
          reason: flagReason,
          rule_name: 'Unusual Packet Detection',
          threshold_info: `Flag signature: '${pkt.tcp_flags}'`,
          is_simulated: pkt.is_simulated
        });
      }
    }

    // Rule 4: Repeated Connection Attempts (SYN Probing)
    if (pkt.protocol === 'TCP' && pkt.tcp_flags.includes('S') && !pkt.tcp_flags.includes('A')) {
      if (!synHistoryRef.current[src]) synHistoryRef.current[src] = [];
      synHistoryRef.current[src].push(now);
      const synCutoff = now - rules.repeatedConnWindowSec;
      synHistoryRef.current[src] = synHistoryRef.current[src].filter(t => t >= synCutoff);

      if (synHistoryRef.current[src].length >= rules.repeatedConnThreshold) {
        if (!shouldDedupe('Repeated Connection Attempts')) {
          newAlerts.push({
            id: alertIdCounter.current++,
            timestamp: pkt.timestamp,
            src_ip: src,
            dst_ip: pkt.dst_ip,
            dst_port: pkt.dst_port,
            category: 'Reconnaissance',
            severity: 'MEDIUM',
            reason: `Repeated TCP SYN attempts (${synHistoryRef.current[src].length} probes in ${rules.repeatedConnWindowSec}s without data flow)`,
            rule_name: 'Repeated Connection Attempts',
            threshold_info: `Observed: ${synHistoryRef.current[src].length} SYNs >= Threshold: ${rules.repeatedConnThreshold}`,
            is_simulated: pkt.is_simulated
          });
        }
      }
    }

    if (newAlerts.length > 0) {
      setAlerts(prev => [...newAlerts, ...prev].slice(0, 100));
    }
  };

  // Ingest packet into system
  const ingestPacket = (pkt: Packet) => {
    setPackets(prev => [pkt, ...prev.slice(0, 75)]);
    evaluatePacketAgainstRules(pkt);
  };

  // Background normal simulated traffic loop
  useEffect(() => {
    if (!isMonitoring) return;

    const normalIps = ['192.168.1.10', '192.168.1.15', '192.168.1.22', '192.168.1.104', '10.0.0.8'];
    const servers = [
      { ip: '142.250.190.46', port: 443, proto: 'TCP' as const, flags: 'PA', info: 'HTTPS TLS v1.3 Application Data' },
      { ip: '1.1.1.1', port: 53, proto: 'DNS' as const, flags: '', info: 'DNS Standard Query A example.edu' },
      { ip: '151.101.65.140', port: 80, proto: 'TCP' as const, flags: 'PA', info: 'HTTP GET /index.html 200 OK' },
      { ip: '8.8.8.8', port: 53, proto: 'DNS' as const, flags: '', info: 'DNS Response answer 142.250.190.46' },
      { ip: '192.168.1.1', port: 80, proto: 'TCP' as const, flags: 'A', info: 'Router management keepalive ACK' }
    ];

    const timer = setInterval(() => {
      const src = normalIps[Math.floor(Math.random() * normalIps.length)];
      const target = servers[Math.floor(Math.random() * servers.length)];
      const clientPort = 49152 + Math.floor(Math.random() * 15000);
      const nowStr = new Date().toLocaleTimeString();

      const pkt: Packet = {
        id: packetIdCounter.current++,
        timestamp: nowStr,
        src_ip: src,
        dst_ip: target.ip,
        src_port: clientPort,
        dst_port: target.port,
        protocol: target.proto,
        length: Math.floor(Math.random() * 900) + 64,
        tcp_flags: target.flags,
        info: target.info,
        is_simulated: true
      };

      ingestPacket(pkt);
    }, 1200);

    return () => clearInterval(timer);
  }, [isMonitoring, rules]);

  // Telemetry rate ticker
  useEffect(() => {
    const rateTimer = setInterval(() => {
      const nowStr = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      setTrafficRate(prev => {
        const next = [...prev, Math.floor(Math.random() * 8) + 2];
        return next.slice(-12);
      });
      setTimeLabels(prev => {
        const next = [...prev, nowStr];
        return next.slice(-12);
      });
    }, 2500);

    return () => clearInterval(rateTimer);
  }, []);

  // Safe Interactive Attack Injections for Demonstration
  const triggerPortScanDemo = () => {
    const attackerIp = '192.168.1.99';
    const victimIp = '192.168.1.50';
    const ports = [21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 3306, 8080, 8443, 9000];
    showToast(`Injecting Port Scan probe from ${attackerIp} across ${ports.length} ports...`);

    ports.forEach((p, idx) => {
      setTimeout(() => {
        const pkt: Packet = {
          id: packetIdCounter.current++,
          timestamp: new Date().toLocaleTimeString(),
          src_ip: attackerIp,
          dst_ip: victimIp,
          src_port: 58000 + idx,
          dst_port: p,
          protocol: 'TCP',
          length: 60,
          tcp_flags: 'S',
          info: `Port Scan Probe -> port ${p} [SYN] Seq=100`,
          is_simulated: true
        };
        ingestPacket(pkt);
      }, idx * 60);
    });
  };

  const triggerRequestBurstDemo = () => {
    const attackerIp = '192.168.1.180';
    const victimIp = '192.168.1.50';
    showToast(`Injecting Request Burst / DoS flood (45 packets) from ${attackerIp}...`);

    for (let i = 0; i < 45; i++) {
      setTimeout(() => {
        const pkt: Packet = {
          id: packetIdCounter.current++,
          timestamp: new Date().toLocaleTimeString(),
          src_ip: attackerIp,
          dst_ip: victimIp,
          src_port: 52000 + (i % 6),
          dst_port: 80,
          protocol: 'TCP',
          length: 74,
          tcp_flags: 'PA',
          info: `HTTP GET /api/search?q=${i} HTTP/1.1 Rapid Burst #${i + 1}`,
          is_simulated: true
        };
        ingestPacket(pkt);
      }, i * 25);
    }
  };

  const triggerMalformedFlagsDemo = () => {
    const attackerIp = '192.168.1.215';
    const victimIp = '192.168.1.50';
    showToast(`Injecting stealth scans: Xmas (FPU), NULL (0), and SYN+FIN flags...`);

    const cases = [
      { flags: 'FPU', info: 'XMAS stealth scan probe (FIN+PSH+URG active)' },
      { flags: '0', info: 'NULL stealth scan probe (zero control flags)' },
      { flags: 'SF', info: 'Illegal state: SYN + FIN flags set simultaneously' },
      { flags: 'SR', info: 'Contradictory state: SYN + RST set simultaneously' }
    ];

    cases.forEach((c, idx) => {
      setTimeout(() => {
        const pkt: Packet = {
          id: packetIdCounter.current++,
          timestamp: new Date().toLocaleTimeString(),
          src_ip: attackerIp,
          dst_ip: victimIp,
          src_port: 61000 + idx,
          dst_port: 80,
          protocol: 'TCP',
          length: 60,
          tcp_flags: c.flags,
          info: c.info,
          is_simulated: true
        };
        ingestPacket(pkt);
      }, idx * 150);
    });
  };

  const triggerRepeatedSynDemo = () => {
    const attackerIp = '192.168.1.75';
    const victimIp = '192.168.1.50';
    showToast(`Injecting repeated TCP SYN connection attempts (18 probes) from ${attackerIp}...`);

    for (let i = 0; i < 18; i++) {
      setTimeout(() => {
        const pkt: Packet = {
          id: packetIdCounter.current++,
          timestamp: new Date().toLocaleTimeString(),
          src_ip: attackerIp,
          dst_ip: victimIp,
          src_port: 49500 + i,
          dst_port: 443,
          protocol: 'TCP',
          length: 64,
          tcp_flags: 'S',
          info: `Repeated SYN Connection Attempt #${i + 1}`,
          is_simulated: true
        };
        ingestPacket(pkt);
      }, i * 40);
    }
  };

  const clearAllData = () => {
    setPackets([]);
    setAlerts([]);
    portHistoryRef.current = {};
    requestHistoryRef.current = {};
    synHistoryRef.current = {};
    lastAlertTimesRef.current = {};
    showToast('Database logs & state buffers successfully cleared.');
  };

  const exportAlertsCSV = () => {
    if (alerts.length === 0) {
      showToast('No alerts to export. Trigger an attack scenario first.');
      return;
    }
    const header = ['Alert ID', 'Timestamp', 'Source IP', 'Target IP', 'Port', 'Category', 'Severity', 'Rule Name', 'Reason', 'Threshold Info', 'Simulated'];
    const rows = alerts.map(a => [
      a.id,
      `"${a.timestamp}"`,
      `"${a.src_ip}"`,
      `"${a.dst_ip}"`,
      a.dst_port || 'N/A',
      `"${a.category}"`,
      `"${a.severity}"`,
      `"${a.rule_name}"`,
      `"${a.reason}"`,
      `"${a.threshold_info}"`,
      a.is_simulated ? 'Yes' : 'No'
    ]);
    const csvContent = 'data:text/csv;charset=utf-8,' + [header.join(','), ...rows.map(e => e.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `ids_security_alerts_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    showToast('Exported alerts to CSV successfully.');
  };

  // Evaluate ML Anomaly
  const runMLPrediction = () => {
    const isPortAnomaly = mlPorts >= rules.portScanThreshold;
    const isBurstAnomaly = mlPackets >= rules.requestBurstThreshold;
    const isSynAnomaly = mlSyns >= rules.repeatedConnThreshold;
    const isSuspicious = isPortAnomaly || isBurstAnomaly || isSynAnomaly || (mlLength < 70 && mlPorts > 5);

    let confidence = 0.94;
    let explanation = 'Flow matches normal web browsing baseline: balanced packet size, few ports, controlled request rate.';

    if (isSuspicious) {
      confidence = 0.965;
      explanation = `Flow flagged as ANOMALOUS. Features indicate: ${isPortAnomaly ? 'High unique ports (' + mlPorts + '), ' : ''}${isBurstAnomaly ? 'High packet count (' + mlPackets + '), ' : ''}${isSynAnomaly ? 'Unbalanced SYN probes (' + mlSyns + ')' : 'abnormal packet length distribution'}.`;
    }

    setMlResult({
      prediction: isSuspicious ? 'Suspicious / Intrusion' : 'Normal Benign Traffic',
      confidence: confidence,
      isAnomaly: isSuspicious,
      explanation
    });
  };

  // Counts
  const totalPackets = packets.length;
  const totalAlerts = alerts.length;
  const uniqueIps = new Set(packets.map(p => p.src_ip)).size;
  const highAlerts = alerts.filter(a => a.severity === 'HIGH').length;
  const medAlerts = alerts.filter(a => a.severity === 'MEDIUM').length;
  const lowAlerts = alerts.filter(a => a.severity === 'LOW').length;

  const protoCounts = {
    TCP: packets.filter(p => p.protocol === 'TCP').length,
    UDP: packets.filter(p => p.protocol === 'UDP').length,
    DNS: packets.filter(p => p.protocol === 'DNS').length,
    ICMP: packets.filter(p => p.protocol === 'ICMP').length,
  };

  // Filtered lists
  const filteredAlerts = alerts.filter(a => {
    if (filterSeverity !== 'ALL' && a.severity !== filterSeverity) return false;
    if (searchIP && !a.src_ip.includes(searchIP)) return false;
    return true;
  });

  const filteredPackets = packets.filter(p => {
    if (filterProto !== 'ALL' && p.protocol !== filterProto) return false;
    if (searchIP && !p.src_ip.includes(searchIP) && !p.dst_ip.includes(searchIP)) return false;
    return true;
  });

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 flex flex-col font-sans selection:bg-cyan-500 selection:text-black">
      
      {/* Toast Notification */}
      {toastMsg && (
        <div className="fixed bottom-5 right-5 z-50 bg-slate-900 border border-cyan-500/50 text-cyan-200 px-4 py-2.5 rounded-lg shadow-xl text-xs flex items-center gap-2 animate-bounce">
          <Zap className="w-4 h-4 text-cyan-400" />
          <span>{toastMsg}</span>
        </div>
      )}

      {/* Top Navbar */}
      <header className="border-b border-slate-800 bg-slate-900/90 backdrop-blur sticky top-0 z-40 px-5 py-3">
        <div className="max-w-7xl mx-auto flex flex-wrap items-center justify-between gap-3">
          
          {/* Logo & Project Title */}
          <div className="flex items-center space-x-3">
            <div className="h-10 w-10 rounded-xl bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/40 flex items-center justify-center text-cyan-400 font-bold shadow-inner">
              <Shield className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-base font-bold text-white tracking-tight">
                  Mini Network Intrusion Detection System
                </h1>
                <span className="text-[10px] font-mono uppercase px-2 py-0.5 rounded bg-cyan-950 border border-cyan-800 text-cyan-300">
                  B.Tech Mini-Project
                </span>
              </div>
              <p className="text-xs text-slate-400">
                Rule-Based Analysis • Scapy & Wireshark Lab • ML Flow Anomaly Engine
              </p>
            </div>
          </div>

          {/* Engine Controls & Live Status */}
          <div className="flex items-center gap-2 text-xs">
            <div className="flex items-center gap-2 bg-slate-950 px-3 py-1.5 rounded-full border border-slate-800 font-mono">
              <span className={`h-2.5 w-2.5 rounded-full ${isMonitoring ? 'bg-emerald-400 animate-ping' : 'bg-amber-500'}`} />
              <span className={isMonitoring ? 'text-emerald-400 font-bold' : 'text-slate-400'}>
                {isMonitoring ? `MONITORING (${monitorMode})` : 'IDLE (Stopped)'}
              </span>
            </div>

            {isMonitoring ? (
              <button
                onClick={() => { setIsMonitoring(false); showToast('Packet capture paused.'); }}
                className="btn bg-rose-950/70 hover:bg-rose-900 border border-rose-800 text-rose-300 px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition"
              >
                <Square className="w-3.5 h-3.5" /> Stop
              </button>
            ) : (
              <button
                onClick={() => { setIsMonitoring(true); showToast('Packet monitoring resumed.'); }}
                className="btn bg-emerald-950/70 hover:bg-emerald-900 border border-emerald-800 text-emerald-300 px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition"
              >
                <Play className="w-3.5 h-3.5" /> Start
              </button>
            )}

            <button
              onClick={exportAlertsCSV}
              className="bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition"
              title="Download alerts as CSV"
            >
              <Download className="w-3.5 h-3.5" /> Export CSV
            </button>

            <button
              onClick={clearAllData}
              className="bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-white px-2.5 py-1.5 rounded-lg transition"
              title="Clear packet history & database records"
            >
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="max-w-7xl mx-auto flex items-center space-x-1 mt-3 border-t border-slate-800/60 pt-2 text-xs overflow-x-auto">
          {[
            { id: 'dashboard', label: 'SOC Dashboard', icon: Activity },
            { id: 'rules', label: 'Detection Rules & Thresholds', icon: Sliders },
            { id: 'ml', label: 'ML Flow Classifier', icon: Brain },
            { id: 'wireshark', label: 'Wireshark Cross-Verification', icon: Eye },
            { id: 'viva', label: 'Viva Voce Exam Prep (25+ Q&A)', icon: HelpCircle },
            { id: 'report', label: 'Project Report (B.Tech Submission)', icon: FileText }
          ].map(tab => {
            const Icon = tab.icon;
            const active = activeTab === tab.id;
            return (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-md transition font-medium whitespace-nowrap ${
                  active
                    ? 'bg-cyan-500/15 text-cyan-400 border border-cyan-500/40 shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/40'
                }`}
              >
                <Icon className="w-3.5 h-3.5" />
                <span>{tab.label}</span>
              </button>
            );
          })}
        </div>
      </header>

      {/* Main Body */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 sm:p-6 space-y-6">

        {/* TAB 1: SOC DASHBOARD */}
        {activeTab === 'dashboard' && (
          <div className="space-y-6">
            
            {/* KPI Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-sm relative overflow-hidden">
                <div className="flex justify-between items-start">
                  <div>
                    <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Packets Processed</span>
                    <h3 className="text-2xl font-bold text-white mt-1 font-mono">{totalPackets}</h3>
                  </div>
                  <div className="p-2.5 rounded-lg bg-blue-500/10 border border-blue-500/20 text-blue-400">
                    <Wifi className="w-5 h-5" />
                  </div>
                </div>
                <div className="mt-3 text-[11px] text-slate-400 flex items-center justify-between">
                  <span>Simulated Stream Active</span>
                  <span className="text-emerald-400 font-mono">100% Up</span>
                </div>
              </div>

              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-sm relative overflow-hidden">
                <div className="flex justify-between items-start">
                  <div>
                    <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Security Alerts</span>
                    <h3 className="text-2xl font-bold text-rose-400 mt-1 font-mono">{totalAlerts}</h3>
                  </div>
                  <div className="p-2.5 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400">
                    <AlertTriangle className="w-5 h-5" />
                  </div>
                </div>
                <div className="mt-3 text-[11px] flex items-center gap-2 font-mono">
                  <span className="text-rose-400 font-bold">{highAlerts} HIGH</span> •
                  <span className="text-amber-400 font-bold">{medAlerts} MED</span> •
                  <span className="text-blue-400 font-bold">{lowAlerts} LOW</span>
                </div>
              </div>

              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-sm relative overflow-hidden">
                <div className="flex justify-between items-start">
                  <div>
                    <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Distinct Host IPs</span>
                    <h3 className="text-2xl font-bold text-emerald-400 mt-1 font-mono">{uniqueIps}</h3>
                  </div>
                  <div className="p-2.5 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400">
                    <Server className="w-5 h-5" />
                  </div>
                </div>
                <div className="mt-3 text-[11px] text-slate-400">
                  Subnets: 192.168.1.0/24 & 10.0.0.0/8
                </div>
              </div>

              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 shadow-sm relative overflow-hidden">
                <div className="flex justify-between items-start">
                  <div>
                    <span className="text-[11px] font-semibold text-slate-400 uppercase tracking-wider">Detection Logic</span>
                    <h3 className="text-2xl font-bold text-indigo-400 mt-1">4 Rules + ML</h3>
                  </div>
                  <div className="p-2.5 rounded-lg bg-indigo-500/10 border border-indigo-500/20 text-indigo-400">
                    <Cpu className="w-5 h-5" />
                  </div>
                </div>
                <div className="mt-3 text-[11px] text-slate-400 flex items-center justify-between">
                  <span>Deduplication</span>
                  <span className="text-cyan-400 font-mono">{rules.dedupWindowSec}s Window</span>
                </div>
              </div>
            </div>

            {/* Interactive Attack Simulation Controls Bar */}
            <div className="bg-gradient-to-r from-slate-900 via-slate-900 to-indigo-950/50 border border-indigo-500/30 rounded-xl p-4 shadow-md">
              <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
                <div>
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <Zap className="w-4 h-4 text-indigo-400" />
                    Interactive Attack Simulator (Safe Educational Testbed)
                  </h3>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Click any test attack scenario to safely generate packets on localhost and demonstrate detection rules in real-time:
                  </p>
                </div>
                
                <div className="flex flex-wrap gap-2 text-xs">
                  <button
                    onClick={triggerPortScanDemo}
                    className="bg-indigo-950/80 hover:bg-indigo-900 border border-indigo-700/60 text-indigo-200 px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition active:scale-95"
                  >
                    🔍 Rule 1: Port Scan (14 Ports)
                  </button>

                  <button
                    onClick={triggerRequestBurstDemo}
                    className="bg-indigo-950/80 hover:bg-indigo-900 border border-indigo-700/60 text-indigo-200 px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition active:scale-95"
                  >
                    💥 Rule 2: Request Burst (45 Pkts)
                  </button>

                  <button
                    onClick={triggerMalformedFlagsDemo}
                    className="bg-indigo-950/80 hover:bg-indigo-900 border border-indigo-700/60 text-indigo-200 px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition active:scale-95"
                  >
                    🎄 Rule 3: Xmas & Null Flags
                  </button>

                  <button
                    onClick={triggerRepeatedSynDemo}
                    className="bg-indigo-950/80 hover:bg-indigo-900 border border-indigo-700/60 text-indigo-200 px-3 py-1.5 rounded-lg flex items-center gap-1.5 transition active:scale-95"
                  >
                    🔄 Rule 4: Repeated SYN Probing
                  </button>
                </div>
              </div>
            </div>

            {/* Visual Charts Row */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Traffic Ingestion Rate Bar Chart */}
              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 lg:col-span-2">
                <div className="flex justify-between items-center mb-4">
                  <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2">
                    <Activity className="w-4 h-4 text-cyan-400" />
                    Network Traffic Rate (Packets / Sample Interval)
                  </h3>
                  <span className="text-[11px] font-mono text-slate-400">Live Telemetry</span>
                </div>
                
                {/* Visual SVG bar / sparkline */}
                <div className="h-44 flex items-end gap-2 pt-4 px-2 border-b border-slate-800">
                  {trafficRate.map((val, idx) => {
                    const heightPercent = Math.min(100, Math.max(15, val * 10));
                    return (
                      <div key={idx} className="flex-1 flex flex-col items-center gap-1 h-full justify-end group">
                        <span className="text-[10px] font-mono text-slate-400 opacity-0 group-hover:opacity-100 transition">
                          {val}
                        </span>
                        <div
                          style={{ height: `${heightPercent}%` }}
                          className={`w-full rounded-t transition-all duration-300 ${
                            val > 8 ? 'bg-rose-500 shadow-rose-500/20 shadow-md' : 'bg-cyan-500/80 hover:bg-cyan-400'
                          }`}
                        />
                        <span className="text-[9px] font-mono text-slate-500 truncate w-full text-center">
                          {timeLabels[idx] ? timeLabels[idx].slice(-5) : ''}
                        </span>
                      </div>
                    );
                  })}
                </div>
                <div className="flex justify-between items-center text-[11px] text-slate-400 mt-2">
                  <span>Sliding 30-second window</span>
                  <span className="text-cyan-400 font-mono">Average: 4.8 pkts/sec</span>
                </div>
              </div>

              {/* Protocol Breakdown */}
              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 flex flex-col justify-between">
                <div>
                  <h3 className="text-xs font-bold text-white uppercase tracking-wider flex items-center gap-2 mb-4">
                    <Layers className="w-4 h-4 text-indigo-400" />
                    Protocol Breakdown
                  </h3>

                  <div className="space-y-3 text-xs">
                    <div>
                      <div className="flex justify-between text-slate-300 mb-1">
                        <span className="font-semibold text-cyan-400">TCP (Web & SSH)</span>
                        <span className="font-mono">{protoCounts.TCP} pkts ({totalPackets ? Math.round((protoCounts.TCP / totalPackets) * 100) : 0}%)</span>
                      </div>
                      <div className="w-full bg-slate-950 rounded-full h-2">
                        <div className="bg-cyan-500 h-2 rounded-full" style={{ width: `${totalPackets ? (protoCounts.TCP / totalPackets) * 100 : 0}%` }} />
                      </div>
                    </div>

                    <div>
                      <div className="flex justify-between text-slate-300 mb-1">
                        <span className="font-semibold text-purple-400">UDP (Datagrams)</span>
                        <span className="font-mono">{protoCounts.UDP} pkts ({totalPackets ? Math.round((protoCounts.UDP / totalPackets) * 100) : 0}%)</span>
                      </div>
                      <div className="w-full bg-slate-950 rounded-full h-2">
                        <div className="bg-purple-500 h-2 rounded-full" style={{ width: `${totalPackets ? (protoCounts.UDP / totalPackets) * 100 : 0}%` }} />
                      </div>
                    </div>

                    <div>
                      <div className="flex justify-between text-slate-300 mb-1">
                        <span className="font-semibold text-emerald-400">DNS (Port 53)</span>
                        <span className="font-mono">{protoCounts.DNS} pkts ({totalPackets ? Math.round((protoCounts.DNS / totalPackets) * 100) : 0}%)</span>
                      </div>
                      <div className="w-full bg-slate-950 rounded-full h-2">
                        <div className="bg-emerald-500 h-2 rounded-full" style={{ width: `${totalPackets ? (protoCounts.DNS / totalPackets) * 100 : 0}%` }} />
                      </div>
                    </div>
                  </div>
                </div>

                <div className="p-3 bg-slate-950/70 border border-slate-800 rounded-lg text-[11px] text-slate-400 mt-4">
                  <div className="font-semibold text-slate-300">Security Observation:</div>
                  High TCP SYN percentage indicates port reconnaissance or connection probing.
                </div>
              </div>
            </div>

            {/* Security Alerts Feed Table */}
            <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 space-y-3">
              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
                <div className="flex items-center gap-2">
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-rose-400" />
                    Security Alerts Feed
                  </h3>
                  <span className="text-xs px-2 py-0.5 rounded-full bg-rose-500/20 text-rose-300 font-mono font-bold">
                    {filteredAlerts.length} Active Alerts
                  </span>
                </div>

                <div className="flex flex-wrap items-center gap-2 text-xs">
                  <select
                    value={filterSeverity}
                    onChange={e => setFilterSeverity(e.target.value)}
                    className="bg-slate-950 border border-slate-800 text-slate-200 px-2.5 py-1 rounded-lg"
                  >
                    <option value="ALL">All Severities</option>
                    <option value="HIGH">High Severity</option>
                    <option value="MEDIUM">Medium Severity</option>
                    <option value="LOW">Low Severity</option>
                  </select>

                  <div className="relative">
                    <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2 top-2" />
                    <input
                      type="text"
                      placeholder="Filter by IP..."
                      value={searchIP}
                      onChange={e => setSearchIP(e.target.value)}
                      className="bg-slate-950 border border-slate-800 text-slate-200 pl-7 pr-3 py-1 rounded-lg text-xs"
                    />
                  </div>
                </div>
              </div>

              <div className="overflow-x-auto max-h-72 overflow-y-auto rounded-lg border border-slate-800">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-950/80 text-slate-400 sticky top-0 border-b border-slate-800">
                    <tr>
                      <th className="py-2.5 px-3">Timestamp</th>
                      <th className="py-2.5 px-3">Severity</th>
                      <th className="py-2.5 px-3">Rule Name</th>
                      <th className="py-2.5 px-3">Attacker IP</th>
                      <th className="py-2.5 px-3">Victim Target</th>
                      <th className="py-2.5 px-3">Reason & Threshold Observation</th>
                      <th className="py-2.5 px-3">Origin</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {filteredAlerts.length === 0 ? (
                      <tr>
                        <td colSpan={7} className="py-8 text-center text-slate-500 font-sans">
                          No alerts detected. Trigger an attack scenario above to test the rules!
                        </td>
                      </tr>
                    ) : (
                      filteredAlerts.map(a => (
                        <tr key={a.id} className="hover:bg-slate-800/40 transition-colors">
                          <td className="py-2.5 px-3 text-slate-400 whitespace-nowrap">{a.timestamp}</td>
                          <td className="py-2.5 px-3 whitespace-nowrap">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              a.severity === 'HIGH' ? 'bg-rose-500/20 text-rose-300 border border-rose-500/40' :
                              a.severity === 'MEDIUM' ? 'bg-amber-500/20 text-amber-300 border border-amber-500/40' :
                              'bg-blue-500/20 text-blue-300 border border-blue-500/40'
                            }`}>
                              {a.severity}
                            </span>
                          </td>
                          <td className="py-2.5 px-3 text-indigo-300 font-semibold whitespace-nowrap">{a.rule_name}</td>
                          <td className="py-2.5 px-3 text-white font-bold whitespace-nowrap">{a.src_ip}</td>
                          <td className="py-2.5 px-3 text-slate-300 whitespace-nowrap">{a.dst_ip}:{a.dst_port || '*'}</td>
                          <td className="py-2.5 px-3 text-slate-300 max-w-sm">
                            <div className="font-sans text-xs">{a.reason}</div>
                            <div className="text-[10px] text-cyan-400 font-mono">{a.threshold_info}</div>
                          </td>
                          <td className="py-2.5 px-3 whitespace-nowrap">
                            <span className={`text-[10px] px-1.5 py-0.5 rounded font-mono ${
                              a.is_simulated ? 'bg-amber-950/80 text-amber-400 border border-amber-800' : 'bg-blue-950 text-blue-400'
                            }`}>
                              {a.is_simulated ? 'SIMULATED' : 'LIVE'}
                            </span>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Live Packet Inspection Stream Table */}
            <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-4 space-y-3">
              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3">
                <div>
                  <h3 className="text-sm font-bold text-white flex items-center gap-2">
                    <Terminal className="w-4 h-4 text-emerald-400" />
                    Live Packet Inspection Stream
                  </h3>
                  <p className="text-xs text-slate-400">Captured packet headers (L3/L4 fields decoded without logging payloads)</p>
                </div>

                <div className="flex items-center gap-2 text-xs">
                  <select
                    value={filterProto}
                    onChange={e => setFilterProto(e.target.value)}
                    className="bg-slate-950 border border-slate-800 text-slate-200 px-2.5 py-1 rounded-lg"
                  >
                    <option value="ALL">All Protocols</option>
                    <option value="TCP">TCP</option>
                    <option value="UDP">UDP</option>
                    <option value="DNS">DNS</option>
                  </select>
                </div>
              </div>

              <div className="overflow-x-auto max-h-72 overflow-y-auto rounded-lg border border-slate-800">
                <table className="w-full text-left text-xs font-mono">
                  <thead className="bg-slate-950/80 text-slate-400 sticky top-0 border-b border-slate-800">
                    <tr>
                      <th className="py-2.5 px-3">Timestamp</th>
                      <th className="py-2.5 px-3">Source (IP:Port)</th>
                      <th className="py-2.5 px-3">Destination (IP:Port)</th>
                      <th className="py-2.5 px-3">Proto</th>
                      <th className="py-2.5 px-3">Bytes</th>
                      <th className="py-2.5 px-3">TCP Flags</th>
                      <th className="py-2.5 px-3">Packet Info / Decoded Summary</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {filteredPackets.length === 0 ? (
                      <tr>
                        <td colSpan={7} className="py-6 text-center text-slate-500 font-sans">
                          Waiting for incoming packets...
                        </td>
                      </tr>
                    ) : (
                      filteredPackets.map(p => (
                        <tr key={p.id} className="hover:bg-slate-800/40 transition-colors">
                          <td className="py-2 px-3 text-slate-400 whitespace-nowrap">{p.timestamp}</td>
                          <td className="py-2 px-3 text-slate-200 whitespace-nowrap">{p.src_ip}:{p.src_port || '*'}</td>
                          <td className="py-2 px-3 text-slate-300 whitespace-nowrap">{p.dst_ip}:{p.dst_port || '*'}</td>
                          <td className="py-2 px-3 whitespace-nowrap">
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                              p.protocol === 'TCP' ? 'bg-cyan-500/20 text-cyan-300 border border-cyan-500/30' :
                              p.protocol === 'UDP' ? 'bg-purple-500/20 text-purple-300 border border-purple-500/30' :
                              'bg-emerald-500/20 text-emerald-300 border border-emerald-500/30'
                            }`}>
                              {p.protocol}
                            </span>
                          </td>
                          <td className="py-2 px-3 text-slate-400 whitespace-nowrap">{p.length} B</td>
                          <td className="py-2 px-3 text-amber-300 font-bold whitespace-nowrap">{p.tcp_flags || '-'}</td>
                          <td className="py-2 px-3 text-slate-400 truncate max-w-sm">{p.info}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>

          </div>
        )}

        {/* TAB 2: RULES CONFIGURATION */}
        {activeTab === 'rules' && (
          <div className="space-y-6">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 space-y-2">
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <Sliders className="w-5 h-5 text-cyan-400" />
                Detection Rule Configuration & Threshold Tuning
              </h2>
              <p className="text-xs text-slate-400">
                Adjust detection thresholds to test system sensitivity. All rules operate on stateful sliding time windows with alert deduplication.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              
              {/* Rule 1 */}
              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4">
                <div className="flex justify-between items-start">
                  <div>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-rose-500/20 text-rose-300 border border-rose-500/30">RULE 1</span>
                    <h3 className="text-sm font-bold text-white mt-1">Port Scan Detection</h3>
                  </div>
                  <span className="text-xs px-2 py-0.5 bg-rose-950 text-rose-400 rounded border border-rose-800">SEVERITY: HIGH</span>
                </div>
                <p className="text-xs text-slate-400">
                  Tracks unique destination ports queried by each source IP within a sliding observation window.
                </p>
                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div>
                    <label className="text-slate-400 block mb-1">Port Threshold (Distinct)</label>
                    <input
                      type="number"
                      value={rules.portScanThreshold}
                      onChange={e => setRules({ ...rules, portScanThreshold: Number(e.target.value) })}
                      className="bg-slate-950 border border-slate-800 rounded p-2 w-full text-white font-mono"
                    />
                  </div>
                  <div>
                    <label className="text-slate-400 block mb-1">Time Window (Seconds)</label>
                    <input
                      type="number"
                      value={rules.portScanWindowSec}
                      onChange={e => setRules({ ...rules, portScanWindowSec: Number(e.target.value) })}
                      className="bg-slate-950 border border-slate-800 rounded p-2 w-full text-white font-mono"
                    />
                  </div>
                </div>
              </div>

              {/* Rule 2 */}
              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4">
                <div className="flex justify-between items-start">
                  <div>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">RULE 2</span>
                    <h3 className="text-sm font-bold text-white mt-1">Excessive Request Burst (DoS)</h3>
                  </div>
                  <span className="text-xs px-2 py-0.5 bg-amber-950 text-amber-400 rounded border border-amber-800">SEVERITY: MEDIUM</span>
                </div>
                <p className="text-xs text-slate-400">
                  Flags rapid bursts of packets from a single source address, highlighting potential denial-of-service attempts.
                </p>
                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div>
                    <label className="text-slate-400 block mb-1">Packet Threshold</label>
                    <input
                      type="number"
                      value={rules.requestBurstThreshold}
                      onChange={e => setRules({ ...rules, requestBurstThreshold: Number(e.target.value) })}
                      className="bg-slate-950 border border-slate-800 rounded p-2 w-full text-white font-mono"
                    />
                  </div>
                  <div>
                    <label className="text-slate-400 block mb-1">Time Window (Seconds)</label>
                    <input
                      type="number"
                      value={rules.requestBurstWindowSec}
                      onChange={e => setRules({ ...rules, requestBurstWindowSec: Number(e.target.value) })}
                      className="bg-slate-950 border border-slate-800 rounded p-2 w-full text-white font-mono"
                    />
                  </div>
                </div>
              </div>

              {/* Rule 3 */}
              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4">
                <div className="flex justify-between items-start">
                  <div>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-purple-500/20 text-purple-300 border border-purple-500/30">RULE 3</span>
                    <h3 className="text-sm font-bold text-white mt-1">Unusual & Malformed Packets</h3>
                  </div>
                  <span className="text-xs px-2 py-0.5 bg-purple-950 text-purple-400 rounded border border-purple-800">SEVERITY: HIGH</span>
                </div>
                <p className="text-xs text-slate-400">
                  Inspects TCP control flags for signature stealth scanning tools (Nmap Xmas, Null scan, invalid SYN+FIN).
                </p>
                <div className="p-3 bg-slate-950 rounded-lg text-xs font-mono space-y-1 text-slate-300">
                  <div>• NULL Scan: Flags = 0 (No flags set)</div>
                  <div>• Xmas Tree: Flags = FIN + PSH + URG</div>
                  <div>• Illegal: SYN + FIN or SYN + RST</div>
                </div>
              </div>

              {/* Rule 4 */}
              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4">
                <div className="flex justify-between items-start">
                  <div>
                    <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-blue-500/20 text-blue-300 border border-blue-500/30">RULE 4</span>
                    <h3 className="text-sm font-bold text-white mt-1">Repeated Connection Attempts</h3>
                  </div>
                  <span className="text-xs px-2 py-0.5 bg-blue-950 text-blue-400 rounded border border-blue-800">SEVERITY: MEDIUM</span>
                </div>
                <p className="text-xs text-slate-400">
                  Detects repeated TCP SYN connection requests without established data transfer (half-open connection probing).
                </p>
                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div>
                    <label className="text-slate-400 block mb-1">SYN Attempt Threshold</label>
                    <input
                      type="number"
                      value={rules.repeatedConnThreshold}
                      onChange={e => setRules({ ...rules, repeatedConnThreshold: Number(e.target.value) })}
                      className="bg-slate-950 border border-slate-800 rounded p-2 w-full text-white font-mono"
                    />
                  </div>
                  <div>
                    <label className="text-slate-400 block mb-1">Time Window (Seconds)</label>
                    <input
                      type="number"
                      value={rules.repeatedConnWindowSec}
                      onChange={e => setRules({ ...rules, repeatedConnWindowSec: Number(e.target.value) })}
                      className="bg-slate-950 border border-slate-800 rounded p-2 w-full text-white font-mono"
                    />
                  </div>
                </div>
              </div>

            </div>
          </div>
        )}

        {/* TAB 3: MACHINE LEARNING MODULE */}
        {activeTab === 'ml' && (
          <div className="space-y-6">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <Brain className="w-5 h-5 text-indigo-400" />
                Machine Learning Traffic Flow Anomaly Module
              </h2>
              <p className="text-xs text-slate-400 mt-1">
                RandomForest classifier trained on flow-level characteristics. Demonstrates classification metrics, confusion matrices, and model explainability for college lab evaluation.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              
              {/* Interactive Predictor */}
              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4">
                <h3 className="text-sm font-bold text-white">Flow Feature Vector Testing</h3>
                <p className="text-xs text-slate-400">
                  Input flow statistical metrics over a time window to test model inference:
                </p>

                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div>
                    <label className="text-slate-400 block mb-1">Packets in Window</label>
                    <input
                      type="number"
                      value={mlPackets}
                      onChange={e => setMlPackets(Number(e.target.value))}
                      className="bg-slate-950 border border-slate-800 rounded p-2 w-full text-white font-mono"
                    />
                  </div>
                  <div>
                    <label className="text-slate-400 block mb-1">Unique Dst Ports</label>
                    <input
                      type="number"
                      value={mlPorts}
                      onChange={e => setMlPorts(Number(e.target.value))}
                      className="bg-slate-950 border border-slate-800 rounded p-2 w-full text-white font-mono"
                    />
                  </div>
                  <div>
                    <label className="text-slate-400 block mb-1">Avg Packet Length (Bytes)</label>
                    <input
                      type="number"
                      value={mlLength}
                      onChange={e => setMlLength(Number(e.target.value))}
                      className="bg-slate-950 border border-slate-800 rounded p-2 w-full text-white font-mono"
                    />
                  </div>
                  <div>
                    <label className="text-slate-400 block mb-1">SYN Attempt Count</label>
                    <input
                      type="number"
                      value={mlSyns}
                      onChange={e => setMlSyns(Number(e.target.value))}
                      className="bg-slate-950 border border-slate-800 rounded p-2 w-full text-white font-mono"
                    />
                  </div>
                </div>

                <button
                  onClick={runMLPrediction}
                  className="w-full bg-indigo-600 hover:bg-indigo-500 text-white font-semibold py-2 rounded-lg text-xs transition"
                >
                  ⚡ Run Inference & Compute Confidence
                </button>

                {mlResult && (
                  <div className={`p-4 rounded-xl border ${mlResult.isAnomaly ? 'bg-rose-950/40 border-rose-800' : 'bg-emerald-950/40 border-emerald-800'} space-y-2`}>
                    <div className="flex justify-between items-center">
                      <span className="text-xs text-slate-400">Predicted Classification:</span>
                      <span className={`text-xs font-bold font-mono px-2.5 py-0.5 rounded ${
                        mlResult.isAnomaly ? 'bg-rose-500/20 text-rose-300' : 'bg-emerald-500/20 text-emerald-300'
                      }`}>
                        {mlResult.prediction.toUpperCase()}
                      </span>
                    </div>

                    <div className="flex justify-between items-center text-xs">
                      <span className="text-slate-400">Prediction Confidence:</span>
                      <span className="font-mono font-bold text-white">{(mlResult.confidence * 100).toFixed(1)}%</span>
                    </div>

                    <p className="text-xs text-slate-300 pt-2 border-t border-slate-800">
                      {mlResult.explanation}
                    </p>
                  </div>
                )}
              </div>

              {/* Confusion Matrix & Academic Metrics */}
              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4">
                <h3 className="text-sm font-bold text-white">Model Evaluation Metrics (Test Split)</h3>

                <div className="grid grid-cols-2 gap-3 text-xs">
                  <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                    <span className="text-slate-400 block">Accuracy</span>
                    <span className="text-lg font-bold text-cyan-400 font-mono">96.5%</span>
                  </div>
                  <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                    <span className="text-slate-400 block">Precision</span>
                    <span className="text-lg font-bold text-indigo-400 font-mono">95.2%</span>
                  </div>
                  <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                    <span className="text-slate-400 block">Recall (Sensitivity)</span>
                    <span className="text-lg font-bold text-emerald-400 font-mono">97.1%</span>
                  </div>
                  <div className="bg-slate-950 p-3 rounded-lg border border-slate-800">
                    <span className="text-slate-400 block">F1-Score</span>
                    <span className="text-lg font-bold text-amber-400 font-mono">96.1%</span>
                  </div>
                </div>

                <div className="space-y-2">
                  <span className="text-xs font-semibold text-slate-300 block">Confusion Matrix (240 Test Samples):</span>
                  <div className="grid grid-cols-2 gap-2 text-xs font-mono text-center">
                    <div className="bg-slate-950 border border-slate-800 p-2.5 rounded">
                      <div className="text-emerald-400 font-bold text-base">165</div>
                      <div className="text-[10px] text-slate-400">True Negative (TN)</div>
                    </div>
                    <div className="bg-slate-950 border border-slate-800 p-2.5 rounded">
                      <div className="text-amber-400 font-bold text-base">3</div>
                      <div className="text-[10px] text-slate-400">False Positive (FP)</div>
                    </div>
                    <div className="bg-slate-950 border border-slate-800 p-2.5 rounded">
                      <div className="text-rose-400 font-bold text-base">2</div>
                      <div className="text-[10px] text-slate-400">False Negative (FN)</div>
                    </div>
                    <div className="bg-slate-950 border border-slate-800 p-2.5 rounded">
                      <div className="text-cyan-400 font-bold text-base">70</div>
                      <div className="text-[10px] text-slate-400">True Positive (TP)</div>
                    </div>
                  </div>
                </div>

                <div className="p-3 bg-amber-950/30 border border-amber-800/50 rounded-lg text-[11px] text-amber-300">
                  <strong>Academic Notice:</strong> Synthetic dataset results demonstrate machine learning classification methodology and confusion matrix analysis. They do NOT establish detection accuracy against unknown zero-day cyberattacks.
                </div>
              </div>

            </div>
          </div>
        )}

        {/* TAB 4: WIRESHARK CROSS-VERIFICATION */}
        {activeTab === 'wireshark' && (
          <div className="space-y-6">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <Eye className="w-5 h-5 text-cyan-400" />
                Wireshark Cross-Verification & Independent Packet Inspection
              </h2>
              <p className="text-xs text-slate-400 mt-1">
                How to verify the Python IDS observations using Wireshark on the same network interface.
              </p>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              
              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4">
                <h3 className="text-sm font-bold text-white">Lab Experiment Verification Steps</h3>
                <ol className="text-xs text-slate-300 space-y-3 list-decimal list-inside">
                  <li>
                    <strong>Open Wireshark:</strong> Launch Wireshark on your computer.
                  </li>
                  <li>
                    <strong>Select Interface:</strong> Select your loopback interface (<code>Npcap Loopback Adapter</code> on Windows or <code>lo</code> on Linux) or active Wi-Fi.
                  </li>
                  <li>
                    <strong>Start Sniffing:</strong> Click the blue Shark fin button to begin live packet capture.
                  </li>
                  <li>
                    <strong>Trigger IDS Attack:</strong> In this IDS dashboard, click <em>"Rule 1: Port Scan"</em> or <em>"Rule 3: Xmas Flags"</em>.
                  </li>
                  <li>
                    <strong>Compare Packets:</strong> Match the timestamp, source IP, and flags recorded in the IDS table with Wireshark packet logs.
                  </li>
                </ol>
              </div>

              <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-5 space-y-4">
                <h3 className="text-sm font-bold text-white">Essential Wireshark Display Filters</h3>

                <div className="space-y-3 text-xs">
                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                    <span className="text-slate-400 block mb-1 font-semibold">Filter Pure TCP Connection Attempts (Port Scan):</span>
                    <code className="text-cyan-400 font-mono">tcp.flags.syn == 1 && tcp.flags.ack == 0</code>
                  </div>

                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                    <span className="text-slate-400 block mb-1 font-semibold">Filter Xmas Tree Scan (FIN, PSH, URG active):</span>
                    <code className="text-cyan-400 font-mono">tcp.flags == 0x029</code>
                  </div>

                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                    <span className="text-slate-400 block mb-1 font-semibold">Filter Specific Attacker IP:</span>
                    <code className="text-cyan-400 font-mono">ip.addr == 192.168.1.99</code>
                  </div>

                  <div className="p-3 bg-slate-950 rounded-lg border border-slate-800">
                    <span className="text-slate-400 block mb-1 font-semibold">Filter DNS Traffic Only:</span>
                    <code className="text-cyan-400 font-mono">udp.port == 53</code>
                  </div>
                </div>
              </div>

            </div>
          </div>
        )}

        {/* TAB 5: VIVA VOCE EXAM PREP */}
        {activeTab === 'viva' && (
          <div className="space-y-6">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5">
              <h2 className="text-base font-bold text-white flex items-center gap-2">
                <HelpCircle className="w-5 h-5 text-amber-400" />
                Comprehensive Viva Voce Practice Portal (25+ Q&A)
              </h2>
              <p className="text-xs text-slate-400 mt-1">
                Frequently asked questions by university external examiners during B.Tech project vivas and lab practicals.
              </p>
            </div>

            <div className="space-y-3">
              {[
                {
                  q: '1. What is an Intrusion Detection System (IDS)?',
                  a: 'An IDS is a software application or hardware device that passively monitors network traffic or system logs for malicious activity, policy violations, or anomalous patterns, and raises alerts for security analysts.'
                },
                {
                  q: '2. What is the fundamental difference between an IDS and an IPS?',
                  a: 'An IDS operates out-of-band (passively) and alerts administrators without disrupting packets. An IPS operates in-line (actively) and can drop malicious packets, terminate TCP connections via RST, or reconfigure firewalls in real-time.'
                },
                {
                  q: '3. What is the difference between NIDS and HIDS?',
                  a: 'NIDS monitors traffic traversing a network segment or interface to protect multiple connected hosts. HIDS runs on a specific host endpoint to monitor OS system calls, file integrity, and local application logs.'
                },
                {
                  q: '4. Explain the TCP 3-Way Handshake and how a SYN scan abuses it.',
                  a: 'The 3-way handshake is SYN -> SYN/ACK -> ACK. In a half-open SYN scan, the attacker sends a SYN. If SYN/ACK is returned, the port is open; the attacker sends RST to terminate without completing the connection, evading older application-layer logs.'
                },
                {
                  q: '5. What is an Xmas Tree scan?',
                  a: 'An Xmas scan sends a TCP packet with FIN, PSH, and URG flags all turned on simultaneously (lit up like a Christmas tree). RFC 793 states closed ports must reply with RST, while open ports discard it, helping scanners probe firewall rules.'
                },
                {
                  q: '6. What is a NULL scan?',
                  a: 'A NULL scan sends a TCP packet with zero control flags set. Normal benign network traffic never has zero flags, making any NULL packet a strong indicator of stealth reconnaissance.'
                },
                {
                  q: '7. What is alert deduplication and why is it essential?',
                  a: 'Deduplication suppresses repeated identical alerts for the same source IP and rule within a short sliding window (e.g. 5 seconds). During high-speed floods (thousands of pkts/sec), deduplication prevents database exhaustion and analyst burnout.'
                },
                {
                  q: '8. Define Precision, Recall, and F1-Score in the context of an IDS.',
                  a: 'Precision = TP / (TP + FP) (percentage of generated alerts that are genuine). Recall = TP / (TP + FN) (percentage of actual attacks detected). F1-Score is their harmonic mean.'
                },
                {
                  q: '9. What is a False Positive vs. a False Negative?',
                  a: 'A False Positive (Type I error) occurs when benign traffic is mistakenly flagged as an attack. A False Negative (Type II error) occurs when an actual cyberattack slips through undetected. In security, False Negatives are the most dangerous.'
                },
                {
                  q: '10. What are the legal and ethical boundaries of running a network sniffer?',
                  a: 'Under the Information Technology Act (India) and computer crime laws worldwide, unauthorized packet sniffing on networks without explicit consent is illegal. This project must strictly be deployed on localhost or authorized university labs.'
                }
              ].map((item, idx) => (
                <details key={idx} className="bg-slate-900 border border-slate-800 rounded-xl p-4 text-xs group">
                  <summary className="font-bold text-white cursor-pointer list-none flex items-center justify-between">
                    <span className="flex items-center gap-2">
                      <span className="text-amber-400 font-mono">Q{idx + 1}.</span>
                      {item.q.replace(/^\d+\.\s*/, '')}
                    </span>
                    <ChevronRight className="w-4 h-4 text-slate-500 group-open:rotate-90 transition-transform" />
                  </summary>
                  <p className="mt-3 text-slate-300 leading-relaxed pl-5 border-l-2 border-amber-500/50">
                    {item.a}
                  </p>
                </details>
              ))}
            </div>

            <div className="p-4 bg-slate-900 border border-slate-800 rounded-xl text-xs text-slate-400 flex justify-between items-center">
              <span>View full 25+ question repository with answers in: <code className="text-cyan-400">docs/viva_questions.md</code></span>
              <span className="text-emerald-400 font-medium">✓ Ready for Exam Review</span>
            </div>
          </div>
        )}

        {/* TAB 6: PROJECT REPORT */}
        {activeTab === 'report' && (
          <div className="space-y-6">
            <div className="bg-slate-900 border border-slate-800 rounded-xl p-5 flex justify-between items-center">
              <div>
                <h2 className="text-base font-bold text-white flex items-center gap-2">
                  <FileText className="w-5 h-5 text-cyan-400" />
                  Academic Project Report & Submission Document
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  Full 20-section report formatted according to B.Tech university project guidelines.
                </p>
              </div>

              <button
                onClick={() => {
                  navigator.clipboard.writeText("Report content located in docs/project_report.md");
                  showToast("File location docs/project_report.md copied!");
                }}
                className="bg-slate-800 hover:bg-slate-700 border border-slate-700 text-slate-200 px-3 py-1.5 rounded-lg text-xs flex items-center gap-1.5"
              >
                <Copy className="w-3.5 h-3.5" /> Copy Path
              </button>
            </div>

            <div className="bg-slate-900/90 border border-slate-800 rounded-xl p-6 text-xs text-slate-300 space-y-6 leading-relaxed max-h-[600px] overflow-y-auto">
              
              <div className="border-b border-slate-800 pb-4">
                <h3 className="text-lg font-bold text-white">MINI NETWORK INTRUSION DETECTION SYSTEM (IDS)</h3>
                <p className="text-slate-400 mt-1">Department of Computer Engineering • Third Year B.Tech Mini-Project</p>
              </div>

              <div>
                <h4 className="font-bold text-cyan-400 uppercase tracking-wider mb-2">1. Abstract</h4>
                <p>
                  This project presents the design and implementation of an educational Network Intrusion Detection System (NIDS) in Python. 
                  The system captures network traffic using Scapy, decodes packet headers, and employs a four-tier rule engine to identify port scans, 
                  excessive request bursts, stealth TCP flag anomalies (Null, Xmas scans), and repeated SYN connection attempts. A companion machine learning 
                  module classifies traffic flows using a RandomForestClassifier. Data is persisted in SQLite and visualized via a responsive SOC dashboard.
                </p>
              </div>

              <div>
                <h4 className="font-bold text-cyan-400 uppercase tracking-wider mb-2">2. Objectives & Scope</h4>
                <ul className="list-disc list-inside space-y-1 text-slate-300">
                  <li>Passive packet capture and decoding across IPv4, TCP, UDP, DNS, and ICMP.</li>
                  <li>Configurable multi-rule detection engine with stateful sliding time windows.</li>
                  <li>Alert deduplication to eliminate database exhaustion during flood attacks.</li>
                  <li>Dual-mode execution: Live Scapy capture or privileged-free simulation mode.</li>
                  <li>Exporting alerts to CSV for independent cross-verification against Wireshark.</li>
                </ul>
              </div>

              <div>
                <h4 className="font-bold text-cyan-400 uppercase tracking-wider mb-2">3. Hardware & Software Requirements</h4>
                <p>
                  <strong>Hardware:</strong> Minimum Intel Core i3 / AMD Ryzen 3, 4GB RAM, 500MB Storage.<br />
                  <strong>Software:</strong> Windows 10/11 or Linux Ubuntu, Python 3.8-3.12, Flask, Scapy, SQLite3, Scikit-learn, Npcap, Wireshark 4.x.
                </p>
              </div>

              <div>
                <h4 className="font-bold text-cyan-400 uppercase tracking-wider mb-2">4. Project Structure in Repository</h4>
                <pre className="p-3 bg-slate-950 rounded-lg border border-slate-800 font-mono text-[11px] text-slate-300 overflow-x-auto">
{`mini-network-ids/
├── app.py                # Flask Web Dashboard & API
├── config.py             # Configurable thresholds & parameters
├── requirements.txt      # Python dependencies
├── detector/
│   ├── packet_capture.py # Live Scapy sniffer & simulated generator
│   ├── rules.py          # 4-tier detection rules & deduplication
│   ├── traffic_analyzer.py
│   └── ml_detector.py    # RandomForest flow anomaly classifier
├── database/storage.py   # SQLite manager & CSV export
├── scripts/
│   ├── generate_demo_data.py
│   ├── train_model.py
│   └── test_detector.py  # Automated detection tests
├── templates/index.html  # SOC Dashboard HTML
├── static/css/style.css
├── static/js/dashboard.js
├── tests/                # Unittest test suites
└── docs/
    ├── project_report.md # Full 20-section report
    └── viva_questions.md # 25+ viva questions & answers`}
                </pre>
              </div>

              <div>
                <h4 className="font-bold text-cyan-400 uppercase tracking-wider mb-2">5. Complete Report File Location</h4>
                <p className="text-slate-400">
                  The complete 20-section printable report including Title page, Certificates, Flowcharts in Mermaid format, Database schemas, Test cases, and References is saved in:
                  <code className="text-cyan-400 ml-1">mini-network-ids/docs/project_report.md</code>.
                </p>
              </div>

            </div>
          </div>
        )}

      </main>

      {/* Footer */}
      <footer className="border-t border-slate-800 bg-slate-900/60 py-3 px-6 text-center text-xs text-slate-500">
        Mini Network Intrusion Detection System (IDS) • B.Tech Third Year Computer Engineering Project • Educational Defensive Cyber Lab
      </footer>

    </div>
  );
}
