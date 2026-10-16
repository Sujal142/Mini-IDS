# MINI NETWORK INTRUSION DETECTION SYSTEM (IDS)
## COMPREHENSIVE VIVA VOCE QUESTIONS & ANSWERS (25+ QUESTIONS)

This document is prepared to help students confidently answer questions during their B.Tech Computer Engineering project examination, external viva, or lab practicals.

---

### **Section 1: Intrusion Detection Fundamentals**

#### **Q1. What is an Intrusion Detection System (IDS)?**
**Answer:** An Intrusion Detection System (IDS) is a hardware device or software application that monitors network or system activities for malicious activities or policy violations. Any detected activity or violation is typically reported either to an administrator or collected centrally using a Security Information and Event Management (SIEM) system.

#### **Q2. What is the fundamental difference between an IDS and an IPS?**
**Answer:**
- **IDS (Intrusion Detection System):** Operates **passively** (out-of-band). It listens to a copy of traffic (via TAP, port mirror, or promiscuous mode), analyzes packets, and generates alerts when anomalies are found. It does **not** stop the traffic directly.
- **IPS (Intrusion Prevention System):** Operates **actively** (in-line). Traffic passes directly through the IPS. It can actively drop malicious packets, terminate TCP connections by sending RST packets, or immediately block offending IP addresses at the firewall.

#### **Q3. What is the difference between NIDS and HIDS?**
**Answer:**
- **NIDS (Network IDS):** Analyzes traffic on a network subnet or interface to protect multiple connected hosts (e.g., this mini-project, Snort, Zeek).
- **HIDS (Host-based IDS):** Runs directly on a single endpoint operating system to inspect local system calls, log files, file integrity changes, and registry modifications (e.g., OSSEC, Wazuh).

#### **Q4. What is the difference between Signature/Rule-Based Detection and Anomaly-Based Detection?**
**Answer:**
- **Signature / Rule-Based Detection:** Compares network traffic against known attack patterns or pre-programmed rules (e.g., searching for known exploit bytes or counting distinct ports against a threshold). Highly accurate for known attacks with very low false positives, but cannot detect novel zero-day attacks.
- **Anomaly-Based Detection:** Establishes a baseline of "normal" behavior (e.g., typical bandwidth, average packet length, standard ports) and flags any deviation exceeding normal statistical bounds. Can detect novel attacks, but has a higher rate of false positives.

---

### **Section 2: Networking, TCP/IP, & Packet Inspection**

#### **Q5. Explain the TCP 3-Way Handshake and how it relates to port scanning.**
**Answer:**
The standard TCP connection establishment involves:
1. **Client -> Server:** SYN (Synchronize sequence numbers).
2. **Server -> Client:** SYN + ACK (Acknowledge client SYN, send server SYN).
3. **Client -> Server:** ACK (Acknowledge server SYN; connection established).

In a **TCP SYN Scan (Half-Open Scan)**, an attacker sends SYN packets to various ports. If the port responds with SYN+ACK, the port is open; if it responds with RST, it is closed. The scanner sends an RST or fails to send the final ACK to avoid completing a full connection, attempting to stay stealthy.

#### **Q6. What are TCP Flags, and what role do they play in intrusion detection?**
**Answer:**
TCP header flags (control bits) manage state transitions:
- **SYN (Synchronize):** Initiates connection.
- **ACK (Acknowledgment):** Acknowledges receipt of data/packets.
- **FIN (Finish):** Gracefully terminates connection.
- **RST (Reset):** Abruptly aborts/rejects connection.
- **PSH (Push):** Forces data delivery to application without buffer wait.
- **URG (Urgent):** Indicates urgent pointer field is valid.

Detecting illegal flag combinations (like `SYN+FIN` or `FIN+PSH+URG` in Xmas scans) immediately exposes scanning software crafting raw packets.

#### **Q7. What is an Xmas Tree Scan? Why is it called that?**
**Answer:**
An Xmas Tree scan sends a TCP packet with the **FIN**, **PSH**, and **URG** flags all turned on simultaneously. It is called an "Xmas scan" because all the flag lights are turned on like ornaments on a Christmas tree. According to RFC 793, a closed port must respond with an RST, while an open port drops the packet. Windows systems often drop it regardless, making it useful for OS fingerprinting.

#### **Q8. What is a NULL Scan?**
**Answer:**
A NULL scan is a TCP packet where **no flags are set** (flags field is 0). RFC-compliant Unix/Linux TCP stacks will reply with RST if the destination port is closed, but will quietly discard the packet if the port is open. Standard benign traffic virtually never has zero flags.

#### **Q9. What is Promiscuous Mode on a Network Interface Card (NIC)?**
**Answer:**
By default, a NIC only passes frames addressed to its own MAC address, broadcast frames, or multicast frames to the OS kernel. In **promiscuous mode**, the NIC captures and passes **all** network traffic traversing the physical or virtual segment, regardless of destination MAC address. This is required for full-segment packet sniffing.

---

### **Section 3: Technologies Used (Python, Scapy, SQLite, Wireshark)**

#### **Q10. What is Scapy, and why was it chosen for this project?**
**Answer:**
Scapy is a powerful Python packet manipulation and sniffing library. It allows decoding, crafting, sending, and capturing network packets across dozens of protocols. It was chosen because it allows high-level Python access to raw packet headers, making the detection logic transparent and easy to extend.

#### **Q11. What is Npcap, and why is it needed on Windows?**
**Answer:**
Windows does not natively support low-level raw socket sniffing without special device drivers. **Npcap** is a Windows packet capture library and architecture (the modern successor to WinPcap) that provides the kernel-level driver enabling Scapy and Wireshark to capture raw link-layer Ethernet and Wi-Fi packets.

#### **Q12. What role does Wireshark play in this project?**
**Answer:**
Wireshark is an industry-standard graphical network protocol analyzer. In our project, it serves as an **independent verification tool**. We can run Wireshark simultaneously on the same network interface, apply display filters (e.g., `tcp.flags.syn == 1`), and verify that the packets captured in Wireshark match the alerts and packet table shown in our IDS dashboard.

#### **Q13. Why did you use SQLite instead of a heavy database like MySQL or PostgreSQL?**
**Answer:**
SQLite is a serverless, self-contained, zero-configuration SQL database engine. It stores data in a single cross-platform file (`ids_alerts.db`). For an educational B.Tech mini-project monitoring local traffic, SQLite provides full ACID compliance, high speed, and zero installation burden for the evaluator or student.

#### **Q14. Why did you implement a Simulation Mode?**
**Answer:**
In many college computer laboratories or restricted environments, students do not possess administrator or root rights on laboratory workstations. Without raw socket permissions, Scapy live sniffing will fail with a `PermissionError`. The built-in Simulation Mode generates realistic normal and attack traffic patterns entirely in software, allowing safe demonstration and grading.

---

### **Section 4: Detection Logic, Deduplication & Thresholds**

#### **Q15. How does your Port Scan detection rule work?**
**Answer:**
Our system maintains a dictionary mapping each `src_ip` to a list of timestamps and destination ports accessed. When a packet arrives, we prune entries older than the sliding window (`PORT_SCAN_WINDOW_SEC = 15s`). We then count the set of **unique** destination ports. If `len(unique_ports) >= PORT_SCAN_THRESHOLD (8)`, a `HIGH` severity alert is generated.

#### **Q16. How does your system detect excessive request bursts (DoS-like patterns)?**
**Answer:**
We count total packets originating from each `src_ip` within a sliding observation window (`REQUEST_BURST_WINDOW_SEC = 10s`). If the count exceeds `REQUEST_BURST_THRESHOLD (40)`, an alert is raised. We label this as "suspicious traffic / potential DoS" rather than definitive proof of an attack, acknowledging that legitimate batch file downloads or video streaming could also cause bursts.

#### **Q17. What is Alert Deduplication, and why is it critical?**
**Answer:**
During high-speed network attacks (e.g., a SYN flood generating 5,000 packets per second), an IDS evaluating every packet without deduplication would attempt to write 5,000 alerts per second to the database, exhausting disk I/O and overwhelming the security analyst. Our deduplication engine remembers the last alert timestamp for each `(src_ip, rule_name)` pair and suppresses identical alerts within a 5-second suppression window.

---

### **Section 5: Machine Learning & Performance Evaluation**

#### **Q18. What features did you feed into your Machine Learning model?**
**Answer:**
We extracted four flow-level statistical features:
1. `packets_per_window`: Total number of packets sent in the observation window.
2. `unique_dst_ports`: Number of different destination ports contacted.
3. `avg_packet_len`: Average packet length in bytes.
4. `syn_attempt_count`: Total count of pure TCP SYN connection attempts.

#### **Q19. Which algorithm was used, and why?**
**Answer:**
We implemented a **RandomForestClassifier**. Random Forest is an ensemble of decision trees. It is robust to outliers, handles non-linear feature boundaries effectively, resists overfitting through bagging and feature subsampling, and provides high interpretability for flow-based network classification.

#### **Q20. What is a Confusion Matrix? Explain TP, FP, TN, and FN in the context of an IDS.**
**Answer:**
A confusion matrix is a table summarizing classification performance:
- **True Positive (TP):** Malicious attack traffic correctly flagged as an alert.
- **True Negative (TN):** Normal benign traffic correctly identified as harmless.
- **False Positive (FP) [Type I Error]:** Benign traffic mistakenly flagged as an attack (e.g., a legitimate developer running tests flagged as a port scanner).
- **False Negative (FN) [Type II Error]:** Actual attack traffic that slips through undetected. In cybersecurity, False Negatives are the most dangerous.

#### **Q21. Define Precision, Recall, and F1-Score for an IDS.**
**Answer:**
- **Precision:** $\frac{TP}{TP + FP}$  
  *Meaning:* Out of all alerts generated, what percentage were genuine attacks? (High precision means analysts don't waste time on false alarms).
- **Recall (Sensitivity):** $\frac{TP}{TP + FN}$  
  *Meaning:* Out of all attacks that actually occurred, what percentage did the IDS catch? (High recall means attacks rarely escape).
- **F1-Score:** Harmonic mean of precision and recall: $2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$.

#### **Q22. Can a machine learning model detect 100% of cyberattacks?**
**Answer:**
No. In cybersecurity, no single detection system achieves 100% detection. Attackers frequently utilize adversarial evasion, low-and-slow reconnaissance (spreading port probes over hours or days), encryption, and protocol mimicry. Machine learning complements, but does not replace, deterministic rules and defense-in-depth principles.

---

### **Section 6: Ethics, Legalities, & Best Practices**

#### **Q23. What are the legal and ethical implications of running a packet sniffer?**
**Answer:**
Capturing packets on a network inspects data belonging to other users and machines. Under the Information Technology (IT) Act, 2000 (Section 43 & Section 66 in India) and similar cybersecurity laws internationally (such as the CFAA in the US), unauthorized interception of communications without explicit written consent is illegal. Our IDS must only be deployed on **localhost**, a **private home lab**, or **explicitly authorized educational laboratory environments**.

#### **Q24. Why did your project choose NOT to capture full packet payloads or passwords?**
**Answer:**
1. **Privacy & Ethics:** Capturing payloads could inadvertently log plain-text credentials, personal emails, or private messages.
2. **Performance:** Analyzing packet headers (L3/L4) requires negligible memory and processing power, whereas storing full payloads exhausts memory buffers rapidly.
3. **Encrypted Reality:** Modern web traffic uses TLS 1.3 / HTTPS, making payload inspection futile without active TLS termination or MITM certificates.

#### **Q25. How would you handle high-speed 10 Gbps enterprise traffic in a real-world deployment?**
**Answer:**
In production enterprise environments, Python-level packet parsing is too slow for 10+ Gbps links. Real-world solutions use:
1. **Hardware Offloading:** Kernel bypass mechanisms like **DPDK (Data Plane Development Kit)** or **AF_PACKET / eBPF (Extended Berkeley Packet Filter)** in the Linux kernel.
2. **C/C++ Core Engines:** Systems like Snort 3 or Suricata written in multi-threaded C/C++ or Rust.
3. **Hardware TAP / SPAN Ports:** Dedicated optical network TAPs feeding packet analysis appliances.
