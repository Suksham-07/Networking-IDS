# NexIDS — Network Intrusion Detection & Alert Prioritization System

> **Defensive Security & Authorised Monitoring Only.**  
> NexIDS is a passive, explainable network intrusion detection and alert triage platform engineered to monitor network traffic, identify suspicious behavioral patterns, aggregate anomalies into structured security alerts, prioritize critical incidents using transparent multi-factor scoring, and generate comprehensive audit reports.

---

## Table of Contents

1. [Overview](#overview)
2. [Problem Statement](#problem-statement)
3. [Objectives](#objectives)
4. [System Architecture](#system-architecture)
5. [Detection Capabilities](#detection-capabilities)
6. [Alert Model](#alert-model)
7. [Explainable Alert Prioritization](#explainable-alert-prioritization)
8. [SOC Web Dashboard](#soc-web-dashboard)
9. [Security Reporting (JSON & HTML)](#security-reporting-json--html)
10. [Installation & Setup](#installation--setup)
11. [Running NexIDS](#running-nexids)
12. [Demo Mode & Step-by-Step Scenario](#demo-mode--step-by-step-scenario)
13. [Test Suite & Verification](#test-suite--verification)
14. [Configuration Management](#configuration-management)
15. [Data Privacy & Payload Omission](#data-privacy--payload-omission)
16. [Security & Ethical Use Policy](#security--ethical-use-policy)
17. [System Limitations](#system-limitations)

---

## Overview

Modern Security Operations Centers (SOCs) are inundated with thousands of raw network alerts daily. Traditional intrusion detection systems frequently emit low-fidelity notifications that overwhelm security analysts, leading to alert fatigue and delayed incident response.

**NexIDS** provides an end-to-end, passive network monitoring pipeline that couples multi-vector protocol analysis with an **explainable rule-based alert triage and prioritization engine**. Instead of making unproven assertions of adversary intent, NexIDS analyzes network traffic into structured, evidence-backed security observations, computes an explainable composite risk score ($0.0 - 100.0$), presents the findings on a web-based SOC dashboard, and exports audit-ready JSON and standalone HTML incident reports.

---

## Problem Statement

1. **Alert Fatigue**: High-volume sensor output overwhelms human analysts with low-severity or repetitive alerts.
2. **Opaque Scoring**: Black-box machine learning approaches often fail to provide justifiable rationales for why an alert was prioritized, complicating verification.
3. **Evidence Disconnection**: Alerts frequently lack structured technical evidence or concrete remediation recommendations.
4. **Deployment Friction**: Many IDS solutions depend on complex distributed infrastructure and cannot be easily demonstrated or operated in restricted or permission-constrained environments.

NexIDS addresses these challenges by delivering transparent rule-based prioritization, deterministic evidence preservation, zero-privilege demonstration capabilities, and comprehensive reporting.

---

## Objectives

- **Passive Network Monitoring**: Inspect TCP, UDP, ICMP, and ARP traffic without altering network flow or injecting packets.
- **Suspicious Pattern Detection**: Identify anomalous network behaviors (rapid port scanning, ARP anomalies, ICMP sweeps, traffic volume bursts) with tunable sliding windows.
- **Structured Alert Generation**: Normalize detections into typed alerts featuring severity, confidence, evidence metadata, and remediation recommendations.
- **Explainable Prioritization**: Rank alerts into clear operational tiers (`P1_CRITICAL`, `P2_HIGH`, `P3_MEDIUM`, `P4_LOW`) based on multi-attribute risk scoring.
- **SOC Dashboard Visualization**: Provide a responsive browser interface for live telemetry inspection, drill-down investigations, and monitoring management.
- **Security Audit Reporting**: Export standalone HTML reports and machine-readable JSON documents adhering to zero-payload privacy standards.

---

## System Architecture

NexIDS follows a strictly decoupled, unidirectional defensive pipeline:

```
Network Traffic (Live / Synthetic)
             ↓
    Packet Capture Module          (app/capture/packet_capture.py)
             ↓
    Packet Normalization & Parser  (app/capture/packet_parser.py)
             ↓
    Detection Engine (4 Detectors) (app/detection/)
             ↓
    Alert Aggregation & Engine     (app/alert_engine/)
             ↓
    Explainable Prioritizer        (app/prioritizer/)
             ↓
    Web SOC Dashboard (Flask/JS)   (app/dashboard/ + frontend/)
             ↓
    Report Generator               (app/reporter/report_generator.py)
             ↓
   JSON / Standalone HTML Reports  (reports/)
```

---

## Detection Capabilities

NexIDS implements modular detectors operating on normalized packet dictionaries. Detections represent **potentially suspicious patterns** rather than confirmed intrusions.

| Detector | Target Protocol | Detection Pattern | Default Threshold |
| :--- | :--- | :--- | :--- |
| **Port Scan Detector** | TCP | Probing multiple distinct destination ports from a single source within a sliding temporal window. | 15 unique ports in 10.0s |
| **ARP Anomaly Detector** | ARP | Conflicting IP-to-MAC hardware address mappings or suspicious gratuitous ARP announcements. | State mutation or 20 req/10s |
| **ICMP Anomaly Detector** | ICMP | Excessive echo request generation indicative of subnet ping sweeps or reconnaissance. | 50 echo requests in 5.0s |
| **Traffic Anomaly Detector**| IP / Any | Sudden throughput or packet rate bursts exceeding baseline capacity. | 10 MB or 1,000 pps in 10.0s |

> **Defensive Phrasing Policy:** NexIDS never claims an incident is a "confirmed breach". Reports and UI surfaces strictly use measured terminology: *"Potential Port Scan"*, *"Potential ARP Anomaly"*, *"Unusual ICMP Activity"*, and *"Traffic Anomaly"*.

---

## Alert Model

Each alert generated by the Alert Engine (`app/alert_engine/alert_model.py`) adheres to a standard schema:

- **Alert ID**: Unique UUID4 identifier for lifecycle tracking.
- **Detection Type**: Canonical category of the observed anomaly.
- **Severity**: Base severity assessment (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFO`).
- **Confidence**: Normalized detector confidence score ($0.00 - 1.00$).
- **Source & Destination**: IPv4 / MAC endpoints involved.
- **Protocol**: Transport or network protocol (`TCP`, `UDP`, `ICMP`, `ARP`).
- **Occurrence Count & Temporal Scope**: Deduplication counter with `first_seen` and `last_seen` epoch timestamps.
- **Evidence**: Structured dictionary preserving observation metadata (e.g. scanned ports, previous MAC, observed pps).
- **Risk Context**: Analytical explanation of the potential threat surface.
- **Recommendations**: SOC analyst investigation checklists and containment steps.
- **Status**: Operational triage state (`New`, `Acknowledged`, `Resolved`).

---

## Explainable Alert Prioritization

Alert triage is driven by a deterministic, transparent multi-factor scoring model (`app/prioritizer/`). NexIDS does **not** use opaque black-box machine learning models.

### Composite Score Formula

$$\text{Priority Score} = \text{Base Severity} + \text{Confidence Weight} + \text{Recurrence Boost} + \text{Asset Criticality} + \text{Correlation Boost}$$

Clamped strictly between $0.0$ and $100.0$:

1. **Base Severity Points**: `CRITICAL` (40 pts), `HIGH` (30 pts), `MEDIUM` (20 pts), `LOW` (10 pts).
2. **Confidence Scaling**: Multiplied by detector confidence (up to 20 pts).
3. **Recurrence & Frequency**: Logarithmic scaling based on repeated occurrences (up to 15 pts).
4. **Asset Criticality**: Bonus points if source or target represents a critical gateway, DNS, or server infrastructure (up to 15 pts).
5. **Attack Chain Correlation**: Added if multiple distinct attack types originate from the same IP (up to 10 pts).

### Priority Tiers

| Priority Tier | Score Range | Operational Meaning | Recommended Analyst Action |
| :--- | :---: | :--- | :--- |
| **`P1_CRITICAL`** | $80.0 - 100.0$ | **Critical Threat** | Immediate escalation; high-confidence anomaly actively targeting core infrastructure. |
| **`P2_HIGH`** | $60.0 - 79.9$ | **Elevated Threat** | **Investigate promptly within current shift.** Substantial suspicious pattern or activity against a sensitive asset. |
| **`P3_MEDIUM`** | $40.0 - 59.9$ | **Moderate Risk** | **Routine triage review.** Anomalous network behavior to inspect during scheduled review, without immediate emergency. |
| **`P4_LOW`** | $0.0 - 39.9$ | **Informational** | Low-confidence anomaly or minor deviation. Preserved for baseline auditing and correlation. |

### Severity vs. Priority: What is the Difference?

A common question in SOC operations is why an alert might have a **MEDIUM** severity but still be prioritized as **`P2_HIGH`**, or have a **HIGH** severity but end up as **`P3_MEDIUM`**:

* **Severity (Static)**: Represents the inherent theoretical severity of the detector type (e.g. Traffic Anomaly defaults to `HIGH`, Port Scan defaults to `MEDIUM`).
* **Priority Tier (Dynamic Triage Urgency)**: Represents how urgently the incident must be addressed *right now*, calculated dynamically by evaluating situational factors (gateway targeting, recurrence, multi-vector correlation).

#### Concrete Examples from the Demo Scenario:

1. **Why `Potential ARP Anomaly` is `P2_HIGH` (Score: 61.0)**:
   * **Base Severity**: `MEDIUM` ($20$ pts)
   * **Confidence**: $95\%$ ($+19$ pts)
   * **Asset Criticality**: Targets `192.168.1.1` (the network's **default gateway/router**; $+15$ pts)
   * **Correlation**: Same source IP was also seen port scanning ($+7$ pts)
   * **Result**: **$61.0$ points $\rightarrow$ `P2_HIGH`**.  
     *Why it matters*: An attacker attempting to impersonate the network router poses a serious operational risk.

2. **Why `Traffic Anomaly` is `P3_MEDIUM` (Score: 47.4)**:
   * **Base Severity**: `HIGH` ($30$ pts)
   * **Confidence**: $87\%$ ($+17.4$ pts)
   * **Asset Criticality**: Target is an ordinary workstation (`10.0.0.10`), not a critical server/gateway ($0$ pts boost)
   * **Correlation**: Single standalone occurrence ($0$ pts)
   * **Result**: **$47.4$ points $\rightarrow$ `P3_MEDIUM`**.  
     *Why it matters*: While moving 12 MB/s in a burst is high volume, it could simply be a scheduled backup or file sync rather than a targeted compromise. It warrants routine review, but at a lower priority than the gateway attack.


---

## SOC Web Dashboard

NexIDS includes a lightweight web interface built with Flask, semantic HTML5, CSS3, and native vanilla JavaScript.

### Core Features:
- **Telemetry Overview**: Real-time counters for Packets Inspected, Total Alerts, and severity categories (`HIGH`, `MEDIUM`, `LOW`, `INFO`).
- **Triage Priority Table**: Live sorting of prioritized alerts with rank `#1`, priority tier badges, risk scores, confidence percentages, and timestamps.
- **Incident Drill-down Modal**: Detailed view containing detection evidence, risk rationale, and remediation guidance.
- **Monitoring Controls**: Start and stop passive capture directly from the browser.
- **Demo Mode**: Built-in synthetic event generator for presentations without requiring administrative network permissions.
- **One-Click Export**: Instant generation and direct downloading of JSON and standalone HTML security reports.

---

## Security Reporting (JSON & HTML)

Reports are saved to `reports/` with unique timestamped filenames (e.g. `nexids_report_2026-09-30_150649.json`). Existing reports are never overwritten.

### JSON Report Structure
Machine-readable format suitable for SIEM ingestion:
```json
{
  "metadata": {
    "report_title": "NexIDS Security Audit Report",
    "nexids_version": "0.1.0",
    "timestamp": 1727708809.0,
    "total_packets_observed": 18450,
    "total_alerts": 4,
    "total_prioritized_alerts": 4
  },
  "summary": {
    "severity_counts": { "CRITICAL": 0, "HIGH": 1, "MEDIUM": 3, "LOW": 0, "INFO": 0 },
    "priority_distribution": { "P1_CRITICAL": 0, "P2_HIGH": 3, "P3_MEDIUM": 1, "P4_LOW": 0 }
  },
  "alerts": [ ... ],
  "prioritized_alerts": [ ... ]
}
```

### Standalone HTML Report
Self-contained HTML file formatted with an executive audit layout, color-coded severity badges, technical evidence blocks, and print-ready CSS.

---

## Installation & Setup

### Prerequisites
- **Python**: Version 3.10 to 3.14+
- **Windows Users**: For live packet capture, [Npcap](https://npcap.com/) must be installed. (Demo mode works without Npcap).
- **Linux Users**: Root/sudo permissions (`libpcap`) required for live interface sniffing.

### Installation Steps

```bash
# 1. Clone the repository
git clone https://github.com/Suksham-07/Networking-IDS.git
cd "Net-IDS project"

# 2. (Optional) Create and activate virtual environment
python -m venv venv
# On Windows:
.\venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## Running NexIDS

### 1. Launch the Web SOC Dashboard (Recommended)
```bash
python main.py
```
*Accessible in your browser at: `http://127.0.0.1:5000`*

### 2. Execute Standalone Demonstration (CLI Demo)
```bash
python main.py --demo
```
*Simulates 4 synthetic attack scenarios, runs prioritization, prints the triage table, and exports sample JSON/HTML reports to `reports/`.*

### 3. Command-Line Packet Capture (CLI Mode)
```bash
# Capture traffic on default network interface
python main.py --cli

# Capture on a specific interface with BPF filter
python main.py --cli -i "Wi-Fi" -f "tcp port 80 or tcp port 443"

# Capture up to 500 packets and stop
python main.py --cli -c 500
```

---

## Demo Mode & Step-by-Step Scenario

NexIDS features a dedicated, zero-privilege **Demo Mode** designed specifically for presentations and demonstrations where administrative permissions or live rogue devices are unavailable.

### Demonstration Flow:

1. **Start Application**:
   ```bash
   python main.py
   ```
2. **Open Dashboard**:
   Open `http://127.0.0.1:5000` in Google Chrome, Firefox, or Microsoft Edge.
3. **Trigger Demo Traffic**:
   Click the yellow button: **"⚡ GENERATE DEMO DATA"**.
4. **Observe Telemetry**:
   - `Packets Inspected`: Updates to 18,450.
   - `Total Alerts`: Displays 4 detected anomalies.
   - `Severity Counters`: Shows 1 HIGH and 3 MEDIUM alerts.
   - `DEMO MODE`: Visual badge confirms synthetic execution.
5. **Inspect Priority Rankings**:
   - Notice that alerts are prioritized with transparent scores:
     - `#1`: Potential ARP Anomaly (`P2_HIGH`, score ~61.0)
     - `#2`: Potential Port Scan (`P2_HIGH`, score ~60.4)
     - `#3`: Unusual ICMP Activity (`P2_HIGH`, score ~50.0)
     - `#4`: Traffic Anomaly (`P3_MEDIUM`, score ~47.4)
6. **Examine Alert Drill-down**:
   Click any row to open the modal. Review the **Detection Evidence**, **Risk Reason**, and **Actionable Recommendations**.
7. **Generate Security Reports**:
   - Click **"EXPORT JSON REPORT"** -> Downloads structured audit JSON.
   - Click **"EXPORT HTML REPORT"** -> Downloads and views formatted incident report.

---

## Test Suite & Verification

NexIDS features a 100% synthetic, automated test suite that does not require live network traffic or administrative privileges.

```bash
# Run complete test suite
python -m pytest

# Run with test coverage analysis
python -m pytest --cov=app --cov-report=term-missing
```

### Test Suite Status:
- **Total Tests**: **226 passed** (0 failed, 0 skipped)
- **Execution Time**: ~2.7 seconds
- **Code Coverage**: **90% total test coverage**
  - `app/utils/config.py`: **100%**
  - `app/utils/constants.py`: **100%**
  - `app/capture/packet_parser.py`: **100%**
  - `app/detection/engine.py`: **100%**
  - `app/alert_engine/alert_manager.py`: **99%**
  - `app/alert_engine/alert_model.py`: **97%**
  - `app/prioritizer/rules.py`: **97%**
  - `app/detection/arp_detection.py`: **95%**
  - `app/utils/logger.py`: **95%**
  - `app/dashboard/app.py`: **94%**
  - `app/reporter/report_generator.py`: **91%**
  - `app/prioritizer/models.py`: **91%**

---

## Configuration Management

Configuration values can be configured via environment variables or a `.env` file (see [`.env.example`](.env.example)).

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `NEXIDS_MODE` | `demo` | Default execution mode (`demo`, `live`, `web`, `cli`) |
| `NEXIDS_HOST` | `127.0.0.1` | Web dashboard binding host |
| `NEXIDS_PORT` | `5000` | Web dashboard binding port |
| `NEXIDS_PORT_SCAN_THRESHOLD` | `15` | Unique ports before triggering port scan detection |
| `NEXIDS_PORT_SCAN_WINDOW` | `10.0` | Sliding window for port scan detection in seconds |
| `NEXIDS_ICMP_FLOOD_THRESHOLD` | `50` | ICMP packet threshold within window |
| `NEXIDS_TRAFFIC_BYTES_THRESHOLD`| `10000000` | Byte volume threshold in window (10 MB) |
| `NEXIDS_REPORT_DIR` | `reports` | Target directory for generated reports |
| `NEXIDS_LOG_LEVEL` | `INFO` | Logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`) |

---

## Data Privacy & Payload Omission

NexIDS is engineered with strict privacy safeguards:

- **Zero Payload Storage**: Raw packet application payloads (HTTP POST bodies, credentials, private messages) are never parsed into text, stored in alert models, or exported to reports.
- **Log Sanitization**: A custom `SensitiveDataFilter` actively sanitizes log outputs, scrubbing inadvertent credential patterns (`password=`, `token=`, `api_key=`, `bearer`).
- **Metadata-Only Reports**: Reports preserve only structural network metadata (IP addresses, port numbers, flags, byte counters, and timing) necessary for defensive incident triage.

---

## Security & Ethical Use Policy

NexIDS is an **authorized defensive security monitoring tool** designed solely for educational, academic, research, and defensive administrative purposes.

- **Explicit Authorization**: Only monitor networks, interfaces, and hosts for which you have received prior, explicit written authorization from the system owner.
- **No Offensive Capabilities**: NexIDS contains **no** packet injection, exploit delivery, denial of service, password cracking, or unauthorized surveillance mechanisms.
- **Safe Operation**: All automated tests operate strictly in memory using synthetic Scapy packets without transmitting raw frames over physical interfaces.

---

## System Limitations

1. **Rule-Based Heuristics**: Detection logic relies on sliding-window heuristics and deterministic thresholds. It does not utilize heuristic deep learning or zero-day vulnerability prediction.
2. **False Positives & Negatives**: Benign administrative network scans, vulnerability scanners, or high-throughput file transfers can trigger alerts. Detections warrant analyst verification.
3. **Capture Permissions**: Raw socket access for live packet capture on Windows requires Npcap with administrator privileges; on Linux, it requires `CAP_NET_RAW` or root.
4. **Encrypted Payloads**: As a passive transport-layer IDS, NexIDS inspects protocol headers and traffic patterns; it does not perform SSL/TLS man-in-the-middle decryption.
5. **Not a Full SIEM Replacement**: NexIDS is designed for network-layer anomaly detection and alert prioritization, not as a replacement for full enterprise SIEM or EDR suites.
