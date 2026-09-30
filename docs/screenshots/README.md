# NexIDS SOC Dashboard & Demo Screenshots Guide

This directory is designated for storing visual artifacts and demonstration screenshots for reports, presentations, and technical documentation.

---

## Recommended Demonstration Screenshots

When showcasing NexIDS for academic evaluations, internship reviews, or SOC demonstrations, capture the following 5 views:

### 1. Dashboard Overview (`01_dashboard_overview.png`)
- **Location**: Browser view of `http://127.0.0.1:5000/`
- **Key Elements**:
  - Top header: "NEXIDS - Network Intrusion Detection & Alert Prioritization System".
  - Active monitoring indicator / Demo Mode badge.
  - Telemetry metric cards: Packets Inspected, Total Alerts, and severity counters (HIGH, MEDIUM, LOW, INFO).

### 2. Prioritized Alerts Table (`02_priority_alerts_table.png`)
- **Location**: Priority Alerts section of the SOC dashboard.
- **Key Elements**:
  - Sorted rankings (`#1`, `#2`, etc.).
  - Priority levels (`P1_CRITICAL`, `P2_HIGH`, `P3_MEDIUM`, `P4_LOW`).
  - Alert types: Potential ARP Anomaly, Potential Port Scan, Traffic Anomaly, Unusual ICMP Activity.
  - Confidence ratings, source IP addresses, and occurrence frequencies.

### 3. Alert Drill-down & Remediation Modal (`03_alert_details_modal.png`)
- **Location**: Click any row in the Prioritized Alerts table.
- **Key Elements**:
  - Complete metadata (Alert ID, protocol, timestamp, status).
  - Formatted Detection Evidence (e.g. scanned ports, MAC changes, burst volume).
  - Explainable Risk Reason detailing why the priority tier was assigned.
  - Actionable SOC investigation recommendations.

### 4. Structured JSON Audit Report (`04_json_audit_report.png`)
- **Location**: Opened in an editor (VS Code) or JSON viewer.
- **Key Elements**:
  - Top-level `metadata` block (timestamp, version, session duration, packets observed).
  - Summary statistics block.
  - Machine-readable `alerts` and `prioritized_alerts` arrays with score breakdowns.

### 5. Standalone HTML Security Report (`05_html_audit_report.png`)
- **Location**: Opened directly in a web browser from `reports/nexids_report_*.html`.
- **Key Elements**:
  - Clean, print-friendly layout.
  - Executive summary and audit statistics.
  - Color-coded priority badges, technical evidence tables, and administrator guidance.

---

## How to Capture for Demo

1. Start NexIDS Web Dashboard:
   ```bash
   python main.py
   ```
2. Navigate to `http://127.0.0.1:5000/` in Chrome/Firefox/Edge.
3. Click **"GENERATE DEMO DATA"** or **"START MONITORING"**.
4. Use standard OS shortcuts:
   - **Windows**: `Win + Shift + S`
   - **macOS**: `Cmd + Shift + 4`
   - **Linux**: `Shift + PrtScn`
5. Save captured PNG images into this directory (`docs/screenshots/`).
