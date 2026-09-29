# NexIDS — Network Intrusion Detection System

> **Authorised monitoring only.** NexIDS is a defensive security tool designed to monitor traffic on networks you have explicit permission to inspect.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Project Structure](#project-structure)
4. [Quick Start](#quick-start)
5. [Running Tests](#running-tests)
6. [Development Phases](#development-phases)
7. [Configuration](#configuration)
8. [Limitations & Disclaimer](#limitations--disclaimer)

---

## Overview

NexIDS captures and analyses network traffic to detect potentially suspicious behaviour using explainable, rule-based detection logic. It generates structured alerts with evidence, risk context, and actionable recommendations — without making unsupported claims about intent or confirmed attacks.

### Core Workflow

```
Network Traffic
      ↓
Packet Capture       (app/capture/packet_capture.py)
      ↓
Packet Parsing       (app/capture/packet_parser.py)
      ↓
Detection Engine     (app/detection/)          ← Phase 3
      ↓
Alert Engine         (app/alert_engine/)        ← Phase 4
      ↓
Alert Prioritization (app/prioritizer/)         ← Phase 5
      ↓
Explainable Alerts
      ↓
Dashboard / Reports  (frontend/ + app/reporter/) ← Phases 6–7
```

---

## Architecture

| Component | Module | Status |
|-----------|--------|--------|
| Packet Capture | `app/capture/packet_capture.py` | ✅ Phase 2 |
| Packet Parser | `app/capture/packet_parser.py` | ✅ Phase 2 |
| Shared Logger | `app/utils/logger.py` | ✅ Phase 1 |
| Constants | `app/utils/constants.py` | ✅ Phase 1 |
| Port Scan Detection | `app/detection/port_scan.py` | 🔲 Phase 3 |
| ICMP Anomaly Detection | `app/detection/icmp_detection.py` | 🔲 Phase 3 |
| ARP Anomaly Detection | `app/detection/arp_detection.py` | 🔲 Phase 3 |
| Traffic Anomaly Detection | `app/detection/traffic_anomaly.py` | 🔲 Phase 3 |
| Alert Engine | `app/alert_engine/` | 🔲 Phase 4 |
| Alert Prioritizer | `app/prioritizer/` | 🔲 Phase 5 |
| Reporter | `app/reporter/` | 🔲 Phase 6 |
| Dashboard | `frontend/` | 🔲 Phase 7 |

---

## Project Structure

```
Net-IDS project/
│
├── app/
│   ├── __init__.py
│   ├── capture/
│   │   ├── __init__.py
│   │   ├── packet_capture.py   # PacketCapture class (threaded)
│   │   └── packet_parser.py    # parse_packet() / parse_packets()
│   ├── detection/              # Phase 3: detection modules
│   ├── alert_engine/           # Phase 4: alert generation
│   ├── prioritizer/            # Phase 5: rule-based prioritisation
│   ├── reporter/               # Phase 6: JSON/HTML reports
│   └── utils/
│       ├── __init__.py
│       ├── constants.py        # Project-wide constants
│       └── logger.py           # Coloured console + rotating file logger
│
├── frontend/                   # Phase 7: Flask dashboard
├── reports/                    # Generated report output
├── tests/
│   ├── conftest.py
│   ├── test_capture.py         # 54 tests — Phases 1 & 2
│   ├── test_detection.py       # Phase 3 stubs
│   ├── test_alert_engine.py    # Phase 4 stubs
│   └── test_prioritizer.py     # Phase 5 stubs
│
├── conftest.py                 # Root pytest path setup
├── main.py                     # CLI entry point
├── requirements.txt
└── README.md
```

---

## Quick Start

### Prerequisites

- Python 3.10+
- Scapy 2.5+ (already installed if requirements are met)
- On Windows: [Npcap](https://npcap.com/) must be installed for live capture

### Install dependencies

```bash
pip install -r requirements.txt
```

### Run NexIDS

```bash
# Default interface, capture until Ctrl-C
python main.py

# Specific interface
python main.py --interface "Wi-Fi"

# Capture exactly 500 packets then exit
python main.py --count 500

# Run for 60 seconds
python main.py --timeout 60

# Filter to only TCP traffic on port 443
python main.py --filter "tcp port 443"

# Verbose debug output
python main.py --log-level DEBUG
```

---

## Running Tests

```bash
# Run all tests
python -m pytest tests/ -v

# Run only Phase 1 & 2 tests
python -m pytest tests/test_capture.py -v

# Run with coverage
python -m pytest tests/test_capture.py -v --cov=app --cov-report=term-missing
```

### Phase 1 & 2 Test Results

```
54 tests collected
54 passed in 0.59s
```

All tests use **synthetic/mock packet objects** — no live network access required.

---

## Development Phases

| Phase | Scope | Status |
|-------|-------|--------|
| 1 | Project structure, utils, constants, logger | ✅ Complete |
| 2 | Packet capture + packet parsing | ✅ Complete |
| 3 | Detection modules (port scan, ICMP, ARP, traffic) | 🔲 Planned |
| 4 | Alert engine (structured alert generation) | 🔲 Planned |
| 5 | Alert prioritisation (explainable rules) | 🔲 Planned |
| 6 | Reporting (JSON + HTML) | 🔲 Planned |
| 7 | Frontend dashboard (Flask) | 🔲 Planned |
| 8 | End-to-end integration testing | 🔲 Planned |
| 9 | Documentation, error handling, UI polish | 🔲 Planned |

---

## Configuration

Key detection thresholds are in [`app/utils/constants.py`](app/utils/constants.py):

| Constant | Default | Description |
|----------|---------|-------------|
| `PORT_SCAN_THRESHOLD` | 15 | Unique ports from one source to flag potential scan |
| `PORT_SCAN_WINDOW_SECONDS` | 10 | Sliding window for port scan detection |
| `ICMP_FLOOD_THRESHOLD` | 50 | ICMP packets per source before flagging |
| `ICMP_WINDOW_SECONDS` | 5 | Sliding window for ICMP anomaly detection |
| `TRAFFIC_BYTES_THRESHOLD` | 10,000,000 | Bytes in window to flag anomaly (10 MB) |

---

## Alert Terminology

NexIDS uses cautious, evidence-based language:

| ✅ Used | ❌ Avoided |
|---------|-----------|
| "Potential Port Scan" | "Port Scan Attack Detected" |
| "Unusual ICMP Activity" | "ICMP Flood Attack" |
| "Potential ARP Anomaly" | "ARP Spoofing Confirmed" |
| "Traffic Anomaly" | "Intrusion Detected" |

---

## Limitations & Disclaimer

- **Authorised use only.** Only monitor networks and devices you have explicit permission to inspect.
- Live capture on Windows requires **Npcap** to be installed.
- Phase 1 & 2 implement capture and parsing only — no detection or alerting yet.
- This tool is for defensive security monitoring and educational purposes.
- Do not use NexIDS for any form of unauthorised access, surveillance, or offensive activity.
