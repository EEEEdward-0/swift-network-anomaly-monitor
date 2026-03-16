# ANEThreatMonitor

A Swift + Core ML based on-device network anomaly detection and visualization system for local traffic analysis, whitelist matching, and risk monitoring.

## Overview

ANEThreatMonitor is a macOS local network monitoring project that combines:

- **SwiftUI** for the desktop UI
- **Core ML** for on-device binary classification
- **Python** for traffic analysis and rule management
- **SQLite** for local rule storage and audit data
- **Prefix-tree based CIDR matching** for efficient IP/subnet lookup

The system is designed to support local packet analysis, anomaly detection, whitelist management, and risk visualization without relying on cloud-side inference.

## Features

- Real-time local traffic capture and analysis
- On-device anomaly detection with a **binary classification model**
- SwiftUI-based dashboard for risk visualization and history review
- Local whitelist management for:
  - Host
  - IP
  - IP:Port
  - CIDR
- Efficient **IP / CIDR matching** using a prefix-tree structure
- SQLite-backed local rule store and audit-friendly record management
- DNS / IP / CIDR threat-intel style synchronization workflow
- Query panel for checking whether an IP matches exact-IP rules or CIDR ranges

## Tech Stack

- **Frontend:** Swift, SwiftUI
- **ML Inference:** Core ML
- **Backend / Utility Scripts:** Python
- **Database:** SQLite
- **Algorithms / Data Structures:** Prefix Tree (Trie) for CIDR matching

## Project Structure

```text
ANEThreatMonitor/
├── app/ANEThreatMonitor/ANEThreatMonitor/   # SwiftUI macOS app
├── src/                                     # Python scripts
├── data/                                    # Local data / processed files
├── reports/                                 # Analysis results and logs
└── README.md

Core Modules

1. SwiftUI Monitoring Interface

The macOS interface provides:
	•	traffic/risk visualization
	•	session history browsing
	•	whitelist management
	•	IP match query panel
	•	result inspection and raw JSON display

2. Core ML Binary Classification

The system integrates a binary classification model for anomaly detection, enabling:
	•	on-device inference
	•	low-latency classification
	•	privacy-friendly local analysis

3. SQLite Rule Store

A local SQLite database is used to store:
	•	whitelist rules
	•	synchronized DNS / IP / CIDR records
	•	rule metadata
	•	audit-related timestamps and attributes

4. Prefix-tree CIDR Matching

To support efficient subnet lookup, the project uses a prefix-tree based matcher for CIDR rules.
This enables fast IP-to-subnet matching for 4000+ local rules.

Example Capabilities
	•	Check whether an IP is directly whitelisted
	•	Check whether an IP falls into a whitelisted CIDR subnet
	•	Display best-matched CIDR rule and total match count
	•	Review recent risk items and session history
	•	Manage user-defined and system-synchronized rules locally

Environment

Recommended environment:
	•	macOS
	•	Xcode
	•	Python 3.11+
	•	virtual environment (.venv)

Notes

This repository is intended for project demonstration, engineering practice, and portfolio presentation.

Large local artifacts such as:
	•	.venv
	•	processed .npy files
	•	logs
	•	local database files
	•	pcap files

should generally be excluded from version control.

Resume Highlights

This project demonstrates:
	•	Swift / SwiftUI desktop application development
	•	Core ML deployment of a binary classification model
	•	SQLite local database design
	•	Prefix-tree algorithm for IP/CIDR matching
	•	Local network anomaly detection and visualization

Author

Zhuohao Zheng