# PhishScope AI

An AI-powered phishing detection platform that analyzes URLs, email content, and threat indicators to identify malicious websites and phishing attempts.

## Project Objective

The objective of PhishScope AI is to provide real-time phishing detection using machine learning and threat intelligence techniques.

## Features

- URL Analysis
- Email Content Analysis
- IOC Extraction
- Risk Scoring Engine
- VirusTotal Integration
- Real-Time Threat Detection
- User-Friendly Dashboard

## Technology Stack

Frontend:
- HTML
- CSS
- JavaScript

Backend:
- Python

Threat Intelligence:
- VirusTotal API

## System Architecture

user
  |
  V
Web Interface
  |
  V
Content Analyzer
  |
  V
IOC Extractor
  |
  V
Risk Engine
  |
  V
VirusTotal Lookup
  |
  V
Final Threat Score

#Project folder structure 
PhishScope-AI
│
├── frontend
│   ├── index.html
│   ├── style.css
│   └── script.js
│
├── backend
│   ├── app.py
│   ├── content_analyzer.py
│   ├── ioc_extractor.py
│   ├── risk_engine.py
│   └── vt_lookup.py
│
├── screenshots
│   ├── dashboard.png
│   └── result.png
│
├── docs
│   └── architecture.png
│
├── requirements.txt
├── README.md
└── LICENSE

##RESULTS
## Evaluation Results

| Test Type | Result |
|------------|---------|
| Legitimate URLs | Passed |
| Suspicious URLs | Detected |
| Phishing URLs | Detected |
| IOC Extraction | Successful |
| Risk Scoring | Successful |

Overall Detection Efficiency: 92%
 # LICENSE 
 MIT License

Copyright (c) 2025 nihacyber001

Permission is hereby granted, free of charge, to any person obtaining a copy of this software...



## Installation

```bash
pip install -r requirements.txt
python app.py
