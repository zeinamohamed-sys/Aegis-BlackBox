# Aegis-BlackBox: Multi-Language Malware Behavioral Analytics Engine

## Abstract
Aegis-BlackBox is a production-style, multi-language malware behavioral analytics pipeline designed to demonstrate how low-level binary inspection, deterministic threat scoring, and machine-learning-driven anomaly detection can work together inside a modern security engineering workflow. The repository combines **C++** for PE parsing, **Java** for weighted threat modeling and durable analytics storage, and **Python** for downstream anomaly detection and Power BI-ready reporting. The result is a recruiter-grade reference project that showcases secure systems thinking, language interoperability, and practical cyber-defense analytics in one cohesive repository.

> **Important Notice**
> This repository is intended for authorized malware research, defensive analytics, reverse-engineering education, and controlled lab environments only.

---

## System Architecture

```text
                +--------------------------------------+
                |   Windows PE Sample (.exe / .dll)    |
                +-------------------+------------------+
                                    |
                                    v
                    +---------------+----------------+
                    | Module 1: Core Static Analyzer |
                    | C++17 / PE Header + Sections   |
                    | Import Address Table Parsing   |
                    +---------------+----------------+
                                    |
                                    v
                        analysis_results.json
                                    |
                                    v
                  +-----------------+------------------+
                  | Module 2: Data & Risk Logic        |
                  | Java 17 / Weighted Threat Scoring  |
                  | SQLite Persistence (analytics.db)  |
                  +-----------------+------------------+
                                    |
                                    v
                  +-----------------+------------------+
                  | Module 3: AI Classification        |
                  | Python / Pandas / Scikit-learn     |
                  | Anomaly Detection + CSV Export     |
                  +-----------------+------------------+
                                    |
                                    v
                            final_report.csv
                       (Power BI / SOC analytics)
```

### Interaction Model
- **C++ module** performs deterministic binary introspection and emits normalized JSON.
- **Java module** consumes the JSON, calculates a risk-oriented threat score, and stores enriched results in SQLite.
- **Python module** reads historical analysis records from SQLite, detects anomalous samples, and exports a BI-friendly dataset.

---

## Repository Layout

```text
Aegis-BlackBox/
├── Core/
│   └── main.cpp
├── DataProcessor/
│   ├── pom.xml
│   └── src/
│       └── main/
│           └── java/
│               └── com/
│                   └── aegisblackbox/
│                       └── Processor.java
├── AI_Module/
│   ├── ai_classifier.py
│   └── requirements.txt
└── README.md
```

---

## Tech Stack
- **C++17** — low-level PE parsing and JSON generation
- **Java 17** — threat scoring, rule-based analytics, and SQLite persistence
- **Python 3.10+** — anomaly detection and Power BI export pipeline
- **SQLite** — lightweight embedded analytics store
- **Pandas** — tabular data handling
- **Scikit-learn** — anomaly detection with Isolation Forest

---

## Module 1 — Core Static Analyzer (C++)

### Responsibilities
- Parse DOS and NT PE headers
- Extract section metadata
- Enumerate imported libraries and imported functions from the Import Address Table context
- Export normalized output to `analysis_results.json`

### Build
```bash
g++ -std=c++17 -O2 -Wall -Wextra -pedantic -o pe_analyzer Core/main.cpp
```

### Run
```bash
./pe_analyzer /path/to/sample.exe analysis_results.json
```

### Output
The analyzer generates `analysis_results.json` containing:
- File metadata
- PE header details
- Section table entries
- Imported libraries and functions

---

## Module 2 — Data & Risk Logic (Java)

### Responsibilities
- Load `analysis_results.json`
- Apply weighted logic to suspicious Windows APIs
- Produce a normalized **Threat Score**
- Persist all enriched findings into `analytics.db`

### Build
```bash
cd DataProcessor
mvn clean package
```

### Run
```bash
java -jar target/data-processor-1.0.0-jar-with-dependencies.jar ../analysis_results.json ../analytics.db
```

### Threat Logic Examples
The Java processor increases risk when it detects APIs commonly associated with:
- process injection (`CreateRemoteThread`, `WriteProcessMemory`, `VirtualAllocEx`)
- network activity (`InternetConnect`, `HttpOpenRequest`, `socket`, `connect`)
- anti-analysis behavior (`IsDebuggerPresent`, `NtQueryInformationProcess`)
- registry persistence or dynamic loading patterns

---

## Module 3 — AI Classification (Python)

### Responsibilities
- Read historical threat records from `analytics.db`
- Derive ML-ready features
- Perform anomaly detection using **Isolation Forest**
- Export `final_report.csv` for dashboards and reporting tools like Power BI

### Install Dependencies
```bash
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
pip install -r AI_Module/requirements.txt
```

### Run
```bash
python AI_Module/ai_classifier.py --db analytics.db --out final_report.csv
```

### Output
`final_report.csv` includes:
- sample metadata
- threat score and risk level
- anomaly label
- anomaly score
- recommended action for triage

---

## End-to-End Usage Guide

### 1) Analyze a PE sample
```bash
./pe_analyzer /path/to/sample.exe analysis_results.json
```

### 2) Calculate the threat score and persist analytics
```bash
cd DataProcessor
mvn clean package
java -jar target/data-processor-1.0.0-jar-with-dependencies.jar ../analysis_results.json ../analytics.db
cd ..
```

### 3) Run anomaly detection and export BI data
```bash
python AI_Module/ai_classifier.py --db analytics.db --out final_report.csv
```

---

## Operational Notes
- Run the pipeline inside an isolated malware-analysis lab or secure sandbox.
- Prefer read-only ingestion of suspicious binaries.
- Add digital signature validation, YARA integration, entropy scoring, and sandbox telemetry as future enhancements.
- Treat the AI output as analyst-assistive evidence, not as a standalone verdict.

---

## Showcase Value
This project is intentionally structured to demonstrate:
- **systems-level C++ parsing competence**
- **backend analytics engineering in Java**
- **applied ML operations in Python**
- **clean multi-language architecture design for cybersecurity use cases**

It is suitable for portfolio presentation to security engineering teams, malware analysis groups, detection engineering units, and advanced software recruiters.
