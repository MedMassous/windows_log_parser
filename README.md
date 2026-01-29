# 🔐 Windows Security Log Parser

A Python-based security log analysis tool designed for blue team operations and SOC learning. This parser processes Windows Security and Sysmon-style logs, structures them into organized tables, and implements detection logic for common attack patterns like brute-force authentication attempts.

---

## 🎯 Project Overview

This tool helps security analysts and students practice fundamental log analysis skills by:

- Parsing and normalizing Windows Security event logs
- Structuring unstructured log data into queryable formats
- Implementing basic threat detection algorithms
- Simulating real-world SOC analyst workflows

Perfect for building practical blue team skills and demonstrating security analysis capabilities.

---

## 🧱 Data Architecture

The parser organizes log entries into three primary data structures:

### 🔑 Authentication Events

Tracks Windows logon activity using Security Event IDs:
- **4624** — Successful authentication
- **4625** — Failed authentication attempt

**Captured Fields:**
- Event identifier
- User account name
- Source IP address
- Authentication status

---

### ⚙️ Process Execution Events

Monitors process creation from Windows Security and Sysmon logs:
- **4688** — New process started

**Captured Fields:**
- Event identifier
- Account name
- Executable name

---

### 🚨 Security Alerts

Automated detections generated through correlation logic.

**Alert Attributes:**
- Detection name
- Risk level
- Origin IP address
- Event frequency
- Contextual details

---

## 🛠️ Technical Stack

- **Language:** Python 3.x
- **Dependencies:** Standard library only (no external packages required)
- **Log Sources:** Windows Security Events, Sysmon
- **Analysis Framework:** SOC detection methodologies

---

## 📂 Repository Structure

```
windows-log-parser/
├── windows_log_parser.py    # Main parsing engine
├── log_file.txt           # Example log dataset
└── README.md                 # Documentation
```

---

## 📄 Log Format Specification

The parser processes plain-text logs with key-value pairs:

```
EventID=4625 AccountName=admin SourceIP=10.0.0.5 Status=FAIL
EventID=4624 AccountName=admin SourceIP=192.168.1.10 Status=SUCCESS
EventID=4688 AccountName=SYSTEM ProcessName=powershell.exe
```

This format mirrors exported Windows event logs suitable for analysis.

---

## 🚀 Usage Instructions

**Clone the repository:**
```bash
git clone https://github.com/MedMassous/windows-log-parser.git
cd windows-log-parser
```

**Execute the parser:**
```bash
python windows_log_parser.py
```

---

## 📊 Output Examples

The tool generates structured output including:

- Parsed authentication records
- Process execution timeline
- Triggered security alerts

**Sample Alert:**
```
Detection: Possible Brute Force | Severity: Medium | Source: 10.0.0.5 | Events: 3 failed attempts
```

---

## 🔍 Detection Capabilities

### Brute-Force Authentication Detection

The parser implements a threshold-based detection algorithm that:

- Aggregates failed authentication events by source IP
- Identifies patterns exceeding predefined failure counts
- Generates medium-severity alerts for investigation

This approach mirrors correlation rules used in enterprise SIEM platforms.

---

## 📚 Skills Demonstrated

Working with this project develops:

- Log ingestion and parsing techniques
- Security event classification
- Threat detection pattern development
- Incident investigation procedures
- Security automation with Python

---

## 📌 Roadmap

Planned enhancements include:

- CSV export functionality for reporting
- Network connection monitoring (Sysmon Event ID 3)
- MITRE ATT&CK framework technique tagging
- Support for native EVTX file parsing
- Command-line interface with argument handling

---

## 👨‍💻 Author

**Mohamed Massous**  
SOC Analyst | Blue Team Enthusiast

🔗 [LinkedIn Profile](https://linkedin.com/in/massous-med)

---

## 📝 License

This project is available for educational and portfolio purposes.

---

**Note:** This tool is designed for learning environments and authorized security testing only. Always obtain proper authorization before analyzing production systems.
