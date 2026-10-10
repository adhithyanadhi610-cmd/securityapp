# SentinelCloud AI

## 1. Problem Statement
AI-Driven Automated Incident Response and Real-Time Threat Mitigation System for Enterprise Cloud Infrastructure.

Companies face security threats such as brute-force logins, suspicious IPs, traffic spikes and service failures. Manual detection and response is slow, so threats spread before anyone reacts.

## 2. Solution Overview
SentinelCloud AI is a **safe, simulated** cybersecurity incident-response dashboard built with Flask, HTML/CSS and JavaScript. It shows how a company can detect threats, calculate risk, respond automatically, notify the company, recommend actions, and explain incidents through an AI-style assistant.

It does **not** access real servers, accounts, locations or IP addresses. All events are stored in memory only, so restarting the app resets the demo data.

## 3. Key Features
- Administrator login
- Security overview dashboard with server-health cards
- Threat simulation buttons: normal activity, brute-force login, suspicious IP, traffic spike, high CPU, low disk space, service downtime
- Incident table and incident timeline
- Risk-score graph of recent events
- Line-by-line event-processing flow
- AI Security Advisor and company notifications
- **ShieldBot**, a rule-based security chatbot (no external AI service)
- **Login Threat Simulation panel** (username, password attempt, location)
- Reset button and light/dark theme

## 4. Workflow
`Event detected → Risk score assigned → Automated simulated response → Company notification → Recommended actions → ShieldBot explanation`

| Risk level | Simulated response |
|---|---|
| Low | Logged |
| Medium | Monitored |
| High | Isolated or escalated |

### Login Threat Simulation
| Rule | Behaviour |
|---|---|
| First location for a username | Becomes the known location |
| Different location, same username | Unfamiliar-location incident and monitoring alert |
| Distinct password attempts 1 to 5 | Recorded, no brute-force alert |
| 6th distinct password attempt | High-risk "Repeated failed login attempt", simulated temporary account lock, notification, recommendations, graph and timeline entry, ShieldBot explanation |

Only **different** passwords are counted. Passwords are never stored; only a non-readable one-way fingerprint is kept in memory.

## 5. Tech Stack
| Layer | Technology |
|---|---|
| Backend | Python, Flask |
| Frontend | HTML, CSS, JavaScript |
| Storage | In-memory only (no database) |
| Assistant | Rule-based ShieldBot |

## 6. Quick Start Guide
```bash
# 1. Clone the repository
git clone <your-repo-url>
cd security-app

# 2. Create and activate a virtual environment
python -m venv .venv
.venv\Scripts\activate

# 3. Install dependencies
pip install flask

# 4. Run the app
python app.py
```
Open `http://127.0.0.1:5000` and log in with the administrator account: `[admin username / password]`.

**Demo script (Login Threat Simulation)**
1. Enter username `alex`, location `Kochi, India` and a first test password.
2. Submit five different passwords. They are recorded with no alert.
3. Enter the same username with `Delhi, India` to show unfamiliar-location detection.
4. Submit the 6th different password to show the High-risk brute-force alert and simulated account lock.

## 7. Output Screenshots
![Output Screenshot](docs/output.png)

The dashboard shows the incident table, risk graph, timeline, notifications and ShieldBot responding to a High-risk "Repeated failed login attempt" incident for `alex`.

## 8. Future Scope
- Connect to real cloud logs and monitoring APIs (AWS, Azure, GCP)
- Add a real ML model for anomaly detection and risk scoring
- Replace the rule-based ShieldBot with a secure LLM-powered assistant
- Persistent database and audit trail
- Real notifications (email, SMS, Slack) and MFA integration
- Real IP geolocation and threat-intelligence feeds

## 9. Team Contributions
| Member Name | Contribution |
|-------------|--------------|
| [ADITHYAN S,AIVIN VIJU] | [THREAT DETECTION] |
| [BLESSY SHIBU] | [AUTOMATED RESPONSE] |
| [BLESSY BINU GEORGE] | [REAL TIME DASHBOARD] |

## 10. Tools Used
| Tool / Platform | Purpose / Why Used |
|-----------------|--------------------|
| Python and Flask | Backend, simulation engine and API routes |
| HTML, CSS, JavaScript | Dashboard UI, graph and login simulation panel |
| VS Code and Git/GitHub | Development and version control |
| [AI Tool, if used] | [How and why AI was used] |