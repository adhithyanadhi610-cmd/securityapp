import copy
import hashlib
import os
from datetime import datetime
from functools import wraps

from flask import Flask, jsonify, redirect, render_template, request, session, url_for

app = Flask(__name__)

app.config["SECRET_KEY"] = os.environ.get(
    "SENTINEL_SECRET_KEY",
    "demo-only-change-this-secret-key",
)

ADMIN_USERNAME = os.environ.get("SENTINEL_ADMIN_USERNAME", "sentinel")
ADMIN_PASSWORD = os.environ.get("SENTINEL_ADMIN_PASSWORD", "Sentinel123!")

DEFAULT_SERVERS = [
    {
        "name": "Gateway 01",
        "role": "Public API Gateway",
        "status": "Healthy",
        "metric": "Latency 42 ms",
    },
    {
        "name": "Auth 01",
        "role": "Authentication Service",
        "status": "Healthy",
        "metric": "CPU 31%",
    },
    {
        "name": "Database 01",
        "role": "Primary Database",
        "status": "Healthy",
        "metric": "Disk free 64%",
    },
]

servers = []
incidents = []
notifications = []
incident_counter = 1000
notification_counter = 0


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if not session.get("admin_logged_in"):
            if request.path.startswith("/api/"):
                return jsonify({"message": "Admin login required."}), 401
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


def timestamp():
    return datetime.now().strftime("%d %b %Y, %H:%M:%S")


def update_server(name, status, metric):
    for server in servers:
        if server["name"] == name:
            server["status"] = status
            server["metric"] = metric
            return


def add_incident(event_type, server, source_ip, risk, score, response, status, message):
    global incident_counter

    incident_counter += 1
    incidents.append(
        {
            "id": f"INC-{incident_counter}",
            "timestamp": timestamp(),
            "event_type": event_type,
            "server": server,
            "source_ip": source_ip,
            "risk": risk,
            "score": score,
            "response": response,
            "status": status,
            "message": message,
        }
    )


def recommendations_for(event_type):
    event_type = event_type.lower()

    if "failed login" in event_type:
        return [
            "Enable multi-factor authentication for administrator accounts.",
            "Apply login rate limits and temporary account lockouts.",
            "Review authentication logs for other affected accounts.",
        ]

    if "suspicious ip" in event_type:
        return [
            "Keep the suspicious source isolated.",
            "Check threat-intelligence data before allowing access.",
            "Review firewall and WAF rules for similar traffic.",
        ]

    if "traffic spike" in event_type:
        return [
            "Enable traffic rate limiting and DDoS protection.",
            "Review API and firewall logs for abnormal requests.",
            "Scale protected services only after traffic validation.",
        ]

    if "cpu" in event_type:
        return [
            "Review unusual processes and recent deployments.",
            "Scale the affected service if the load is legitimate.",
            "Set CPU alerts before the critical threshold is reached.",
        ]

    if "disk" in event_type:
        return [
            "Remove temporary files and archive old logs safely.",
            "Increase monitored storage capacity.",
            "Configure early disk-space alerts and backup verification.",
        ]

    if "downtime" in event_type:
        return [
            "Check service health, dependencies, and recent changes.",
            "Use an approved failover or recovery procedure.",
            "Review the root cause before restoring normal traffic.",
        ]

    return [
        "Continue monitoring this server for related activity.",
        "Review recent access and configuration changes.",
        "Keep the incident record for the security audit trail.",
    ]


def create_company_notification(new_events):
    global notification_counter

    if not new_events:
        return None

    highest_event = max(new_events, key=lambda event: event["score"])

    # 20/100 is the company's alert threshold.
    if highest_event["score"] < 20:
        return None

    notification_counter += 1
    event_types = sorted({event["event_type"] for event in new_events})

    notification = {
        "id": f"ALERT-{notification_counter:03d}",
        "timestamp": timestamp(),
        "risk": highest_event["risk"],
        "risk_score": highest_event["score"],
        "server": highest_event["server"],
        "subject": f"{highest_event['risk']} security alert: {highest_event['event_type']}",
        "details": (
            f"{len(new_events)} related simulated event(s) detected. "
            f"Risk score: {highest_event['score']}/100."
        ),
        "response": highest_event["response"],
        "status": "Company notification generated (simulated)",
        "recommendations": recommendations_for(highest_event["event_type"]),
        "event_types": event_types,
    }

    notifications.append(notification)
    return notification


def reset_demo_data():
    global servers, incidents, notifications, incident_counter, notification_counter, simulated_login_profiles

    servers = copy.deepcopy(DEFAULT_SERVERS)
    incidents = []
    notifications = []
    incident_counter = 1000
    notification_counter = 0
    simulated_login_profiles = {}


def create_scenario(scenario):
    if scenario == "normal":
        add_incident(
            "Normal server activity",
            "gateway-01",
            "10.10.2.18",
            "Low",
            8,
            "Event logged — no response required",
            "Logged",
            "Normal API request completed successfully.",
        )
        return 1

    if scenario == "brute_force":
        risk_levels = ["Low", "Low", "Low", "Medium", "Medium", "High"]

        for number, risk in enumerate(risk_levels, start=1):
            if risk == "High":
                response = "Source isolated (simulated)"
                status = "Isolated"
            elif risk == "Medium":
                response = "Monitoring enabled and alert flagged"
                status = "Monitoring"
            else:
                response = "Event logged — no response required"
                status = "Logged"

            add_incident(
                "Repeated failed login attempt",
                "auth-01",
                "203.0.113.44",
                risk,
                number * 15,
                response,
                status,
                f"Failed login attempt {number} from a simulated source.",
            )

        update_server("Auth 01", "Critical", "Authentication attack detected")
        return 6

    if scenario == "suspicious_ip":
        add_incident(
            "Suspicious IP detected",
            "gateway-01",
            "198.51.100.77",
            "High",
            88,
            "Source isolated (simulated)",
            "Isolated",
            "Known suspicious source detected in simulated traffic.",
        )
        update_server("Gateway 01", "Critical", "Suspicious source isolated")
        return 1

    if scenario == "traffic_spike":
        add_incident(
            "Unusual traffic spike",
            "gateway-01",
            "198.51.100.30",
            "Medium",
            64,
            "Monitoring enabled and alert flagged",
            "Monitoring",
            "Traffic exceeded the simulated monitoring threshold.",
        )
        update_server("Gateway 01", "Warning", "Traffic 890 Mbps")
        return 1

    if scenario == "cpu_high":
        add_incident(
            "High CPU utilization",
            "auth-01",
            "internal-monitor",
            "High",
            93,
            "Critical alert raised for operations team",
            "Escalated",
            "CPU utilization exceeded the simulated critical threshold.",
        )
        update_server("Auth 01", "Critical", "CPU 96%")
        return 1

    if scenario == "disk_low":
        add_incident(
            "Low disk space",
            "database-01",
            "internal-monitor",
            "High",
            91,
            "Critical alert raised for operations team",
            "Escalated",
            "Available database storage is below the simulated safe threshold.",
        )
        update_server("Database 01", "Critical", "Disk free 7%")
        return 1

    if scenario == "service_down":
        add_incident(
            "Service downtime detected",
            "gateway-01",
            "internal-monitor",
            "High",
            95,
            "Critical alert raised for operations team",
            "Escalated",
            "Gateway health check failed in the simulation.",
        )
        update_server("Gateway 01", "Critical", "Health check failed")
        return 1

    return 0


@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("admin_logged_in"):
        return redirect(url_for("dashboard"))

    error = None

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session.clear()
            session["admin_logged_in"] = True
            session["admin_username"] = ADMIN_USERNAME
            return redirect(url_for("dashboard"))

        error = "Invalid username or password."

    return render_template("login.html", error=error)


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
@login_required
def dashboard():
    return render_template("index.html", admin_username=session.get("admin_username"))


@app.get("/api/dashboard")
@login_required
def api_dashboard():
    return jsonify(
        {
            "stats": {
                "total_events": len(incidents),
                "high_risk": sum(item["risk"] == "High" for item in incidents),
                "monitoring": sum(item["status"] == "Monitoring" for item in incidents),
                "isolated": sum(item["status"] == "Isolated" for item in incidents),
            },
            "servers": servers,
            "incidents": list(reversed(incidents)),
            "notifications": list(reversed(notifications)),
        }
    )


@app.post("/api/simulate/<scenario>")
@login_required
def simulate(scenario):
    event_count_before = len(incidents)
    processed = create_scenario(scenario)

    if processed == 0:
        return jsonify({"message": "Unknown simulation scenario."}), 404

    new_events = incidents[event_count_before:]
    notification = create_company_notification(new_events)

    message = f"{processed} simulated event(s) processed."
    if notification:
        message += f" {notification['id']} company alert generated."

    return jsonify({"message": message, "notification": notification})
@app.post("/api/login-threat")
@login_required
def simulate_login_threat():
    payload = request.get_json(silent=True) or {}

    username = payload.get("username", "").strip()
    password = payload.get("password", "")
    location = payload.get("location", "").strip()

    if not username or not password or not location:
        return jsonify({
            "message": "Enter a username, password, and location."
        }), 400

    username_key = username.lower()

    profile = simulated_login_profiles.setdefault(
        username_key,
        {
            "password_hashes": set(),
            "known_locations": set(),
            "brute_force_alerted": False,
        },
    )

    password_hash = hashlib.sha256(
        password.encode("utf-8")
    ).hexdigest()

    new_events = []
    messages = []

    if password_hash not in profile["password_hashes"]:
        profile["password_hashes"].add(password_hash)
        is_new_password = True
    else:
        is_new_password = False

    attempt_count = len(profile["password_hashes"])

    if not profile["known_locations"]:
        profile["known_locations"].add(location.lower())
        messages.append(
            f"Known location set to {location} for {username}."
        )

    elif location.lower() not in profile["known_locations"]:
        profile["known_locations"].add(location.lower())

        add_incident(
            "Login from unfamiliar location",
            "auth-01",
            location,
            "Medium",
            72,
            "Additional verification requested (simulated)",
            "Monitoring",
            f"Simulated login for {username} came from a new location: {location}.",
        )

        new_events.append(incidents[-1])

        messages.append(
            f"Unfamiliar location detected: {location}."
        )

    if attempt_count > 5 and not profile["brute_force_alerted"]:
        profile["brute_force_alerted"] = True

        add_incident(
            "Repeated failed login attempt",
            "auth-01",
            username,
            "High",
            90,
            "Account temporarily locked (simulated)",
            "Isolated",
            f"More than five distinct password attempts were entered for {username}.",
        )

        new_events.append(incidents[-1])

        update_server(
            "Auth 01",
            "Critical",
            "Brute-force threshold exceeded"
        )

        messages.append(
            "Brute-force threshold exceeded — High-risk alert generated."
        )

    elif is_new_password:
        messages.append(
            f"Distinct password attempt {attempt_count}/5 recorded. "
            "A High-risk alert triggers on attempt 6."
        )

    else:
        messages.append(
            "This password was already used, so the count did not increase."
        )

    notification = create_company_notification(new_events)

    if notification:
        messages.append(
            f"{notification['id']} company notification generated."
        )

    return jsonify({
        "message": " ".join(messages),
        "attempt_count": attempt_count,
        "notification": notification,
    })
@app.post("/api/shieldbot")
@login_required
def shieldbot():
    payload = request.get_json(silent=True) or {}
    question = payload.get("question", "").strip().lower()

    if not question:
        return jsonify({"answer": "Please ask ShieldBot a security question."}), 400

    latest_incident = incidents[-1] if incidents else None
    latest_notification = notifications[-1] if notifications else None

    if (
        "graph" in question
        or "analyse" in question
        or "analyze" in question
        or "risk trend" in question
    ):
        if not incidents:
            answer = "The risk graph has no events yet. Run a simulation first."
        else:
            total = len(incidents)
            low_count = sum(item["risk"] == "Low" for item in incidents)
            medium_count = sum(item["risk"] == "Medium" for item in incidents)
            high_count = sum(item["risk"] == "High" for item in incidents)
            average_score = round(
                sum(item["score"] for item in incidents) / total
            )
            highest_event = max(incidents, key=lambda item: item["score"])

            if high_count:
                trend = "High-risk events are present, so the environment needs attention."
            elif medium_count:
                trend = "Medium-risk events are present, so the environment should be monitored."
            else:
                trend = "All detected events are currently Low risk."

            answer = (
                f"Risk graph analysis: {total} simulated event(s) detected — "
                f"{low_count} Low, {medium_count} Medium, and {high_count} High risk. "
                f"Average risk score: {average_score}/100. "
                f"Highest event: {highest_event['event_type']} on "
                f"{highest_event['server']} with score {highest_event['score']}/100. "
                f"{trend}"
            )

    elif "latest" in question or "recent" in question:
        if not latest_incident:
            answer = "There are no simulated incidents yet. Run a simulation first."
        else:
            answer = (
                f"The latest incident is {latest_incident['event_type']} on "
                f"{latest_incident['server']}. It is {latest_incident['risk']} risk "
                f"with score {latest_incident['score']}/100. "
                f"Automated response: {latest_incident['response']}."
            )

    elif "brute" in question or "login" in question:
        answer = (
            "Repeated failed logins can indicate a brute-force attack. "
            "Enable MFA, apply login rate limits, use temporary account lockouts, "
            "and review authentication logs."
        )

    elif "cpu" in question:
        answer = (
            "High CPU can indicate unexpected load or suspicious activity. "
            "Review active processes and recent deployments, validate traffic, "
            "and configure CPU threshold alerts."
        )

    elif "ip" in question or "suspicious" in question:
        answer = (
            "A suspicious IP should be isolated in this simulation. In production, "
            "check approved threat-intelligence data and review firewall and WAF rules."
        )

    elif "disk" in question:
        answer = (
            "Low disk space can disrupt databases and logging. Archive old logs safely, "
            "increase capacity, verify backups, and configure early storage alerts."
        )

    elif "service" in question or "down" in question:
        answer = (
            "Service downtime requires health-check and dependency review. Follow an "
            "approved recovery procedure, then investigate the root cause."
        )

    elif "recommend" in question or "security" in question:
        if latest_notification:
            actions = "; ".join(latest_notification["recommendations"])
            answer = f"ShieldBot recommends: {actions}"
        else:
            answer = (
                "ShieldBot recommends MFA, least-privilege access, rate limiting, "
                "server-health alerts, regular backups, and log monitoring."
            )

    elif "alert" in question or "notification" in question:
        if latest_notification:
            answer = (
                f"Latest company alert: {latest_notification['id']} — "
                f"{latest_notification['subject']}. "
                f"Risk score: {latest_notification['risk_score']}/100."
            )
        else:
            answer = "No company notification has been generated yet."

    else:
        answer = (
            "I am ShieldBot, the SentinelCloud simulated security assistant. "
            "Ask about the graph, latest incident, alerts, brute-force logins, "
            "suspicious IPs, CPU, disk space, service downtime, or recommendations."
        )

    return jsonify({"answer": answer})
@app.post("/api/reset")
@login_required
def reset():
    reset_demo_data()
    return jsonify({"message": "Demo data reset."})


@app.get("/health")
def health():
    return jsonify({"status": "healthy", "mode": "simulation"})


reset_demo_data()

if __name__ == "__main__":
    app.run(debug=True)