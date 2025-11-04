# Syslog Analysis Framework

This document contains a complete, self-contained prototype repository for a **Syslog Analysis Framework** targeted at the university-scale problem described. It includes code for collecting syslogs over the network, normalizing/parsing them, storing them (Elasticsearch production + SQLite demo fallback), analyzing/correlating events, alerting (email + Slack webhook), and a simple web dashboard (Flask) for visualization and investigation.

> **Note:** This is a prototype reference implementation you can run on a test network. For production at scale, follow the production recommendations below (Use rsyslog/syslog-ng + Kafka + OpenSearch/Elasticsearch cluster + Kibana/Carrot2/Graylog + proper security, ACLs, TLS, secrets manager, and alerting).

---

## Repository layout

```
syslog-analysis-framework/
├── docker-compose.yml
├── Dockerfile
├── README.md
├── requirements.txt
├── collector/
│   ├── main.py
│   ├── parser.py
│   ├── storage.py
│   ├── analyzer.py
│   └── alerting.py
├── webapp/
│   └── app.py
├── tests/
│   └── test_analyzer.py
└── sample_data/
    └── sample_syslogs.txt
```

---

## Quick summary of components

* **collector/main.py** — UDP/TCP syslog server (non-root ports) that receives raw syslog messages, timestamps them, dedupes briefly, sends to parser.
* **collector/parser.py** — Normalizes multiple common syslog formats (Linux auth, OpenSSH, Cisco/Juniper firewall logs) into a standard JSON schema.
* **collector/storage.py** — Stores normalized logs into Elasticsearch if available, otherwise an on-disk SQLite for demo.
* **collector/analyzer.py** — Rule-based correlation engine. Example detection: multiple failed SSH attempts from same IP followed by success => intrusion alert.
* **collector/alerting.py** — Sends alert via SMTP email and Slack webhook (configurable).
* **webapp/app.py** — Flask-based dashboard to search logs, view recent alerts, and simple charts.
* **docker-compose.yml** — Example to run Elasticsearch + the collector + webapp, for local testing.

---

## Run demo (local quickstart)

1. Install Python 3.9+ and Docker.
2. Create a virtualenv and install requirements:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

3. (Optional) Start Elasticsearch for production-like storage using docker-compose:

```bash
docker-compose up -d elasticsearch
```

4. Start the collector:

```bash
python collector/main.py --udp-port 5514 --tcp-port 5514
```

5. Start the web dashboard in another shell:

```bash
python webapp/app.py
```

6. Send sample syslogs (provided `sample_data/sample_syslogs.txt`), or configure a lab server to forward syslogs to this machine on UDP/TCP port 5514.

You can test by sending sample logs:

```bash
# Send sample logs via netcat
cat sample_data/sample_syslogs.txt | nc -u localhost 5514
```

7. Access the web dashboard at http://localhost:5000

---

## Running tests

```bash
pytest tests/
```

---

## Docker deployment

To run the entire stack using Docker:

```bash
docker-compose up --build
```

This will start:
- Elasticsearch on port 9200
- Collector on UDP/TCP port 5514
- Web dashboard on port 5000

---

## Configuration

### Environment variables for alerting

* `ALERT_EMAIL_FROM` - Email address to send alerts from (default: alert@example.com)
* `ALERT_EMAIL_TO` - Email address to send alerts to (default: itsec@example.com)
* `SMTP_HOST` - SMTP server host (default: localhost)
* `SMTP_PORT` - SMTP server port (default: 25)
* `SLACK_WEBHOOK` - Slack webhook URL for alerts (optional)

Example:

```bash
export ALERT_EMAIL_TO="security@mycompany.com"
export SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
python collector/main.py
```

---

## Production notes & improvements

This prototype is intentionally compact. For a production-grade deployment at a university you should consider:

* Use **rsyslog** or **syslog-ng** or native device forwarding to a message broker (Kafka, RabbitMQ) for reliable ingestion.
* Normalize logs with scalable stream processors (Logstash, Fluentd, Vector) or custom microservices with schema registries.
* Use **OpenSearch / Elasticsearch** cluster (with TLS, authentication) for storage and Kibana/OpenSearch Dashboards for visualization.
* Implement enrichment: GeoIP for source IPs, asset inventory to map hostnames -> owner -> criticality, and identity context from AD/LDAP.
* Use **SIEM**-style correlation: combine rules (Sigma rules), use anomaly detection (statistical baselining, ML models), and integrate with incident response (PagerDuty, ServiceNow).
* Harden alerting: rate limits, deduplication, enriched context, playbooks attached to alerts.
* Audit logging, role-based access, secure storage of secrets, and processing in private networks.

---

## License

MIT