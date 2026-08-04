# Fleet CIS Compliance Dashboard

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Docker](https://img.shields.io/badge/Docker-Enabled-blue?logo=docker)](https://www.docker.com/)
[![Python 3.11](https://img.shields.io/badge/Python-3.11-blue?logo=python)](https://www.python.org/)
[![PostgreSQL 16](https://img.shields.io/badge/PostgreSQL-16-blue?logo=postgresql)](https://www.postgresql.org/)

A real-time compliance dashboard that transforms CIS Benchmarks into actionable security intelligence. Built for security teams who need to move beyond checkbox compliance to understanding their actual defensive posture.

---

## Who This Is For

| Audience | What You'll Get |
|----------|----------------|
| **IT Auditors** | Clear compliance percentages, failed policy lists, and remediation steps for audit evidence |
| **Security Teams** | MITRE ATT&CK mapping, D3FEND defensive techniques, and risk prioritization |
| **Executives** | High-level compliance scores, trend analysis, and priority action items |
| **SOC Analysts** | Real-time visibility into endpoint security gaps and their business impact |

---

## Quick Start

### Prerequisites

- Docker and Docker Compose
- A running Fleet instance with CIS policies deployed
- Fleet API token with read access

### Supported Platforms

This dashboard integrates with CIS Controls v8.1 benchmarks from the [fleet_policies](https://github.com/karmine05/fleet_policies) repo:

- **macOS 26.x**: [CIS-8.1/macOS26](https://github.com/karmine05/fleet_policies/tree/main/CIS-8.1/macOS26)
- **Windows 11**: [CIS-8.1/win11/intune](https://github.com/karmine05/fleet_policies/tree/main/CIS-8.1/win11/intune)
- **Ubuntu 24.04**: [CIS-8.1/ubuntu24](https://github.com/karmine05/fleet_policies/blob/main/CIS-8.1/ubuntu24/24.04)

### Setup

1. **Configure Fleet credentials**

   Copy the example environment file and edit it with your Fleet credentials:

   ```bash
   cp .env.example .env
   ```

   Edit `.env` and set your values:

   ```
   FLEET_URL=https://your-fleet-instance.com
   FLEET_API_TOKEN=your-fleet-api-token
   ```

   Docker Compose automatically loads variables from `.env` when you run `docker-compose up`.

2. **Start the dashboard**

   ```bash
   docker-compose up -d --build
   ```

3. **Access the dashboard**

   Open [http://localhost:8081](http://localhost:8081)

---

## Features

### Dashboard Views

| View | Purpose |
|------|---------|
| **Summary** | Compliance percentage, device counts, risk level indicator |
| **Security Architecture** | Interactive D3FEND heatmap showing defensive coverage |
| **Compliance Audit** | Detailed list of failed policies with remediation steps |
| **Executive Strategy** | Fleet leaderboard, trends, and priority actions |

### Framework Integrations

- **CIS Controls v8.1**: Base benchmark framework
- **MITRE ATT&CK**: Maps failed controls to adversary techniques
- **D3FEND**: Recommends defensive countermeasures for gaps

### Risk Level Logic

The dashboard automatically handles edge cases:

| Condition | Risk Level |
|-----------|------------|
| No hosts enrolled | UNAVAAILABLE |
| No policy results (mapping not possible) | HIGH |
| Compliance < 50% | CRITICAL |
| Compliance 50-70% | HIGH |
| Compliance 70-85% | MEDIUM |
| Compliance > 85% | LOW |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Nginx (Port 8081)                      │
│                    Serves UI + Reverse Proxy                │
└─────────────────────────┬───────────────────────────────────┘
                          │
          ┌───────────────┴───────────────┐
          │                               │
    ┌─────▼─────┐                  ┌────▼────┐
    │  Backend  │                  │  Sync   │
    │ (Flask)   │◄─────────────────│ Daemon  │
    └─────┬─────┘                  └─────────┘
          │
    ┌─────┴─────┐
    │           │
┌───▼───┐   ┌──▼────┐
│  DB   │   │ Redis │
│(Postgres)│ (Cache)│
└───────┘   └───────┘
```

| Component | Technology | Purpose |
|-----------|------------|---------|
| Frontend | Vanilla JS + Chart.js | Interactive dashboard |
| Backend | Flask + Gunicorn | REST API |
| Sync | Python daemon | Fleet data synchronization |
| Database | PostgreSQL 16 | Persistent storage with time partitioning |
| Cache | Redis 7 | API response caching |
| Web Server | Nginx | UI serving + reverse proxy |

---

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FLEET_URL` | Your Fleet instance URL | Required |
| `FLEET_API_TOKEN` | Fleet API token | Required |
| `DATABASE_URL` | PostgreSQL connection | `postgresql://postgres:postgres@db:5432/fleet_cis` |
| `REDIS_URL` | Redis connection | `redis://redis:6379/0` |
| `ALLOWED_ORIGINS` | CORS allowed domains | `http://localhost:8081` |
| `SYNC_INTERVAL_MINUTES` | Sync frequency | `15` |

### Adjusting Thresholds

Access the Settings page to configure:

- **Risk Exposure Multiplier**: Weight for risk calculations
- **Impact Thresholds**: Define what counts as high/medium impact
- **Effort Keywords**: Classify remediation effort by query output
- **Framework Multipliers**: Customize scoring by compliance framework

---

## Data Sync

The sync daemon runs every 15 minutes automatically. View logs:

```bash
docker-compose logs -f sync
```

Force an immediate sync:

```bash
docker-compose exec sync python backend/sync_fleet_data.py
```

---

## Security

- **Non-root container**: Backend runs as unprivileged `appuser`
- **Network isolation**: Services communicate on internal network only
- **CORS protection**: API restricted to configured origins
- **No secrets in image**: All credentials passed via environment

---

## Troubleshooting

### No data showing up

1. Check Fleet credentials in `.env`
2. Verify sync daemon is running: `docker-compose ps`
3. Check sync logs: `docker-compose logs sync`

### Database connection errors

1. Wait for PostgreSQL to be healthy: `docker-compose ps`
2. Check logs: `docker-compose logs db`

### Frontend not loading

1. Verify nginx is running: `docker-compose ps`
2. Check logs: `docker-compose logs nginx`

---

## License

MIT License. See [LICENSE](LICENSE) for details.
