<p align="center">
  <img src="docs/images/logo.svg" alt="Fleet CIS logo" width="120" height="120">
</p>

<h1 align="center">Fleet CIS Compliance Dashboard</h1>

<p align="center">
  <strong>Real-time CIS intelligence for Fleet endpoints</strong><br>
  Turn CIS Benchmark results into ATT&amp;CK risk, D3FEND coverage, and executive action.
</p>

<p align="center">
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License: MIT"></a>
  <a href="https://www.docker.com/"><img src="https://img.shields.io/badge/Docker-Compose-2496ED?logo=docker&logoColor=white" alt="Docker"></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.11-3776AB?logo=python&logoColor=white" alt="Python 3.11"></a>
  <a href="https://www.postgresql.org/"><img src="https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white" alt="PostgreSQL 16"></a>
  <img src="https://img.shields.io/badge/CIS-Controls%20v8.1-E53935" alt="CIS Controls v8.1">
  <img src="https://img.shields.io/badge/MITRE-ATT%26CK%20%2B%20D3FEND-B71C1C" alt="MITRE ATT&CK + D3FEND">
</p>

<p align="center">
  <a href="#platform-tour">Platform tour</a> ·
  <a href="#features">Features</a> ·
  <a href="#quick-start">Quick start</a> ·
  <a href="#architecture">Architecture</a> ·
  <a href="#configuration">Configuration</a>
</p>

---

## Why Fleet CIS?

Checkbox compliance is not security. Fleet already runs CIS policies across your fleet — this dashboard answers the harder questions:

| Question | Answer |
|----------|--------|
| **How exposed are we?** | Pass rate, risk level, open failures, fully-compliant devices |
| **What should we fix first?** | Top violations ranked by host impact |
| **What can adversaries exploit?** | Failed CIS controls mapped to MITRE ATT&CK techniques |
| **What defenses cover the gap?** | Interactive D3FEND heatmap and architecture view |
| **What do executives need?** | Strategy gauges, security debt, and priority actions |

Built for auditors, SOC teams, security engineers, and leadership — one source of truth, refreshed on a schedule from your Fleet instance.

---

## Platform tour

Animated walkthrough of every major surface:

<p align="center">
  <img src="docs/images/demo-tour.gif" alt="Fleet CIS platform tour — Summary, Architecture, Audit, Strategy, Settings" width="720">
</p>

<table>
  <tr>
    <td align="center" width="50%">
      <img src="docs/images/01-summary.png" alt="Security Posture Summary" width="100%"><br>
      <sub><b>Summary</b> — KPIs, heat map, top violations</sub>
    </td>
    <td align="center" width="50%">
      <img src="docs/images/02-architecture.png" alt="Security Architecture" width="100%"><br>
      <sub><b>Architecture</b> — gauge + ATT&amp;CK matrix</sub>
    </td>
  </tr>
  <tr>
    <td align="center" width="50%">
      <img src="docs/images/03-audit.png" alt="Compliance Audit" width="100%"><br>
      <sub><b>Audit</b> — failed policies, remediation, SQL</sub>
    </td>
    <td align="center" width="50%">
      <img src="docs/images/04-strategy.png" alt="Executive Strategy" width="100%"><br>
      <sub><b>Strategy</b> — debt, roadmap, priorities</sub>
    </td>
  </tr>
</table>

---

## Who this is for

| Audience | What you get |
|----------|----------------|
| **IT Auditors** | Compliance percentages, failed policy lists, remediation text for evidence packs |
| **Security teams** | ATT&CK mapping, D3FEND countermeasures, heat maps, risk prioritization |
| **Executives** | Scores, trends, security debt, and clear priority actions |
| **SOC analysts** | Live endpoint gaps, host impact, and filterable fleet/platform/label views |

---

## Features

### Dashboard views

| View | Purpose |
|------|---------|
| **Summary** | Pass rate, risk level, device counts, heat map, top violations |
| **Security Architecture** | Compliance gauge + MITRE ATT&CK matrix |
| **Compliance Audit** | Failed policies with remediation and SQL |
| **Executive Strategy** | Roadmap, debt, leaderboard, priorities |
| **Settings** | Risk/impact/effort/framework configuration |

### Framework integrations

- **CIS Controls v8.1** — base benchmark results from Fleet
- **MITRE ATT&CK** — maps failed controls to adversary techniques
- **D3FEND** — surfaces defensive techniques tied to gaps

### Filtering

Filter any view by **Fleet / team**, **platform** (darwin, windows, ubuntu), **labels**, and **OS version**.

### Risk level logic

| Condition | Risk level |
|-----------|------------|
| No hosts enrolled | UNAVAILABLE |
| No policy results (mapping not possible) | HIGH |
| Compliance &lt; 50% | CRITICAL |
| Compliance 50–70% | HIGH |
| Compliance 70–85% | MEDIUM |
| Compliance &gt; 85% | LOW |

---

## Quick start

### Prerequisites

- Docker and Docker Compose
- A running [Fleet](https://fleetdm.com/) instance with CIS policies deployed
- Fleet API token with **read** access

### Supported platforms

CIS Controls v8.1 benchmarks from [fleet_policies](https://github.com/karmine05/fleet_policies):

| Platform | Benchmark path |
|----------|----------------|
| **macOS 26.x** | [CIS-8.1/macOS26](https://github.com/karmine05/fleet_policies/tree/main/CIS-8.1/macOS26) |
| **Windows 11** | [CIS-8.1/win11/intune](https://github.com/karmine05/fleet_policies/tree/main/CIS-8.1/win11/intune) |
| **Ubuntu 24.04** | [CIS-8.1/ubuntu24](https://github.com/karmine05/fleet_policies/blob/main/CIS-8.1/ubuntu24/24.04) |

### Setup

1. **Configure Fleet credentials**

   ```bash
   cp .env.example .env
   ```

   Edit `.env`:

   ```env
   FLEET_URL=https://your-fleet-instance.com
   FLEET_API_TOKEN=your-fleet-api-token
   DASHBOARD_API_TOKEN=a-long-random-write-token
   ```

2. **Start the stack**

   ```bash
   docker-compose up -d --build
   ```

3. **Open the dashboard**

   **[http://localhost:8082](http://localhost:8082)**

   > Host port **8082** is used by default (avoids clashes with services on 8081). Override in `docker-compose.yml` if needed.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                 Nginx (host :8082 → :80)                    │
│              Serves UI + reverse-proxies /api               │
└─────────────────────────┬───────────────────────────────────┘
                          │
          ┌───────────────┴───────────────┐
          │                               │
    ┌─────▼─────┐                  ┌────▼────┐
    │  Backend  │                  │  Sync   │
    │  Flask    │◄─────────────────│ Daemon  │
    └─────┬─────┘                  └────┬────┘
          │                             │
    ┌─────┴─────┐                       │
    │           │                       │
┌───▼───┐   ┌──▼────┐            ┌──────▼──────┐
│  DB   │   │ Redis │            │ Fleet API   │
│Postgres│   │ Cache │            │ (CIS data)  │
└───────┘   └───────┘            └─────────────┘
```

| Component | Technology | Role |
|-----------|------------|------|
| Frontend | Vanilla JS + Chart.js | Interactive multi-page UI |
| Backend | Flask + Gunicorn | REST API |
| Sync | Python daemon | Pulls Fleet policy/host results |
| Database | PostgreSQL 16 | Persistent storage |
| Cache | Redis 7 | API response caching |
| Edge | Nginx | Static UI + reverse proxy |

---

## Configuration

### Environment variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FLEET_URL` | Fleet instance URL | **Required** |
| `FLEET_API_TOKEN` | Fleet API token | **Required** |
| `FLEET_SSL_VERIFY` | Verify Fleet TLS certs | `true` |
| `DASHBOARD_API_TOKEN` | Bearer token for Settings writes (`PUT /api/config`) | Required to save settings |
| `DATABASE_URL` | PostgreSQL connection | `postgresql://postgres:postgres@db:5432/fleet_cis` |
| `REDIS_URL` | Redis connection | `redis://redis:6379/0` |
| `ALLOWED_ORIGINS` | CORS allowlist | `http://localhost:8081,http://localhost:8082` |
| `SYNC_INTERVAL_MINUTES` | Sync frequency | `15` |

### In-app settings

From **Settings** you can adjust:

- Risk exposure multiplier
- Impact thresholds (high / medium)
- Effort keywords for remediation classification
- Framework multipliers for scoring

---

## Data sync

The sync daemon runs on the configured interval (default **15 minutes**).

```bash
# Follow sync logs
docker-compose logs -f sync

# Force an immediate sync
docker-compose exec sync python backend/sync_fleet_data.py
```

---

## Security

- **Non-root containers** — backend runs as unprivileged `appuser`
- **Network isolation** — services talk on an internal Compose network
- **CORS** — API restricted to `ALLOWED_ORIGINS`
- **Write auth** — `PUT /api/config` requires `Authorization: Bearer $DASHBOARD_API_TOKEN` (fail-closed if unset)
- **TLS to Fleet** — `FLEET_SSL_VERIFY` defaults to `true` (set `false` only for lab self-signed certs)
- **No secrets in images** — credentials via environment / `.env` only

---

## Troubleshooting

### No data showing up

1. Confirm `FLEET_URL` and `FLEET_API_TOKEN` in `.env`
2. Check services: `docker-compose ps`
3. Inspect sync: `docker-compose logs sync`

### Database connection errors

1. Wait until Postgres is healthy: `docker-compose ps`
2. Logs: `docker-compose logs db`

### Frontend not loading

1. Confirm nginx: `docker-compose ps`
2. Logs: `docker-compose logs nginx`
3. Open **http://localhost:8082** (not 8081 unless you remapped ports)

---

## Project layout

```
fleet-cis-dashboard/
├── backend/          # Flask API, sync, policy catalog, DB
├── frontend/         # UI (logo, app, styles)
├── docs/images/      # README screenshots, logo, demo GIF
├── scripts/          # Mapping / catalog maintenance tools
├── tests/            # Mapping rule tests
├── docker-compose.yml
└── README.md
```

---

## License

MIT License. See [LICENSE](LICENSE) for details.

---

<p align="center">
  <img src="docs/images/logo.svg" alt="Fleet CIS" width="48" height="48"><br>
  <sub>Fleet CIS — Compliance Intelligence</sub>
</p>
