# GrooveHub

> **The MCP Server Registry with Automated Security Scoring**
>
> Every MCP server scored 0-100 with [GrooveGuard](https://github.com/GrooveXlabs/grooveguard) — because trust shouldn't be blind.

---

## Why GrooveHub?

The Model Context Protocol (MCP) ecosystem is exploding. Thousands of servers connect LLMs to databases, APIs, filesystems, and critical infrastructure. But **not a single registry scores them for security**.

| Platform | Lists Servers | Scores Security |
|----------|--------------|-----------------|
| Cline MCP Marketplace | ✅ | ❌ |
| xPack Registry | ✅ | ❌ |
| Signet Registry | ✅ | ❌ |
| Agent Discover | ✅ | ❌ |
| **GrooveHub** | ✅ | **✅** |

GrooveHub closes this gap. Register any MCP server by GitHub URL, and GrooveGuard automatically audits its code for secrets, CVEs, unsafe permissions, and supply-chain risks — then assigns a **0-100 score with a letter grade (A-F)**.

---

## Quick Start

```bash
# Install
pip install groovehub

# Register a server
groovehub register https://github.com/modelcontextprotocol/servers

# Scan it
groovehub scan https://github.com/modelcontextprotocol/servers

# See the leaderboard
groovehub leaderboard

# Start the API
groovehub serve
```

---

## API

GrooveHub exposes a FastAPI REST API:

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/servers` | Register a server by GitHub URL |
| `GET`  | `/servers` | List registered servers |
| `GET`  | `/servers/{id}` | Get server details + latest scan |
| `POST` | `/servers/{id}/scan` | Trigger a security scan |
| `GET`  | `/servers/{id}/scans` | List all scans for a server |
| `GET`  | `/servers/{id}/mitre` | MITRE ATT&CK mapping |
| `GET`  | `/servers/{id}/sigma` | Generated Sigma detection rules |
| `GET`  | `/servers/{id}/atomic` | Generated atomic test scripts |
| `GET`  | `/servers/{id}/gap-report` | Purple team gap analysis |
| `GET`  | `/leaderboard` | Top servers by security score |

```bash
curl -X POST "http://127.0.0.1:8000/servers?repo_url=https://github.com/modelcontextprotocol/servers"
curl "http://127.0.0.1:8000/leaderboard"
curl "http://127.0.0.1:8000/servers/1/mitre"
curl "http://127.0.0.1:8000/servers/1/sigma"
curl "http://127.0.0.1:8000/servers/1/atomic"
curl "http://127.0.0.1:8000/servers/1/gap-report"
```

---

## PurpleForge — Auto-Generated Security Artifacts

Every scan automatically produces four artifacts via the PurpleForge engine:

1. **MITRE ATT&CK Mapping** — Each finding mapped to technique ID, tactic, and data sources
2. **Sigma Rules** — Platform-specific detection rules for your SIEM (Windows Event Logs)
3. **Atomic Tests** — Safe PowerShell scripts that simulate each attack vector for validation
4. **Gap Analysis Report** — Coverage matrix showing what's detected vs what's tested

Access via API or CLI:
```bash
# API
curl http://127.0.0.1:8000/servers/1/sigma
curl http://127.0.0.1:8000/servers/1/atomic

# CLI
groovehub artifacts 1 --type sigma
groovehub artifacts 1 --type all
```

---

## Scoring Algorithm

| Severity | Deduction |
|----------|-----------|
| CRITICAL | -20 |
| HIGH | -10 |
| MEDIUM | -5 |
| LOW | -2 |
| INFO | 0 |

| Bonus | +Points |
|-------|---------|
| Test suite present | +10 |
| LICENSE file | +5 |
| SECURITY.md | +5 |
| Lockfile present | +5 |
| CI/CD config | +5 |

**Score = max(0, min(100, 100 - deductions + bonuses))**

| Grade | Range | Label |
|-------|-------|-------|
| A | 90-100 | Excellent |
| B | 80-89 | Good |
| C | 70-79 | Fair |
| D | 60-69 | Poor |
| F | 0-59 | Critical |

---

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   GitHub    │────▶│  GrooveHub  │────▶│  SQLite DB  │
│   Repo URL  │     │   Registry  │     │             │
└─────────────┘     └──────┬──────┘     └─────────────┘
                           │
                           ▼
                    ┌─────────────┐
                    │ GrooveGuard │
                    │   Scanner   │
                    │  (AI + SAST)│
                    └──────┬──────┘
                           │
                           ▼
                    ┌─────────────┐
                    │  Score 0-100│
                    │  Grade A-F  │
                    └─────────────┘
```

---

## Development

```bash
git clone https://github.com/GrooveXlabs/groovehub.git
cd groovehub
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest -v
```

---

## Ecosystem

| Project | Description |
|---------|-------------|
| [grooveguard](https://github.com/GrooveXlabs/grooveguard) | AI-powered security scanner for MCP servers |
| **groovehub** | Registry + leaderboard for scored MCP servers |

---

## License

MIT — GrooveXlabs
