# 🛡 CTI Automation Platform v2.0

> Full-stack SOC CTI advisory automation for Managed Security Service Providers.  
> Python FastAPI · PostgreSQL + pgvector · Celery · Claude API · React

---

## What's New in v2

| Feature | Details |
|---|---|
| **Two-layer matching** | CPE exact match + `all-mpnet-base-v2` semantic similarity via pgvector |
| **RAG report generation** | Upload 20+ sample reports → Claude writes in your exact style |
| **Priority scoring** | CVSS + EPSS + KEV flag → composite 0–100 priority score per CVE |
| **EPSS enrichment** | first.org exploit probability pulled for every CVE |
| **9 RSS feeds** | BleepingComputer, TheHackersNews, SecurityWeek, PacketStorm, Exploit-DB, Rapid7, GitHub Security, Cisco advisories, Microsoft security |
| **WeasyPrint PDF** | HTML/CSS template → pixel-perfect branded PDF (no wkhtmltopdf) |
| **Celery workers** | All polling and report generation fully async + scheduled |

---

## Quick Start (Ubuntu VM + VS Code)

### Prerequisites
```bash
# Install Docker & Docker Compose
sudo apt update && sudo apt install -y docker.io docker-compose-v2
sudo usermod -aG docker $USER   # then log out and back in

# Install Node.js (for frontend dev)
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs
```

### 1. Clone and configure
```bash
git clone <your-repo> cti-platform
cd cti-platform
cp .env.example .env
# Edit .env — at minimum set ANTHROPIC_API_KEY
nano .env
```

### 2. Start everything
```bash
docker compose up -d
```

Services started:
| Service | URL |
|---|---|
| Frontend UI | http://localhost:5173 |
| Backend API | http://localhost:8000 |
| API Docs (Swagger) | http://localhost:8000/docs |

### 3. Upload your sample reports
Go to **Sample Reports** tab → Upload your 20+ handmade advisories (PDF or TXT).
These are indexed into PostgreSQL and used as style anchors by the AI report generator.

### 4. Add clients and assets
Go to **Clients & Assets** → Add clients → Add product names to each client's asset registry.
Assets are automatically embedded in the background (⊕ icon when ready).
Add CPE strings for exact matching on well-known products.

### 5. CVE feeds start automatically
Within 10 seconds of startup, the system polls CISA KEV and RSS feeds.
NVD poll runs every 6 hours. You can trigger manual polls from the Feed tab.

---

## Development Mode (without Docker)

```bash
# Terminal 1 — PostgreSQL + Redis via Docker
docker compose up postgres redis -d

# Terminal 2 — Backend
cd backend
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000

# Terminal 3 — Celery worker
cd backend
source venv/bin/activate
celery -A workers.celery_app worker --loglevel=info -Q cti_feeds,reports,default

# Terminal 4 — Celery beat (scheduler)
cd backend
source venv/bin/activate
celery -A workers.celery_app beat --loglevel=info

# Terminal 5 — Frontend
cd frontend
npm install && npm run dev
```

---

## Architecture

```
CVE Sources          Matching Engine           Report Pipeline
─────────────        ───────────────           ───────────────
NVD API 2.0    ──►  Layer 1: CPE exact  ──►   RAG query (PostgreSQL (RAG))
CISA KEV       ──►  Layer 2: Semantic   ──►   + 3 similar examples
8 RSS feeds    ──►  pgvector cosine     ──►   Claude API (few-shot)
Manual ingest  ──►  EPSS enrichment     ──►   JSON validation
                    Priority score      ──►   WeasyPrint PDF
                         │                         │
                         ▼                         ▼
                    Postgres DB              /generated_reports/
                    Alert created            Report saved to DB
                         │
                         ▼
                    Analyst queue
                    Approve → Generate
                    Reject → Archive
```

---

## Key Design Decisions

### Embedding model: all-mpnet-base-v2
- 420MB, runs on CPU, ~5ms per sentence
- Pre-downloaded in Docker image (no cold start)
- 768-dimensional embeddings stored in pgvector
- Excellent performance for short product name similarity

### Semantic match threshold: 0.55
Tuned for security product names. Adjust in `.env`:
- **0.65+** → fewer false positives, may miss paraphrased names
- **0.45** → broader matching, more alerts (review carefully)

### RAG few-shot with your own reports
Claude is prompted with 2–3 of your actual advisory reports as style examples.
The more examples you upload (aim for 20+), the better it matches your:
- Writing tone and vocabulary
- Section structure and paragraph style
- Level of technical detail
- Client-specific framing

### Priority score formula
```
priority = (CVSS × 4) + (EPSS × 40) + (is_kev ? 20 : 0) + severity_mod
         max=40          max=40        max=20                CRITICAL=0, HIGH=-5, MEDIUM=-15
```
Score 0–100. CRITICAL KEV CVE with EPSS=0.5 = 95/100.

---

## Adding Your Sample Reports

Supported formats: **PDF**, **TXT**, **Markdown**

For best RAG performance:
1. Upload at least 10 reports before going live
2. Cover a variety of severity levels (CRITICAL, HIGH, MEDIUM)
3. Cover different vulnerability types (RCE, auth bypass, SQLi, etc.)
4. The system chunks reports by section (Description, Impact, Remediation, etc.)
5. At generation time it retrieves the most similar sections by CVE type + severity

PDF text extraction uses `pdfplumber` (primary) with `PyPDF2` fallback.
If extraction fails, save the report as `.txt` and re-upload.

---

## API Reference

Full interactive docs at `/docs` (Swagger UI).

```
GET  /api/clients              List all clients
POST /api/clients              Create client {name, email, company}
PUT  /api/clients/:id/assets   Replace asset list [{asset_name, cpe_string?}]

GET  /api/cves                 List CVEs ?severity=&search=&is_kev=
POST /api/cves                 Manual ingest (triggers matching immediately)
POST /api/cves/poll/all        Trigger all feed polls

GET  /api/alerts               List alerts ?status=pending
PATCH /api/alerts/:id          {status: "approved"/"rejected", notes?}

GET  /api/reports              List reports
GET  /api/reports/:id/pdf      Download PDF
POST /api/reports/:id/send     Mark as sent
POST /api/reports/:id/regenerate  Re-run AI generation

POST /api/sample-reports/upload  Upload sample report (multipart)
GET  /api/system/health        Service health check
GET  /api/system/stats         Dashboard statistics
```

---

## Troubleshooting

**Embedding model slow on first request**
Pre-downloaded in Docker image. If running locally, it downloads once on first use.

**"No sample reports" warning**
Upload at least one sample report in the Sample Reports tab before approving alerts.
Reports will still generate (zero-shot) but quality is better with examples.

**NVD API rate limiting**
Get a free API key at https://nvd.nist.gov/developers/request-an-api-key
Set `NVD_API_KEY` in `.env` for 10x higher rate limit.

**WeasyPrint fonts**
If PDF fonts look wrong, ensure `fonts-liberation` is installed (handled in Dockerfile).

**Celery tasks not running**
Check worker logs: `docker compose logs worker -f`
Check Redis: `docker compose exec redis redis-cli ping`
