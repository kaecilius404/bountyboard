# BountyBoard 🎯

**Professional-grade automated bug bounty reconnaissance pipeline.**

BountyBoard doesn't just find subdomains. It finds *forgotten infrastructure* — the admin panel from 2019 still running on an old AWS IP, the dev server someone exposed "for 5 minutes" 8 months ago, the staging environment with production data, the load balancer with no auth. The machines paying $5000+ bounties because nobody knows they exist.

```
██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗
██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝
██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝
██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝
██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║
╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝
```

---

## Quick Start

```bash
# 1. Install
git clone https://github.com/yourhandle/bountyboard
cd bountyboard
pip install -e .
playwright install chromium

# 2. Configure
cp config.yaml config.yaml.example   # already provided
# Edit config.yaml — add your target domains

# 3. Scan
bountyboard scan

# 4. See results
bountyboard brief
```

**One-line quick scan of a single domain:**
```bash
bountyboard scan --domain example.com --quick
```

---

## Installation

### Requirements
- Python 3.11+
- pip

### Full Install

```bash
git clone https://github.com/yourhandle/bountyboard
cd bountyboard
pip install -e .
playwright install chromium  # For screenshots
```

### Minimal Install (no screenshots)

```bash
pip install -e .
# Skip playwright install — screenshots will be disabled automatically
```

---

## Configuration

Edit `config.yaml`:

```yaml
programs:
  - name: "Example Corp"
    platform: "hackerone"
    domains:
      - "example.com"
    wildcard_scope:
      - "*.example.com"
    exclude:
      - "*.cdn.example.com"   # Exclude CDN subdomains
    notes: "Full scope, no rate limit restrictions"

settings:
  threads: 100
  screenshot_enabled: true
  brute_force_enabled: false  # Only enable with explicit permission

  # Optional API keys (tool works without any of these)
  github_token: ""          # Increases GitHub rate limit 60→5000 req/hr
  shodan_api_key: ""
  securitytrails_api_key: ""
  chaos_api_key: ""

  # Notifications
  discord_webhook: ""       # Instant alerts for critical findings
  slack_webhook: ""
```

### Adding Programs Interactively

```bash
bountyboard add-program
```

---

## CLI Reference

```bash
# === SCANNING ===
bountyboard scan                          # Full scan, all programs
bountyboard scan --program "Target Corp"  # Scan one program
bountyboard scan --domain example.com     # Quick single-domain scan
bountyboard scan --quick                  # Fast mode (no screenshots/brute)
bountyboard scan --no-screenshots         # Skip screenshot capture

# Run individual phases
bountyboard discover                      # Phase 1: Discovery only
bountyboard probe                         # Phase 3: HTTP probing only
bountyboard exposures                     # Phase 6: Exposure scan only

bountyboard resume                        # Resume interrupted scan

# === REPORTING ===
bountyboard brief                         # Terminal morning brief
bountyboard brief --html                  # Generate + open HTML report

# === FINDINGS ===
bountyboard findings                      # All findings
bountyboard findings --severity critical  # Filter by severity
bountyboard findings --new               # Only unnotified findings
bountyboard findings --program "Target"  # Filter by program

# === EXPORT ===
bountyboard export --format json --output findings.json
bountyboard export --format csv  --output findings.csv
bountyboard export --format markdown --output REPORT.md

# === MANAGEMENT ===
bountyboard add-program                   # Interactive program wizard
bountyboard list-programs                 # Show all programs + stats
bountyboard stats                         # Overall statistics
bountyboard stats --program "Target"      # Per-program stats
bountyboard validate-config               # Validate config.yaml

# === CONTINUOUS ===
bountyboard watch --interval 6h           # Scan every 6 hours
bountyboard watch --interval 30m          # Scan every 30 minutes
```

---

## How It Works: 7 Phases

### Phase 1 — Subdomain Discovery

Queries **14+ sources simultaneously** with zero rate-limit hammering:

| Source | Type | Key Required | Notes |
|--------|------|-------------|-------|
| **crt.sh** | CT logs | No | Queries JSON API + HTML for full coverage |
| **AlienVault OTX** | Passive DNS | No | Historical records going back years |
| **Wayback Machine CDX** | Archive | No | 🔥 Finds subdomains from 2010+ |
| **CommonCrawl** | Web crawl | No | Cross-references 3 recent crawl indexes |
| **URLScan.io** | Scan index | No | Finds subdomains from phishing/malware campaigns |
| **CertSpotter** | CT logs | No | Different CT log source than crt.sh |
| **RapidDNS** | Passive DNS | No | Fast cross-reference |
| **BufferOver.run** | Passive DNS | No | FDNS + TLS data |
| **HackerTarget** | DNS recon | No | Quick subdomain lookup |
| **DNSDumpster** | DNS recon | No | Scrapes DNS data |
| **GitHub Code Search** | Code search | Optional† | Finds hardcoded subdomains in repos |
| **SecurityTrails** | Passive DNS | Optional | Historical data back to 2012 |
| **Chaos (ProjectDiscovery)** | Dataset | Optional | Curated bug bounty subdomain data |
| **Shodan** | Internet scan | Optional | SSL cert + org search |

†GitHub works without a token but has 60 req/hr limit. With a token: 5000/hr.

**Permutation Engine:** Takes discovered subdomains and generates mutations:
- `dev-api.example.com`, `api-dev.example.com`, `api.dev.example.com`
- `api-us.example.com`, `api-eu.example.com`, `api-us-east-1.example.com`
- `api1.example.com`, `api01.example.com`, `api-old.example.com`

All permutations are DNS-resolved — only real ones are kept.

### Phase 2 — DNS Resolution

- Resolves A, AAAA, CNAME, MX, NS, TXT records
- Detects wildcard DNS (skips unreliable results)
- Classifies IPs: Public, Internal (10.x, 172.x, 192.168.x), Loopback, CDN
- Classifies CNAMEs: Cloudflare, CloudFront, Akamai, Fastly, AWS, GCP, Azure...
- Groups subdomains by IP address for co-hosted service discovery

### Phase 3 — HTTP Probing

Probes **18 ports** on every resolved subdomain:

```
80, 443, 8008, 8080, 8443, 3000, 4443, 5000, 5443,
7001, 8000, 8888, 9000, 9090, 9200, 9443, 10000, 10443
```

Collects: status code, all headers, response size, timing, SSL cert details, redirect chain, page title, body preview. Accepts self-signed certs (marked as interesting findings themselves).

### Phase 4 — Technology Fingerprinting

Wappalyzer-style detection for **60+ technologies** including:
- CMS: WordPress, Drupal, Joomla, Magento, Shopify, Ghost, Strapi
- Frameworks: Laravel, Django, Flask, Rails, Express, Next.js, Spring Boot, ASP.NET
- Web servers: Apache, Nginx, IIS, Tomcat, JBoss, WebLogic, Jetty
- CDNs: Cloudflare, CloudFront, Akamai, Fastly, Varnish, Netlify, Vercel
- DevOps: Jenkins, GitLab, Grafana, Kibana, Prometheus, ArgoCD
- Auth: Keycloak, Auth0, Okta, Cognito, Firebase
- Databases: Elasticsearch, CouchDB, Redis, Solr

### Phase 5 — Screenshot Capture

Uses **Playwright** (headless Chromium) — not Selenium. Captures:
- Full-page screenshots at 1920×1080
- Thumbnails for quick review
- Waits for JavaScript rendering (3s after page load)
- Self-signed SSL accepted
- Console errors logged (bug hints)
- Network requests captured (API endpoint discovery)

### Phase 6 — Exposure Scanning

Checks **150+ paths and endpoints** across 4 severity levels:

**🚨 CRITICAL** (instant bounty potential):
- `.git/HEAD`, `.git/config` — full source code
- `.env`, `.env.production` — database passwords, API keys
- `backup.sql`, `dump.sql` — database dumps
- `id_rsa`, `id_ed25519` — SSH private keys
- `.aws/credentials` — AWS account access
- `/actuator/env`, `/actuator/heapdump` — Spring Boot secrets
- Jenkins Groovy console — RCE
- WordPress wp-config.php — DB credentials

**⚠️ HIGH** (likely bounty within 30 minutes):
- phpinfo() pages, Apache server-status
- Swagger/OpenAPI on non-public domains
- GraphQL introspection enabled
- Symfony profiler, Yii debug panel
- Elasticsearch without auth
- Docker registry catalog

**🔵 MEDIUM** (worth investigating):
- Expired SSL (forgotten servers)
- Internal IPs resolving publicly
- Default server pages
- Admin panels on non-standard ports

**⬜ LOW** (track for later):
- Technology stack disclosure
- Missing security headers
- Version information in responses

### Phase 7 — Prioritization

Scores every finding 0-100 based on:
- Severity weight
- Whether subdomain name suggests internal/forgotten service
- Non-standard port (more likely forgotten)
- Response size patterns

Generates actionable recommendations with specific manual testing steps.

---

## Morning Brief Output

After every scan:

```
╔═══════════════════════════════════════════════════════════════╗
║  BOUNTYBOARD MORNING BRIEF — 2024-01-15 08:00 UTC            ║
╚═══════════════════════════════════════════════════════════════╝

EXECUTIVE DASHBOARD
┌─────────────────┬─────────────────┬─────────────────┬─────────┐
│  4,821          │  312            │  14             │ 2h ago  │
│  Total Subs     │  Live Services  │  New This Run   │ Last Run│
└─────────────────┴─────────────────┴─────────────────┴─────────┘
┌──────────┬────────┬────────┬──────┐
│  3 CRIT  │ 7 HIGH │ 12 MED │ 8 LO │
└──────────┴────────┴────────┴──────┘

NEW SUBDOMAINS (14 discovered)
  dev-api-internal.target.com    [crt.sh]     2h ago
  backup.staging.target.com      [wayback]    2h ago
  admin-old.target.com           [permutation]2h ago
  ...

🚨 CRITICAL FINDINGS
  git_head         dev-api-internal.target.com    200  47B
  env_file         backup.staging.target.com      200  3.2KB
  actuator_env     internal-app.target.com:8080   200  124KB

RECOMMENDATIONS
  1. 🚨 CRITICAL: git_head @ https://dev-api-internal.target.com/.git/HEAD
     Manual test: git clone https://dev-api-internal.target.com/.git/ /tmp/repo
     — look for hardcoded credentials, internal hostnames, API keys.

  2. 🚨 CRITICAL: env_file @ https://backup.staging.target.com/.env
     curl https://backup.staging.target.com/.env
     — look for DB_PASSWORD, SECRET_KEY, AWS_ACCESS_KEY_ID...
```

The HTML report adds:
- Sortable, filterable findings tables
- Screenshot gallery with lightbox
- Technology distribution charts
- One-click `curl` reproduction commands
- JSON/CSV/Markdown export

---

## Database

Everything is stored in SQLite (`bountyboard.db`). Zero external dependencies — runs anywhere. Kill the scan mid-run and resume with `bountyboard resume`. All historical data preserved indefinitely.

**Differential scanning:** Every run shows only *new* findings since the last run. You don't wade through 5000 known subdomains — you see the 14 that appeared today.

---

## Free API Sources

BountyBoard works with **zero API keys**. These free sources are always active:

- **crt.sh** — Certificate Transparency logs (Comodo)
- **AlienVault OTX** — https://otx.alienvault.com
- **Wayback Machine CDX** — https://web.archive.org (Internet Archive)
- **CommonCrawl** — https://commoncrawl.org
- **URLScan.io** — https://urlscan.io
- **CertSpotter** — https://sslmate.com/certspotter (SSLMate)
- **RapidDNS** — https://rapiddns.io
- **BufferOver.run** — https://dns.bufferover.run
- **HackerTarget** — https://hackertarget.com
- **DNSDumpster** — https://dnsdumpster.com

---

## Legal & Ethics

**Is this legal?**

BountyBoard performs *passive reconnaissance* using public data sources. All built-in sources query data that is:
1. Publicly accessible (Certificate Transparency logs, web archives)
2. Specifically designed for security research
3. Already indexed and available without targeting the company directly

**Always:**
- ✅ Only target programs where you have explicit authorization (bug bounty scope)
- ✅ Respect scope restrictions in `config.yaml` exclusions
- ✅ Follow responsible disclosure practices
- ✅ Check program rules before submitting

**Never:**
- ❌ Enable DNS brute force (`brute_force_enabled: true`) without explicit permission
- ❌ Target systems outside your authorized scope
- ❌ Use found credentials — report them immediately
- ❌ Cause disruption (the tool is designed to be read-only and respectful)

The exposure scanning phase makes real HTTP requests to discovered URLs. This is standard vulnerability scanning and expected as part of bug bounty research, but ensure the target is in scope.

---

## Architecture

```
bountyboard/
├── bountyboard/
│   ├── cli.py              # Click CLI — all commands
│   ├── engine.py           # Orchestration — chains all phases
│   ├── config.py           # YAML config loading + validation
│   ├── database.py         # SQLite layer
│   │
│   ├── discovery/          # Phase 1: 14+ subdomain sources
│   │   ├── crtsh.py
│   │   ├── alienvault.py
│   │   ├── wayback.py      # The cheat code
│   │   ├── commoncrawl.py
│   │   ├── urlscan.py
│   │   ├── github_search.py
│   │   ├── rapiddns.py
│   │   ├── bufferover.py
│   │   ├── certspotter.py
│   │   ├── dnsdumpster.py
│   │   ├── hackertarget.py
│   │   ├── securitytrails.py   # Premium
│   │   ├── chaos.py            # Premium
│   │   ├── shodan.py           # Premium
│   │   ├── brute.py            # DNS brute force
│   │   └── permutations.py     # Mutation engine
│   │
│   ├── dns/                # Phase 2: Async DNS resolution
│   ├── probing/            # Phase 3: HTTP probing (18 ports)
│   ├── fingerprinting/     # Phase 4: Tech detection (60+ techs)
│   ├── screenshot/         # Phase 5: Playwright capture
│   ├── exposures/          # Phase 6: 150+ exposure checks
│   ├── prioritization/     # Phase 7: Scoring + recommendations
│   ├── reporting/          # Terminal + HTML + JSON/CSV/MD
│   └── notifications/      # Discord + Slack webhooks
```

Everything is async. Everything is concurrent. One phase failing never stops the pipeline.

---

## FAQ

**Q: How many subdomains can it handle?**  
A: Tested to 100,000+ subdomains. The `max_subdomains_per_domain` setting (default: 50,000) prevents runaway scans. Processing is batched — memory-efficient even for massive scopes.

**Q: How long does a full scan take?**  
A: For a typical target (100-500 subdomains): 15-30 minutes. Large scope (5000+ subdomains): 2-4 hours. Use `--quick` to skip screenshots and permutations for 10x faster scans.

**Q: Can I run multiple programs in parallel?**  
A: Programs run sequentially to respect rate limits. The pipeline is internally concurrent per phase.

**Q: What if a source API is down?**  
A: Graceful failure — it logs a warning and continues with all other sources. One bad API never kills the scan.

**Q: How do I integrate with other tools (Nuclei, etc.)?**  
A: The database contains all discovered URLs. Use `bountyboard export` to get a target list, or query the SQLite directly. Future: native Nuclei integration.

**Q: Does it find subdomain takeovers?**  
A: It discovers CNAME records pointing to cloud services (AWS, Azure, GCP, Heroku, etc.) and flags them. Full takeover confirmation requires manual testing.

---

## Contributing

PRs welcome. Priority areas:
- New discovery sources
- Additional exposure checks
- Better technology signatures
- Nuclei template generation from findings

---

## Credits

Built with ❤️ for the bug bounty community.

Free data sources that make this possible:
- Internet Archive / Wayback Machine
- Certificate Transparency (crt.sh, CertSpotter)
- CommonCrawl
- AlienVault OTX
- URLScan.io
- HackerTarget
- RapidDNS
- BufferOver.run
