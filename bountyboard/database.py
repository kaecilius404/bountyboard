"""SQLite database layer with async support and full schema management."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Generator, Optional


SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS programs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    platform TEXT DEFAULT 'private',
    root_domains TEXT DEFAULT '[]',
    wildcard_scopes TEXT DEFAULT '[]',
    exclusions TEXT DEFAULT '[]',
    notes TEXT DEFAULT '',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN DEFAULT 1
);

CREATE TABLE IF NOT EXISTS subdomains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    program_id INTEGER REFERENCES programs(id),
    subdomain TEXT NOT NULL,
    source TEXT,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    still_exists BOOLEAN DEFAULT 1,
    UNIQUE(subdomain)
);

CREATE TABLE IF NOT EXISTS dns_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subdomain_id INTEGER REFERENCES subdomains(id),
    record_type TEXT,
    record_value TEXT,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(subdomain_id, record_type, record_value)
);

CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subdomain_id INTEGER REFERENCES subdomains(id),
    url TEXT NOT NULL UNIQUE,
    ip_address TEXT,
    port INTEGER,
    is_https BOOLEAN DEFAULT 0,
    status_code INTEGER,
    response_headers TEXT DEFAULT '{}',
    response_size INTEGER,
    response_time_ms INTEGER,
    server_header TEXT,
    content_type TEXT,
    technologies TEXT DEFAULT '[]',
    ssl_cert_subject TEXT,
    ssl_cert_issuer TEXT,
    ssl_cert_expiry TIMESTAMP,
    ssl_cert_self_signed BOOLEAN DEFAULT 0,
    screenshot_path TEXT,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    still_alive BOOLEAN DEFAULT 1
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    service_id INTEGER REFERENCES services(id),
    check_name TEXT NOT NULL,
    url TEXT NOT NULL,
    status_code INTEGER,
    response_size INTEGER,
    response_snippet TEXT,
    severity TEXT DEFAULT 'LOW',
    found_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    still_present BOOLEAN DEFAULT 1,
    resolved_at TIMESTAMP,
    notified BOOLEAN DEFAULT 0,
    UNIQUE(url, check_name)
);

CREATE TABLE IF NOT EXISTS scan_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    programs_scanned INTEGER DEFAULT 0,
    subdomains_total INTEGER DEFAULT 0,
    subdomains_new INTEGER DEFAULT 0,
    services_total INTEGER DEFAULT 0,
    services_new INTEGER DEFAULT 0,
    findings_critical INTEGER DEFAULT 0,
    findings_high INTEGER DEFAULT 0,
    findings_medium INTEGER DEFAULT 0,
    findings_low INTEGER DEFAULT 0,
    status TEXT DEFAULT 'running'
);

CREATE INDEX IF NOT EXISTS idx_subdomains_program ON subdomains(program_id);
CREATE INDEX IF NOT EXISTS idx_subdomains_domain ON subdomains(subdomain);
CREATE INDEX IF NOT EXISTS idx_dns_subdomain ON dns_records(subdomain_id);
CREATE INDEX IF NOT EXISTS idx_services_url ON services(url);
CREATE INDEX IF NOT EXISTS idx_services_subdomain ON services(subdomain_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_check ON findings(check_name);
CREATE INDEX IF NOT EXISTS idx_findings_service ON findings(service_id);
CREATE INDEX IF NOT EXISTS idx_findings_present ON findings(still_present);
"""


class Database:
    """Thread-safe SQLite database wrapper."""

    def __init__(self, path: str | Path = "bountyboard.db"):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def conn(self) -> Generator[sqlite3.Connection, None, None]:
        c = self._connect()
        try:
            yield c
            c.commit()
        except Exception:
            c.rollback()
            raise
        finally:
            c.close()

    # ---- Programs ----

    def upsert_program(self, name: str, platform: str, domains: list[str],
                        wildcard_scopes: list[str], exclusions: list[str],
                        notes: str = "") -> int:
        with self.conn() as c:
            c.execute("""
                INSERT INTO programs (name, platform, root_domains, wildcard_scopes, exclusions, notes)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(name) DO UPDATE SET
                    platform=excluded.platform,
                    root_domains=excluded.root_domains,
                    wildcard_scopes=excluded.wildcard_scopes,
                    exclusions=excluded.exclusions,
                    notes=excluded.notes
            """, (name, platform, json.dumps(domains), json.dumps(wildcard_scopes),
                  json.dumps(exclusions), notes))
            row = c.execute("SELECT id FROM programs WHERE name=?", (name,)).fetchone()
            return row["id"]

    def get_programs(self, active_only: bool = True) -> list[dict]:
        with self.conn() as c:
            q = "SELECT * FROM programs"
            if active_only:
                q += " WHERE active=1"
            rows = c.execute(q).fetchall()
            return [dict(r) for r in rows]

    def get_program_id(self, name: str) -> Optional[int]:
        with self.conn() as c:
            row = c.execute("SELECT id FROM programs WHERE name=?", (name,)).fetchone()
            return row["id"] if row else None

    # ---- Subdomains ----

    def upsert_subdomain(self, program_id: int, subdomain: str, source: str) -> tuple[int, bool]:
        """Insert or update subdomain. Returns (id, is_new)."""
        subdomain = subdomain.lower().rstrip(".")
        now = datetime.utcnow().isoformat()
        with self.conn() as c:
            existing = c.execute(
                "SELECT id FROM subdomains WHERE subdomain=?", (subdomain,)
            ).fetchone()

            if existing:
                c.execute(
                    "UPDATE subdomains SET last_seen=?, still_exists=1 WHERE id=?",
                    (now, existing["id"])
                )
                return existing["id"], False
            else:
                c.execute(
                    "INSERT INTO subdomains (program_id, subdomain, source, first_seen, last_seen) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (program_id, subdomain, source, now, now)
                )
                row = c.execute("SELECT last_insert_rowid() as id").fetchone()
                return row["id"], True

    def get_subdomains(self, program_id: Optional[int] = None,
                       still_exists: bool = True) -> list[dict]:
        with self.conn() as c:
            q = "SELECT * FROM subdomains WHERE 1=1"
            params: list[Any] = []
            if program_id is not None:
                q += " AND program_id=?"
                params.append(program_id)
            if still_exists:
                q += " AND still_exists=1"
            rows = c.execute(q, params).fetchall()
            return [dict(r) for r in rows]

    def count_subdomains(self, program_id: Optional[int] = None) -> int:
        with self.conn() as c:
            q = "SELECT COUNT(*) as cnt FROM subdomains WHERE still_exists=1"
            params: list[Any] = []
            if program_id is not None:
                q += " AND program_id=?"
                params.append(program_id)
            return c.execute(q, params).fetchone()["cnt"]

    def mark_subdomain_gone(self, subdomain: str) -> None:
        with self.conn() as c:
            c.execute("UPDATE subdomains SET still_exists=0 WHERE subdomain=?", (subdomain,))

    # ---- DNS Records ----

    def upsert_dns_record(self, subdomain_id: int, record_type: str,
                           record_value: str) -> None:
        now = datetime.utcnow().isoformat()
        with self.conn() as c:
            c.execute("""
                INSERT INTO dns_records (subdomain_id, record_type, record_value, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(subdomain_id, record_type, record_value) DO UPDATE SET last_seen=?
            """, (subdomain_id, record_type, record_value, now, now, now))

    def get_dns_records(self, subdomain_id: int) -> list[dict]:
        with self.conn() as c:
            rows = c.execute(
                "SELECT * FROM dns_records WHERE subdomain_id=?", (subdomain_id,)
            ).fetchall()
            return [dict(r) for r in rows]

    # ---- Services ----

    def upsert_service(self, subdomain_id: int, url: str, data: dict) -> tuple[int, bool]:
        """Insert or update service. Returns (id, is_new)."""
        now = datetime.utcnow().isoformat()
        with self.conn() as c:
            existing = c.execute("SELECT id FROM services WHERE url=?", (url,)).fetchone()
            if existing:
                c.execute("""
                    UPDATE services SET
                        ip_address=?, port=?, is_https=?, status_code=?,
                        response_headers=?, response_size=?, response_time_ms=?,
                        server_header=?, content_type=?, technologies=?,
                        ssl_cert_subject=?, ssl_cert_issuer=?, ssl_cert_expiry=?,
                        ssl_cert_self_signed=?, last_seen=?, still_alive=1
                    WHERE id=?
                """, (
                    data.get("ip_address"), data.get("port"), data.get("is_https", 0),
                    data.get("status_code"), json.dumps(data.get("response_headers", {})),
                    data.get("response_size"), data.get("response_time_ms"),
                    data.get("server_header"), data.get("content_type"),
                    json.dumps(data.get("technologies", [])),
                    data.get("ssl_cert_subject"), data.get("ssl_cert_issuer"),
                    data.get("ssl_cert_expiry"), data.get("ssl_cert_self_signed", 0),
                    now, existing["id"]
                ))
                return existing["id"], False
            else:
                c.execute("""
                    INSERT INTO services (
                        subdomain_id, url, ip_address, port, is_https, status_code,
                        response_headers, response_size, response_time_ms,
                        server_header, content_type, technologies,
                        ssl_cert_subject, ssl_cert_issuer, ssl_cert_expiry,
                        ssl_cert_self_signed, first_seen, last_seen
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    subdomain_id, url, data.get("ip_address"), data.get("port"),
                    data.get("is_https", 0), data.get("status_code"),
                    json.dumps(data.get("response_headers", {})),
                    data.get("response_size"), data.get("response_time_ms"),
                    data.get("server_header"), data.get("content_type"),
                    json.dumps(data.get("technologies", [])),
                    data.get("ssl_cert_subject"), data.get("ssl_cert_issuer"),
                    data.get("ssl_cert_expiry"), data.get("ssl_cert_self_signed", 0),
                    now, now
                ))
                row = c.execute("SELECT last_insert_rowid() as id").fetchone()
                return row["id"], True

    def update_service_screenshot(self, service_id: int, path: str) -> None:
        with self.conn() as c:
            c.execute("UPDATE services SET screenshot_path=? WHERE id=?", (path, service_id))

    def get_services(self, program_id: Optional[int] = None,
                     alive_only: bool = True) -> list[dict]:
        with self.conn() as c:
            if program_id is not None:
                q = """
                    SELECT s.* FROM services s
                    JOIN subdomains sub ON s.subdomain_id = sub.id
                    WHERE sub.program_id=?
                """
                params: list[Any] = [program_id]
                if alive_only:
                    q += " AND s.still_alive=1"
            else:
                q = "SELECT * FROM services WHERE 1=1"
                params = []
                if alive_only:
                    q += " AND still_alive=1"
            rows = c.execute(q, params).fetchall()
            return [dict(r) for r in rows]

    def get_service_by_url(self, url: str) -> Optional[dict]:
        with self.conn() as c:
            row = c.execute("SELECT * FROM services WHERE url=?", (url,)).fetchone()
            return dict(row) if row else None

    # ---- Findings ----

    def upsert_finding(self, service_id: int, check_name: str, url: str,
                        data: dict) -> tuple[int, bool]:
        """Insert or update finding. Returns (id, is_new)."""
        now = datetime.utcnow().isoformat()
        with self.conn() as c:
            existing = c.execute(
                "SELECT id, still_present FROM findings WHERE url=? AND check_name=?",
                (url, check_name)
            ).fetchone()

            if existing:
                c.execute(
                    "UPDATE findings SET still_present=1, status_code=?, "
                    "response_size=?, response_snippet=? WHERE id=?",
                    (data.get("status_code"), data.get("response_size"),
                     data.get("response_snippet"), existing["id"])
                )
                return existing["id"], not existing["still_present"]
            else:
                c.execute("""
                    INSERT INTO findings (
                        service_id, check_name, url, status_code, response_size,
                        response_snippet, severity, found_at, still_present
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1)
                """, (
                    service_id, check_name, url,
                    data.get("status_code"), data.get("response_size"),
                    data.get("response_snippet"), data.get("severity", "LOW"), now
                ))
                row = c.execute("SELECT last_insert_rowid() as id").fetchone()
                return row["id"], True

    def get_findings(self, program_id: Optional[int] = None,
                     severity: Optional[str] = None,
                     only_new: bool = False,
                     only_present: bool = True) -> list[dict]:
        with self.conn() as c:
            if program_id is not None:
                q = """
                    SELECT f.*, s.url as service_url, sub.subdomain, sub.program_id
                    FROM findings f
                    JOIN services s ON f.service_id = s.id
                    JOIN subdomains sub ON s.subdomain_id = sub.id
                    WHERE sub.program_id=?
                """
                params: list[Any] = [program_id]
            else:
                q = """
                    SELECT f.*, s.url as service_url, sub.subdomain, sub.program_id
                    FROM findings f
                    JOIN services s ON f.service_id = s.id
                    JOIN subdomains sub ON s.subdomain_id = sub.id
                    WHERE 1=1
                """
                params = []

            if severity:
                q += " AND f.severity=?"
                params.append(severity.upper())
            if only_present:
                q += " AND f.still_present=1"
            if only_new:
                q += " AND f.notified=0"

            q += " ORDER BY CASE f.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 WHEN 'MEDIUM' THEN 3 ELSE 4 END, f.found_at DESC"

            rows = c.execute(q, params).fetchall()
            return [dict(r) for r in rows]

    def mark_finding_notified(self, finding_id: int) -> None:
        with self.conn() as c:
            c.execute("UPDATE findings SET notified=1 WHERE id=?", (finding_id,))

    def mark_finding_resolved(self, finding_id: int) -> None:
        now = datetime.utcnow().isoformat()
        with self.conn() as c:
            c.execute(
                "UPDATE findings SET still_present=0, resolved_at=? WHERE id=?",
                (now, finding_id)
            )

    def count_findings_by_severity(self, program_id: Optional[int] = None) -> dict:
        with self.conn() as c:
            if program_id is not None:
                q = """
                    SELECT f.severity, COUNT(*) as cnt
                    FROM findings f
                    JOIN services s ON f.service_id = s.id
                    JOIN subdomains sub ON s.subdomain_id = sub.id
                    WHERE sub.program_id=? AND f.still_present=1
                    GROUP BY f.severity
                """
                rows = c.execute(q, (program_id,)).fetchall()
            else:
                rows = c.execute(
                    "SELECT severity, COUNT(*) as cnt FROM findings "
                    "WHERE still_present=1 GROUP BY severity"
                ).fetchall()
            return {r["severity"]: r["cnt"] for r in rows}

    # ---- Scan Runs ----

    def start_scan_run(self) -> int:
        with self.conn() as c:
            c.execute("INSERT INTO scan_runs (started_at, status) VALUES (?, 'running')",
                      (datetime.utcnow().isoformat(),))
            return c.execute("SELECT last_insert_rowid() as id").fetchone()["id"]

    def finish_scan_run(self, run_id: int, stats: dict) -> None:
        now = datetime.utcnow().isoformat()
        with self.conn() as c:
            c.execute("""
                UPDATE scan_runs SET
                    completed_at=?, status='completed',
                    programs_scanned=?, subdomains_total=?, subdomains_new=?,
                    services_total=?, services_new=?,
                    findings_critical=?, findings_high=?, findings_medium=?, findings_low=?
                WHERE id=?
            """, (
                now,
                stats.get("programs_scanned", 0),
                stats.get("subdomains_total", 0),
                stats.get("subdomains_new", 0),
                stats.get("services_total", 0),
                stats.get("services_new", 0),
                stats.get("findings_critical", 0),
                stats.get("findings_high", 0),
                stats.get("findings_medium", 0),
                stats.get("findings_low", 0),
                run_id
            ))

    def fail_scan_run(self, run_id: int) -> None:
        with self.conn() as c:
            c.execute("UPDATE scan_runs SET status='failed', completed_at=? WHERE id=?",
                      (datetime.utcnow().isoformat(), run_id))

    def get_last_scan_run(self) -> Optional[dict]:
        with self.conn() as c:
            row = c.execute(
                "SELECT * FROM scan_runs WHERE status='completed' "
                "ORDER BY completed_at DESC LIMIT 1"
            ).fetchone()
            return dict(row) if row else None

    def get_scan_runs(self, limit: int = 20) -> list[dict]:
        with self.conn() as c:
            rows = c.execute(
                "SELECT * FROM scan_runs ORDER BY started_at DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]

    # ---- Statistics ----

    def get_stats(self, program_id: Optional[int] = None) -> dict:
        """Get comprehensive statistics."""
        with self.conn() as c:
            if program_id:
                total_subs = c.execute(
                    "SELECT COUNT(*) as cnt FROM subdomains WHERE program_id=? AND still_exists=1",
                    (program_id,)
                ).fetchone()["cnt"]
                total_services = c.execute(
                    """SELECT COUNT(*) as cnt FROM services s
                       JOIN subdomains sub ON s.subdomain_id=sub.id
                       WHERE sub.program_id=? AND s.still_alive=1""",
                    (program_id,)
                ).fetchone()["cnt"]
            else:
                total_subs = c.execute(
                    "SELECT COUNT(*) as cnt FROM subdomains WHERE still_exists=1"
                ).fetchone()["cnt"]
                total_services = c.execute(
                    "SELECT COUNT(*) as cnt FROM services WHERE still_alive=1"
                ).fetchone()["cnt"]

            findings = self.count_findings_by_severity(program_id)
            last_run = self.get_last_scan_run()

            return {
                "total_subdomains": total_subs,
                "total_services": total_services,
                "findings_critical": findings.get("CRITICAL", 0),
                "findings_high": findings.get("HIGH", 0),
                "findings_medium": findings.get("MEDIUM", 0),
                "findings_low": findings.get("LOW", 0),
                "last_run": last_run,
            }
