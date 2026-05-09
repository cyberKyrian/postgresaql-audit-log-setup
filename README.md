# PostgreSQL Database Activity Monitoring with pgAudit

## Project Overview

In financial environments, knowing *who did what* to a database — and *when* — is not optional. Regulations like **PCI-DSS Requirement 10**, **CBN Cybersecurity Framework**, and **NDPR** all mandate that sensitive data access and schema changes be logged, retained, and reviewable.

This project demonstrates a **Defense-First** approach to database security monitoring. I deployed a PostgreSQL instance from scratch, configured **pgAudit** for granular session-level logging, populated a realistic banking dataset, and then simulated five real-world insider threat and attacker scenarios — capturing full forensic evidence for each.

This simulates the workflow of a **Database Security Engineer** or **SOC Analyst** investigating suspicious database activity in a banking environment.

---

## Tech Stack & Tools

| Component | Tool |
|---|---|
| **Database** | PostgreSQL 15 (Docker) |
| **Audit Extension** | pgAudit |
| **Containerisation** | Docker Desktop (Windows) |
| **Log Analysis** | PowerShell (`Select-String`) |
| **Environment** | Windows 11, VS Code |

---

## Lab Architecture

```
┌─────────────────────────────────────────┐
│            Docker Container             │
│                                         │
│  ┌──────────────────────────────────┐   │
│  │        PostgreSQL 15             │   │
│  │                                  │   │
│  │  ┌────────────┐  ┌────────────┐  │   │
│  │  │  customers │  │transactions│  │   │
│  │  │  table     │  │  table     │  │   │
│  │  └────────────┘  └────────────┘  │   │
│  │                                  │   │
│  │  pgAudit → Session Audit Log     │   │
│  └──────────────────────────────────┘   │
│                                         │
└─────────────────────────────────────────┘
          │
          ▼
   audit_report.txt  (forensic evidence)
```

**Audit Coverage:**
- `DDL` — Table creation, schema changes, DROP operations
- `DML` — All reads (SELECT) and writes (INSERT, UPDATE, DELETE)
- `ROLE` — User creation, privilege grants and revocations
- `MISC` — Configuration queries and system commands

---

## Lab Execution Steps

### 1. Build a pgAudit-Ready PostgreSQL Image

The official PostgreSQL Docker image does not ship with pgAudit pre-installed. I wrote a custom `Dockerfile` to install the extension cleanly:

```dockerfile
FROM postgres:15

RUN apt-get update && \
    apt-get install -y postgresql-15-pgaudit && \
    rm -rf /var/lib/apt/lists/*
```

```bash
# Build and run the container
docker build -t pgaudit-custom .

docker run --name pgaudit-lab \
  -e POSTGRES_PASSWORD=SecureLab123 \
  -e POSTGRES_USER=labadmin \
  -e POSTGRES_DB=bankdb \
  -p 5432:5432 \
  -d pgaudit-custom
```

---

### 2. Configure pgAudit for Full Session Logging

```sql
-- Load the pgAudit extension
CREATE EXTENSION IF NOT EXISTS pgaudit;

-- Enable comprehensive audit coverage
ALTER SYSTEM SET shared_preload_libraries = 'pgaudit';
ALTER SYSTEM SET pgaudit.log = 'all';
ALTER SYSTEM SET log_line_prefix = '%t [%p] %u@%d ';
```

After restarting the container, verified configuration:

```sql
SHOW pgaudit.log;
-- Returns: all
```

> **Screenshot:** pgAudit extension loaded and `log = all` confirmed
> *(add screenshot here)*

---

### 3. Build the Simulated Banking Database

Created a realistic schema representing customer and transaction data typical of a core banking system:

```sql
CREATE TABLE customers (
  id             SERIAL PRIMARY KEY,
  full_name      VARCHAR(100),
  account_number VARCHAR(20),
  bvn            VARCHAR(11),       -- Regulated PII under NDPR
  balance        DECIMAL(15,2)
);

CREATE TABLE transactions (
  id          SERIAL PRIMARY KEY,
  customer_id INT REFERENCES customers(id),
  amount      DECIMAL(15,2),
  txn_type    VARCHAR(10),
  txn_date    TIMESTAMP DEFAULT NOW()
);
```

Populated with four synthetic customer records and three transactions.

---

### 4. Simulate Insider Threat & Attacker Scenarios

Five suspicious actions were executed to generate realistic audit events:

| # | Action | SQL | Threat Modelled |
|---|--------|-----|-----------------|
| 1 | Bulk data dump | `SELECT * FROM customers` | Insider exfiltration |
| 2 | Targeted PII access | `SELECT full_name, bvn FROM customers` | Regulated data harvesting |
| 3 | Unauthorised schema change | `ALTER TABLE customers ADD COLUMN notes TEXT` | Backdoor staging / tampering |
| 4 | Rogue account creation | `CREATE USER suspicious_user` + `GRANT ALL` | Privilege escalation / persistence |
| 5 | Destructive action | `DROP TABLE transactions` | Audit trail destruction / sabotage |

---

### 5. Extract & Analyse Audit Logs

```powershell
# Extract all AUDIT log entries (Windows PowerShell)
docker logs pgaudit-lab 2>&1 | Select-String "AUDIT" > audit_report.txt
```

---

## Findings & Analysis

### Finding 1 — Bulk SELECT on Sensitive Table *(High)*
```
SESSION,6,1,READ,SELECT,,,SELECT * FROM customers
SESSION,7,1,READ,SELECT,,,SELECT * FROM customers
```
**Risk:** Full table dump executed twice in under 2 minutes — classic data exfiltration pattern. In a production environment, a rule triggering on `SELECT *` returning more than 100 rows from a regulated table should fire an immediate alert.

---

### Finding 2 — Targeted BVN Data Access *(Critical)*
```
SESSION,8,1,READ,SELECT,,,"SELECT full_name, bvn FROM customers"
```
**Risk:** BVN is regulated personal data under Nigerian law. Direct column-level targeting of BVN outside of an approved application context is a critical event. This should trigger automatic escalation to the Data Protection Officer.

---

### Finding 3 — Unauthorised Schema Modification *(High)*
```
SESSION,9,1,DDL,ALTER TABLE,TABLE,public.customers,ALTER TABLE customers ADD COLUMN notes TEXT
```
**Risk:** Schema changes in production require change management approval. An unapproved `ALTER TABLE` could be used to stage data for exfiltration (e.g., copying sensitive values into a less-monitored column).

---

### Finding 4 — Privilege Escalation via Rogue Account *(Critical)*
```
SESSION,10,1,ROLE,CREATE ROLE,,,CREATE USER suspicious_user WITH PASSWORD <REDACTED>
SESSION,11,1,ROLE,GRANT,,,GRANT ALL PRIVILEGES ON DATABASE bankdb TO suspicious_user
```
**Risk:** A new database user was created and immediately granted full privileges. Note: pgAudit automatically redacted the password from logs — good security hygiene. This two-step pattern (create + grant) is a textbook persistence mechanism after initial compromise.

---

### Finding 5 — Destructive DDL: Table Dropped *(Critical)*
```
SESSION,12,1,DDL,DROP TABLE,TABLE,public.transactions
SESSION,12,1,DDL,DROP TABLE,SEQUENCE,public.transactions_id_seq
SESSION,12,1,DDL,DROP TABLE,TABLE CONSTRAINT,...
```
**Risk:** Entire transactions table destroyed, along with all dependent sequences, indexes, constraints, and triggers. The cascade of DROP events logged by pgAudit provides exactly the forensic detail needed to reconstruct what was lost and when.

---

## Security Recommendations

Based on the audit findings, the following controls should be implemented in a production banking environment:

1. **Alert on bulk reads** — Trigger on `SELECT *` returning >100 rows from regulated tables (customers, accounts, BVN records)
2. **Column-level access control** — Restrict direct BVN and account number access to approved application service accounts only; human users should never query these raw
3. **DDL change gating** — All `ALTER TABLE` and `DROP` operations should require a change management ticket and DBA approval before execution
4. **Privilege monitoring** — Any `CREATE USER` or `GRANT` event should trigger an automated alert to the IAM/security team within 5 minutes
5. **Log retention** — Audit logs should be shipped to an immutable SIEM store and retained for a minimum of 12 months (PCI-DSS Req 10.7 / CBN requirement)
6. **Separation of duties** — Application accounts should never have DDL or ROLE privileges; these should be restricted to named DBA accounts only

---

## Compliance Mapping

| Control | PCI-DSS | CBN Cyber Framework | NDPR |
|---|---|---|---|
| Audit logging enabled | Req 10.2 | CC-7 | Art. 2.4 |
| Privileged user activity logged | Req 10.2.2 | CC-7 | — |
| Log retention ≥ 12 months | Req 10.7 | CC-7 | — |
| BVN / PII access monitored | Req 7 | — | Art. 2.1 |
| Schema change tracking | Req 10.2.5 | CC-6 | — |

---

## Key Takeaways

- pgAudit provides **session-level granularity** that PostgreSQL's native logging cannot match — every statement, every object affected, every user action is captured
- Audit logs captured **cascade effects** automatically (e.g., dropping a table logged all dependent sequences, indexes, and triggers) — critical for forensic reconstruction
- pgAudit **redacted credentials** from ROLE events automatically (`PASSWORD <REDACTED>`) — demonstrating security-conscious default behaviour
- A properly configured audit trail turns a database from a black box into a **forensic asset**

---

## 📬 Connect with Me

- **LinkedIn:** [Kyrian Onyeagusi](https://www.linkedin.com/in/kyrian-onyeagusi/)
- **Email:** c_kyrian@icloud.com
