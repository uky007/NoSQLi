# 🛡️ NoSQLi — Paranoid SQL Injection Defense

> **"No SQL Injection shall pass. Neither shall most of your legitimate queries."**

NoSQLi is a database query proxy concept that pre-screens ALL SQL queries against known SQLi attack patterns before they reach the database. It operates at the middleware layer, meaning **your web application's code quality doesn't matter** — NoSQLi blocks malicious queries regardless of implementation.

The trade-off? It also blocks a significant number of perfectly legitimate queries. We consider this an acceptable trade-off.

## 🔴 Demo

**[Live Demo →](https://uky007.github.io/NoSQLi/)**

## How It Works

NoSQLi intercepts every SQL query and matches it against 48+ regex patterns covering:

- **UNION-based injection** — `UNION SELECT`, `UNION ALL SELECT`
- **Authentication bypass** — `OR 1=1`, `OR TRUE`, tautology attacks
- **Destructive operations** — `DROP TABLE`, `DROP DATABASE`, `DELETE`
- **Time-based blind SQLi** — `SLEEP()`, `BENCHMARK()`, `WAITFOR DELAY`
- **Schema reconnaissance** — `information_schema`, `sys.tables`, `pg_catalog`
- **Command execution** — `EXEC()`, `xp_cmdshell`
- **Error-based injection** — `EXTRACTVALUE()`, `UPDATEXML()`
- **Data exfiltration** — `LOAD_FILE()`, `INTO OUTFILE`
- **Encoding bypass** — `CHAR()`, hex encoding, comment obfuscation

And more. If it looks even remotely suspicious, it gets blocked.

## Known Side Effects

- Users named `O'Brien` cannot create accounts
- The `SELECT` committee cannot be searched
- Any column named `drop` renders the table inaccessible
- PostgreSQL developers cannot use `--` comments
- DBAs cannot query `information_schema` for legitimate maintenance
- Batch operations with semicolons are permanently disabled
- The word "sleep" in any context triggers a time-based blind SQLi alert

## Getting Started

```bash
npm install
npm run dev
```

## Build & Deploy

```bash
npm run build    # Output in dist/
npm run preview  # Preview production build
```

Deployable to GitHub Pages via the included workflow.

## Tech Stack

- React + Vite
- Zero dependencies beyond React

## License

MIT
