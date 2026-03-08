# CLAUDE.md — BaoTa Panel Security Audit Workspace

## Mission

Full-depth security audit of BaoTa (宝塔) Linux server management panel.
Goal: Find every exploitable path — prioritizing unauthenticated access and RCE.
Zero simplification. Every route, every sink, every chain documented with proof.

---

## Codebase Architecture

### Core Entry Points
- `BTPanel/__init__.py` (3731 lines) — Flask app, ALL route handlers, CSRF, dispatcher
- `runserver.py` — WSGI entry, starts the panel
- `task.py` — Background task worker (runs as root, separate process)

### Authentication Layer
- `class/common.py` (481 lines) — `comm.local()` → `check_login()` gate on every route
- `class/userlogin.py` — Login form handler, brute force protection
- `class/users.py` — User management

### Backend Modules (called by routes via `getattr()`)
- `class/sites.py` — Website management (nginx/apache vhosts)
- `class/files.py` — File manager (read/write/upload/download)
- `class/crontab.py` — Cron job management
- `class/firewalld.py` / `firewalls.py` / `firewall_new.py` — Firewall rules
- `class/ftp.py` — FTP user management
- `class/database.py` / `data.py` / `datatool.py` — Database operations
- `class/system.py` — System info/operations
- `class/config.py` — Panel configuration
- `class/ajax.py` — AJAX utility endpoints
- `class/ssh_terminal.py` — SSH terminal backend
- `class/acme_v2.py` / `letsencrypt.py` / `setPanelLets.py` — SSL/ACME
- `class/pluginAuth.py` / `plugin_tool.py` — Plugin system
- `class/ssl_manage.py` / `ssl_info.py` — SSL certificate management

### Utility Layer
- `class/public.py` (9055 lines) — Mega utility: ExecShell, MD5, sessions, input filtering
- `class/db.py` / `db_mysql.py` — Database abstraction
- `class/http_requests.py` — Outbound HTTP client

### Modular System (newer)
- `mod/base/` — Database tools, backup, git, messaging
- `mod/` — Modular route handlers loaded dynamically

### Background/Scripts
- `script/` — Cron scripts, backup, SSL renewal, monitoring
- `tools.py` — CLI management tools

---

## Security-Critical Functions (Sinks)

### Command Execution
- `public.ExecShell(cmd)` — `subprocess.Popen(cmd, shell=True)` — THE primary sink
- `public.ExecShell_line(cmd)` — Same, line-buffered output
- `os.system(cmd)` — Direct system calls in some modules
- `subprocess.Popen(cmd, shell=True)` — Direct usage in some files

### File System
- `public.writeFile(path, content)` — Arbitrary file write
- `public.readFile(path)` — Arbitrary file read
- `open(path, 'w')` — Direct file writes

### Deserialization
- `pickle.loads()` — Used in task.py cache
- `json.loads()` — Used everywhere (safe)

### Database
- SQLite queries with string formatting (potential SQLi)

---

## Authentication Architecture

### Session System
- Flask-Session with filesystem backend
- Secret key: `md5(str(os.uname()) + str(psutil.boot_time()))`
- Session files stored in: `/www/server/panel/data/session/`
- Cookie name: `md5(secret_key)` or `md5(secret_key) + "_ssl"`
- Signed sessions: `SESSION_USE_SIGNER = True`

### Auth Check Flow
```
Every route → comm.local() → check_login() → validates:
  1. session['login'] exists and is True
  2. client_hash matches (IP + User-Agent)
  3. session not expired
  4. login_token matches server-side token
```

### CSRF System
- Token in header: `x-http-token`
- Compared to: `session['request_token_head']`
- Bypassed when: DEBUG mode, or token not yet in session

### API Key Auth (alternate path)
- Config: `config/api.json`
- Token: `md5(request_time + api_token)`
- IP whitelist enforced
- Bypasses session requirement

---

## Route Map (condensed)

### Unauthenticated Routes (DO NOT call comm.local or check before it)
- `/login` — Login page (GET)
- `/do_login` — Login handler (POST)
- `/check_login` — Login status check
- Static file routes
- Need to verify: `/hook`, `/down`, `/mail_unsubscribe`, `/safe/index`

### Authenticated Routes (all call comm.local first)
- `/site/<action>`, `/ftp/<action>`, `/database/<action>` — Module CRUD
- `/files/<action>` — File operations
- `/crontab/<action>` — Cron management
- `/firewall/<action>` — Firewall rules
- `/config/<action>` — Panel config
- `/system/<action>` — System operations
- `/plugin` — Plugin execution
- `/ajax/<action>` — AJAX utilities
- `/<name>/<fun>/<stype>` — Catch-all plugin/module route
- `/ws_panel` — WebSocket terminal
- `/sock_shell` — WebSocket shell

---

## Memory Management Protocol

### Chunked Analysis Strategy
When analyzing large files (>500 lines), read in chunks:
1. First pass: Read line 1-200 (imports, globals, setup)
2. Route map pass: Grep for `@app.route` to get all endpoints
3. Per-route deep dive: Read each route handler ±50 lines
4. Sink trace: For each interesting route, follow the call chain to sinks

### Cross-File Trace Protocol
For each potential vulnerability:
1. **Entry**: Route handler in `BTPanel/__init__.py` — note line number
2. **Gate**: Does it call `comm.local()`? At what point? Any early returns before it?
3. **Dispatch**: How does input reach the backend class? Via `publicObject()` or direct?
4. **Sink**: What dangerous function does user input reach? With what sanitization?
5. **Proof**: Exact parameter flow from HTTP request to dangerous function call

### State Tracking
Track findings in these files:
- `EXPLOIT_CHAINS.md` — Confirmed exploit chains with full detail
- `CLAUDE.md` — This file, updated with new architectural discoveries
- Use git commits to checkpoint progress

### Large File Navigation Index
Key line ranges in `BTPanel/__init__.py`:
- Lines 1-104: Imports, Flask app setup, session config
- Lines 105-600: Template routes, static, login/logout
- Lines 600-1400: Module route handlers (/site, /ftp, /database, /files, etc.)
- Lines 1400-2100: Plugin routes, model routes, catch-all routes
- Lines 2100-2500: WebSocket handlers
- Lines 2500-2800: Dispatcher (publicObject, run_exec, check_csrf)
- Lines 2800-3100: Input parsing, response handling
- Lines 3100-3731: WebSocket CSRF, utility functions

Key line ranges in `class/public.py`:
- Lines 1-500: Imports, paths, basic utilities
- Lines 500-1500: ExecShell, file operations, system utilities
- Lines 1500-3000: Network, SSL, panel utilities
- Lines 3000-5000: Session, auth, CSRF functions
- Lines 5000-7000: Input validation, sanitization
- Lines 7000-9055: Client hash, misc utilities

---

## Discovered Vulnerabilities (Running Index)

### Confirmed Post-Auth Chains
1. CHAIN-1: Cron injection via `crontab.py` (shell metachar in name)
2. CHAIN-2: Firewall injection via `firewalls.py` (port parameter)
3. CHAIN-3: File write via `files.py` (path traversal + content)
4. CHAIN-4: Plugin code execution (arbitrary Python via plugin load)
5. CHAIN-5: WebSocket shell (no method whitelist on ws_panel)
6. CHAIN-6: Task pickle deserialization (crafted cache)
7. CHAIN-7: FTP user injection (shell chars in username/password)
8. CHAIN-8: Log injection to cron (via log file written to cron path)

### Auth Layer Weaknesses
- AUTH-1: Predictable secret key
- AUTH-2: Debug CSRF bypass
- AUTH-3: WebSocket CSRF bypass via AES/API flags
- AUTH-4: 2-min client hash grace period
- AUTH-5: Cookie name leaks key hash

### Confirmed Unconditional Zero-Days (NO auth, NO brute force, NO conditions)
- **ZERO-DAY-1**: MITM panel update → unsigned ZIP extracted as root (ajax.py:997, http_requests.py verify=False)
- **ZERO-DAY-2**: curl -k|bash auto-recovery (task.py:1901, jobs.py:1094) — TLS verification disabled
- **ZERO-DAY-3**: MITM plugin install → install.sh runs as root unsignedt (panelPlugin.py:704,3882)
- **ZERO-DAY-4**: Debug error handler leaks system info to unauth users → enables session forgery
- **ZERO-DAY-5**: Predictable secret key md5(uname+boot_time) + cookie name oracle → session forgery → RCE

### Confirmed Local Privilege Escalation (no panel auth needed)
- LOCAL-1: Pickle deserialization in session files (restricted_loads disabled, session_simpile.py:29)
- LOCAL-2: SQLite task queue → shell exec as root (task.py:2227)
- LOCAL-3: Task JSON files in data/tasks/ → plugin/module function execution (task.py:1824)
- LOCAL-4: Pickle in system_cache.pkl (task.py:2444)
- LOCAL-5: World-writable /dev/shm IPC → trigger task execution

### Confirmed Supply Chain Failures
- UPDATE-1: upgrade_panel.py downloads over plain HTTP (line 498)
- UPDATE-2: Download node URL from writable JSON file (public.py:856)
- UPDATE-3: No code signing anywhere — not updates, not plugins, not scripts

---

## Working Notes

- Panel runs as root — any code execution = root RCE
- Python 3.x (check exact version for known CVEs)
- Flask + Flask-Session + Flask-SocketIO stack
- All backend classes instantiated fresh per-request
- `dict_obj` input object filters: blocks dunder, allows `[\w\s\[\]\-\.]` keys, string-only values
- `ExecShell` is THE sink — appears 500+ times across codebase
