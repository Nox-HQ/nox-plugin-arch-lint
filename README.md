# nox-plugin-arch-lint

**Detect architectural anti-patterns that create security risks.**

<!-- badges -->
![Track: Threat Modeling](https://img.shields.io/badge/track-Threat%20Modeling-red)
![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)
![Go 1.25+](https://img.shields.io/badge/go-1.25%2B-00ADD8)

---

## Overview

`nox-plugin-arch-lint` identifies architectural design flaws that amplify security risk. It detects circular dependencies that resist modular security boundaries, god objects that concentrate too much logic in a single file, security-critical code (cryptography and authentication) mixed with business logic in the same file, and handler functions that make direct database calls without an abstraction layer.

Architecture is a security control. When cryptographic logic lives in the same file as HTTP handlers and business logic, a vulnerability in any part of that file exposes all parts. When a handler makes direct SQL queries, the attack surface for injection extends into the presentation layer. When god objects concentrate hundreds of exports in a single file, the blast radius of any bug is maximized.

This plugin does not require a formal architecture definition. It infers architectural concerns from code patterns -- import graphs, export counts, function signatures, and the co-location of security-critical and business logic. This makes it usable on any codebase without upfront configuration.

## Use Cases

### Security Architecture Review

Before a major release, your security architect needs to identify files where cryptographic operations, authentication logic, and business operations are mixed together. This plugin flags every file where `crypto/` imports coexist with HTTP route handlers and database queries, giving the architect a prioritized list of files that need separation.

### Technical Debt Triage for Security

Your engineering team maintains a large codebase where several files have grown beyond 500 lines with dozens of exported symbols. These god objects are security liabilities because they concentrate risk and resist code review. This plugin quantifies the problem, reporting exact line counts and export counts for each oversized file.

### Clean Architecture Enforcement

Your team follows hexagonal architecture principles where handlers should not contain direct database access. A developer adds a `db.Query("SELECT * FROM users WHERE id = ?", userID)` call directly inside an HTTP handler. This plugin catches the missing abstraction layer, enforcing that data access goes through a repository or service layer.

### Dependency Graph Analysis

Circular dependencies between packages create tightly coupled systems that are difficult to test, reason about, and secure in isolation. This plugin builds an import graph across the workspace and flags mutual import patterns where package A imports package B and package B imports package A.

## 5-Minute Demo

### Prerequisites

- Go 1.25+
- [Nox](https://github.com/Nox-HQ/nox) installed

### Quick Start

1. **Install the plugin**

   ```bash
   nox plugin install Nox-HQ/nox-plugin-arch-lint
   ```

2. **Create a test file** (`demo/user_handler.go`):

   ```go
   package main

   import (
       "crypto/bcrypt"
       "database/sql"
       "encoding/json"
       "net/http"
   )

   var db *sql.DB

   func handleCreateUser(w http.ResponseWriter, r *http.Request) {
       var req struct {
           Email    string `json:"email"`
           Password string `json:"password"`
       }
       json.NewDecoder(r.Body).Decode(&req)

       hash, _ := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)

       db.Exec("INSERT INTO users (email, password_hash) VALUES (?, ?)", req.Email, hash)

       w.WriteHeader(http.StatusCreated)
   }

   func handleLogin(w http.ResponseWriter, r *http.Request) {
       email := r.URL.Query().Get("email")
       row := db.QueryRow("SELECT password_hash FROM users WHERE email = ?", email)
       var hash string
       row.Scan(&hash)
       json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
   }

   func main() {
       http.HandleFunc("/users", handleCreateUser)
       http.HandleFunc("/login", handleLogin)
       http.ListenAndServe(":8080", nil)
   }
   ```

3. **Run the scan**

   ```bash
   nox scan --plugin nox/arch-lint demo/
   ```

4. **Review findings**

   ```
   nox-plugin-arch-lint: 3 findings

   ARCH-003 [HIGH] Security-critical code (crypto) mixed with business logic in
     same file
     demo/user_handler.go:4:4
     has_crypto: true, has_auth: false, has_business_logic: true
     language: go

   ARCH-004 [LOW] Missing abstraction layer: direct database call in handler:
     db.Exec("INSERT INTO users (email, password_hash) VALUES (?, ?)", req.Email, hash)
     demo/user_handler.go:21:21
     language: go

   ARCH-004 [LOW] Missing abstraction layer: direct database call in handler:
     row := db.QueryRow("SELECT password_hash FROM users WHERE email = ?", email)
     demo/user_handler.go:28:28
     language: go
   ```

## Rules

| ID | Description | Severity | Confidence |
|----|-------------|----------|------------|
| ARCH-001 | Circular dependency risk: mutual imports between packages | Medium | High |
| ARCH-002 | God object/file detected: file exceeds 500 lines with 10+ exports | Medium | Medium |
| ARCH-003 | Security-critical code (crypto/auth) mixed with business logic in same file | High | High |
| ARCH-004 | Missing abstraction layer: direct database call in handler/controller | Low | Medium |

### Thresholds

| Parameter | Value | Description |
|-----------|-------|-------------|
| God file line threshold | 500 | Files must exceed this line count to trigger ARCH-002 |
| God file export threshold | 10 | Files must have at least this many exports to trigger ARCH-002 |

## Supported Languages / File Types

| Language | Extensions | Detection Scope |
|----------|-----------|-----------------|
| Go | `.go` | Import graphs, exported symbols (`func/type/var/const` starting with uppercase), `crypto/` imports, auth function names, `db.Query`/`db.Exec` calls, HTTP handlers |
| Python | `.py` | Import/from statements, `def`/`class` definitions, `cryptography`/`hashlib`/`bcrypt` imports, auth function names, SQL patterns |
| JavaScript | `.js` | `import`/`require` statements, `export` declarations, `crypto`/`bcrypt`/`jsonwebtoken` requires, auth function names, SQL patterns |
| TypeScript | `.ts` | `import`/`require` statements, `export` declarations, `crypto`/`bcrypt`/`jsonwebtoken` requires, auth function names, SQL patterns |

## Configuration

This plugin requires no configuration.

| Environment Variable | Description | Default |
|---------------------|-------------|---------|
| _None_ | This plugin has no environment variables | -- |

## Installation

### Via Nox (recommended)

```bash
nox plugin install Nox-HQ/nox-plugin-arch-lint
```

### Standalone

```bash
git clone https://github.com/Nox-HQ/nox-plugin-arch-lint.git
cd nox-plugin-arch-lint
go build -o nox-plugin-arch-lint .
```

## Development

```bash
# Build
go build ./...

# Run tests
go test ./...

# Run a specific test
go test ./... -run TestSecurityMixing

# Lint
golangci-lint run

# Run in Docker
docker build -t nox-plugin-arch-lint .
docker run --rm nox-plugin-arch-lint
```

## Architecture

The plugin is built on the Nox plugin SDK and communicates via the Nox plugin protocol over stdio.

**Scan pipeline:**

1. **Workspace walk and file parsing** -- Recursively traverses the workspace root (skipping `.git`, `vendor`, `node_modules`, `__pycache__`, `.venv`, `dist`, `build`). Each source file is fully parsed in a single pass to extract imports, export counts, line counts, and all line content.

2. **Import graph construction** -- As files are parsed, their import statements are recorded in a workspace-wide import graph mapping relative file paths to lists of imported modules.

3. **Multi-analysis pass** -- After all files are parsed, four analyses run on each file:
   - **ARCH-001 (Circular Dependencies):** Checks each file's imports against the import graph to detect mutual import patterns. Reports once per file.
   - **ARCH-002 (God Objects):** Flags files exceeding 500 lines with 10 or more exports.
   - **ARCH-003 (Security Mixing):** Detects files containing crypto or auth patterns alongside business logic, DB access, or HTTP routes.
   - **ARCH-004 (Missing Abstraction):** First checks if the file contains handler/controller patterns, then flags any direct SQL or DB calls within those files.

4. **Output** -- Findings include detailed metadata about what was detected (crypto presence, auth presence, line counts, etc.).

## Contributing

Contributions are welcome. Please open an issue first to discuss proposed changes.

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/new-check`)
3. Write tests for new architectural checks
4. Ensure `go test ./...` and `golangci-lint run` pass
5. Submit a pull request

## License

Apache-2.0
