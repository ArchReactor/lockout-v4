# Static Application Security Testing (SAST)

This repository uses **GitHub CodeQL** for automated static application security testing. This document explains the security scanning configuration and design decisions.

## Why SAST?

This project bridges **memory-safe PHP** (web backend) with **memory-unsafe C++** (ESP firmware). Data flows from CiviCRM through PHP scripts to ESP devices, where it's parsed using C string functions. Without bounds checking, this creates potential buffer overflow vulnerabilities.

### Identified Risk Areas

| Component | Risk | Severity |
|-----------|------|----------|
| `membercards.cpp:13-14` | `strcpy` without bounds checking | High |
| `membercards.cpp:87` | `sscanf` with unbounded `%s`/`%[^|]` | High |
| `fetch.php` → ESP | CiviCRM data parsed as C strings | Medium |

## Configuration Overview

```
.github/
├── codeql/
│   ├── codeql-config.yml      # Main CodeQL configuration
│   └── queries/
│       ├── qlpack.yml         # Query pack definition
│       ├── unsafe-strcpy.ql   # Detects strcpy with external data
│       ├── unsafe-sscanf.ql   # Detects unbounded format specifiers
│       └── fixed-buffer-risk.ql # Detects fixed buffers + dangerous functions
└── workflows/
    └── codeql-analysis.yml    # GitHub Actions workflow
```

## Design Decisions

### Why `ubuntu-latest`?

CodeQL requires a full Linux environment with:
- Pre-installed CodeQL CLI (~500MB)
- Sufficient RAM for semantic analysis (~4GB)
- Disk space for code databases (~1GB per language)

GitHub-hosted `ubuntu-latest` runners include CodeQL tooling pre-installed. Lightweight alternatives (Alpine, minimal containers) are not available as GitHub-hosted runners, and self-hosted runners would require manual CodeQL installation.

**For public repositories, `ubuntu-latest` is free with unlimited minutes.**

### Why Custom Queries?

The default CodeQL security queries are excellent for general vulnerabilities, but this codebase has specific patterns:

1. **`unsafe-strcpy.ql`**: Standard queries detect `strcpy`, but don't trace data flow from configuration parameters. This custom query specifically tracks `groups` and `host` parameters through to `strcpy` calls.

2. **`unsafe-sscanf.ql`**: Detects `sscanf` format strings like `%s` and `%[^|]` that lack field width limits. The pattern `sscanf(l.c_str(), "%d|%[^|]|%s", &id, name, card)` is flagged because `%[^|]` and `%s` can overflow `char name[40]` and `char card[40]`.

3. **`fixed-buffer-risk.ql`**: Identifies the specific fixed-size buffers declared in `membercards.h` and cross-references with dangerous function usage.

### Why Both C++ and PHP?

The workflow scans both languages because:

- **C++**: ESP firmware contains the buffer overflow risks
- **PHP**: While memory-safe, PHP still has injection risks (SQL, command, XSS) worth scanning

### Trigger Conditions

```yaml
on:
  push:
    paths:
      - 'config/components/**'  # ESP C++ code
      - 'web/**'                # PHP backend
  schedule:
    - cron: '0 0 * * 0'         # Weekly full scan
```

Scans only run when security-relevant code changes, reducing unnecessary workflow runs.

## Limitations

### ESP/Arduino Build Environment

Full CodeQL analysis requires compiling the code to build a complete semantic database. ESP/Arduino code requires PlatformIO and ESP-IDF toolchains that aren't installed on standard GitHub runners.

**Current approach**: Source-level analysis without full compilation. This still catches most string function vulnerabilities but may miss some data flow paths that depend on template instantiation.

**For complete coverage**, run CodeQL locally:
```bash
codeql database create lockout-db \
  --language=cpp \
  --source-root=config/components \
  --command="platformio run"

codeql database analyze lockout-db \
  .github/codeql/queries \
  --format=sarif-latest \
  --output=results.sarif
```

## Remediation Guidance

When CodeQL flags an issue, here are the recommended fixes:

### Unsafe `strcpy`
```cpp
// Before (vulnerable)
strcpy(this->groups, groups);

// After (bounded)
strncpy(this->groups, groups, sizeof(this->groups) - 1);
this->groups[sizeof(this->groups) - 1] = '\0';
```

### Unsafe `sscanf`
```cpp
// Before (vulnerable)
sscanf(l.c_str(), "%d|%[^|]|%s", &id, name, card);

// After (bounded)
sscanf(l.c_str(), "%d|%39[^|]|%39s", &id, name, card);
```

## Cost

| Repository Type | CodeQL Cost | Actions Minutes |
|-----------------|-------------|-----------------|
| Public | Free | Unlimited |
| Private | Requires GHAS license | 2,000/month free |

## References

- [CodeQL Documentation](https://codeql.github.com/docs/)
- [CWE-120: Buffer Copy without Checking Size of Input](https://cwe.mitre.org/data/definitions/120.html)
- [CWE-134: Use of Externally-Controlled Format String](https://cwe.mitre.org/data/definitions/134.html)
- [CWE-676: Use of Potentially Dangerous Function](https://cwe.mitre.org/data/definitions/676.html)
