# Mobile Sentinel

[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Target Platform](https://img.shields.io/badge/platform-Android%20%7C%20Flutter-brightgreen.svg)](https://flutter.dev)
[![Architecture](https://img.shields.io/badge/architecture-Local--First%20%7C%20Deterministic-orange.svg)]()
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Mobile Sentinel** is a production-quality, local-first automated security and QA auditing platform designed for Android and Flutter mobile applications (`.apk`).

It executes deterministic, reproducible, end-to-end evaluations across static security, exposed attack surface, hardcoded secrets, runtime stability, autonomous UI exploration, UX quality, and accessibility standards — running entirely on your local machine with zero external cloud dependencies or telemetry.

---

## Table of Contents

- [Key Capabilities](#key-capabilities)
- [10-Step Pipeline Architecture](#10-step-pipeline-architecture)
- [System Requirements](#system-requirements)
- [Installation & Setup](#installation--setup)
- [CLI Reference & Usage](#cli-reference--usage)
  - [`sentinel doctor`](#1-system-diagnostics-sentinel-doctor)
  - [`sentinel devices`](#2-device-enumeration-sentinel-devices)
  - [`sentinel test`](#3-automated-security--qa-audit-sentinel-test)
  - [`sentinel version`](#4-version-information-sentinel-version)
- [Testing Authenticated Applications](#testing-authenticated-applications)
- [Safety Model & Policy Enforcement](#safety-model--policy-enforcement)
- [Risk Scoring Engine](#risk-scoring-engine)
- [Generated Reports & Evidence](#generated-reports--evidence)
- [Repository Structure](#repository-structure)
- [Development & Testing](#development--testing)
- [License](#license)

---

## Key Capabilities

### 1. Autonomous UI State Graph Exploration
- **State Machine Discovery**: Dynamically traverses application screens using UI hierarchy dumps (`uiautomator`) to build a deterministic directed graph of screen states (`ScreenState`) and transitions (`StateTransition`).
- **Normalized Spatial Fingerprinting**: Normalizes element bounding boxes into spatial grid coordinates to prevent duplicate states caused by minor layout shifts or rendering animations.
- **Interactive Element Classification**: Recognizes buttons, input fields, password inputs, tabs, navigation drawers, scrollable containers, switches, checkboxes, and dialogs.
- **Resilient Focus Guarding**: Automatically detects foreign overlay dialogs (such as system permission prompts or system ANR dialogs) and dismisses them to keep the target application in the foreground.

### 2. Safe Authentication & Wizard Handling
- **Onboarding Flow Advancement**: Automatically detects intro wizards, tutorials, and multi-step onboarding flows, progressing past them via detected "Next", "Continue", or "Skip" actions.
- **Login & Registration Detection**: Identifies login and signup screens by analyzing password fields, email/username inputs, and submission buttons.
- **Credential Injection**: Supports authorized test credentials provided via YAML with zero plaintext leakage in test output or logs.
- **Multi-Signal Verification**: Verifies login success through multiple indicators: disappearance of password fields, change in screen signature, and emergence of authenticated dashboard states.
- **Transparent Fallback**: When credentials are not provided for a protected app, Sentinel reports authentication as `BLOCKED (No authorized test credentials supplied)` while safely exploring all reachable unauthenticated routes.

### 3. Safety Model & Policy Enforcement
- **Action Tiering**: Classifies every interactive action into `SAFE`, `CAUTION`, or `DESTRUCTIVE`.
- **Destructive Action Protection**: Operations matching destructive patterns (e.g., account deletion, data reset, factory restore, logout, payment processing, fund transfers) are **discovered and audited but excluded from execution** (`DISCOVERED_NOT_EXECUTED`), preventing state corruption or accidental data loss.

### 4. Comprehensive Static Security Analysis
- **Manifest Audit (`android_manifest`)**: Evaluates `AndroidManifest.xml` for exported activities, broadcast receivers, background services, and content providers; audits deep links, intent filters, `android:debuggable`, `android:allowBackup`, and verifies target SDK posture against current platform baselines (SDK 34+).
- **Permissions Classification**: Categorizes declared permissions into Normal, Dangerous (e.g., Camera, Location, Contacts, SMS), and Special/Signature (e.g., System Alert Window, Install Packages, Accessibility Service).
- **High-Entropy Secret Scanner (`secret_scanner`)**: Scans compiled binaries, assets, and dex files using regular expressions and Shannon entropy calculation for cloud API keys (Google Maps/Cloud, AWS Access Keys, GitHub Personal Access Tokens, Firebase database URLs, private key blocks, and hardcoded database connection URIs).
- **Flutter Framework Detection (`flutter_detector`)**: Identifies Flutter engines (`libflutter.so`), inspects Dart compilation mode (AOT Release vs Debug / JIT via `libapp.so` and `kernel_blob.bin`), and catalogs embedded asset manifests.
- **Network Configuration Audit (`network_analyzer`)**: Discovers cleartext `http://` URLs embedded in binaries and dex files, and flags internal/development endpoints (`localhost`, `127.0.0.1`, `10.0.2.2`).

### 5. Runtime Stability & Performance Monitoring
- **Real-Time Logcat Inspection**: Filters up to 6,000 logcat lines per run specifically for the target application process.
- **Crash & Exception Fingerprinting**: Automatically captures and deduplicates fatal Java exceptions (`AndroidRuntime: FATAL EXCEPTION`), native signals (`SIGSEGV`, `SIGABRT`), and Dart/Flutter runtime errors (`FlutterError`, `Unhandled Exception`).
- **ANR Detection**: Tracks Application Not Responding events and input dispatching timeouts.
- **UI Thread Jank Tracking**: Tracks Android choreographer frame drops (`Skipped XX frames!`) and generates audit findings when main-thread blockages exceed acceptable thresholds (>300 frames).
- **Memory Profiling**: Captures target package memory consumption via `dumpsys meminfo` (Java Heap, Native Heap, Total PSS).
- **Network Resilience Testing**: Toggles device Wi-Fi and mobile data to evaluate application offline handling and reconnection behavior.

### 6. Accessibility & UI/UX Auditing
- **Touch Target Sizing**: Identifies interactive components failing Google's 48x48dp minimum physical touch target standard (`TOUCH_TARGET_TOO_SMALL`).
- **Semantic Labels**: Detects clickable elements that lack `contentDescription` or visible text, impairing screen readers (`MISSING_ACCESSIBILITY_LABEL`).

### 7. Strict Target Isolation
- **Single-Target Lock**: Every scan operates strictly on one APK and one target package at a time. The ADB controller enforces package boundaries and raises a `TargetPackageViolation` if any operation attempts to manipulate an unauthorized application or OS process.
- **Automated Cleanup**: Test applications are cleanly stopped and completely uninstalled upon scan completion (unless `--keep-installed` is specified).

---

## 10-Step Pipeline Architecture

Mobile Sentinel runs an automated, end-to-end 10-step pipeline when testing an application:

```text
       Target Android APK
               │
               ▼
┌──────────────────────────────────────────────────────────┐
│ [1/10] APK Validation & Metadata Extraction              │
│        - SHA-256 hash, package name, SDKs, badging       │
│        - Enforces strict target package isolation lock   │
└──────────────────────────────┬───────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────┐
│ [2/10] Android Device & Environment Detection            │
│        - Queries ADB, device model, Android OS version   │
└──────────────────────────────┬───────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────┐
│ [3/10] Clean Package Installation                        │
│        - Installs APK and verifies package registration  │
└──────────────────────────────┬───────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────┐
│ [4/10] Application Launch & Foreground Verification      │
│        - Cold start launch, polls process until settled  │
└──────────────────────────────┬───────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────┐
│ [5/10] Static Security Analysis                          │
│        - Manifest, permissions, secrets, Flutter, network│
└──────────────────────────────┬───────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────┐
│ [6/10] Authentication & Credential Inspection            │
│        - Detects login requirements & loads credentials  │
└──────────────────────────────┬───────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────┐
│ [7/10] Autonomous UI Exploration & State Graph           │
│        - Traverses screens, tabs, menus, tests forms     │
│        - Evaluates accessibility & classifies safety     │
└──────────────────────────────┬───────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────┐
│ [8/10] Runtime Monitoring                                │
│        - Captures logcat, crashes, ANRs, frame skips, mem│
└──────────────────────────────┬───────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────┐
│ [9/10] Deterministic Multi-Category Risk Scoring         │
│        - Calculates Security, Stability, UX, A11y scores │
└──────────────────────────────┬───────────────────────────┘
                               │
┌──────────────────────────────▼───────────────────────────┐
│ [10/10] Report & Evidence Generation                     │
│         - Generates report.txt, report.json, screenshots │
└──────────────────────────────────────────────────────────┘
```

---

## System Requirements

| Dependency | Minimum Version | Recommended | Notes |
| :--- | :--- | :--- | :--- |
| **Python** | 3.11+ | Python 3.14 | Modern typing & dataclass support |
| **Android SDK** | platform-tools (`adb`) | Latest | Found on PATH or under `ANDROID_HOME` / `ANDROID_SDK_ROOT` |
| **Android Build Tools** | `aapt` | Latest | For fast manifest & resource extraction |
| **Android Device / Emulator** | Android 7.0+ (API 24+) | Android 14 (API 34) | Connected and authorized via `adb devices` |
| **Java** | JRE/JDK 17+ | OpenJDK 17 / Android Studio JBR | Optional; used for extended static tooling |
| **Flutter SDK** | Optional | Stable channel | Helpful for Flutter project context |

---

## Installation & Setup

### 1. Clone the Repository
```bash
git clone https://github.com/your-org/testing_pipeline.git
cd testing_pipeline
```

### 2. Set Up a Virtual Environment
```bash
# Create virtual environment
python -m venv .venv

# Activate on Linux / macOS:
source .venv/bin/activate

# Activate on Windows (PowerShell):
.venv\Scripts\Activate.ps1

# Or Windows (Command Prompt):
.venv\Scripts\activate.bat
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
pip install -e .
```

### 4. Verify Local Environment
Run the built-in diagnostic tool:
```bash
sentinel doctor
```

You should see a status report confirming Python, ADB, Android SDK, and Java readiness.

---

## CLI Reference & Usage

Mobile Sentinel provides a Click-based command-line interface via the `sentinel` executable or via `python -m sentinel`.

### Global Options
```bash
sentinel --help              # Display available commands and global options
sentinel -v, --version       # Show application version and exit
```

---

### 1. System Diagnostics: `sentinel doctor`
Evaluates local developer tooling, SDK locations, and readiness for static and runtime analysis.

```bash
# Standard console report:
sentinel doctor

# Machine-readable JSON output:
sentinel doctor --json-output
```

**Diagnostic Checks**:
- Python runtime version & platform
- Android Debug Bridge (`adb`) availability and version
- Android SDK path (`ANDROID_HOME` / `ANDROID_SDK_ROOT`), `platform-tools`, and `build-tools`
- Java runtime (`JAVA_HOME` or Android Studio JBR)
- Flutter SDK presence and version

---

### 2. Device Enumeration: `sentinel devices`
Lists all connected Android emulators and physical hardware devices, including their Android OS versions and device models.

```bash
sentinel devices
```

Example Output:
```text
Connected Android Devices:
  - emulator-5554      (Android 14, sdk_gphone64_x86_64)
```

---

### 3. Automated Security & QA Audit: `sentinel test`
Runs the complete automated 10-step audit against a target APK.

```bash
sentinel test <APK_PATH> [OPTIONS]
```

#### Command Options & Flags:

| Option | Flag | Description | Default |
| :--- | :--- | :--- | :--- |
| `--output` | `-o` | Base directory for generated reports and evidence | `reports` |
| `--auth-config` | `-a` | Path to authorized test credentials YAML configuration | Auto-discovered from `config/` |
| `--no-ui` | | Skip dynamic UI exploration (runs static analysis, cold-start launch & runtime monitoring only) | `False` |
| `--no-network` | | Skip offline network toggle resilience test | `False` |
| `--keep-installed` | | Retain test application on device after completion (skips cleanup uninstall) | `False` |

#### Real-World Examples:

```bash
# 1. Test Card Vault (credentials auto-discovered from config/card-vault-auth.yaml):
sentinel test "D:\card_vault\build\app\outputs\flutter-apk\app-release.apk"

# 2. Test Aurum with custom report output directory:
sentinel test "D:\Aurum\build\app\outputs\flutter-apk\app-release.apk" --output "custom_reports"

# 3. Explicit credentials configuration:
sentinel test "path/to/app.apk" --auth-config "config/my-app-auth.yaml"

# 4. Fast static & runtime launch audit without UI exploration:
sentinel test "path/to/app.apk" --no-ui

# 5. Keep APK on device after testing for manual verification:
sentinel test "path/to/app.apk" --keep-installed

# 6. Run via Python module directly:
python -m sentinel test "path/to/app.apk"
```

---

### 4. Version Information: `sentinel version`
Displays detailed version and operational mode information.

```bash
sentinel version
```

---

## Testing Authenticated Applications

Mobile Sentinel intelligently handles applications that require authentication.

### Auto-Discovery Mechanism
When running `sentinel test path/to/app.apk`, Sentinel inspects the application label (e.g., "Card Vault") and looks for a corresponding configuration in the `config/` directory:
```text
config/<slugified-app-name>-auth.yaml
(e.g., config/card-vault-auth.yaml)
```

If found, it loads the credentials automatically without requiring the `--auth-config` flag.

### Setting Up Credentials
1. Copy the example configuration template:
   ```bash
   cp config/card-vault-auth.example.yaml config/card-vault-auth.yaml
   ```

2. Populate with authorized test account credentials:
   ```yaml
   # config/card-vault-auth.yaml
   auth:
     email: "authorized-tester@example.com"
     password: "YourSecureTestPassword123!"
   ```

### Security & Privacy Protections
- **Zero Credential Leaking**: Passwords and secret values are scrubbed and replaced with `[REDACTED]` in reports, state graphs, and logs.
- **Git Ignored**: All local configuration files matching `config/*-auth.yaml` are ignored by `.gitignore` to prevent committing sensitive passwords.
- **Unauthenticated Safe Exploration**: If no credentials are supplied for an authenticated app, Sentinel explores all available unauthenticated screens (e.g., login, registration, password reset, help) and reports authentication status as `BLOCKED (No authorized test credentials supplied)`.

---

## Safety Model & Policy Enforcement

To prevent accidental data loss, account destruction, or external financial operations during autonomous exploration, Mobile Sentinel classifies every discovered interactive UI control into three safety tiers:

| Tier | Matching Action Patterns | Exploration Policy |
| :--- | :--- | :--- |
| **SAFE** | Navigation buttons, tabs, menu items, drawers, back/home buttons, onboarding skip/next/continue, non-sensitive form input fields. | **Executed automatically** during state graph traversal. |
| **CAUTION** | Save, edit, update, upload, export, share, submit, apply, confirm. | **Executed selectively** when non-destructive. |
| **DESTRUCTIVE** | Delete, remove, erase, clear all, clear data, factory reset, purge, destroy, unlink, logout, sign out, close account, delete account, buy, payment, checkout, pay now, transfer funds, withdraw. | **Excluded by default** (`DISCOVERED_NOT_EXECUTED`). Logged in reports with location and evidence. |

---

## Risk Scoring Engine

Mobile Sentinel calculates transparent, bounded scores (0–100) across six dedicated categories, combining them into a weighted overall score:

### Category Weights

| Category | Weight | Description |
| :--- | :--- | :--- |
| **Security Score** | 35% | Static manifest risks, exported components, permissions, hardcoded secrets, network cleartext. |
| **Stability Score** | 25% | Fatal runtime crashes, native signals, ANRs, unhandled Dart exceptions. |
| **Performance Score** | 15% | Main-thread frame drops (choreographer frame skips > 300) and excessive resource lag. |
| **Configuration Score** | 10% | Target SDK compliance (<34), backup flags, debuggable build mode, framework flags. |
| **UX Score** | 8% | Screen traversal depth, navigation flow health, blocked screens. |
| **Accessibility Score** | 7% | Touch targets below 48x48dp, interactive components missing semantic accessibility labels. |

$$\text{Overall Score} = (0.35 \times \text{Sec}) + (0.25 \times \text{Stab}) + (0.15 \times \text{Perf}) + (0.10 \times \text{Cfg}) + (0.08 \times \text{UX}) + (0.07 \times \text{A11y})$$

### Severity Penalty Deductions

- **CRITICAL**: -25.0 points
- **HIGH**: -12.0 points
- **MEDIUM**: -5.0 points
- **LOW**: -2.0 points
- **INFO**: 0.0 points

### Overall Risk Classification

- **CRITICAL**: Any Critical severity finding OR $\ge$ 3 High severity findings.
- **HIGH**: Any High severity finding OR $\ge$ 3 Medium severity findings.
- **MEDIUM**: Any Medium severity finding OR $\ge$ 5 Low severity findings.
- **LOW**: Low or minor findings only.

---

## Generated Reports & Evidence

All scan evidence and reports are structured cleanly per application under `reports/<app_name>/`:

```text
reports/
└── <app_name>/
    ├── report.txt          # Human-readable executive summary, metrics, and remediation guide
    ├── report.json         # Complete machine-readable data, state graph, and telemetry
    ├── screenshots/        # High-resolution PNG screenshots captured per screen transition
    │   ├── screen_01.png
    │   ├── screen_02.png
    │   └── ...
    ├── logs/
    │   └── logcat.log      # Complete runtime logcat stream filtered for the target process
    ├── metadata/
    │   └── metadata.json   # Scan timestamps, package hash, SDK versions, duration
    └── artifacts/          # Extracted APK artifacts (manifests, resources)
```

### Plain-Text Report (`report.txt`) Structure
1. **Header & Metadata**: Application label, package name, version, APK size, SHA-256 hash, device info, duration.
2. **Executive Summary**: Overall Risk Rating and individual scores (Security, Stability, Performance, UX, Accessibility).
3. **Exploration Summary**: Screens discovered, actions executed, screens fully tested, destructive controls excluded, screen/action coverage %.
4. **Severity Summary**: Counts of Critical, High, Medium, Low, and Info findings.
5. **Detailed Findings**: Each finding includes:
   - Unique Finding ID (e.g., `ANDROID_EXPORTED_ACTIVITY`, `SECRETS_AWS_ACCESS_KEY`, `A11Y-TOUCH_TARGET_TOO_SMALL`)
   - Severity & Confidence
   - Impact Assessment
   - Technical Evidence
   - Actionable Remediation Guidance

---

## Repository Structure

```text
testing_pipeline/
├── config/                         # Configuration templates and local auth files
│   ├── card-vault-auth.example.yaml # Credentials template
│   └── card-vault-auth.yaml        # Local test credentials (git-ignored)
├── reports/                        # Default output directory for scan reports
├── sentinel/                       # Core Mobile Sentinel package
│   ├── analyzers/                  # Static security & package analyzers
│   │   ├── android/                # Manifest & permission analyzer
│   │   ├── apk/                    # APK extraction & badging parser
│   │   ├── flutter/                # Flutter engine & build mode detector
│   │   ├── network/                # Cleartext HTTP & endpoint scanner
│   │   └── secrets/                # High-entropy secret & regex scanner
│   ├── cli/                        # Command-line interface commands & options
│   │   └── main.py                 # Click entry point (sentinel / test / doctor / devices)
│   ├── core/                       # Data models, enumerations, exceptions, logging
│   │   ├── enums.py                # Severity, FindingCategory, ToolStatus
│   │   ├── exceptions.py           # Custom Sentinel exceptions
│   │   ├── logging.py              # Log formatting & output handlers
│   │   └── models.py               # Finding, ScanMetadata, RiskScoreSummary
│   ├── environment/                # System diagnostics & dependency detection
│   │   └── doctor.py               # EnvironmentDoctor implementation
│   ├── orchestrator/               # Pipeline execution coordinator
│   │   └── pipeline.py             # 10-step ScanPipeline & progress runner
│   ├── reporting/                  # Output report rendering
│   │   ├── json_report.py          # Structured JSON generator
│   │   └── text_report.py          # Plain-text executive summary generator
│   ├── risk/                       # Deterministic scoring engine
│   │   └── scoring.py              # RiskScoringEngine implementation
│   ├── runtime/                    # Low-level device interactions & monitors
│   │   ├── adb.py                  # ADBController & single-package isolation guard
│   │   └── monitor.py              # Logcat runtime monitor, crash & ANR detector
│   └── ui_testing/                 # Autonomous UI exploration engine
│       ├── auth.py                 # Authentication manager & credential injector
│       ├── explorer.py             # Frontier-based UI state graph explorer
│       ├── hierarchy.py            # XML view hierarchy parser & touch target auditor
│       ├── models.py               # ScreenState, UIElement, UIAction, StateGraph
│       └── safety.py               # Control safety classifier (SAFE/CAUTION/DESTRUCTIVE)
├── tests/                          # Test suite
│   └── unit/                       # Unit tests (ADB, CLI, Analyzers, Isolation, Explorer)
├── HOW_TO_TEST.txt                 # Step-by-step application testing cheat sheet
├── pyproject.toml                  # Build system & package metadata (PEP 517/621)
├── requirements.txt                # Production dependencies
└── README.md                       # Platform documentation
```

---

## Development & Testing

Run the automated unit test suite using `pytest`:

```bash
# Run all unit tests:
pytest

# Run with verbose output:
pytest -v

# Run a specific test module:
pytest tests/unit/test_cli.py
pytest tests/unit/test_ui_testing.py
pytest tests/unit/test_isolation.py
```

---

## License

This project is licensed under the MIT License - see the `pyproject.toml` specification for details.
