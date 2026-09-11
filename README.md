# Essential (Toolbox)

[English](README.md) | [简体中文](README_zh.md)

Version: 0.4.3

## Overview

Essential (Toolbox) is a native Windows toolbox built with WinUI 3. Its core execution pipeline is: Codex / Pi → Task-specific AGENTS.md → Analysis Summary → Actionable Recommendations. Currently, it provides Security Audit: Extended mode runs by default under standard user privileges to collect logs and call the configured AI Hub; Full-access mode requests elevation to inspect the Security log and firewall audits.

## 0.4.3 Release Entry

The release distribution package is located at `artifacts\publish\Essential-0.4.3-x64.zip`. Unpack it completely and launch `Essential.exe` normally (do not copy the executable in isolation). The x64 distribution embeds .NET and Windows App SDK runtime dependencies, requiring no administrator setup. Legacy assistant or unconfigured modes automatically migrate to extended mode; HTTP kernel selections migrate to Codex; existing endpoints and audit history are fully preserved.

The Issue Overview provides a "Priority view / All findings" switch. Priority view highlights the top five findings and shows their percentage relative to the total; All findings expands categories, and changing log source or severity filters automatically expands matching items. You can search by event ID, provider name, or title text (e.g., `WindowsUpdateClient 20`, `Volsnap`, or `36`; purely numeric queries perform exact Event ID matching).

"Settings → AI Analysis" offers Codex and Pi CLI kernels, supporting installation, update downloads, and checking official releases. "Download or update" probes the local CLI version against official release metadata, skipping download if the local version is identical or newer. Updates are validated via SHA-256 and CLI version checks before replacing the installed binaries; Pi also installs required runtime themes and assets. Transient file locks upon CLI exit are handled with bounded retries, preserving previous installations upon failure. Codex utilizes the Responses API; Pi supports both Responses and Chat Completions. The application provisions an isolated ephemeral configuration for each invocation, honoring selected models and reasoning efforts, and cleans up temporary directories upon completion.

Connection testing exercises the selected kernel and endpoint with a minimal payload. The left-hand sidebar displays test and scan progress, status, and token usage (showing actual input/output numbers when returned by the kernel, or estimated input before completion). Codex reconnection and error states are surfaced in real time, with retries managed by Codex itself; results are accepted only upon receiving a complete terminal event. Feedback banners in Settings stay pinned at the top while scrolling through configuration fields.

"Settings → Hub" manages AGENTS.md policies per task; currently offering the Security Audit rule card, with the editor collapsed by default. Navigation items and Hub rule cards share the same task identifier (`security-audit`), allowing Codex / Pi to load corresponding task rules to generate summaries and actionable advice. Policies persist to `%LOCALAPPDATA%\LocalSecurityAudit\chains\security-audit\AGENTS.md`. Legacy shared AGENTS.md or customized rules in settings are migrated on first launch, keeping original files intact. Resetting AI connection settings preserves audit rules. Each audit request writes the active policy and contract into an isolated execution directory loaded via the standard Codex/Pi pipeline.

The navigation sidebar features native WinUI 3 top-aligned collapse toggling, with Security Audit positioned at the top and Settings at the bottom. When collapsed, clicking the Token icon displays total and cyclical usage. Token usage is viewable even when idle; "Settings → Appearance → Token display cycle" allows toggling between local calendar Day, Monday-aligned Week, or Month. Only kernel-reported actual tokens are counted, deduplicated per request, and recorded in the SQLite `TokenUsage` table, surviving app restarts and audit history retention cleanups. Scans, connection tests, historical translations, and failed requests that returned token counts are included; input estimations are excluded.

Codex communicates with AI Hub using the standard Responses protocol. The application exports built-in model catalogs from the installed kernel and configures `model_catalog_json` to disable internal Responses-Lite. This preserves model parameters, reasoning efforts, AGENTS.md loading, and streaming retries, preventing `unsupported_value` errors on public reverse proxies caused by internal Lite headers and reasoning context combinations.

"Settings → Mode" allows choosing between Extended or Full-access mode, followed by "Save and Exit" and launching normally. Only Full-access mode requests UAC approval for the current Windows account; cancelling drops back to Extended mode without altering startup preferences. Extended mode operates under standard privileges. Configured API credentials are passed strictly via child process environments, with diagnostic logs redacting sensitive keys and logging execution status, models, and error summaries.

Only a single application instance is allowed per Windows user session; Debug/Release builds, different directories, and different modes share a unified single-instance mutex. Launching an additional instance activates and restores the existing window instead of creating duplicates. Completely exit older versions (including tray icons) before upgrading.

| Mode | Behavior | Database (Relative to Data Directory) |
| --- | --- | --- |
| Extended (default) | Standard user privileges, skips Security, collects 4 log channels and calls AI Hub | `audit_data.db` (reuses existing database) |
| Full-access | Same-account UAC approval, collects 5 log channels (including Security) and calls AI Hub | Shared with Extended (`audit_data.db`) |

Application executable: `Essential.exe`. Continues using existing data directories, settings, kernels, history, and single-instance identity.

Data directory defaults to `%LOCALAPPDATA%\LocalSecurityAudit`. New audit records write to `audit_data.db`; legacy `assistant\audit_data.db` acts solely as a format-validated, read-only historical source without modifying existing entries.

The application directory houses only executables, runtime dependencies, and assets. User settings (`settings.json`), audit policies (`chains\security-audit\AGENTS.md`), optional credentials (`API.txt`), and `diagnostic.log` reside in the user data directory. Build outputs are unified under `artifacts`: `bin` for executables, `obj` for build caches, and `publish` for versioned distribution packages. Debug and Release maintain dedicated output folders. Debug can optionally package kernel ZIPs; Release and publish packages omit kernel archives and retired external tools.

## Key Features

- **Automatic Audit (Extended / Full-access)**: Automatically runs scheduled audits every 4 hours.
- **Log Collection & Analysis**: Collects Application, Setup, System, and ForwardedEvents by default; Full-access adds Security and Firewall/WFP audits. Respects security event ID whitelists and Critical / Error / Warning filters for other channels; capped at 2,000 events per channel with truncation indicators.
- **AI-Driven Analysis**: Supports gpt-5.6-luna / terra / sol, gpt-6-astra, and gateway alias gpt-5.6, unified with 256k context; respects reasoning effort configurations.
- **Model Progression**: Strict model hierarchy: Luna < Terra < Sol < Astra. Higher-tier models replace lower-tier results only for their fully analyzed timeframes and log channels; lower or equal tiers append incrementally. Unknown models and partial coverage do not overwrite known findings.
- **Security Audit Dashboard**:
  - Health card displays score (0-100), High / Medium / Low counts, and priority recommendations; retains All / 30D / 7D audit counts, cumulative findings, active days, and scope-specific averages.
  - Date selector and historical statistics periods partition views; daily-scope and full-scope averages compute independently.
  - Calendar picker reviews the latest audit for selected dates; filters for log sources, severities, and actionable advice are centrally organized.
- **Automatic Refresh**: Automatically surfaces latest valid audits, bypassing damaged records; updates immediately upon scan completion or bilingual back-translation.
- **Data Retention (Extended Mode)**: Retains the latest 30 local calendar days by default (migrates legacy 7-day settings to 30 days on first launch); read-only legacy databases are excluded from pruning.
- **Mica Styling**: Modernized user experience utilizing Windows 11 Mica material, adapting dynamically to system dark/light themes.

Activity statistics include the current day; "All" covers all retained history, counting repeated issues per audit. Health averages align with the selected audit: daily scope excludes Security, and full scope includes only complete assessments; unassessed records show no score.

Fast Scan and Full Scan advance incrementally from the latest valid `ScanEnd`; initial scans or model upgrades cover the selected 1d / 2d / 1w timeframe. Model tiers do not degrade from subsequent lower-tier runs; unscanned gaps prior to lookback windows are retained. Full-access progress with Security is tracked separately; query failures or truncations do not advance cursors.

Scans with zero events skip AI invocations, displaying "No AI analysis" and the reason in the sidebar. After switching kernels and saving settings, the context menu next to the scan button ("⋯ → Reanalyze selected range") allows reanalyzing the chosen 1d / 2d / 1w timeframe with the new kernel while backfilling older unscanned gaps. This action clears the analysis cache for that range.

Change history: [docs/CHANGES.md](docs/CHANGES.md); Event ID reference: [docs/EVENT_ID_REFERENCE.md](docs/EVENT_ID_REFERENCE.md).

## Technology Stack

- **UI Framework**: WinUI 3 (Windows App SDK 1.4)
- **Architecture**: MVVM (CommunityToolkit.Mvvm)
- **Database**: SQLite (Microsoft.Data.Sqlite)
- **Charts**: LiveCharts2
- **Dependency Injection**: Microsoft.Extensions.DependencyInjection
- **AI API**: OpenAI-compatible interfaces (Responses / Chat Completions)

## Project Structure

```
Essential/
├── Models/                  # Data models
│   ├── SecurityEvent.cs     # Event log model
│   ├── AuditIssue.cs        # Audit finding model
│   ├── AuditResult.cs       # Audit result model
│   ├── HubTaskCatalog.cs    # Hub task definitions & catalog
│   ├── AiKernelCatalog.cs   # Codex and Pi kernel catalog
│   └── AppSettings.cs       # Application settings & audit policy fields
├── Services/                # Core business services
│   ├── EventLogService.cs   # Windows event log reader
│   ├── AiAnalysisService.cs # AI analysis service (Codex/Pi invocation & parsing)
│   ├── KernelManagerService.cs # Kernel management, downloads & updates
│   ├── DataStorageService.cs # SQLite storage & TokenUsage table
│   ├── AuditSchedulerService.cs # Audit scheduler & background status
│   └── SettingsService.cs   # Settings & Hub policy persistence
├── ViewModels/              # MVVM ViewModels
│   ├── MainViewModel.cs     # Main navigation, single instance & Token display
│   ├── DashboardViewModel.cs # Unified security audit ViewModel
│   └── SettingsViewModel.cs # Hub policy, AI analysis & settings ViewModel
├── Views/                   # XAML views
│   ├── MainWindow.xaml      # Main window (collapsible sidebar & status bar)
│   ├── DashboardPage.xaml   # Unified security audit page (score card & filters)
│   ├── SettingsPage.xaml    # Hub, kernel & application settings
│   ├── FindingDetailsDialog.xaml # Finding detail & event evidence dialog
│   └── TrayIcon.cs          # System tray icon & context menu
├── Helpers/                 # Utility helpers
│   ├── EventLogParser.cs    # Event log parser
│   └── Converters.cs        # XAML value converters
├── docs/                    # Change logs (CHANGES.md) & event references (EVENT_ID_REFERENCE.md)
├── tools/                   # Development, testing & regression scripts
├── artifacts/               # Generated build artifacts (not tracked in Git)
│   ├── bin/x64/Debug/       # Debug binaries
│   ├── bin/x64/Release/     # Release binaries
│   ├── obj/                # NuGet & build cache
│   └── publish/            # Versioned publish packages & ZIPs
├── Directory.Build.props    # Unified build output configuration
├── App.xaml                 # Application entry definition
└── LocalSecurityAudit.csproj # Project file (outputs Essential.exe)
```

## Build and Run

### Prerequisites

1. Windows 11 (recommended for Mica material; Windows 10 supported)
2. Visual Studio 2022 or higher
3. .NET 8 SDK
4. Windows App SDK 1.4 dependencies
5. Extended mode requires standard user privileges; Full-access mode requires same-account UAC approval

### Build Steps

1. Clone or open the repository.
2. Restore NuGet dependencies:
   ```powershell
   dotnet restore -p:Platform=x64
   ```

3. Build the project:
   ```powershell
   dotnet build --no-restore -p:Platform=x64 -c Release
   ```

4. Launch normally (runs saved mode, default Extended):
   ```powershell
   .\artifacts\bin\x64\Release\net8.0-windows10.0.19041.0\Essential.exe
   ```

Or via Visual Studio:
- Launch Visual Studio as a standard user
- Open `LocalSecurityAudit.csproj`
- Press F5 to run

Flags `--extended` / `--full` can override the launch mode for the current session without altering saved preferences.

### x64 Self-Contained Publishing

Run in Visual Studio Developer PowerShell (Win2D uses `win10-x64` RID; compatible with Windows 10 and 11):

```powershell
MSBuild LocalSecurityAudit.csproj /restore /t:Publish /p:Configuration=Release /p:Platform=x64 /p:RuntimeIdentifier=win10-x64 /p:SelfContained=true /p:WindowsPackageType=None /p:PublishSingleFile=false /p:PublishTrimmed=false /p:PublishProfile= /p:PublishDir=artifacts\publish\Essential-0.4.3-x64
```

Distribute Visual Studio's `msvcp140.dll`, `vcruntime140.dll`, and `vcruntime140_1.dll` from `VC\Redist\MSVC\<version>\x64\Microsoft.VC*.CRT` alongside the binaries (do not copy from System32). Validate before packaging using `tools/test-publish.ps1 -PublishDirectory <Directory>`, and attach `-ZipPath <ZIP>` after archive creation.

### Synthetic Regression Tests (No Real Logs or Remote AI Calls)

```powershell
pwsh -NoProfile -File tools/test-modes.ps1
python tools/test-assistant-workflow.py
pwsh -NoProfile -File tools/test-history.ps1
pwsh -NoProfile -File tools/test-analysis.ps1
pwsh -NoProfile -File tools/test-ai-transport.ps1
pwsh -NoProfile -File tools/test-ai-kernels.ps1
pwsh -NoProfile -File tools/test-audit-policy.ps1
pwsh -NoProfile -File tools/test-bundled-kernels.ps1
pwsh -NoProfile -File tools/test-kernel-updates.ps1
pwsh -NoProfile -File tools/test-token-usage.ps1
pwsh -NoProfile -File tools/test-single-instance.ps1
pwsh -NoProfile -File tools/test-workflow.ps1
pwsh -NoProfile -File tools/test-workflow.ps1 -SimulateConcurrentEdit
pwsh -NoProfile -File tools/test-workflow-ui.ps1
```

PowerShell regressions load Debug by default; use `-AssemblyPath` to point to Release or self-contained publish outputs. Tests use synthetic logs, temporary folders, mock kernels, and loopback endpoints. UI regression compiles a separate test entry point in real WinUI windows to assert layouts and output screenshots without running background schedulers.

### API Configuration

Extended and Full-access modes require configuring an AI Hub under "Settings → AI Analysis" for Main and optional Fallback endpoints. Defaults can initialize from `%LOCALAPPDATA%\LocalSecurityAudit\API.txt`:

```
https://api.falsemeet.site
<your-api-key>
```

## Detailed Features

### Unified Security Audit Dashboard

- **Health Score**: 0-100 based on detected issue counts and severities:
  - High severity: -15 points per issue (capped at -60)
  - Medium severity: -6 points per issue (capped at -25)
  - Low severity: -1.5 points per issue, rounded away from zero (capped at -15)
  - Incomplete coverage or unanalyzed runs show no score; both modes share the same scoring logic, with daily scope excluding Security.
- **Finding List**: Details detected security concerns:
  - Description
  - Severity (High/Medium/Low)
  - Category (Login/Privilege/Firewall/System/etc.)
  - Root Cause Analysis
  - Remediation Advice
- **Manual Audits**: Trigger immediate audits via "Fast scan" or "Full scan".

### Audit Execution Pipeline

1. **Log Collection**: Incremental reads from shared progress cursors; initial runs or model upgrades use selected lookback windows.
   - Security (Full-access only): Logon, account/group, privilege, policy, and audit changes.
   - System / Application / Setup / ForwardedEvents: Critical, Error, and Warning events, including Kernel-Power 41.
   - Firewall (Full-access only): Events 5152, 5157, 4946-4950 from Security.

2. **AI Analysis**: Codex / Pi executes with Hub AGENTS.md rules, analyzing batches across Main and Fallback routes.

3. **Storage**: Persists to local SQLite databases.

4. **Automatic Retention**: Prunes data according to configured retention periods (default 30 local calendar days).

Progress percentages reflect completed log chunks, analysis batches, and lifecycle phases.

## Data Storage

Database locations:
```
%LOCALAPPDATA%\LocalSecurityAudit\audit_data.db
%LOCALAPPDATA%\LocalSecurityAudit\assistant\audit_data.db
```

Database Schema:
```sql
CREATE TABLE AuditResults (
    Id INTEGER PRIMARY KEY AUTOINCREMENT,
    Timestamp DATETIME NOT NULL,
    HealthScore INTEGER NOT NULL,
    FindingsJson TEXT NOT NULL,
    MetadataJson TEXT
);
CREATE INDEX idx_timestamp ON AuditResults(Timestamp DESC);

CREATE TABLE TokenUsage (
    RequestId TEXT PRIMARY KEY NOT NULL,
    Timestamp DATETIME NOT NULL,
    InputTokens INTEGER NOT NULL,
    OutputTokens INTEGER NOT NULL
);
CREATE INDEX idx_token_usage_timestamp ON TokenUsage(Timestamp);

CREATE TABLE ScanCheckpoints (
    Scope TEXT NOT NULL,
    ModelRank INTEGER NOT NULL,
    ScanEnd DATETIME NOT NULL,
    PRIMARY KEY (Scope, ModelRank)
);
```

## Security & Permissions

`app.manifest` defines `asInvoker`; the application window does not prompt for elevation. Only Full-access mode requests administrator authorization to access the Security channel. CLI kernel execution permissions remain isolated from Windows admin tokens.

## Known Limitations

1. Windows 11 required for Mica material (operates cleanly on Windows 10 without Mica).
2. Initial run requires downloading NuGet package dependencies.
3. AI analysis depends on network availability to configured endpoints; download kernels in Settings if missing.
4. Firewall logging may require enabling advanced Windows audit policies.

## Troubleshooting

### Cannot Read Event Logs
- Only Full-access requires confirming UAC. Extended mode intentionally skips Security; check channel coverage if other logs fail.
- Verify the Windows Event Log service (`EventLog`) is running.

### AI Analysis Failures
- Verify kernel selection, endpoint URLs, API mode, and keys under "Settings → AI Analysis", and run connection tests.
- Check network routing and proxy connectivity.
- Review detailed messages in `diagnostic.log`.

### Database Errors
- Confirm write permissions for `%LOCALAPPDATA%\LocalSecurityAudit`.
- Backup and inspect before repairing; avoid directly deleting audit databases.

## Roadmap

- [ ] Real-time event monitoring (EventLogWatcher)
- [ ] Additional customizable audit rules
- [ ] Export audit reports (PDF / Excel)
- [ ] Email and push notifications
- [ ] Multi-language UI support
- [x] Adaptive dark/light theme and logo tracking system appearance

## License

MIT License

## Contributing

Issues and Pull Requests are welcome!
