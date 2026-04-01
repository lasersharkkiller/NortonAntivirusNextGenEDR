# NortonAntivirusNextGenEDR

A Windows kernel-mode EDR built on top of [BestEdrOfTheMarket v3](https://xacone.github.io/BestEdrOfTheMarketV3.html), extended with Sysmon integration, SACL-based auditing, and structured detection telemetry for defensive lab environments.

---

## Defensive Capabilities

### Kernel-Level Telemetry
- Kernel callbacks for process/thread creation, image loading, registry operations, and object access
- System call interception via alternative system call handlers with integrity checking
- VAD tree exploitation for image integrity verification
- Shadow Stack verification for thread call stack integrity
- Code injection detection via thread call stack inspection

### Detection Engine
- YARA rule engine with recursive auto-loading from configurable paths
- Sigma-Lite rule support with full boolean logic (`selection`, `filter`, `1 of`, `all of`, `and`, `or`, `not`) and string operators (`contains`, `contains|all`, `startswith`, `endswith`)
- LOLDrivers detection via cached JSON database
- Deterministic severity scoring with live UI security score
- PID-level short-window correlation alerts across detection methods

### Sysmon & SACL Integration
- Sysmon event ingestion for host-based telemetry enrichment
- SACL (System Access Control List) auditing for object-level access visibility
- Process context cache enrichment: parent PID and image path appended to detection details

### Logging & API
- Persistent JSONL telemetry logging to `beotm_events.jsonl`
- Trace targeting (`--trace`) with optional child-process inheritance (`--trace-children`)
- Local REST API on `127.0.0.1` — endpoints: `/api/stats`, `/api/events`, `/api/processes`, `/api/reset`

---

## Requirements

- Windows 10 20H1–22H2 test VM in `TESTSIGNING` mode
- Visual Studio 2022, C++20, WDK
- vcpkg with `yara` package installed

---

## Disclaimer

For educational and controlled lab use only.
