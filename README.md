# NortonAntivirusNextGenEDR

A Windows kernel-mode EDR built on top of [BestEdrOfTheMarket v3](https://xacone.github.io/BestEdrOfTheMarketV3.html), extended with Sysmon integration, SACL-based auditing, hook detection, and structured detection telemetry for defensive lab environments.

---

## Defensive Capabilities

### Kernel-Level Telemetry
- Kernel callbacks for process/thread creation, image loading, registry operations, and object access
- System call interception via alternative system call handlers with integrity checking
- VAD tree exploitation for image integrity verification
- Shadow Stack (CET) verification for thread call stack integrity
- Code injection detection via thread call stack inspection

### Hook Detection
- **SSDT integrity** — baseline snapshot of `nt!KiServiceTable` taken at driver load; subsequent scans compare live entries against the snapshot and alert on any modified syscall dispatch pointer
- **Inline hooks** — prologue scan across all ntoskrnl exports detecting `JMP near` (E9), `JMP far` (FF 25), `MOV RAX + JMP RAX` (48 B8 … FF E0), and `PUSH + RET` (68 … C3) trampoline patterns
- **EAT hooks** — export address table walk of the kernel module; flags any EAT entry whose resolved address falls outside the module's image bounds
- **ETW hooks** — prologue scan of `EtwWrite`, `EtwWriteEx`, `EtwWriteTransfer`, and `EtwRegister`; detects inline patches used to silence kernel telemetry
- **Alt syscall handler integrity** — resolves `PspAltSystemCallHandlers` via the same `LEA R14,[RIP+]` scan used at registration; verifies slot 1 still points to the driver's `SyscallHandler` and alerts if it has been nulled out or replaced

All hook detections emit a `KERNEL_STRUCTURED_NOTIFICATION` with severity Critical, the hooked address, hook type, and resolved trampoline target into the driver's notification queue.

### Process & PE Scanning
- **Reflective DLL injection** — VAD tree walk on every new process; flags private executable regions containing an MZ/PE header that have no file backing
- **Anonymous RWX regions** — same VAD walk flags private `EXECUTE_READWRITE` regions with no PE header as shellcode staging areas
- **PE header in protect buffer** — `NtProtectVirtualMemory` hook checks the region content when memory is made executable; alerts if an MZ/PE header is present
- **Cross-process PE write** — `NtWriteVirtualMemory` hook checks written data for an MZ/PE signature on remote writes (process injection in progress)
- **Process ghosting** — `SeAuditProcessCreationInfo` null-check detects processes launched from deleted files
- **PPID spoofing** — parent PID vs. creating thread process mismatch detected at process creation
- **Process hollowing** — VAD/LDR cross-check verifies the main image VAD start address matches the PEB loader entry

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
