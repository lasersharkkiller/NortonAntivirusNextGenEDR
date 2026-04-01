# NortonAntivirusNextGenEDR

A Windows kernel-mode EDR extended with Sysmon integration, SACL-based auditing, hook detection, and structured detection telemetry for defensive lab environments.

---

## Defensive Capabilities

### Kernel-Level Telemetry
- Kernel callbacks for process/thread creation, image loading, registry operations, and object access
- System call interception via alternative system call handlers — active handlers: `NtAllocateVirtualMemory` (RWX), `NtWriteVirtualMemory`, `NtProtectVirtualMemory`, `NtReadVirtualMemory` (cross-process/lsass), `NtWriteFile`, `NtQueueApcThread`, `NtQueueApcThreadEx`, `NtSetContextThread`, `NtResumeThread`, `NtContinue` (private exec region)
- VAD tree exploitation for image integrity verification
- Shadow Stack (CET) verification for thread call stack integrity
- Code injection detection via thread call stack inspection
- **WFP network callout** — `FwpsCalloutRegister` + `FwpmFilterAdd` on `FWPM_LAYER_OUTBOUND_TRANSPORT_V4`; logs connection tuples and blocks configurable ports

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

### AMSI Integration

#### Kernel — Bypass Detection
- **AMSI export scan** — `ImageLoadNotifyRoutine` intercepts `amsi.dll` load events; immediately scans `AmsiScanBuffer`, `AmsiOpenSession`, `AmsiInitialize`, and `AmsiScanString` prologues for known bypass patches
- Detected patch patterns: `XOR EAX,EAX; RET` (33 C0 C3 / 31 C0 C3), `XOR RAX,RAX; RET` (48 31 C0 C3), `MOV EAX,0x80070057; RET` (E_INVALIDARG patch), `JMP near` trampoline, `JMP far` indirect redirect
- Detections emitted as `KERNEL_STRUCTURED_NOTIFICATION` with severity Critical and `AmsiBypassCheck` method flag

#### User-Mode — AMSI Provider (`AmsiProvider.dll`)
- COM in-process server implementing `IAntimalwareProvider` (CLSID `{C18BED31-4E42-4E0F-B00D-A7E3FE09E18D}`)
- Registered under `HKLM\SOFTWARE\Microsoft\AMSI\Providers\` — receives every `AmsiScanBuffer` call from PowerShell, VBScript, .NET, and other AMSI-aware hosts
- Keyword detection engine covers: Mimikatz invocations, credential-theft commands, PowerSploit/PowerView/BloodHound, AMSI bypass reflection patterns, shellcode stager strings, Meterpreter/Cobalt Strike indicators
- Self-registers via `regsvr32 AmsiProvider.dll`; self-unregisters via `regsvr32 /u AmsiProvider.dll`
- Logs detections to `norton_amsi_detections.log` alongside the binary

### Detection Engine
- YARA rule engine with recursive auto-loading from configurable paths
- Sigma-Lite rule support with full boolean logic (`selection`, `filter`, `1 of`, `all of`, `and`, `or`, `not`) and string operators (`contains`, `contains|all`, `startswith`, `endswith`)
- LOLDrivers detection via cached JSON database
- **Capa capabilities scanning** — on every kernel detection event, the flagged PE is submitted to a `capa.exe` worker (deduped by path); matched capabilities surface as High-severity events in the TUI and JSONL telemetry
- Deterministic severity scoring with live UI security score
- PID-level short-window correlation alerts across detection methods

### ETW Integration

#### Kernel as ETW Provider
- Driver registers as an ETW provider (GUID `D6E3E932-B0B9-4E8C-A2C3-F7A9B8C5D4E1`) via `EtwRegister` at load time
- Every detection notification dequeued from the kernel ring is simultaneously written to ETW via `EtwWrite` — enables external consumers (xperf, WPA, SIEMs) without the TUI running
- Six event IDs map to detection families: Hook(1), PE/VAD(2), Process(3), AMSI(4), Syscall(5), Generic(6)
- Fields per event: process name, message, PID, scooped address

#### ETW-TI Consumer (Microsoft-Windows-Threat-Intelligence)
- Starts a real-time ETW session for `{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}` via `StartTrace` + `EnableTraceEx2`
- Surfaces remote injection operations: `AllocVM-Remote`, `ProtectVM-Remote`, `MapView-Remote`, `QueueUserAPC-Remote`, `SetThreadContext-Remote`, `WriteVM-Remote`, `ReadVM-Remote`
- Falls back gracefully with an informational message if the process lacks PPL or `SeSystemEnvironmentPrivilege`

#### Additional ETW Consumers
- **PowerShell script-block logging** — `Microsoft-Windows-PowerShell/Operational` EID 4104; script content routed through Sigma-Lite rule engine
- **DNS-Client queries** — `Microsoft-Windows-DNS-Client/Operational` EID 3006; query names routed through Sigma for DGA/C2 detection; enables the channel automatically if disabled
- **WinRM lateral movement** — `Microsoft-Windows-WinRM/Operational` EIDs 6, 8, 91, 132; flags WSMan session creation and HTTP requests as Medium/Low severity

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
