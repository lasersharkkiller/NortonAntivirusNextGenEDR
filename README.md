# NortonAntivirusNextGenEDR

A Windows kernel-mode EDR featuring kernel-level telemetry, hook detection, process & PE scanning, AMSI bypass detection, user-mode API interception, ETW integration, YARA/Sigma/Capa detection engines, and Sysmon/SACL enrichment — built for defensive lab environments.

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
- **Section entropy analysis** — Shannon entropy computed per section; alerts at ≥ 7.2 bits/byte (packed/encrypted code)
- **Section anomaly checks** — writable+executable sections (W+X), raw size < virtual size/2 flagged per section
- **TLS callback detection** — `IMAGE_DIRECTORY_ENTRY_TLS` parsed; alerts if `AddressOfCallBacks` is non-zero (TLS injection vector)
- **Import hash (imphash)** — MD5 of sorted `module.funcname` pairs computed for every flagged PE; surfaced as Info event for threat-intel correlation alongside SHA256
- **LOLDrivers hash matching** — SHA256 of loaded `.sys` files checked against hash database in addition to filename lookup; catches renamed known-bad drivers

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

### User-Mode API Hook DLL (`HookDll.dll`)

- Standalone injectable DLL with dual-layer hook engine (IAT patching + inline prologue hooks) targeting 13 Win32/Native APIs
- **Monitored APIs**: `VirtualAlloc` (RWX), `VirtualAllocEx` (remote), `WriteProcessMemory`, `CreateRemoteThread`, `CreateRemoteThreadEx`, `LoadLibraryA/W/ExA/ExW`, `ResumeThread` (cross-process), `SetThreadContext` (cross-process), `RegSetValueExA/W`
- `WriteProcessMemory` hook checks written data for an MZ/PE signature and tags the event
- `SetThreadContext` hook extracts the new RIP from the `CONTEXT` struct and surfaces it
- `RegSetValueExA/W` hook flags known persistence value names (`Run`, `AppInit_DLLs`, etc.) at High severity; all other writes at Info
- **Inline hooks** patch each function's prologue with a 14-byte absolute `JMP [RIP+0]` + 8-byte address, catching callers who resolve APIs via `GetProcAddress` at runtime (IAT patching alone misses these); `IsSafeToCopy` rejects prologues containing relative branches or RIP-relative memory operands before patching
- **Trampolines** per hook: displaced prologue bytes (14) + `JMP` back to `target+14`; allocated in a single `PAGE_EXECUTE_READWRITE` pool; `GetCallThrough()` returns the trampoline when inline hooks are active so IAT stubs don't re-enter the patched prologue
- **SetWindowsHookEx** intentionally excluded — it reaches only GUI message-loop threads and is irrelevant for the targeted injection/persistence APIs
- Telemetry reported via named pipe `\\.\pipe\NortonEDR_HookDll` using a tab-delimited line protocol (`SEVERITY\tCALLER_PID\tAPI_NAME\tTARGET_PID\tDETAIL\n`)
- NortonEDR hosts a multi-client pipe server thread; each client connection is dispatched to a detached thread for concurrent handling
- `DllMain` calls `InstallHooks`/`RemoveHooks` automatically; exports allow explicit control
- **Kernel APC injection** — `DllInjector.cpp` hooks `ImageLoadNotifyRoutine`; on every `ntdll.dll` map the loading thread is used as the APC target (`PsGetCurrentThread()`); path buffer allocated in the target process via `ZwAllocateVirtualMemory(NtCurrentProcess())` while attached; `KeInitializeApc`/`KeInsertQueueApc` queues `LoadLibraryW(hookDllPath)` for user-mode delivery; system processes (`smss`, `csrss`, `wininit`, `lsass`) and NortonEDR itself are excluded
- **IOCTL `NORTONAV_SET_INJECT_CONFIG`** — at startup NortonEDR sends `LoadLibraryW` VA (valid in all processes — shared DLL section, boot-time ASLR only), HookDll full path, and own PID to the driver; injection activates automatically for all subsequent process creations

### Sysmon & SACL Integration
- Sysmon event ingestion for host-based telemetry enrichment
- SACL (System Access Control List) auditing for object-level access visibility
- Process context cache enrichment: parent PID and image path appended to detection details

### Logging & API
- Persistent JSONL telemetry logging to `nortonav_events.jsonl`
- Trace targeting (`--trace`) with optional child-process inheritance (`--trace-children`)
- Local REST API on `127.0.0.1` — endpoints: `/api/stats`, `/api/events`, `/api/processes`, `/api/reset`

### Elasticsearch Forwarding
- Background shipper thread batches detection events and POSTs to an Elasticsearch `/_bulk` endpoint via WinHTTP
- Events emitted as **ECS (Elastic Common Schema)** documents — `@timestamp`, `agent.name`, `host.name`, `event.kind/category/severity/action`, `process.pid`, `rule.name`, `message`, `nortonav.method`, `nortonav.details`
- Severity mapped to ECS numeric scale: Critical=100, High=75, Medium=50, Low=25, Info=10
- Configurable batch size (50 events) and flush interval (5 s); queue capped at 1 000 events
- Supports **API key** auth (`--elastic-api-key`) or **HTTP Basic** auth (`--elastic-user` / `--elastic-pass`); optional TLS verification skip (`--elastic-no-verify`) for self-signed certs
- Default index: `nortonav-edr`; enabled via `--elastic-host https://host:9200`

---

## Requirements

- Windows 10 20H1–22H2 test VM in `TESTSIGNING` mode
- Visual Studio 2022, C++20, WDK
- vcpkg with `yara` package installed
- `capa.exe` (FLARE) on `PATH` or alongside the NortonEDR binary for capabilities scanning

---

## Disclaimer

For educational and controlled lab use only.
