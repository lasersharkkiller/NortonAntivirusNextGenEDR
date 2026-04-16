// VS Code tunnel and extension abuse fingerprints. Recent campaigns (2024-
// 2025) use VS Code Remote Tunnels as a full-featured C2 channel: the
// attacker runs "code tunnel" on the victim, gets an authenticated browser
// shell through Azure Relay with TLS-encrypted traffic to Microsoft
// infrastructure — indistinguishable from legitimate developer usage at the
// network layer. Detection must happen at the endpoint.
//
// Tier: signal-only — VS Code tunnels are legitimate developer tools.
// Chain with: non-developer user, non-interactive parent (svchost, wmiprvse,
// scheduled task), unsigned/renamed binary, and outbound to
// tunnels.api.visualstudio.com / *.devtunnels.ms.

// ---------------------------------------------------------------------------
// VS Code tunnel launch — the canonical "code tunnel" / "code-tunnel" CLI
// invocation that creates the Azure Relay reverse tunnel.
// ---------------------------------------------------------------------------
rule VSCode_Tunnel_Launch
{
    meta:
        description = "VS Code tunnel CLI launch: code.exe tunnel / code-tunnel / devtunnel host — Azure Relay reverse tunnel (T1219.001)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        $t1  = "code.exe tunnel"                                       ascii nocase
        $t2  = "code tunnel"                                           ascii nocase
        $t3  = "code-tunnel"                                           ascii nocase
        $t4  = "code-insiders.exe tunnel"                              ascii nocase
        $t5  = "code-insiders tunnel"                                  ascii nocase
        $t6  = "devtunnel host"                                        ascii nocase
        $t7  = "devtunnel.exe host"                                    ascii nocase
        $t8  = "code serve-web"                                        ascii nocase
        $t9  = "code.exe serve-web"                                    ascii nocase
        $t10 = "tunnel --accept-server-license-terms"                  ascii nocase
        $t11 = "tunnel --name"                                         ascii nocase

        // Wide forms for PowerShell / script in-memory buffers
        $t1w = "code.exe tunnel"                                       wide nocase
        $t3w = "code-tunnel"                                           wide nocase
        $t6w = "devtunnel host"                                        wide nocase

    condition:
        any of them
}


// ---------------------------------------------------------------------------
// VS Code tunnel service persistence. "code tunnel service install"
// registers a Windows service or systemd unit that auto-starts the tunnel
// on boot — persistent C2 without scheduled tasks or Run keys.
// ---------------------------------------------------------------------------
rule VSCode_Tunnel_Service_Persistence
{
    meta:
        description = "VS Code tunnel service install — persistent tunnel registration (T1219.001 + T1543)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        $s1 = "tunnel service install"                                 ascii nocase
        $s2 = "tunnel service uninstall"                               ascii nocase
        $s3 = "code_tunnel.service"                                    ascii nocase
        $s4 = "code-tunnel-service"                                    ascii nocase

        $s1w = "tunnel service install"                                wide nocase

    condition:
        any of them
}


// ---------------------------------------------------------------------------
// VS Code silent extension sideloading. Attackers push trojanized .vsix
// files via "code --install-extension <path>" or override the extension
// directory to load malicious extensions from an attacker-controlled path.
// ---------------------------------------------------------------------------
rule VSCode_Extension_Sideload
{
    meta:
        description = "VS Code silent extension install or directory override — extension sideloading (T1059 + T1176)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        $e1 = "--install-extension"                                    ascii nocase
        $e2 = "code --install-extension"                               ascii nocase
        $e3 = "code.exe --install-extension"                           ascii nocase
        $e4 = "code-insiders --install-extension"                      ascii nocase
        $e5 = "--extensions-dir"                                       ascii nocase
        $e6 = "code --extensions-dir"                                  ascii nocase

        // .vsix file reference (zipped extension package)
        $vsix = ".vsix"                                                ascii nocase

        // Known malicious extension patterns
        $mal1 = "ms-python.python-"                                    ascii nocase
        $mal2 = "ms-toolsai.jupyter-"                                  ascii nocase

    condition:
        any of ($e*) or ($vsix and any of ($e*))
}


// ---------------------------------------------------------------------------
// Electron run-as-node escape. The flag --ms-enable-electron-run-as-node
// turns code.exe into a full Node.js runtime, allowing arbitrary JS
// execution from what appears to be a signed Microsoft binary. Used by
// attackers to run malicious scripts under code.exe's digital signature.
// ---------------------------------------------------------------------------
rule VSCode_Electron_RunAsNode
{
    meta:
        description = "Electron --ms-enable-electron-run-as-node — code.exe used as signed Node.js runtime for script execution"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        $r1 = "--ms-enable-electron-run-as-node"                       ascii nocase
        $r2 = "ELECTRON_RUN_AS_NODE"                                   ascii nocase
        $r3 = "ELECTRON_RUN_AS_NODE=1"                                 ascii nocase
        $r4 = "VSCODE_AMD_ENTRYPOINT"                                 ascii nocase

        $r1w = "--ms-enable-electron-run-as-node"                      wide nocase
        $r2w = "ELECTRON_RUN_AS_NODE"                                  wide nocase

    condition:
        any of them
}


// ---------------------------------------------------------------------------
// VS Code tunnel infrastructure domains. Scripts or configs that reference
// the Azure Relay / Dev Tunnels endpoints used by VS Code tunnels. At the
// network layer these are indistinguishable from legitimate traffic; finding
// the domain string in a script, .bat, .ps1, or task scheduler XML is the
// signal.
// ---------------------------------------------------------------------------
rule VSCode_Tunnel_Infrastructure_Reference
{
    meta:
        description = "VS Code tunnel infrastructure domain reference in script or config — tunnels.api.visualstudio.com / *.devtunnels.ms"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "medium"
        scan_target = "file,process_memory"

    strings:
        $d1 = "tunnels.api.visualstudio.com"                           ascii nocase
        $d2 = ".devtunnels.ms"                                         ascii nocase
        $d3 = "global-relay.codedev.ms"                                ascii nocase
        $d4 = "vscode-remote://"                                       ascii nocase
        $d5 = "tunnel-relay.azurewebsites.net"                         ascii nocase
        $d6 = ".tunnels.api.visualstudio.com"                          ascii nocase

    condition:
        any of them
}


// ---------------------------------------------------------------------------
// VS Code tasks.json / launch.json auto-exec. A malicious .vscode/
// directory dropped into a project can auto-execute commands when the
// project is opened (shellCommand, preLaunchTask, command fields). Often
// paired with social engineering ("clone this repo and open in VS Code").
// ---------------------------------------------------------------------------
rule VSCode_TasksJson_AutoExec
{
    meta:
        description = "VS Code tasks.json / launch.json with shell command auto-execution — repo-level code execution (T1059)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file"

    strings:
        // tasks.json markers
        $t1 = "\"type\": \"shell\""                                    ascii nocase
        $t2 = "\"command\":"                                           ascii nocase
        $t3 = "\"tasks\":"                                             ascii nocase
        $t4 = "\"runOn\": \"folderOpen\""                              ascii nocase
        $t5 = "\"isBackground\": true"                                 ascii nocase

        // Dangerous command payloads inside tasks/launch
        $c1 = "cmd.exe"                                                ascii nocase
        $c2 = "powershell"                                             ascii nocase
        $c3 = "curl "                                                  ascii nocase
        $c4 = "wget "                                                  ascii nocase
        $c5 = "Invoke-WebRequest"                                      ascii nocase
        $c6 = "certutil"                                               ascii nocase
        $c7 = "bitsadmin"                                              ascii nocase
        $c8 = "mshta"                                                  ascii nocase
        $c9 = "/bin/bash"                                              ascii nocase

        // launch.json preLaunchTask / postDebugTask
        $l1 = "\"preLaunchTask\""                                      ascii nocase
        $l2 = "\"postDebugTask\""                                      ascii nocase

    condition:
        ($t1 and $t2 and $t3 and any of ($c*))
        or ($t4 and $t2 and any of ($c*))
        or (($l1 or $l2) and $t2 and any of ($c*))
}
