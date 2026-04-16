// Fileless in-memory-script fingerprints. Catches the PowerShell / .NET
// runtime-hosting shapes that let attackers keep second-stage source as a
// string inside the host process — constructed, compiled, and executed
// without ever touching disk, the scriptblock cache, or MOTW.
//
// Scan targets include process_memory (primary) and file (for stager scripts
// that build the in-memory payload). EID 4104 script-block logging feeds
// these rules through the same Sigma-Lite pipeline once the AMSI-captured
// content lands.
//
// Tier: signal-only — ScriptBlock::Create and Runspace hosting have benign
// uses in module authors, DSC, remoting, test harnesses, and RMM agents.
// Chain with parentage, path, and network context.

// ---------------------------------------------------------------------------
// [ScriptBlock]::Create / $ExecutionContext in-memory compile & execute.
// The canonical "payload is a string variable, then executed" shape. Every
// fileless PS loader eventually reaches this primitive: Empire's Invoke-
// Empire launchers, Covenant's PS stagers, Cobalt Strike PS profiles, and
// commodity stealers that reflectively unpack a second stage.
// ---------------------------------------------------------------------------
rule Fileless_PS_ScriptBlock_Create_Invoke
{
    meta:
        description = "In-memory-only PS script execution: [ScriptBlock]::Create / $ExecutionContext.InvokeCommand.InvokeScript / NewScriptBlock (T1059.001 + T1027.011)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        // Core primitives
        $sb1 = "[ScriptBlock]::Create("                                               ascii nocase
        $sb2 = "[System.Management.Automation.ScriptBlock]::Create("                  ascii nocase
        $sb3 = "$ExecutionContext.InvokeCommand.InvokeScript("                        ascii nocase
        $sb4 = "$ExecutionContext.InvokeCommand.NewScriptBlock("                      ascii nocase
        $sb5 = "$ExecutionContext.SessionState.InvokeCommand.InvokeScript("           ascii nocase
        $sb6 = ".InvokeCommand.InvokeScript("                                         ascii nocase
        $sb7 = ".NewScriptBlock("                                                     ascii nocase

        // Dot-source / call-operator invocation of a constructed scriptblock
        $call1 = "& ([ScriptBlock]::Create("                                          ascii nocase
        $call2 = ". ([ScriptBlock]::Create("                                          ascii nocase
        $call3 = "(([ScriptBlock]::Create("                                           ascii nocase

        // AST / Parser construction (fileless via language services)
        $ast1 = "[System.Management.Automation.Language.Parser]::ParseInput("         ascii nocase
        $ast2 = "[Parser]::ParseInput("                                               ascii nocase
        $ast3 = ".Ast.GetScriptBlock()"                                               ascii nocase

        // IEX of a variable — the payload lives as string data, not as a file
        $iex_var1 = /Invoke-Expression\s+\$[A-Za-z_][A-Za-z0-9_]{0,32}\s*$/           nocase
        $iex_var2 = /\biex\s+\$[A-Za-z_][A-Za-z0-9_]{0,32}/                           nocase
        $iex_var3 = /\|\s*iex\s*\b/                                                   nocase

        // Wide forms for in-memory PS host buffers
        $sb1w = "[ScriptBlock]::Create("                                              wide  nocase
        $sb3w = "$ExecutionContext.InvokeCommand.InvokeScript("                       wide  nocase
        $call1w = "& ([ScriptBlock]::Create("                                         wide  nocase

    condition:
        any of ($sb*) or any of ($call*) or any of ($ast*)
        or (any of ($iex_var*))
        or any of ($sb1w, $sb3w, $call1w)
}


// ---------------------------------------------------------------------------
// Embedded-runspace / PowerShell-Hosting fileless pattern. An attacker that
// wants to run PS without powershell.exe hosts the runtime inline:
//   [PowerShell]::Create().AddScript($s).Invoke()
// This is the canonical "unmanaged PowerShell" shape (UnmanagedPowerShell,
// NPS, p0wnedShell, Nishang/PowerLessShell). By rule, they never touch disk.
// ---------------------------------------------------------------------------
rule Fileless_PS_Embedded_Runspace_Host
{
    meta:
        description = "Embedded PowerShell runspace host: [PowerShell]::Create().AddScript().Invoke() / RunspaceFactory — unmanaged fileless PS (T1059.001)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        $h1 = "[PowerShell]::Create()"                                                ascii nocase
        $h2 = "[System.Management.Automation.PowerShell]::Create()"                   ascii nocase
        $h3 = "[RunspaceFactory]::CreateRunspace"                                     ascii nocase
        $h4 = "[RunspaceFactory]::CreateRunspacePool"                                 ascii nocase
        $h5 = "[System.Management.Automation.Runspaces.RunspaceFactory]"              ascii nocase

        $a1 = ".AddScript("                                                           ascii nocase
        $a2 = ".AddCommand("                                                          ascii nocase
        $a3 = ".AddArgument("                                                         ascii nocase
        $a4 = ".Invoke()"                                                             ascii nocase
        $a5 = ".BeginInvoke("                                                         ascii nocase

        // Wide
        $h1w = "[PowerShell]::Create()"                                               wide nocase
        $a1w = ".AddScript("                                                          wide nocase

        // Managed C# importing System.Management.Automation to host PS inline
        $ref1 = "System.Management.Automation.dll"                                    ascii nocase
        $ref2 = "using System.Management.Automation"                                  ascii nocase

    condition:
        (any of ($h*) and any of ($a*))
        or ($h1w and $a1w)
        or (($ref1 or $ref2) and any of ($a*))
}


// ---------------------------------------------------------------------------
// Rebuilt-from-bytes script — the payload is an encoded string literal that
// gets decoded (base64, XOR, gzip, AES) into a PS source string which is
// then piped to IEX or fed to ScriptBlock::Create. This is the shape that
// survives even with AMSI enabled until the final decode lands in the AMSI
// buffer; catching it at rest surfaces the stager.
// ---------------------------------------------------------------------------
rule Fileless_PS_Decoded_String_Execute
{
    meta:
        description = "Encoded-string → decode → IEX / ScriptBlock::Create chain — fileless script rebuilt from bytes (T1027.011)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "high"
        scan_target = "file,process_memory"

    strings:
        // Decoders that produce a script string
        $d1 = "[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String"  ascii nocase
        $d2 = "[System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String"     ascii nocase
        $d3 = "[System.Text.Encoding]::ASCII.GetString([Convert]::FromBase64String"    ascii nocase
        $d4 = "[Text.Encoding]::Unicode.GetString([Convert]::FromBase64String"         ascii nocase
        $d5 = "[System.IO.Compression.GzipStream]"                                     ascii nocase
        $d6 = "[System.IO.Compression.DeflateStream]"                                  ascii nocase
        $d7 = "[System.Security.Cryptography.Aes]::Create()"                           ascii nocase
        $d8 = "[System.Security.Cryptography.Rijndael]"                                ascii nocase

        // Executor landings
        $e1 = "| IEX"                                                                  ascii nocase
        $e2 = "|IEX"                                                                   ascii nocase
        $e3 = "Invoke-Expression ("                                                    ascii nocase
        $e4 = "[ScriptBlock]::Create("                                                 ascii nocase
        $e5 = "$ExecutionContext.InvokeCommand.InvokeScript("                          ascii nocase

        $d1w = "[System.Text.Encoding]::Unicode.GetString([Convert]::FromBase64String" wide nocase
        $e1w = "| IEX"                                                                 wide nocase

    condition:
        (any of ($d*) and any of ($e*))
        or ($d1w and $e1w)
}


// ---------------------------------------------------------------------------
// Fileless .NET assembly load from in-memory byte buffer. The managed-side
// twin of reflective DLL injection — Assembly.Load(byte[]) / AppDomain.Load
// of a buffer that was decoded/decrypted/downloaded in the same process.
// Once loaded, ::EntryPoint.Invoke($null, $args) kicks execution.
// ---------------------------------------------------------------------------
rule Fileless_DotNet_Assembly_Load_Bytes
{
    meta:
        description = "Managed .NET assembly loaded from an in-memory byte buffer — fileless .NET stager (T1620)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "critical"
        scan_target = "file,process_memory"

    strings:
        $l1 = "[Reflection.Assembly]::Load($"                                         ascii nocase
        $l2 = "[System.Reflection.Assembly]::Load($"                                  ascii nocase
        $l3 = "[AppDomain]::CurrentDomain.Load($"                                     ascii nocase
        $l4 = "[Reflection.Assembly]::Load([Convert]::FromBase64String"               ascii nocase
        $l5 = "[System.Reflection.Assembly]::Load([Convert]::FromBase64String"        ascii nocase
        $l6 = "Assembly.Load(bytes"                                                   ascii nocase
        $l7 = "::Load((New-Object Net.WebClient).DownloadData"                        ascii nocase

        $i1 = "::EntryPoint.Invoke("                                                  ascii nocase
        $i2 = ".GetType("                                                             ascii nocase
        $i3 = ".GetMethod("                                                           ascii nocase
        $i4 = ".InvokeMember("                                                        ascii nocase

        $l1w = "[Reflection.Assembly]::Load($"                                        wide nocase

    condition:
        any of ($l*) or $l1w
        or (($i1 or $i2 or $i3 or $i4) and any of ($l*))
}


// ---------------------------------------------------------------------------
// Invoke-Command / Invoke-Expression against a scriptblock variable — the
// "script lives in $sb, never in a .ps1" pattern, widely used by operator
// frameworks and hands-on-keyboard actors pasting scriptblocks into a live
// shell. Pair with a long string assignment nearby for higher precision.
// ---------------------------------------------------------------------------
rule Fileless_PS_Invoke_Against_Variable
{
    meta:
        description = "Invoke-Command / IEX against a scriptblock variable — payload lives in memory only (T1059.001 + T1027.011)"
        author      = "NortonEDR"
        tier        = "signal-only"
        severity    = "medium"
        scan_target = "file,process_memory"

    strings:
        $ic1 = /Invoke-Command\s+-ScriptBlock\s+\$[A-Za-z_][A-Za-z0-9_]{0,32}/        nocase
        $ic2 = /Invoke-Command\s+-ComputerName\s+\$?[A-Za-z0-9_.-]{1,64}\s+-ScriptBlock\s+\$/ nocase
        $ic3 = /icm\s+-ScriptBlock\s+\$/                                              nocase
        $ic4 = /\&\s*\$[A-Za-z_][A-Za-z0-9_]{0,32}\s*$/                               nocase
        $ic5 = /\.\s*\$[A-Za-z_][A-Za-z0-9_]{0,32}\s*$/                               nocase

        // Large string literal (>1KB) near an IEX — common fileless stager shape
        $large_str = /\$[A-Za-z_][A-Za-z0-9_]{0,32}\s*=\s*'[^']{1024,}'/              nocase

        $iex = /\|\s*iex\b/                                                           nocase

    condition:
        any of ($ic*)
        or ($large_str and $iex)
}
