#pragma once

#ifdef HOOKDLL_EXPORTS
#define HOOKDLL_API __declspec(dllexport)
#else
#define HOOKDLL_API __declspec(dllimport)
#endif

// IAT-hook engine.
// InstallHooks patches every currently-loaded module's IAT and opens a named
// pipe connection to the NortonEDR process for telemetry reporting.
// RemoveHooks restores all original IAT entries and closes the pipe.

extern "C" {
    HOOKDLL_API void InstallHooks();
    HOOKDLL_API void RemoveHooks();
}
