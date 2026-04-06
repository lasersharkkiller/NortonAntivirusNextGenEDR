import subprocess

# Search for SetupBuildEnv.cmd across drives
for drive in ['C', 'D', 'E', 'F', 'G']:
    result = subprocess.run(
        ['cmd.exe', '/c', f'dir /b /s {drive}:\\SetupBuildEnv.cmd 2>nul'],
        capture_output=True, text=True, timeout=15
    )
    if result.stdout.strip():
        print(f'{drive}: FOUND -', result.stdout.strip())
    else:
        print(f'{drive}: not found')

# Also check PATH for msbuild
result2 = subprocess.run(
    ['cmd.exe', '/c', 'set PATH'],
    capture_output=True, text=True, timeout=10
)
print('\nPATH contains:', [l for l in result2.stdout.splitlines() if 'PATH' in l.upper()][:5])
