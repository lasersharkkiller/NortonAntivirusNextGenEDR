@echo off
setlocal enabledelayedexpansion

REM Find Visual Studio installation
for /f "usebackq tokens=*" %%i in (`vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VS_PATH=%%i"

if not defined VS_PATH (
    echo Visual Studio not found
    exit /b 1
)

echo Found Visual Studio at: !VS_PATH!

REM Set up environment
call "!VS_PATH!\VC\Auxiliary\Build\vcvars64.bat"

REM Build the solution
cd /d "D:\githubProjects\NortonEDR"
msbuild NortonEDR.sln /p:Configuration=Debug /p:Platform=x64 /m

endlocal
