@echo off
setlocal enabledelayedexpansion

REM Set up environment using known VS2022 paths
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" 2>nul

REM Build the solution
cd /d "D:\githubProjects\NortonEDR"
msbuild NortonEDR.sln /p:Configuration=Debug /p:Platform=x64 /m

endlocal
