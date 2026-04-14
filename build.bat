@echo off
cd /d "D:\githubProjects\NortonEDR"
msbuild NortonEDR.sln /p:Configuration=Debug /p:Platform=x64
