# VibeRATor

VibeRATor is an insanely basic Windows RAT that I vibe coded with Copilot. This took me like 20 minutes to make.

## Build and Install
1. Install Visual Studio Build Tools or MSVC.
2. Compile:
- Open Developer Command Prompt and run: cl /EHsc /MD main.cpp iphlpapi.lib ws2_32.lib Shlwapi.lib
3. Create install locations and registry key for token:
- Create folder C:\AgentFiles and ensure service account has write access.
- Set token: run elevated PowerShell: New-Item -Path "HKLM:\SOFTWARE\AgentExample" -Force | Out-Null; Set-ItemProperty -Path "HKLM:\SOFTWARE\AgentExample" -Name "Token" -Value "your-secret-token"
4. Install as service (simplest: use sc to run as own process via srvany or implement service framework). For testing, run the EXE elevated; for production, wrap into a proper Windows Service or use NSSM:
- Using NSSM: nssm install AgentExample "C:\path\to\agent.exe"
- Ensure firewall allows inbound access only as required; prefer loopback and use reverse tunnel if remote reach is needed.

