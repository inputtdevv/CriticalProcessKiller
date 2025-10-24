# CriticalProcessKiller

To add a file to critical process check out my other [repo](https://github.com/inputtdevv/SetCriticalProcess/tree/main)


**Made by Inputt Please star my repo!**  
GitHub: [https://github.com/inputtdevv/CriticalProcessKiller](https://github.com/inputtdevv/CriticalProcessKiller/)

A C# tool designed to terminate **critical Windows processes safely** by disabling the critical process flag before killing them. Useful for testing, debugging, or managing stubborn processes that normally cannot be terminated.

> ⚠️ **Warning:** Killing critical system processes can crash your system. Use this tool **responsibly** at your own risk I am not liable for any damages caused.

---

## Features

- Detects if the process is critical and disables the critical flag safely.
- Works only when run with **Administrator privileges**.
- Requires **SeDebugPrivilege** to terminate protected processes.
- Console UI with a gradient-style text display.
- Prompts for confirmation before killing the target process.

---

## How It Works

This tool leverages Windows API calls and P/Invoke to interact with processes:

1. **Check Admin Rights**:  
   The program checks if it is running as Administrator. If not, it relaunches itself with elevated privileges.

2. **Enable Debug Privilege**:  
   Grants the program `SeDebugPrivilege` using `OpenProcessToken`, `LookupPrivilegeValue`, and `AdjustTokenPrivileges`.  
   This allows it to access and modify protected processes.

3. **Read PID**:  
   Prompts the user to enter the PID of the target process.

4. **Check if Critical**:  
   Uses `NtSetInformationProcess` from `ntdll.dll` to check if the process has the **BreakOnTermination** flag (critical process).

5. **Disable Critical Flag (if needed)**:  
   If the target is critical, the program disables the flag to avoid a system crash.

6. **Terminate Process**:  
   Prompts for confirmation, then kills the process with `Process.Kill()`.

7. **Output Status**:  
   Provides feedback in color-coded console output for success, warnings, and errors.

---

## Requirements

- Windows OS
- .NET Framework (any modern version supporting P/Invoke)
- Administrator privileges to access protected processes

---

## Usage

 1. Clone the repository:

```bash
git clone https://github.com/inputtdevv/CriticalProcessKiller.git
```
2. Build it into an exe with Visual Studio

3. Run the executable.
