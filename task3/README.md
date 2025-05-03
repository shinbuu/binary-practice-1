# Assignment 3: Dynamic Malware Analysis

**Objective:**  
Study of advanced dynamic malware analysis techniques, including sandbox setup, anti-debugging bypass, API tracing, and network communication analysis.

## Tasks Overview

### Task 1: Setting Up a Complex Sandbox  
**File:** `eicar.com`  
- Set up a Windows 10 VM to emulate a real work environment.  
- Installed Cuckoo Sandbox for automated malware analysis.  
- Integrated API Monitor and FakeNet-NG for API call tracing and network traffic interception.  
- Modified system parameters to bypass detection by the `eicar.com` test file.  
- **Result:** A fully functional sandbox undetectable by the test file.


### Task 3: Bypassing Anti-Debugging Techniques  
**File:** `ice9.exe`  
- Opened `ice9.exe` in x64dbg and WinDbg.  
- Identified anti-debugging functions such as `IsDebuggerPresent`.  
- Modified the executable code by NOP'ing out the anti-debugging checks.  
- Relaunched the file under the debugger.  
- **Result:** Successfully bypassed anti-debugging measures and ran the executable under debugging conditions.

