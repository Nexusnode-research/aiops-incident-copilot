# Windows OpenSSH Key Authentication Fix

**Date:** 2025-12-30
**Status:** Resolved
**Components:** Windows Server (DC), Windows Client (PC1), OpenSSH Server

## Problem
SSH connections to Windows hosts (DC and PC1) consistently prompted for passwords, failing to utilize SSH key authentication despite keys being present.

## Root Cause
On Windows OpenSSH, accounts in the **Administrators** group are forced to use the default administrative authorized keys file:
`C:\ProgramData\ssh\administrators_authorized_keys`

For authentication to succeed, this file must:
1. Be **ASCII** encoded (UTF-8 or UTF-16 will fail).
2. Have precise **ACLs** (Access Control Lists).
   - `SYSTEM`: Full Control
   - `Administrators`: Full Control
   - No inheritance
   - No other users

If these conditions are not met, OpenSSH ignores the file and falls back to password authentication.

## Fix
The following steps were executed on each Windows host (DC and PC1) as Administrator:

### 1. Configure Admin Keys File
Write the public key to the correct location with ASCII encoding.

```powershell
$pub  = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI... aiops-lab' # Replace with actual public key
$path = "$env:ProgramData\ssh\administrators_authorized_keys"
Set-Content -Encoding ascii -Path $path -Value $pub.Trim()
```

### 2. Fix Permissions (ACLs)
Remove inheritance and restrict access to only System and Administrators.

```powershell
icacls $path /inheritance:r | Out-Null
icacls $path /grant "BUILTIN\Administrators:(F)" "NT AUTHORITY\SYSTEM:(F)" | Out-Null
```

### 3. Restart SSHD
Apply the changes by restarting the service.

```powershell
Restart-Service sshd
```

## Verification
### Server-side Check
Verify the key file fingerprint matches the private key.
```powershell
& "$env:WINDIR\System32\OpenSSH\ssh-keygen.exe" -lf $path
```

### Client-side Connection
Connect without password prompts:
```powershell
ssh -o IdentitiesOnly=yes -i $env:USERPROFILE\.ssh\aiops_lab dc "whoami"
ssh -o IdentitiesOnly=yes -i $env:USERPROFILE\.ssh\aiops_lab pc1 "whoami"
```

## Result
Both DC and PC1 now authenticate via **publickey** successfully.

## Notes
- `StrictModes no` was temporarily set in `sshd_config` during debugging, but the definitive fix was the **ASCII encoding** and **ACLs** on the key file.
