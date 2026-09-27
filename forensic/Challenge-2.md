# Forensic Challenge 2 — Tampered Account SID

## Question

What are the last eight digits of the tampered user account's Security Identifier (SID)?

## Write-up

To identify the tampered account, I examined the PowerShell command history located at `C:\Users\forensic\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`. The history contained commands showing that the `forensic` account and its profile directory were deleted, after which an account with the same name was recreated and added to the Administrators group. This established `forensic` as the tampered account.

Although the account had been recreated, remnants associated with its original SID remained in the user's DPAPI and RSA directories. The paths under `C:\Users\forensic\AppData\Roaming\Microsoft\Protect\` and `C:\Users\forensic\AppData\Roaming\Microsoft\Crypto\RSA\` contained the SID `S-1-5-21-1883243207-2011820343-4193110713-1001`. Taking the final eight numeric digits of the SID, while excluding the separator, produces `07131001`.

## Answer

```text
07131001
```

## Flag

```text
bcsctf{07131001}
```
