# Forensic Challenge 1 — Workstation Hostname

## Question

What is the exact hostname of the investigated Windows workstation?

## Write-up

The supplied `BCSCTF.7z` archive contained a segmented EnCase disk image consisting of `bcsctf.E01` through `bcsctf.E06`. I loaded `bcsctf.E01` into FTK Imager, which automatically detected the remaining segments. From the Windows partition, I exported the `C:\Windows\System32\config\SYSTEM` registry hive and opened it in Registry Explorer. The `SYSTEM\Select` key showed that `ControlSet001` was the active control set. I then navigated to `ControlSet001\Control\ComputerName\ComputerName`, where the `ComputerName` value revealed the workstation's exact hostname as `DESKTOP-N106FR1`. The result could also be corroborated using the hostname information stored under `ControlSet001\Services\Tcpip\Parameters`.

## Answer

```text
DESKTOP-N106FR1
```

## Flag

```text
bcsctf{DESKTOP-N106FR1}
```
