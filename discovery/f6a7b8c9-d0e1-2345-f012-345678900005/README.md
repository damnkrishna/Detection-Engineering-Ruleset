# Device Driver Enumeration (AN2092)

## Metadata
- **Rule ID**: f6a7b8c9-d0e1-2345-f012-345678900005
- **Technique**: T1652

## Details
Detects command-line utilities enumerating installed device drivers, used to identify security software or kernel exploitation targets. Covers renamed binaries via OriginalFileName to resist trivial binary-rename evasion.
